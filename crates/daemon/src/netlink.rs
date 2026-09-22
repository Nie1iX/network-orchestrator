//! rtnetlink executor. Message building and errno mapping are pure and
//! unit-tested; the socket lives in a dedicated actor thread with its own
//! `current_thread` runtime, so synchronous callers never nest `block_on`.

use crate::core::LinkExecutor;
use ipnet::IpNet;
use net_manager_core::models::AppliedRoute;
use net_manager_core::policy::RouteExecutor;
use netlink_packet_route::link::{LinkFlag, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::AddressFamily;
use std::ffi::CString;
use std::io;
use std::net::IpAddr;
use std::sync::mpsc;
use tokio::sync::mpsc as async_mpsc;

/// `RTPROT` stamped on every route the daemon installs; deletes filter on
/// it, so routes installed by anyone else are never removed.
pub const RTPROT_NETWORK_ORCHESTRATOR: u8 = 79;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOp {
    Add,
    Delete,
}

/// Build the `RTM_NEWROUTE`/`RTM_DELROUTE` body for `route`. Adds go out
/// with `NLM_F_EXCL` (rtnetlink's default), so an existing identical route
/// is a conflict rather than being taken over.
pub fn route_request(route: &AppliedRoute, op: RouteOp) -> RouteMessage {
    let mut message = RouteMessage::default();
    let header = &mut message.header;
    header.protocol = RouteProtocol::from(RTPROT_NETWORK_ORCHESTRATOR);
    header.kind = RouteType::Unicast;
    header.destination_prefix_length = route.destination.prefix_len();
    header.table = RouteHeader::RT_TABLE_MAIN;
    header.scope = match (op, route.destination, route.gateway) {
        // Like `ip route del`: match whatever scope the route has.
        (RouteOp::Delete, _, _) => RouteScope::NoWhere,
        (RouteOp::Add, IpNet::V4(_), None) => RouteScope::Link,
        (RouteOp::Add, _, _) => RouteScope::Universe,
    };
    match route.destination {
        IpNet::V4(net) => {
            header.address_family = AddressFamily::Inet;
            message
                .attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet(
                    net.network(),
                )));
        }
        IpNet::V6(net) => {
            header.address_family = AddressFamily::Inet6;
            message
                .attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet6(
                    net.network(),
                )));
        }
    }
    match route.table {
        None => {}
        Some(table) if table <= 255 => message.header.table = table as u8,
        Some(table) => {
            message.header.table = RouteHeader::RT_TABLE_UNSPEC;
            message.attributes.push(RouteAttribute::Table(table));
        }
    }
    message
        .attributes
        .push(RouteAttribute::Oif(route.interface_index));
    message
        .attributes
        .push(RouteAttribute::Priority(route.metric));
    if let Some(gateway) = route.gateway {
        let address = match gateway {
            IpAddr::V4(addr) => RouteAddress::Inet(addr),
            IpAddr::V6(addr) => RouteAddress::Inet6(addr),
        };
        message.attributes.push(RouteAttribute::Gateway(address));
    }
    message
}

/// `RTM_SETLINK` body toggling only `IFF_UP`.
pub fn link_request(index: u32, up: bool) -> LinkMessage {
    let mut message = LinkMessage::default();
    message.header.index = index;
    if up {
        message.header.flags.push(LinkFlag::Up);
    }
    message.header.change_mask.push(LinkFlag::Up);
    message
}

pub fn classify_errno(errno: i32) -> io::ErrorKind {
    match errno {
        libc::EEXIST => io::ErrorKind::AlreadyExists,
        libc::ESRCH | libc::ENOENT | libc::ENODEV => io::ErrorKind::NotFound,
        libc::EPERM | libc::EACCES => io::ErrorKind::PermissionDenied,
        libc::EINVAL | libc::ENETUNREACH | libc::EHOSTUNREACH => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    }
}

pub fn netlink_error_to_io(err: rtnetlink::Error) -> io::Error {
    match err {
        rtnetlink::Error::NetlinkError(message) => {
            let errno = message.raw_code().abs();
            io::Error::new(classify_errno(errno), message.to_io().to_string())
        }
        other => io::Error::other(other.to_string()),
    }
}

enum Command {
    Route {
        op: RouteOp,
        route: AppliedRoute,
        reply: mpsc::Sender<io::Result<()>>,
    },
    Link {
        index: u32,
        up: bool,
        reply: mpsc::Sender<io::Result<()>>,
    },
}

/// Handle to the netlink actor thread. Cloneable; every call blocks the
/// calling (non-async) thread until the kernel answers.
#[derive(Clone)]
pub struct NetlinkExecutor {
    tx: async_mpsc::UnboundedSender<Command>,
}

impl NetlinkExecutor {
    /// Start the actor and open the rtnetlink socket. Needs no privileges
    /// to open; mutations need `CAP_NET_ADMIN`.
    pub fn spawn() -> io::Result<Self> {
        let (tx, rx) = async_mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = mpsc::channel::<io::Result<()>>();
        std::thread::Builder::new()
            .name("netlink-actor".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        let _ = ready_tx.send(Err(err));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let (connection, handle, _) = match rtnetlink::new_connection() {
                        Ok(parts) => parts,
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                            return;
                        }
                    };
                    tokio::spawn(connection);
                    let _ = ready_tx.send(Ok(()));
                    run_actor(handle, rx).await;
                });
            })?;
        ready_rx.recv().map_err(|_| actor_gone())??;
        Ok(Self { tx })
    }

    fn call(
        &self,
        command: impl FnOnce(mpsc::Sender<io::Result<()>>) -> Command,
    ) -> io::Result<()> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx.send(command(reply_tx)).map_err(|_| actor_gone())?;
        reply_rx.recv().map_err(|_| actor_gone())?
    }
}

async fn run_actor(handle: rtnetlink::Handle, mut rx: async_mpsc::UnboundedReceiver<Command>) {
    while let Some(command) = rx.recv().await {
        match command {
            Command::Route { op, route, reply } => {
                let message = route_request(&route, op);
                let result = match op {
                    RouteOp::Add => {
                        let mut request = handle.route().add();
                        *request.message_mut() = message;
                        request.execute().await
                    }
                    RouteOp::Delete => handle.route().del(message).execute().await,
                };
                let _ = reply.send(result.map_err(netlink_error_to_io));
            }
            Command::Link { index, up, reply } => {
                let mut request = handle.link().set(index);
                *request.message_mut() = link_request(index, up);
                let _ = reply.send(request.execute().await.map_err(netlink_error_to_io));
            }
        }
    }
}

fn actor_gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "netlink actor is not running")
}

impl RouteExecutor for NetlinkExecutor {
    fn add_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
        let route = route.clone();
        self.call(|reply| Command::Route {
            op: RouteOp::Add,
            route,
            reply,
        })
    }

    fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
        let route = route.clone();
        self.call(|reply| Command::Route {
            op: RouteOp::Delete,
            route,
            reply,
        })
    }
}

impl LinkExecutor for NetlinkExecutor {
    /// `name` is validated by `DaemonCore` before it gets here.
    fn set_link_state(&mut self, name: &str, up: bool) -> io::Result<()> {
        let c_name = CString::new(name).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
        })?;
        // SAFETY: `c_name` is a valid NUL-terminated string for the call.
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "interface not found",
            ));
        }
        self.call(|reply| Command::Link { index, up, reply })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteHeader};
    use netlink_packet_route::AddressFamily;
    use std::num::NonZeroI32;

    fn attrs(message: &RouteMessage) -> &[RouteAttribute] {
        &message.attributes
    }

    #[test]
    fn route_request_v4_on_link_has_link_scope_and_own_protocol() {
        let route = AppliedRoute::on_link("203.0.113.0/24".parse().unwrap(), 2, 5);
        let message = route_request(&route, RouteOp::Add);
        assert_eq!(message.header.address_family, AddressFamily::Inet);
        assert_eq!(message.header.destination_prefix_length, 24);
        assert_eq!(message.header.table, RouteHeader::RT_TABLE_MAIN);
        assert_eq!(u8::from(message.header.protocol), 79);
        assert_eq!(message.header.scope, RouteScope::Link);
        assert_eq!(message.header.kind, RouteType::Unicast);
        assert!(
            attrs(&message).contains(&RouteAttribute::Destination(RouteAddress::Inet(
                "203.0.113.0".parse().unwrap()
            )))
        );
        assert!(attrs(&message).contains(&RouteAttribute::Oif(2)));
        assert!(attrs(&message).contains(&RouteAttribute::Priority(5)));
        assert!(!attrs(&message)
            .iter()
            .any(|attr| matches!(attr, RouteAttribute::Gateway(_))));
    }

    #[test]
    fn route_request_v4_gateway_has_universe_scope() {
        let mut route = AppliedRoute::on_link("203.0.113.0/24".parse().unwrap(), 2, 5);
        route.gateway = Some("192.168.1.1".parse().unwrap());
        let message = route_request(&route, RouteOp::Add);
        assert_eq!(message.header.scope, RouteScope::Universe);
        assert!(
            attrs(&message).contains(&RouteAttribute::Gateway(RouteAddress::Inet(
                "192.168.1.1".parse().unwrap()
            )))
        );
    }

    #[test]
    fn route_request_v6_uses_inet6_and_universe_scope() {
        let mut route = AppliedRoute::on_link("2001:db8::/32".parse().unwrap(), 3, 7);
        route.gateway = Some("fe80::1".parse().unwrap());
        let message = route_request(&route, RouteOp::Add);
        assert_eq!(message.header.address_family, AddressFamily::Inet6);
        assert_eq!(message.header.destination_prefix_length, 32);
        assert_eq!(message.header.scope, RouteScope::Universe);
        assert!(
            attrs(&message).contains(&RouteAttribute::Destination(RouteAddress::Inet6(
                "2001:db8::".parse().unwrap()
            )))
        );
        assert!(
            attrs(&message).contains(&RouteAttribute::Gateway(RouteAddress::Inet6(
                "fe80::1".parse().unwrap()
            )))
        );
        assert!(attrs(&message).contains(&RouteAttribute::Oif(3)));
    }

    #[test]
    fn route_request_table_above_255_uses_table_attribute() {
        let mut route = AppliedRoute::on_link("10.0.0.0/8".parse().unwrap(), 2, 5);
        route.table = Some(51820);
        let message = route_request(&route, RouteOp::Add);
        assert_eq!(message.header.table, RouteHeader::RT_TABLE_UNSPEC);
        assert!(attrs(&message).contains(&RouteAttribute::Table(51820)));

        route.table = Some(100);
        assert_eq!(route_request(&route, RouteOp::Add).header.table, 100);
    }

    #[test]
    fn delete_request_matches_any_scope_but_only_own_protocol() {
        let route = AppliedRoute::on_link("203.0.113.0/24".parse().unwrap(), 2, 5);
        let message = route_request(&route, RouteOp::Delete);
        assert_eq!(message.header.scope, RouteScope::NoWhere);
        assert_eq!(
            u8::from(message.header.protocol),
            RTPROT_NETWORK_ORCHESTRATOR
        );
        assert!(attrs(&message).contains(&RouteAttribute::Priority(5)));
        assert!(attrs(&message).contains(&RouteAttribute::Oif(2)));
    }

    #[test]
    fn link_request_toggles_up_flag_with_change_mask() {
        let up = link_request(4, true);
        assert_eq!(up.header.index, 4);
        assert_eq!(up.header.flags, vec![LinkFlag::Up]);
        assert_eq!(up.header.change_mask, vec![LinkFlag::Up]);

        let down = link_request(4, false);
        assert!(down.header.flags.is_empty());
        assert_eq!(down.header.change_mask, vec![LinkFlag::Up]);
    }

    #[test]
    fn classify_errno_maps_kernel_errors() {
        assert_eq!(classify_errno(libc::EEXIST), io::ErrorKind::AlreadyExists);
        assert_eq!(classify_errno(libc::ESRCH), io::ErrorKind::NotFound);
        assert_eq!(classify_errno(libc::ENOENT), io::ErrorKind::NotFound);
        assert_eq!(classify_errno(libc::ENODEV), io::ErrorKind::NotFound);
        assert_eq!(classify_errno(libc::EPERM), io::ErrorKind::PermissionDenied);
        assert_eq!(
            classify_errno(libc::EACCES),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(classify_errno(libc::EINVAL), io::ErrorKind::InvalidInput);
        assert_eq!(
            classify_errno(libc::ENETUNREACH),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(classify_errno(libc::EBUSY), io::ErrorKind::Other);
    }

    #[test]
    fn netlink_error_uses_negative_kernel_code() {
        let mut err = rtnetlink::Error::NetlinkError(Default::default());
        if let rtnetlink::Error::NetlinkError(message) = &mut err {
            message.code = NonZeroI32::new(-libc::EEXIST);
        }
        assert_eq!(
            netlink_error_to_io(err).kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            netlink_error_to_io(rtnetlink::Error::RequestFailed).kind(),
            io::ErrorKind::Other
        );
    }
}
