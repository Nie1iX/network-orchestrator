//! rtnetlink executor. Message building and errno mapping are pure and
//! unit-tested; the socket lives in a dedicated actor thread with its own
//! `current_thread` runtime, so synchronous callers never nest `block_on`.

use crate::core::{LinkExecutor, PolicyRuleExecutor, WgSystem};
use futures::TryStreamExt;
use ipnet::IpNet;
use net_manager_core::daemon_protocol::{IpFamily, OwnedRuleResource};
use net_manager_core::models::AppliedRoute;
use net_manager_core::policy::RouteExecutor;
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkFlag, LinkInfo, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::rule::{RuleAction, RuleAttribute, RuleFlag, RuleMessage};
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

fn owned_route_snapshot(message: &RouteMessage) -> Option<AppliedRoute> {
    if message.header.protocol != RouteProtocol::from(RTPROT_NETWORK_ORCHESTRATOR)
        || message.header.kind != RouteType::Unicast
    {
        return None;
    }
    let destination = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(address)) => Some(IpAddr::V4(*address)),
            RouteAttribute::Destination(RouteAddress::Inet6(address)) => Some(IpAddr::V6(*address)),
            _ => None,
        })
        .or_else(|| {
            if message.header.destination_prefix_length != 0 {
                return None;
            }
            match message.header.address_family {
                AddressFamily::Inet => Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                AddressFamily::Inet6 => Some(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
                _ => None,
            }
        })?;
    let destination = IpNet::new(destination, message.header.destination_prefix_length)
        .ok()?
        .trunc();
    let interface_index = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })?;
    let metric = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Priority(metric) => Some(*metric),
            _ => None,
        })
        .unwrap_or(0);
    let gateway = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Gateway(RouteAddress::Inet(address)) => Some(IpAddr::V4(*address)),
            RouteAttribute::Gateway(RouteAddress::Inet6(address)) => Some(IpAddr::V6(*address)),
            _ => None,
        });
    let table = message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .or_else(|| {
            (message.header.table != RouteHeader::RT_TABLE_MAIN)
                .then_some(message.header.table as u32)
        })
        .filter(|table| *table != RouteHeader::RT_TABLE_MAIN as u32);
    Some(AppliedRoute {
        destination,
        interface_index,
        metric,
        gateway,
        table,
    })
}

fn rule_family(family: IpFamily) -> AddressFamily {
    match family {
        IpFamily::Ipv4 => AddressFamily::Inet,
        IpFamily::Ipv6 => AddressFamily::Inet6,
    }
}

fn rule_snapshot(message: &RuleMessage) -> OwnedRuleResource {
    OwnedRuleResource {
        family: if message.header.family == AddressFamily::Inet6 {
            IpFamily::Ipv6
        } else {
            IpFamily::Ipv4
        },
        priority: rule_priority(message).unwrap_or(0),
        table: rule_table(message),
        fwmark: message.attributes.iter().find_map(|attr| match attr {
            RuleAttribute::FwMark(value) => Some(*value),
            _ => None,
        }),
        invert: message.header.flags.contains(&RuleFlag::Invert),
        suppress_prefix_length: message.attributes.iter().find_map(|attr| match attr {
            RuleAttribute::SuppressPrefixLen(value) => Some(*value),
            _ => None,
        }),
    }
}

fn rule_request(rule: &OwnedRuleResource) -> RuleMessage {
    let mut message = RuleMessage::default();
    message.header.family = rule_family(rule.family);
    message.header.action = RuleAction::ToTable;
    if rule.invert {
        message.header.flags.push(RuleFlag::Invert);
    }
    if rule.table <= u8::MAX as u32 {
        message.header.table = rule.table as u8;
    } else {
        message.attributes.push(RuleAttribute::Table(rule.table));
    }
    message
        .attributes
        .push(RuleAttribute::Priority(rule.priority));
    if let Some(mark) = rule.fwmark {
        message.attributes.push(RuleAttribute::FwMark(mark));
        message.attributes.push(RuleAttribute::FwMask(u32::MAX));
    }
    if let Some(prefix) = rule.suppress_prefix_length {
        message
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(prefix));
    }
    message
        .attributes
        .push(RuleAttribute::Protocol(RouteProtocol::from(
            RTPROT_NETWORK_ORCHESTRATOR,
        )));
    message
}

fn rule_priority(message: &RuleMessage) -> Option<u32> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Priority(value) => Some(*value),
            _ => None,
        })
}

fn rule_table(message: &RuleMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Table(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(message.header.table as u32)
}

fn route_table(message: &RouteMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(message.header.table as u32)
}

fn is_owned_rule(message: &RuleMessage, rule: &OwnedRuleResource) -> bool {
    let expected = rule_request(rule);
    if message.header.family != expected.header.family
        || message.header.src_len != 0
        || message.header.dst_len != 0
        || message.header.tos != 0
        || message.header.action != RuleAction::ToTable
        || message.header.flags != expected.header.flags
        || rule_table(message) != rule.table
        || (message.header.table != expected.header.table
            && !(rule.table <= u8::MAX as u32 && message.header.table == 0)
            && !(rule.table > u8::MAX as u32 && message.header.table == 252))
    {
        return false;
    }
    // The kernel may echo FRA_TABLE even for a one-byte table. Compare the
    // complete attribute set, allowing only that equivalent encoding.
    let mut attributes = message.attributes.clone();
    // The kernel echoes an unset suppress length as UINT_MAX.
    if rule.suppress_prefix_length.is_none() {
        attributes.retain(
            |attr| !matches!(attr, RuleAttribute::SuppressPrefixLen(value) if *value == u32::MAX),
        );
    }
    // `FRA_FWMASK` is optional; without it the kernel uses all bits.
    if rule.fwmark.is_some()
        && !attributes
            .iter()
            .any(|attr| matches!(attr, RuleAttribute::FwMask(_)))
    {
        attributes.push(RuleAttribute::FwMask(u32::MAX));
    }
    if rule.table <= u8::MAX as u32 {
        if let Some(pos) = attributes
            .iter()
            .position(|attr| matches!(attr, RuleAttribute::Table(value) if *value == rule.table))
        {
            attributes.remove(pos);
        }
    }
    attributes.len() == expected.attributes.len()
        && expected.attributes.iter().all(|attr| {
            if let Some(pos) = attributes.iter().position(|candidate| candidate == attr) {
                attributes.remove(pos);
                true
            } else {
                false
            }
        })
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

fn wireguard_create_request(name: &str, owner_marker: &str) -> LinkMessage {
    let mut message = LinkMessage::default();
    message.attributes.push(LinkAttribute::IfName(name.into()));
    message
        .attributes
        .push(LinkAttribute::IfAlias(owner_marker.into()));
    message
        .attributes
        .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
            InfoKind::Wireguard,
        )]));
    message
}

fn is_owned_wireguard_link(
    message: &LinkMessage,
    name: &str,
    index: u32,
    owner_marker: &str,
) -> bool {
    is_wireguard_link(message, name, index)
        && message
            .attributes
            .contains(&LinkAttribute::IfAlias(owner_marker.into()))
}

fn is_wireguard_link(message: &LinkMessage, name: &str, index: u32) -> bool {
    (index == 0 || message.header.index == index)
        && message
            .attributes
            .contains(&LinkAttribute::IfName(name.into()))
        && message.attributes.iter().any(|attribute| {
            matches!(attribute, LinkAttribute::LinkInfo(info) if info.contains(&LinkInfo::Kind(InfoKind::Wireguard)))
        })
}

fn address_delete_request(index: u32, address: IpNet) -> AddressMessage {
    let mut message = AddressMessage::default();
    message.header.index = index;
    message.header.prefix_len = address.prefix_len();
    let ip = address.addr();
    message.header.family = match ip {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    message.attributes.push(AddressAttribute::Address(ip));
    message.attributes.push(AddressAttribute::Local(ip));
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

/// RTM_DELADDR reports an address that is already gone as EADDRNOTAVAIL.
pub fn classify_address_delete_errno(errno: i32) -> io::ErrorKind {
    if errno == libc::EADDRNOTAVAIL {
        io::ErrorKind::NotFound
    } else {
        classify_errno(errno)
    }
}

pub fn netlink_error_to_io(err: rtnetlink::Error) -> io::Error {
    netlink_error_with(err, classify_errno)
}

fn netlink_error_with(err: rtnetlink::Error, classify: fn(i32) -> io::ErrorKind) -> io::Error {
    match err {
        rtnetlink::Error::NetlinkError(message) => {
            let errno = message.raw_code().abs();
            io::Error::new(classify(errno), message.to_io().to_string())
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
    OwnedRoutesSnapshot {
        reply: mpsc::Sender<io::Result<Vec<AppliedRoute>>>,
    },
    RulesSnapshot {
        reply: mpsc::Sender<io::Result<Vec<OwnedRuleResource>>>,
    },
    Rule {
        rule: OwnedRuleResource,
        add: bool,
        reply: mpsc::Sender<io::Result<()>>,
    },
    TableInUse {
        table: u32,
        reply: mpsc::Sender<io::Result<bool>>,
    },
    Link {
        index: u32,
        up: bool,
        reply: mpsc::Sender<io::Result<()>>,
    },
    WgCreate {
        name: String,
        owner_marker: String,
        reply: mpsc::Sender<io::Result<u32>>,
    },
    WgDelete {
        name: String,
        index: u32,
        owner_marker: String,
        reply: mpsc::Sender<io::Result<()>>,
    },
    WgOwned {
        name: String,
        index: u32,
        owner_marker: String,
        reply: mpsc::Sender<io::Result<bool>>,
    },
    WgPresent {
        name: String,
        index: u32,
        reply: mpsc::Sender<io::Result<bool>>,
    },
    WgAddress {
        index: u32,
        address: IpNet,
        add: bool,
        reply: mpsc::Sender<io::Result<()>>,
    },
    WgMtu {
        index: u32,
        mtu: u32,
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

    fn call_with<T>(
        &self,
        command: impl FnOnce(mpsc::Sender<io::Result<T>>) -> Command,
    ) -> io::Result<T> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx.send(command(reply_tx)).map_err(|_| actor_gone())?;
        reply_rx.recv().map_err(|_| actor_gone())?
    }

    pub fn owned_routes_snapshot(&self) -> io::Result<Vec<AppliedRoute>> {
        self.call_with(|reply| Command::OwnedRoutesSnapshot { reply })
    }
}

async fn get_link(
    handle: &rtnetlink::Handle,
    name: &str,
    index: u32,
) -> io::Result<Option<LinkMessage>> {
    let request = if index == 0 {
        handle.link().get().match_name(name.into())
    } else {
        handle.link().get().match_index(index)
    };
    match request
        .execute()
        .try_next()
        .await
        .map_err(netlink_error_to_io)
    {
        Ok(message) => Ok(message),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

async fn get_rules(handle: &rtnetlink::Handle) -> io::Result<Vec<RuleMessage>> {
    let mut rules = Vec::new();
    for version in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
        let mut stream = handle.rule().get(version).execute();
        while let Some(message) = stream.try_next().await.map_err(netlink_error_to_io)? {
            rules.push(message);
        }
    }
    Ok(rules)
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
            Command::OwnedRoutesSnapshot { reply } => {
                let result = async {
                    let mut routes = Vec::new();
                    for version in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
                        let mut stream = handle.route().get(version).execute();
                        while let Some(message) =
                            stream.try_next().await.map_err(netlink_error_to_io)?
                        {
                            if let Some(route) = owned_route_snapshot(&message) {
                                routes.push(route);
                            }
                        }
                    }
                    Ok(routes)
                }
                .await;
                let _ = reply.send(result);
            }
            Command::RulesSnapshot { reply } => {
                let result = async {
                    let messages = get_rules(&handle).await?;
                    Ok(messages.iter().map(rule_snapshot).collect())
                }
                .await;
                let _ = reply.send(result);
            }
            Command::Rule { rule, add, reply } => {
                let result = async {
                    let existing = get_rules(&handle).await?;
                    if add {
                        if existing.iter().any(|message| {
                            message.header.family == rule_family(rule.family)
                                && rule_priority(message) == Some(rule.priority)
                        }) {
                            return Err(io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                "policy rule priority is occupied",
                            ));
                        }
                        let mut request = handle.rule().add();
                        *request.message_mut() = rule_request(&rule);
                        request.execute().await.map_err(netlink_error_to_io)
                    } else {
                        let suspicious = existing.iter().any(|message| {
                            message.header.family == rule_family(rule.family)
                                && rule_priority(message) == Some(rule.priority)
                        });
                        let Some(_message) = existing
                            .iter()
                            .find(|message| is_owned_rule(message, &rule))
                        else {
                            return Err(io::Error::new(
                                if suspicious {
                                    io::ErrorKind::Other
                                } else {
                                    io::ErrorKind::NotFound
                                },
                                if suspicious {
                                    "policy rule identity is unverified"
                                } else {
                                    "owned policy rule not found"
                                },
                            ));
                        };
                        match handle
                            .rule()
                            .del(rule_request(&rule))
                            .execute()
                            .await
                            .map_err(netlink_error_to_io)
                        {
                            Ok(()) => {
                                if get_rules(&handle)
                                    .await?
                                    .iter()
                                    .any(|message| is_owned_rule(message, &rule))
                                {
                                    Err(io::Error::other("owned policy rule survived deletion"))
                                } else {
                                    Ok(())
                                }
                            }
                            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                                Err(io::Error::other("owned policy rule could not be deleted"))
                            }
                            Err(err) => Err(err),
                        }
                    }
                }
                .await;
                let _ = reply.send(result);
            }
            Command::TableInUse { table, reply } => {
                let result = async {
                    if get_rules(&handle)
                        .await?
                        .iter()
                        .any(|rule| rule_table(rule) == table)
                    {
                        return Ok(true);
                    }
                    for version in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
                        let mut routes = handle.route().get(version).execute();
                        while let Some(route) =
                            routes.try_next().await.map_err(netlink_error_to_io)?
                        {
                            if route_table(&route) == table {
                                return Ok(true);
                            }
                        }
                    }
                    Ok(false)
                }
                .await;
                let _ = reply.send(result);
            }
            Command::Link { index, up, reply } => {
                let mut request = handle.link().set(index);
                *request.message_mut() = link_request(index, up);
                let _ = reply.send(request.execute().await.map_err(netlink_error_to_io));
            }
            Command::WgCreate {
                name,
                owner_marker,
                reply,
            } => {
                let mut request = handle.link().add();
                *request.message_mut() = wireguard_create_request(&name, &owner_marker);
                let result = async {
                    request.execute().await.map_err(netlink_error_to_io)?;
                    let link = get_link(&handle, &name, 0).await?.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "created interface not found")
                    })?;
                    if !is_wireguard_link(&link, &name, 0) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "created interface identity changed",
                        ));
                    }
                    let index = link.header.index;
                    let mut set = handle.link().set(index);
                    set.message_mut()
                        .attributes
                        .push(LinkAttribute::IfAlias(owner_marker.clone()));
                    let result = set.execute().await.map_err(netlink_error_to_io);
                    if result.is_err() {
                        let _ = delete_fresh_link(&handle, &name, index).await;
                        return result.map(|()| index);
                    }
                    let verified = get_link(&handle, &name, index).await?;
                    if !verified.is_some_and(|link| {
                        is_owned_wireguard_link(&link, &name, index, &owner_marker)
                    }) {
                        let _ = delete_fresh_link(&handle, &name, index).await;
                        return Err(io::Error::other(
                            "created interface owner marker is missing",
                        ));
                    }
                    Ok(index)
                }
                .await;
                let _ = reply.send(result);
            }
            Command::WgDelete {
                name,
                index,
                owner_marker,
                reply,
            } => {
                let result = async {
                    let Some(link) = get_link(&handle, &name, index).await? else {
                        return Ok(());
                    };
                    if !is_owned_wireguard_link(&link, &name, index, &owner_marker) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "interface identity does not match owner",
                        ));
                    }
                    handle
                        .link()
                        .del(link.header.index)
                        .execute()
                        .await
                        .map_err(netlink_error_to_io)
                }
                .await;
                let _ = reply.send(result);
            }
            Command::WgOwned {
                name,
                index,
                owner_marker,
                reply,
            } => {
                let result = get_link(&handle, &name, index).await.map(|link| {
                    link.is_some_and(|link| {
                        is_owned_wireguard_link(&link, &name, index, &owner_marker)
                    })
                });
                let _ = reply.send(result);
            }
            Command::WgPresent { name, index, reply } => {
                let result = get_link(&handle, &name, index)
                    .await
                    .map(|link| link.is_some_and(|link| is_wireguard_link(&link, &name, index)));
                let _ = reply.send(result);
            }
            Command::WgAddress {
                index,
                address,
                add,
                reply,
            } => {
                let result = if add {
                    handle
                        .address()
                        .add(index, address.addr(), address.prefix_len())
                        .execute()
                        .await
                        .map_err(netlink_error_to_io)
                } else {
                    handle
                        .address()
                        .del(address_delete_request(index, address))
                        .execute()
                        .await
                        .map_err(|err| netlink_error_with(err, classify_address_delete_errno))
                };
                let _ = reply.send(result);
            }
            Command::WgMtu { index, mtu, reply } => {
                let _ = reply.send(
                    handle
                        .link()
                        .set(index)
                        .mtu(mtu)
                        .execute()
                        .await
                        .map_err(netlink_error_to_io),
                );
            }
        }
    }
}

async fn delete_fresh_link(handle: &rtnetlink::Handle, name: &str, index: u32) -> io::Result<()> {
    let link = get_link(handle, name, index).await?;
    if link.is_some_and(|link| is_wireguard_link(&link, name, index)) {
        handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(netlink_error_to_io)
    } else {
        Ok(())
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

impl PolicyRuleExecutor for NetlinkExecutor {
    fn rules_snapshot(&mut self) -> io::Result<Vec<OwnedRuleResource>> {
        self.call_with(|reply| Command::RulesSnapshot { reply })
    }

    fn add_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
        self.call(|reply| Command::Rule {
            rule: rule.clone(),
            add: true,
            reply,
        })
    }

    fn remove_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
        self.call(|reply| Command::Rule {
            rule: rule.clone(),
            add: false,
            reply,
        })
    }

    fn table_in_use(&mut self, table: u32) -> io::Result<bool> {
        self.call_with(|reply| Command::TableInUse { table, reply })
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

impl WgSystem for NetlinkExecutor {
    fn create_link(&mut self, name: &str, owner_marker: &str) -> io::Result<u32> {
        self.call_with(|reply| Command::WgCreate {
            name: name.into(),
            owner_marker: owner_marker.into(),
            reply,
        })
    }

    fn delete_link(&mut self, name: &str, index: u32, owner_marker: &str) -> io::Result<()> {
        self.call(|reply| Command::WgDelete {
            name: name.into(),
            index,
            owner_marker: owner_marker.into(),
            reply,
        })
    }

    fn link_owned(&mut self, name: &str, index: u32, owner_marker: &str) -> io::Result<bool> {
        self.call_with(|reply| Command::WgOwned {
            name: name.into(),
            index,
            owner_marker: owner_marker.into(),
            reply,
        })
    }

    fn link_present(&mut self, name: &str, index: u32) -> io::Result<bool> {
        self.call_with(|reply| Command::WgPresent {
            name: name.into(),
            index,
            reply,
        })
    }

    fn add_address(&mut self, index: u32, address: IpNet) -> io::Result<()> {
        self.call(|reply| Command::WgAddress {
            index,
            address,
            add: true,
            reply,
        })
    }

    fn remove_address(&mut self, index: u32, address: IpNet) -> io::Result<()> {
        self.call(|reply| Command::WgAddress {
            index,
            address,
            add: false,
            reply,
        })
    }

    fn set_mtu(&mut self, index: u32, mtu: u32) -> io::Result<()> {
        self.call(|reply| Command::WgMtu { index, mtu, reply })
    }

    fn set_state(&mut self, index: u32, up: bool) -> io::Result<()> {
        self.call(|reply| Command::Link { index, up, reply })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::address::AddressAttribute;
    use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkInfo};
    use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteHeader};
    use netlink_packet_route::AddressFamily;
    use std::num::NonZeroI32;

    fn owned_rule(family: IpFamily) -> OwnedRuleResource {
        OwnedRuleResource {
            family,
            priority: 30100,
            table: 51820,
            fwmark: Some(0x1234),
            invert: true,
            suppress_prefix_length: Some(0),
        }
    }

    #[test]
    fn rule_request_has_exact_v4_selector_and_table() {
        let rule = owned_rule(IpFamily::Ipv4);
        let message = rule_request(&rule);
        assert_eq!(message.header.family, AddressFamily::Inet);
        assert_eq!(message.header.src_len, 0);
        assert_eq!(message.header.dst_len, 0);
        assert_eq!(message.header.action, RuleAction::ToTable);
        assert_eq!(message.header.table, 0);
        assert_eq!(message.header.flags, vec![RuleFlag::Invert]);
        assert!(message.attributes.contains(&RuleAttribute::Priority(30100)));
        assert!(message.attributes.contains(&RuleAttribute::Table(51820)));
        assert!(message.attributes.contains(&RuleAttribute::FwMark(0x1234)));
        assert!(message
            .attributes
            .contains(&RuleAttribute::FwMask(u32::MAX)));
        assert!(message
            .attributes
            .contains(&RuleAttribute::SuppressPrefixLen(0)));
        assert!(message
            .attributes
            .contains(&RuleAttribute::Protocol(RouteProtocol::from(
                RTPROT_NETWORK_ORCHESTRATOR
            ))));
    }

    #[test]
    fn rule_request_has_exact_v6_selector_and_small_table() {
        let mut rule = owned_rule(IpFamily::Ipv6);
        rule.table = 100;
        rule.fwmark = None;
        rule.invert = false;
        rule.suppress_prefix_length = None;
        let message = rule_request(&rule);
        assert_eq!(message.header.family, AddressFamily::Inet6);
        assert_eq!(message.header.table, 100);
        assert!(message.header.flags.is_empty());
        assert!(!message.attributes.iter().any(|attr| matches!(
            attr,
            RuleAttribute::FwMark(_)
                | RuleAttribute::FwMask(_)
                | RuleAttribute::SuppressPrefixLen(_)
                | RuleAttribute::Table(_)
        )));
    }

    #[test]
    fn rule_identity_rejects_foreign_selector_and_protocol() {
        let rule = owned_rule(IpFamily::Ipv4);
        let message = rule_request(&rule);
        assert!(is_owned_rule(&message, &rule));

        let mut foreign = message.clone();
        foreign
            .attributes
            .push(RuleAttribute::Iifname("eth0".into()));
        assert!(!is_owned_rule(&foreign, &rule));

        let mut foreign = message.clone();
        foreign
            .attributes
            .retain(|attr| !matches!(attr, RuleAttribute::Protocol(_)));
        assert!(!is_owned_rule(&foreign, &rule));

        let mut foreign = message.clone();
        foreign
            .attributes
            .retain(|attr| !matches!(attr, RuleAttribute::FwMask(_)));
        foreign.attributes.push(RuleAttribute::FwMask(0xff));
        assert!(!is_owned_rule(&foreign, &rule));

        let mut foreign = message;
        foreign.header.flags.clear();
        assert!(!is_owned_rule(&foreign, &rule));

        let mut foreign = rule_request(&rule);
        foreign.header.table = 100;
        assert!(!is_owned_rule(&foreign, &rule));

        let mut foreign = rule_request(&rule);
        foreign.attributes.push(RuleAttribute::Table(rule.table));
        assert!(!is_owned_rule(&foreign, &rule));
    }

    #[test]
    fn rule_collision_and_table_occupancy_detect_foreign_state() {
        let desired = owned_rule(IpFamily::Ipv4);
        let mut foreign = rule_request(&desired);
        foreign
            .attributes
            .push(RuleAttribute::Iifname("eth0".into()));
        assert!(rule_priority(&foreign) == Some(desired.priority));
        assert!(rule_table(&foreign) == desired.table);

        let mut route = RouteMessage::default();
        route.header.table = 0;
        route.attributes.push(RouteAttribute::Table(desired.table));
        assert_eq!(route_table(&route), desired.table);
    }

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
    fn wireguard_create_request_carries_owner_marker_and_kind() {
        let message = wireguard_create_request("wg-test", "owner-123");
        assert!(message
            .attributes
            .contains(&LinkAttribute::IfName("wg-test".into())));
        assert!(message
            .attributes
            .contains(&LinkAttribute::IfAlias("owner-123".into())));
        assert!(message
            .attributes
            .contains(&LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                InfoKind::Wireguard
            )])));
    }

    #[test]
    fn wireguard_identity_requires_index_name_kind_and_owner() {
        let mut message = wireguard_create_request("wg-test", "owner-123");
        message.header.index = 12;
        assert!(is_owned_wireguard_link(
            &message,
            "wg-test",
            12,
            "owner-123"
        ));
        assert!(!is_owned_wireguard_link(
            &message,
            "wg-test",
            13,
            "owner-123"
        ));
        assert!(!is_owned_wireguard_link(
            &message,
            "wg-other",
            12,
            "owner-123"
        ));
        assert!(!is_owned_wireguard_link(&message, "wg-test", 12, "other"));
        message
            .attributes
            .retain(|attribute| !matches!(attribute, LinkAttribute::LinkInfo(_)));
        assert!(!is_owned_wireguard_link(
            &message,
            "wg-test",
            12,
            "owner-123"
        ));
    }

    #[test]
    fn inverted_fwmark_rule_accepts_kernel_default_full_mask_encoding() {
        let owned = OwnedRuleResource {
            family: IpFamily::Ipv4,
            priority: 10001,
            table: 51820,
            fwmark: Some(51820),
            invert: true,
            suppress_prefix_length: None,
        };
        let mut kernel = rule_request(&owned);
        kernel
            .attributes
            .retain(|attr| !matches!(attr, RuleAttribute::FwMask(_)));
        assert!(is_owned_rule(&kernel, &owned));
    }

    #[test]
    fn inverted_rule_accepts_kernel_compat_table_and_unset_suppress_sentinel() {
        let owned = OwnedRuleResource {
            family: IpFamily::Ipv4,
            priority: 10001,
            table: 51820,
            fwmark: Some(51820),
            invert: true,
            suppress_prefix_length: None,
        };
        let mut kernel = rule_request(&owned);
        kernel.header.table = 252;
        kernel
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(u32::MAX));
        assert!(is_owned_rule(&kernel, &owned));
        kernel
            .attributes
            .retain(|attr| !matches!(attr, RuleAttribute::SuppressPrefixLen(_)));
        kernel.attributes.push(RuleAttribute::SuppressPrefixLen(0));
        assert!(!is_owned_rule(&kernel, &owned));
    }

    #[test]
    fn address_delete_request_targets_exact_interface_address() {
        let address: IpNet = "10.20.30.4/24".parse().unwrap();
        let message = address_delete_request(12, address);
        assert_eq!(message.header.index, 12);
        assert_eq!(message.header.prefix_len, 24);
        assert_eq!(message.header.family, AddressFamily::Inet);
        assert!(message
            .attributes
            .contains(&AddressAttribute::Address("10.20.30.4".parse().unwrap())));
        assert!(message
            .attributes
            .contains(&AddressAttribute::Local("10.20.30.4".parse().unwrap())));
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
    fn address_delete_treats_missing_address_as_already_gone() {
        assert_eq!(
            classify_address_delete_errno(libc::EADDRNOTAVAIL),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            classify_address_delete_errno(libc::EPERM),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(classify_errno(libc::EADDRNOTAVAIL), io::ErrorKind::Other);
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

    #[test]
    fn owned_route_snapshot_requires_proto_and_exact_attributes() {
        let route = AppliedRoute {
            destination: "203.0.113.0/24".parse().unwrap(),
            interface_index: 7,
            metric: 13,
            gateway: Some("192.0.2.1".parse().unwrap()),
            table: None,
        };
        let mut message = route_request(&route, RouteOp::Add);
        assert_eq!(owned_route_snapshot(&message), Some(route.clone()));
        message.header.protocol = RouteProtocol::Static;
        assert_eq!(owned_route_snapshot(&message), None);
        message.header.protocol = RouteProtocol::from(RTPROT_NETWORK_ORCHESTRATOR);
        message
            .attributes
            .retain(|attr| !matches!(attr, RouteAttribute::Oif(_)));
        assert_eq!(owned_route_snapshot(&message), None);

        let default = AppliedRoute::on_link("0.0.0.0/0".parse().unwrap(), 7, 13);
        let mut default_message = route_request(&default, RouteOp::Add);
        default_message
            .attributes
            .retain(|attr| !matches!(attr, RouteAttribute::Destination(_)));
        assert_eq!(owned_route_snapshot(&default_message), Some(default));

        let mut main_table = route_request(&route, RouteOp::Add);
        main_table.attributes.push(RouteAttribute::Table(254));
        assert_eq!(owned_route_snapshot(&main_table), Some(route));
    }
}
