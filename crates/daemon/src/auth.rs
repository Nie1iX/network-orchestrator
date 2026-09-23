//! Authorization: which polkit action each method needs, and the polkit
//! `CheckAuthorization` call itself (Linux only). The decision helpers are
//! pure so they are tested without D-Bus.

use net_manager_core::daemon_protocol::method;
use std::collections::HashMap;
use std::future::Future;
use std::io;

/// Who is on the other end of a connection, captured at accept time.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub uid: u32,
    pub pid: u32,
    /// Process start time (clock ticks since boot) from `/proc/<pid>/stat`.
    pub start_time: Option<u64>,
    /// Kernel pidfd of the peer (`SO_PEERPIDFD`), when supported.
    pub pidfd: Option<Pidfd>,
}

/// Shared pidfd handle; empty on platforms without pidfds.
#[derive(Debug, Clone)]
pub struct Pidfd(#[cfg(unix)] pub std::sync::Arc<std::os::fd::OwnedFd>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// `auth_admin_keep`: changes the host's network configuration.
    SystemNetwork,
    /// `allow_active`: removing what the caller itself owns.
    ConnectProfile,
}

impl Action {
    pub fn polkit_id(self) -> &'static str {
        match self {
            Action::SystemNetwork => "com.netmanager.app.system-network",
            Action::ConnectProfile => "com.netmanager.app.connect-profile",
        }
    }
}

/// Read-only methods (`hello`, `owned.list`, `subscribe`) are scoped by uid
/// and need no polkit action.
pub fn required_action(method_name: &str) -> Option<Action> {
    match method_name {
        method::ROUTES_APPLY
        | method::LINK_SET_STATE
        | method::ALWAYS_ON_SET
        | method::ALWAYS_ON_REMOVE
        | method::ALWAYS_ON_RESUME => Some(Action::SystemNetwork),
        method::ROUTES_REMOVE
        | method::RECOVERY_CLEANUP
        | method::WIREGUARD_CONNECT
        | method::WIREGUARD_DISCONNECT
        | method::OPENVPN_CONNECT
        | method::OPENVPN_PROBE
        | method::OPENVPN_DISCONNECT
        | method::XRAY_CONNECT
        | method::XRAY_DISCONNECT => Some(Action::ConnectProfile),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDecision {
    Authorized,
    Denied,
    /// The user closed the authentication dialog.
    Dismissed,
}

pub trait Authorizer: Send + Sync + 'static {
    fn check(
        &self,
        peer: &PeerIdentity,
        action: Action,
    ) -> impl Future<Output = io::Result<AuthDecision>> + Send;
}

/// Typed value of one `unix-process` subject detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectValue {
    /// The peer's pidfd, attached as a D-Bus unix fd.
    Pidfd,
    U32(u32),
    U64(u64),
    I32(i32),
}

/// polkit `unix-process` subject details. A pidfd pins the exact process;
/// without one, pid + start-time guards against pid reuse. polkit types
/// `uid` as int32.
pub fn subject_fields(peer: &PeerIdentity) -> Vec<(&'static str, SubjectValue)> {
    let uid = ("uid", SubjectValue::I32(peer.uid as i32));
    if peer.pidfd.is_some() {
        vec![("pidfd", SubjectValue::Pidfd), uid]
    } else {
        vec![
            ("pid", SubjectValue::U32(peer.pid)),
            (
                "start-time",
                SubjectValue::U64(peer.start_time.unwrap_or(0)),
            ),
            uid,
        ]
    }
}

/// Map a `CheckAuthorization` reply. We always pass
/// `AllowUserInteraction`, so a remaining challenge means no agent could
/// ask the user: that is a denial.
pub fn decode_authorization(
    is_authorized: bool,
    _is_challenge: bool,
    details: &HashMap<String, String>,
) -> AuthDecision {
    if is_authorized {
        AuthDecision::Authorized
    } else if details.contains_key("polkit.dismissed") {
        AuthDecision::Dismissed
    } else {
        AuthDecision::Denied
    }
}

/// Field 22 (`starttime`) of `/proc/<pid>/stat`. `comm` (field 2) may hold
/// spaces and parentheses, so parsing starts after the last `)`.
pub fn parse_proc_stat_start_time(stat: &str) -> Option<u64> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(target_os = "linux")]
pub use polkit::PolkitAuthorizer;

#[cfg(target_os = "linux")]
mod polkit {
    use super::{decode_authorization, subject_fields, Action, AuthDecision, Authorizer};
    use super::{PeerIdentity, SubjectValue};
    use std::collections::HashMap;
    use std::io;
    use std::os::fd::AsFd;
    use zbus::zvariant::{Fd, Value};

    const ALLOW_USER_INTERACTION: u32 = 1;

    /// polkit over the system bus; connects lazily so a daemon started
    /// before D-Bus still serves read-only methods.
    #[derive(Default)]
    pub struct PolkitAuthorizer {
        connection: tokio::sync::OnceCell<zbus::Connection>,
    }

    impl Authorizer for PolkitAuthorizer {
        async fn check(&self, peer: &PeerIdentity, action: Action) -> io::Result<AuthDecision> {
            let connection = self
                .connection
                .get_or_try_init(zbus::Connection::system)
                .await
                .map_err(unavailable)?;
            let mut subject: HashMap<&str, Value<'_>> = HashMap::new();
            for (key, value) in subject_fields(peer) {
                let value = match value {
                    SubjectValue::Pidfd => match &peer.pidfd {
                        Some(pidfd) => Value::Fd(Fd::from(pidfd.0.as_fd())),
                        None => continue,
                    },
                    SubjectValue::U32(v) => Value::U32(v),
                    SubjectValue::U64(v) => Value::U64(v),
                    SubjectValue::I32(v) => Value::I32(v),
                };
                subject.insert(key, value);
            }
            let details: HashMap<&str, &str> = HashMap::new();
            let reply = connection
                .call_method(
                    Some("org.freedesktop.PolicyKit1"),
                    "/org/freedesktop/PolicyKit1/Authority",
                    Some("org.freedesktop.PolicyKit1.Authority"),
                    "CheckAuthorization",
                    &(
                        ("unix-process", subject),
                        action.polkit_id(),
                        details,
                        ALLOW_USER_INTERACTION,
                        "",
                    ),
                )
                .await
                .map_err(unavailable)?;
            let (is_authorized, is_challenge, details): (bool, bool, HashMap<String, String>) =
                reply.body().deserialize().map_err(unavailable)?;
            Ok(decode_authorization(is_authorized, is_challenge, &details))
        }
    }

    fn unavailable(err: impl std::fmt::Display) -> io::Error {
        io::Error::new(
            io::ErrorKind::NotConnected,
            format!("polkit is unavailable: {err}"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::method;
    use std::collections::HashMap;

    fn peer(pidfd: Option<Pidfd>) -> PeerIdentity {
        PeerIdentity {
            uid: 1000,
            pid: 4242,
            start_time: Some(987654),
            pidfd,
        }
    }

    #[test]
    fn required_action_table() {
        assert_eq!(
            required_action(method::ROUTES_APPLY),
            Some(Action::SystemNetwork)
        );
        assert_eq!(
            required_action(method::LINK_SET_STATE),
            Some(Action::SystemNetwork)
        );
        for method in [
            method::ALWAYS_ON_SET,
            method::ALWAYS_ON_REMOVE,
            method::ALWAYS_ON_RESUME,
        ] {
            assert_eq!(required_action(method), Some(Action::SystemNetwork));
        }
        assert_eq!(
            required_action(method::ROUTES_REMOVE),
            Some(Action::ConnectProfile)
        );
        assert_eq!(
            required_action(method::RECOVERY_CLEANUP),
            Some(Action::ConnectProfile)
        );
        assert_eq!(
            required_action(method::OPENVPN_CONNECT),
            Some(Action::ConnectProfile)
        );
        assert_eq!(
            required_action(method::OPENVPN_PROBE),
            Some(Action::ConnectProfile)
        );
        assert_eq!(
            required_action(method::OPENVPN_DISCONNECT),
            Some(Action::ConnectProfile)
        );
        assert_eq!(
            Action::SystemNetwork.polkit_id(),
            "com.netmanager.app.system-network"
        );
        assert_eq!(
            Action::ConnectProfile.polkit_id(),
            "com.netmanager.app.connect-profile"
        );
    }

    #[test]
    fn readonly_methods_need_no_action() {
        for name in [
            method::HELLO,
            method::OWNED_LIST,
            method::SUBSCRIBE,
            method::ALWAYS_ON_LIST,
            "frobnicate",
        ] {
            assert_eq!(required_action(name), None, "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn subject_prefers_pidfd() {
        let fd: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        let fields = subject_fields(&peer(Some(Pidfd(std::sync::Arc::new(fd)))));
        assert_eq!(
            fields,
            vec![
                ("pidfd", SubjectValue::Pidfd),
                ("uid", SubjectValue::I32(1000))
            ]
        );
    }

    #[test]
    fn subject_falls_back_to_pid_start_time_uid() {
        assert_eq!(
            subject_fields(&peer(None)),
            vec![
                ("pid", SubjectValue::U32(4242)),
                ("start-time", SubjectValue::U64(987654)),
                ("uid", SubjectValue::I32(1000)),
            ]
        );
    }

    #[test]
    fn decode_authorized() {
        assert_eq!(
            decode_authorization(true, false, &HashMap::new()),
            AuthDecision::Authorized
        );
    }

    #[test]
    fn decode_dismissed_details() {
        let details = HashMap::from([("polkit.dismissed".to_string(), "true".to_string())]);
        assert_eq!(
            decode_authorization(false, false, &details),
            AuthDecision::Dismissed
        );
    }

    #[test]
    fn decode_challenge_is_denied() {
        assert_eq!(
            decode_authorization(false, true, &HashMap::new()),
            AuthDecision::Denied
        );
        assert_eq!(
            decode_authorization(false, false, &HashMap::new()),
            AuthDecision::Denied
        );
    }

    #[test]
    fn start_time_parser_handles_parens_and_spaces_in_comm() {
        // Field 22 (starttime) is 20th after the closing paren of comm.
        let stat = "4242 (evil) (name x) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10";
        assert_eq!(parse_proc_stat_start_time(stat), Some(987654));
        assert_eq!(parse_proc_stat_start_time("4242 (short) S 1 2"), None);
        assert_eq!(parse_proc_stat_start_time("garbage"), None);
    }
}
