//! Whether a client (the `netorch` CLI, the app) and the network daemon can
//! work together. The two are separate packages and can be updated apart, so
//! the daemon's handshake is checked before anything is sent:
//!
//! - the wire protocol must be the same (a hard error otherwise);
//! - the daemon must list every method the client calls, which is a better
//!   test than comparing version numbers;
//! - a daemon from an older release line than the client is allowed but
//!   reported, because some newer feature may not be there.
use net_manager_core::daemon_protocol::{method, HelloResult, PROTOCOL_VERSION};

/// Methods `netorch` calls. A daemon without one of them cannot serve it.
pub const REQUIRED_METHODS: &[&str] = &[
    method::WIREGUARD_CONNECT,
    method::WIREGUARD_DISCONNECT,
    method::WIREGUARD_STATUS,
    method::OPENVPN_CONNECT,
    method::OPENVPN_DISCONNECT,
    method::OPENVPN_STATUS,
    method::XRAY_CONNECT,
    method::XRAY_DISCONNECT,
    method::XRAY_STATUS,
    method::ALWAYS_ON_LIST,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Compatible,
    /// Works, but something may be missing; the text says what to update.
    Warning(String),
    /// Must not be used; the text says what to update.
    Incompatible(String),
}

impl Verdict {
    pub fn is_usable(&self) -> bool {
        !matches!(self, Verdict::Incompatible(_))
    }

    pub fn message(&self) -> Option<&str> {
        match self {
            Verdict::Compatible => None,
            Verdict::Warning(text) | Verdict::Incompatible(text) => Some(text),
        }
    }
}

/// `major.minor.patch`, ignoring a pre-release or build suffix.
fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let core = text.trim().split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// Judges the daemon that answered `hello` for a client of `client_version`.
pub fn check(hello: &HelloResult, client_version: &str) -> Verdict {
    if hello.protocol != PROTOCOL_VERSION {
        return Verdict::Incompatible(if hello.protocol < PROTOCOL_VERSION {
            format!(
                "The network daemon ({}) speaks protocol {}, netorch needs {}. Update the \
                 network-orchestrator daemon package.",
                hello.daemon_version, hello.protocol, PROTOCOL_VERSION
            )
        } else {
            format!(
                "The network daemon ({}) speaks protocol {}, newer than netorch's {}. Update \
                 netorch.",
                hello.daemon_version, hello.protocol, PROTOCOL_VERSION
            )
        });
    }
    let missing: Vec<&str> = REQUIRED_METHODS
        .iter()
        .copied()
        .filter(|name| !hello.capabilities.iter().any(|have| have == name))
        .collect();
    if !missing.is_empty() {
        return Verdict::Incompatible(format!(
            "The network daemon ({}) lacks {}. Update the network-orchestrator daemon package.",
            hello.daemon_version,
            missing.join(", ")
        ));
    }
    match (
        parse_version(&hello.daemon_version),
        parse_version(client_version),
    ) {
        (Some(daemon), Some(client)) if (daemon.0, daemon.1) < (client.0, client.1) => {
            Verdict::Warning(format!(
                "The network daemon {} is older than netorch {client_version}; some features \
                 may be missing. Update the network-orchestrator daemon package.",
                hello.daemon_version
            ))
        }
        (Some(daemon), Some(client)) if daemon.0 > client.0 => Verdict::Warning(format!(
            "The network daemon {} is from a newer release than netorch {client_version}. \
             Update netorch.",
            hello.daemon_version
        )),
        _ => Verdict::Compatible,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(protocol: u32, version: &str, drop: &[&str]) -> HelloResult {
        HelloResult {
            protocol,
            daemon_version: version.into(),
            uid: 1000,
            capabilities: REQUIRED_METHODS
                .iter()
                .filter(|name| !drop.contains(name))
                .map(|name| name.to_string())
                .collect(),
            tools: Default::default(),
        }
    }

    #[test]
    fn a_matching_daemon_is_compatible() {
        let verdict = check(&hello(PROTOCOL_VERSION, "0.9.1", &[]), "0.9.1");
        assert_eq!(verdict, Verdict::Compatible);
        assert!(verdict.is_usable() && verdict.message().is_none());
    }

    #[test]
    fn a_different_protocol_is_refused_and_says_which_side_to_update() {
        let older = check(&hello(PROTOCOL_VERSION - 1, "0.5.0", &[]), "0.9.1");
        assert!(
            matches!(&older, Verdict::Incompatible(t) if t.contains("Update the network-orchestrator daemon"))
        );
        let newer = check(&hello(PROTOCOL_VERSION + 1, "2.0.0", &[]), "0.9.1");
        assert!(matches!(&newer, Verdict::Incompatible(t) if t.contains("Update netorch")));
        assert!(!newer.is_usable());
    }

    #[test]
    fn a_daemon_missing_a_method_the_client_calls_is_refused() {
        let verdict = check(
            &hello(PROTOCOL_VERSION, "0.9.1", &[method::XRAY_CONNECT]),
            "0.9.1",
        );
        assert!(
            matches!(&verdict, Verdict::Incompatible(t) if t.contains("xray.connect")),
            "{verdict:?}"
        );
    }

    #[test]
    fn an_older_release_line_only_warns() {
        let verdict = check(&hello(PROTOCOL_VERSION, "0.8.7", &[]), "0.9.1");
        assert!(verdict.is_usable());
        assert!(
            matches!(&verdict, Verdict::Warning(t) if t.contains("0.8.7") && t.contains("0.9.1"))
        );
        // A patch difference inside one line is fine.
        assert_eq!(
            check(&hello(PROTOCOL_VERSION, "0.9.0", &[]), "0.9.4"),
            Verdict::Compatible
        );
    }

    #[test]
    fn a_newer_major_daemon_asks_for_a_newer_client() {
        let verdict = check(&hello(PROTOCOL_VERSION, "2.0.0", &[]), "1.4.0");
        assert!(matches!(&verdict, Verdict::Warning(t) if t.contains("Update netorch")));
    }

    #[test]
    fn unparsable_versions_are_not_held_against_the_daemon() {
        assert_eq!(
            check(&hello(PROTOCOL_VERSION, "dev", &[]), "0.9.1"),
            Verdict::Compatible
        );
        assert_eq!(parse_version("0.10.0-beta.1"), Some((0, 10, 0)));
        assert_eq!(parse_version("1.2"), Some((1, 2, 0)));
    }
}
