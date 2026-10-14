//! Route mutations for the Xray full tunnel, via `route(8)`.
//!
//! Capture mirrors Xray's own Darwin path: instead of one `0.0.0.0/0` (which
//! would replace the system default and break uplink-scoped sockets) eight
//! prefixes `128/1 … 1/8` cover all unicast space except `0.0.0.0/8`, plus
//! two v6 halves via the tunnel interface. Addresses reachable on the uplink
//! subnet keep their connected routes (longer prefixes win), so only hosts
//! that must bypass the tunnel across the gateway need explicit routes.

use crate::sysexec::{Runner, ROUTE};
use serde::{Deserialize, Serialize};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Capture prefixes, `(network, prefix length)`.
pub const PROTECTED_V4: [(Ipv4Addr, u8); 8] = [
    (Ipv4Addr::new(128, 0, 0, 0), 1),
    (Ipv4Addr::new(64, 0, 0, 0), 2),
    (Ipv4Addr::new(32, 0, 0, 0), 3),
    (Ipv4Addr::new(16, 0, 0, 0), 4),
    (Ipv4Addr::new(8, 0, 0, 0), 5),
    (Ipv4Addr::new(4, 0, 0, 0), 6),
    (Ipv4Addr::new(2, 0, 0, 0), 7),
    (Ipv4Addr::new(1, 0, 0, 0), 8),
];
pub const PROTECTED_V6: [(Ipv6Addr, u8); 2] = [
    (Ipv6Addr::UNSPECIFIED, 1),
    (Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1),
];

/// Where a route points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "via", rename_all = "camelCase")]
pub enum Target {
    Gateway { address: IpAddr },
    Interface { name: String },
}

/// One route this helper installed; also the journal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteOp {
    pub network: IpAddr,
    pub prefix: u8,
    pub target: Target,
    /// Best effort (resolver bypasses): a failure skips the route instead of
    /// failing the tunnel, and a skipped route is never deleted on teardown.
    #[serde(default)]
    pub optional: bool,
}

fn netmask_v4(bits: u8) -> Ipv4Addr {
    Ipv4Addr::from(if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    })
}

impl RouteOp {
    fn args(&self, verb: &str) -> Vec<String> {
        let mut args = vec!["-n".to_string(), verb.to_string()];
        match self.network {
            IpAddr::V4(net) => {
                if self.prefix == 32 {
                    args.extend(["-host".into(), net.to_string()]);
                } else {
                    args.extend([
                        "-net".into(),
                        net.to_string(),
                        "-netmask".into(),
                        netmask_v4(self.prefix).to_string(),
                    ]);
                }
            }
            IpAddr::V6(net) => {
                args.push("-inet6".into());
                if self.prefix == 128 {
                    args.extend(["-host".into(), net.to_string()]);
                } else {
                    args.extend([
                        "-net".into(),
                        net.to_string(),
                        "-prefixlen".into(),
                        self.prefix.to_string(),
                    ]);
                }
            }
        }
        match &self.target {
            Target::Gateway { address } => args.extend(["-gateway".into(), address.to_string()]),
            Target::Interface { name } => args.extend(["-interface".into(), name.clone()]),
        }
        args
    }

    pub fn add(&self, runner: &dyn Runner) -> io::Result<()> {
        runner.run(ROUTE, &self.args("add")).map(|_| ())
    }

    /// Delete by destination only, so a route whose gateway changed under us
    /// is still removed. A missing route counts as removed.
    pub fn delete(&self, runner: &dyn Runner) -> io::Result<()> {
        let mut args = self.args("delete");
        // Drop `-gateway X` / `-interface X`.
        args.truncate(args.len() - 2);
        // `route delete` of an absent entry exits non-zero, which is the
        // state teardown wants anyway.
        let _ = runner.run(ROUTE, &args);
        Ok(())
    }
}

/// The physical default route the tunnel must not swallow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uplink {
    pub interface: String,
    pub gateway: Option<Ipv4Addr>,
}

/// Parse `route -n get default` output.
pub fn parse_default_route(output: &str) -> Option<Uplink> {
    let mut interface = None;
    let mut gateway = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("interface:") {
            interface = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("gateway:") {
            gateway = value.trim().parse().ok();
        }
    }
    let interface = interface.filter(|name| !name.is_empty())?;
    Some(Uplink { interface, gateway })
}

pub fn detect_uplink(runner: &dyn Runner) -> io::Result<Uplink> {
    let output = runner.run(ROUTE, &["-n".into(), "get".into(), "default".into()])?;
    let uplink = parse_default_route(&output)
        .ok_or_else(|| io::Error::other("no default route to protect"))?;
    if uplink.interface.starts_with("utun") {
        // Another tunnel already owns the default route; its interface would
        // become our loop-prevention binding and send Xray back into it.
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "another VPN already owns the default route",
        ));
    }
    Ok(uplink)
}

/// Every route to install, bypasses first so no capture window exists where
/// the resolvers are reachable only through the tunnel.
pub fn plan(uplink: &Uplink, tun: &str, bypass: &[Ipv4Addr]) -> Vec<RouteOp> {
    let mut ops = Vec::new();
    if let Some(gateway) = uplink.gateway {
        for host in bypass {
            // Resolvers on the uplink's own subnet (usually the router) are
            // already reachable directly, and adding a route for them fails.
            if *host == gateway {
                continue;
            }
            ops.push(RouteOp {
                network: IpAddr::V4(*host),
                prefix: 32,
                target: Target::Gateway {
                    address: IpAddr::V4(gateway),
                },
                optional: true,
            });
        }
    }
    for (network, prefix) in PROTECTED_V4 {
        ops.push(RouteOp {
            network: IpAddr::V4(network),
            prefix,
            target: Target::Gateway {
                address: IpAddr::V4(crate::tun::GATEWAY),
            },
            optional: false,
        });
    }
    for (network, prefix) in PROTECTED_V6 {
        ops.push(RouteOp {
            network: IpAddr::V6(network),
            prefix,
            target: Target::Interface { name: tun.into() },
            optional: false,
        });
    }
    ops
}

impl RouteOp {
    pub fn describe(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }
}

/// Routes for a secondary Xray tunnel: only `networks`, through the tunnel
/// gateway (IPv6 through the interface). All of them are best effort; the
/// caller decides whether having none installed is an error.
pub fn gateway_routes(gateway: Ipv4Addr, tun: &str, networks: &[ipnet::IpNet]) -> Vec<RouteOp> {
    let mut ops: Vec<RouteOp> = Vec::new();
    for net in networks {
        let target = match net.addr() {
            IpAddr::V4(_) => Target::Gateway {
                address: IpAddr::V4(gateway),
            },
            IpAddr::V6(_) => Target::Interface { name: tun.into() },
        };
        let op = RouteOp {
            network: net.network(),
            prefix: net.prefix_len(),
            target,
            optional: true,
        };
        if !ops
            .iter()
            .any(|have| have.network == op.network && have.prefix == op.prefix)
        {
            ops.push(op);
        }
    }
    ops
}

/// Capture routes for a tunnel that is addressed by interface (WireGuard,
/// OpenVPN): `0.0.0.0/0` and `::/0` become two halves each, which win over the
/// uplink's default without replacing it; every other network is routed as is.
/// Default-capture routes are required, the rest is best effort.
pub fn interface_routes(tun: &str, networks: &[ipnet::IpNet]) -> Vec<RouteOp> {
    let target = |name: &str| Target::Interface { name: name.into() };
    let mut ops: Vec<RouteOp> = Vec::new();
    let push = |ops: &mut Vec<RouteOp>, network: IpAddr, prefix: u8, optional: bool| {
        let op = RouteOp {
            network,
            prefix,
            target: target(tun),
            optional,
        };
        if !ops
            .iter()
            .any(|have| have.network == op.network && have.prefix == op.prefix)
        {
            ops.push(op);
        }
    };
    for net in networks {
        match (net.addr(), net.prefix_len()) {
            (IpAddr::V4(_), 0) => {
                push(&mut ops, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1, false);
                push(&mut ops, IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1, false);
            }
            (IpAddr::V6(_), 0) => {
                push(&mut ops, IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1, false);
                push(
                    &mut ops,
                    IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
                    1,
                    false,
                );
            }
            // The /1 halves of a redirect are as required as a default route.
            (_, prefix) => push(&mut ops, net.network(), prefix, prefix > 1),
        }
    }
    ops
}

/// Install `ops` and return the ones that are really in place. A required
/// route that fails removes everything added so far and reports which one;
/// an optional one is skipped.
pub fn apply(runner: &dyn Runner, ops: &[RouteOp]) -> io::Result<Vec<RouteOp>> {
    let mut installed: Vec<RouteOp> = Vec::new();
    for op in ops {
        match op.add(runner) {
            Ok(()) => installed.push(op.clone()),
            Err(_) if op.optional => {}
            Err(err) => {
                remove(runner, &installed);
                return Err(io::Error::new(
                    err.kind(),
                    format!("route {}: {err}", op.describe()),
                ));
            }
        }
    }
    Ok(installed)
}

/// Remove in reverse order; best effort.
pub fn remove(runner: &dyn Runner, ops: &[RouteOp]) {
    for op in ops.iter().rev() {
        let _ = op.delete(runner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysexec::fake::FakeRunner;

    const DEFAULT: &str = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";

    #[test]
    fn default_route_output_is_parsed() {
        let uplink = parse_default_route(DEFAULT).unwrap();
        assert_eq!(uplink.interface, "en0");
        assert_eq!(uplink.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(parse_default_route("route: writing to routing socket: not in table").is_none());
        // A point-to-point default has no gateway line.
        let p2p = parse_default_route("  interface: ppp0\n").unwrap();
        assert_eq!(p2p.gateway, None);
    }

    #[test]
    fn a_default_route_owned_by_another_tunnel_is_refused() {
        let runner = FakeRunner::default();
        runner.reply(
            "route -n get default",
            "gateway: 10.0.0.1\n interface: utun4\n",
        );
        let err = detect_uplink(&runner).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn protected_prefixes_cover_unicast_space_without_loopback() {
        let covered: u64 = PROTECTED_V4
            .iter()
            .map(|(_, bits)| 1u64 << (32 - bits))
            .sum();
        // Everything except 0.0.0.0/8, like Xray's own Darwin routes.
        assert_eq!(covered, (1u64 << 32) - (1u64 << 24));
    }

    #[test]
    fn plan_installs_bypass_before_capture() {
        let uplink = Uplink {
            interface: "en0".into(),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
        };
        let ops = plan(&uplink, "utun10", &[Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!(ops.len(), 1 + 8 + 2);
        assert_eq!(ops[0].prefix, 32);
        assert!(
            matches!(&ops[0].target, Target::Gateway { address } if address.to_string() == "192.168.1.1")
        );
        assert_eq!(ops[1].network.to_string(), "128.0.0.0");
        assert!(matches!(&ops[9].target, Target::Interface { name } if name == "utun10"));
    }

    #[test]
    fn route_commands_are_well_formed() {
        let runner = FakeRunner::default();
        let uplink = Uplink {
            interface: "en0".into(),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
        };
        apply(
            &runner,
            &plan(&uplink, "utun10", &[Ipv4Addr::new(9, 9, 9, 9)]),
        )
        .unwrap();
        let calls = runner.calls();
        assert_eq!(calls[0], "route -n add -host 9.9.9.9 -gateway 192.168.1.1");
        assert_eq!(
            calls[1],
            "route -n add -net 128.0.0.0 -netmask 128.0.0.0 -gateway 169.254.10.1"
        );
        assert_eq!(
            calls[8],
            "route -n add -net 1.0.0.0 -netmask 255.0.0.0 -gateway 169.254.10.1"
        );
        assert_eq!(
            calls[9],
            "route -n add -inet6 -net :: -prefixlen 1 -interface utun10"
        );
        assert_eq!(
            calls[10],
            "route -n add -inet6 -net 8000:: -prefixlen 1 -interface utun10"
        );
    }

    #[test]
    fn failed_add_rolls_back_in_reverse() {
        let runner = FakeRunner::default();
        runner.fail("route -n add -net 64.0.0.0");
        let uplink = Uplink {
            interface: "en0".into(),
            gateway: None,
        };
        assert!(apply(&runner, &plan(&uplink, "utun10", &[])).is_err());
        let calls = runner.calls();
        assert_eq!(
            calls.last().unwrap(),
            "route -n delete -net 128.0.0.0 -netmask 128.0.0.0"
        );
    }

    #[test]
    fn a_failing_bypass_is_skipped_and_never_deleted() {
        let runner = FakeRunner::default();
        runner.fail("route -n add -host 1.1.1.1");
        let uplink = Uplink {
            interface: "en0".into(),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
        };
        let ops = plan(&uplink, "utun10", &[Ipv4Addr::new(1, 1, 1, 1)]);
        let installed = apply(&runner, &ops).unwrap();
        assert_eq!(installed.len(), 10);
        assert!(installed.iter().all(|op| !op.optional));
        remove(&runner, &installed);
        assert!(!runner
            .calls()
            .iter()
            .any(|c| c.starts_with("route -n delete -host 1.1.1.1")));
    }

    #[test]
    fn the_gateway_itself_needs_no_bypass() {
        let uplink = Uplink {
            interface: "en0".into(),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
        };
        let ops = plan(&uplink, "utun10", &[Ipv4Addr::new(192, 168, 1, 1)]);
        assert_eq!(ops.len(), 10);
    }

    #[test]
    fn a_failing_required_route_names_itself() {
        let runner = FakeRunner::default();
        runner.fail("route -n add -net 64.0.0.0");
        let uplink = Uplink {
            interface: "en0".into(),
            gateway: None,
        };
        let err = apply(&runner, &plan(&uplink, "utun10", &[])).unwrap_err();
        assert!(err.to_string().contains("64.0.0.0/2"), "{err}");
    }

    #[test]
    fn bypass_without_a_gateway_is_skipped() {
        let uplink = Uplink {
            interface: "ppp0".into(),
            gateway: None,
        };
        let ops = plan(&uplink, "utun10", &[Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!(ops.len(), 10);
    }
}
