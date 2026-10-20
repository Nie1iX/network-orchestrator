//! Keeps the user's Tailscale reachable while a primary tunnel is up.
//!
//! Tailscale is a foreign daemon (a Network Extension or `tailscaled`) that
//! owns its utun, its `100.64.0.0/10` route and its MagicDNS. This module never
//! touches that; it only guards two things around it:
//!
//! * the tailnet prefixes: Tailscale's own routes already beat the primary
//!   tunnel's capture because they are longer, but another VPN can take the
//!   same prefix (a pushed `100.64.0.0/10`, a different `/10`). When a lookup
//!   shows something else winning, the prefix is pinned to Tailscale's utun;
//! * Tailscale's own traffic (direct peers, DERP relays, the control server):
//!   host routes through the physical gateway so it never rides inside the
//!   tunnel it is supposed to be reachable next to.
//!
//! The unprivileged side reads Tailscale's state and names the utun by its
//! addresses and the hosts by IP; nothing user-supplied is executed here.
//! Every route is journaled and undone on release, restart or shutdown.

use crate::journal::{Journal, Record};
use crate::routes::{self, RouteOp, Target};
use crate::sysexec::{Runner, IFCONFIG, ROUTE};
use ipnet::{Ipv4Net, Ipv6Net};
use net_manager_core::daemon_protocol::{TailscaleProtectParams, TailscaleProtectResult};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

/// More than this is a misbehaving client, not a tailnet.
const MAX_ENDPOINTS: usize = 64;
const MAX_SELF_IPS: usize = 8;
const JOURNAL_ID: &str = "tailscale";

const TAILNET_V4: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10);
const TAILNET_V6: Ipv6Net =
    Ipv6Net::new_assert(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0), 48);

#[derive(Debug)]
pub enum Error {
    Invalid(String),
    Unavailable(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (Self::Invalid(message) | Self::Unavailable(message)) = self;
        f.write_str(message)
    }
}

pub struct TailscaleGuard {
    runner: Box<dyn Runner>,
    journal: Journal,
    installed: Mutex<Vec<RouteOp>>,
}

fn in_tailnet(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => TAILNET_V4.contains(ip),
        IpAddr::V6(ip) => TAILNET_V6.contains(ip),
    }
}

/// `(interface, addresses)` for every block of `ifconfig` output.
fn parse_interfaces(output: &str) -> Vec<(String, Vec<IpAddr>)> {
    let mut found: Vec<(String, Vec<IpAddr>)> = Vec::new();
    for line in output.lines() {
        if !line.starts_with(char::is_whitespace) {
            if let Some((name, _)) = line.split_once(':') {
                found.push((name.trim().to_string(), Vec::new()));
            }
            continue;
        }
        let mut words = line.split_whitespace();
        if !matches!(words.next(), Some("inet" | "inet6")) {
            continue;
        }
        // `inet6 fe80::1%utun4 prefixlen 64 …`: drop the zone.
        let Some(text) = words
            .next()
            .map(|word| word.split('%').next().unwrap_or(word))
        else {
            continue;
        };
        if let (Ok(ip), Some((_, ips))) = (text.parse::<IpAddr>(), found.last_mut()) {
            ips.push(ip);
        }
    }
    found
}

/// The utun carrying one of Tailscale's own addresses.
fn tailscale_interface(output: &str, self_ips: &[IpAddr]) -> Option<String> {
    parse_interfaces(output)
        .into_iter()
        .find(|(name, ips)| name.starts_with("utun") && ips.iter().any(|ip| self_ips.contains(ip)))
        .map(|(name, _)| name)
}

/// Where the kernel would send `probe`: the interface and, for IPv4, the
/// prefix length of the route that wins.
fn lookup(runner: &dyn Runner, probe: IpAddr) -> Option<(String, Option<u8>)> {
    let mut args = vec!["-n".to_string(), "get".to_string()];
    if probe.is_ipv6() {
        args.push("-inet6".into());
    }
    args.push(probe.to_string());
    let output = runner.run(ROUTE, &args).ok()?;
    let mut interface = None;
    let mut prefix = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("interface:") {
            interface = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("mask:") {
            let value = value.trim();
            prefix = if value == "default" {
                Some(0)
            } else {
                value
                    .parse::<Ipv4Addr>()
                    .ok()
                    .map(|mask| u32::from(mask).count_ones() as u8)
            };
        }
    }
    interface
        .filter(|name| !name.is_empty())
        .map(|name| (name, prefix))
}

/// A remote address worth a bypass: public unicast IPv4.
fn bypassable(ip: &IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V4(ip) = ip else { return None };
    let special = ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || TAILNET_V4.contains(ip);
    (!special).then_some(*ip)
}

fn same_route(a: &RouteOp, b: &RouteOp) -> bool {
    a.network == b.network && a.prefix == b.prefix && a.target == b.target
}

impl TailscaleGuard {
    pub fn new(runner: Box<dyn Runner>, journal: Journal) -> Self {
        Self {
            runner,
            journal,
            installed: Mutex::new(Vec::new()),
        }
    }

    /// Routes a dead helper left behind are undone at start.
    pub fn recover(&self) -> io::Result<bool> {
        let Some(record) = self.journal.load()? else {
            return Ok(false);
        };
        routes::remove(&*self.runner, &record.routes);
        self.journal.clear()?;
        Ok(true)
    }

    fn validate(params: &TailscaleProtectParams) -> Result<(), Error> {
        if params.self_ips.is_empty()
            || params.self_ips.len() > MAX_SELF_IPS
            || !params.self_ips.iter().all(in_tailnet)
        {
            return Err(Error::Invalid(
                "Tailscale's own addresses are not valid".into(),
            ));
        }
        if params.endpoints.len() > MAX_ENDPOINTS {
            return Err(Error::Invalid("too many Tailscale endpoints".into()));
        }
        Ok(())
    }

    fn save(&self, interface: &str, installed: &[RouteOp]) -> Result<(), Error> {
        if installed.is_empty() {
            return self.journal.clear().map_err(|_| {
                Error::Unavailable("The Tailscale state could not be recorded".into())
            });
        }
        self.journal
            .save(&Record {
                profile_id: JOURNAL_ID.into(),
                interface: interface.into(),
                pid: 0,
                routes: installed.to_vec(),
                dns: None,
                resolver_domains: Vec::new(),
            })
            .map_err(|_| Error::Unavailable("The Tailscale state could not be recorded".into()))
    }

    /// Make the helper's Tailscale routes match what `params` call for: pins
    /// where something else wins a tailnet prefix, bypasses for Tailscale's
    /// own remote hosts. Idempotent; routes that are already right are left
    /// alone so a refresh never blinks the tailnet.
    pub fn protect(
        &self,
        params: &TailscaleProtectParams,
    ) -> Result<TailscaleProtectResult, Error> {
        Self::validate(params)?;
        let mut installed = self.installed.lock().unwrap_or_else(|e| e.into_inner());
        let listing = self
            .runner
            .run(IFCONFIG, &[])
            .map_err(|_| Error::Unavailable("The network interfaces could not be read".into()))?;
        // Tailscale that is still starting (or cut off from its relay by the
        // very tunnel being guarded) has no address on its utun yet; its
        // traffic needs the bypass most exactly then, so only the pins wait.
        let interface = tailscale_interface(&listing, &params.self_ips);
        let mut desired: Vec<RouteOp> = Vec::new();
        if let Some(interface) = &interface {
            let target = Target::Interface {
                name: interface.clone(),
            };
            let mut pins: Vec<(IpAddr, u8)> = vec![(IpAddr::V4(TAILNET_V4.network()), 10)];
            if params.self_ips.iter().any(|ip| ip.is_ipv6()) {
                pins.push((IpAddr::V6(TAILNET_V6.network()), 48));
            }
            for (network, prefix) in pins {
                let probe = match network {
                    IpAddr::V4(net) => IpAddr::V4(Ipv4Addr::from(u32::from(net) + 1)),
                    IpAddr::V6(net) => IpAddr::V6(Ipv6Addr::from(u128::from(net) + 1)),
                };
                let ours = installed
                    .iter()
                    .any(|op| op.network == network && op.prefix == prefix && op.target == target);
                let winning = lookup(&*self.runner, probe).is_some_and(|(name, len)| {
                    name == *interface && len.is_none_or(|len| len >= prefix)
                });
                if ours || !winning {
                    desired.push(RouteOp {
                        network,
                        prefix,
                        target: target.clone(),
                        optional: true,
                    });
                }
            }
        }

        // Without a physical gateway there is nothing to route around.
        let gateway = routes::detect_uplink(&*self.runner)
            .ok()
            .and_then(|uplink| uplink.gateway);
        if let Some(gateway) = gateway {
            let mut hosts: Vec<Ipv4Addr> = params.endpoints.iter().filter_map(bypassable).collect();
            hosts.sort();
            hosts.dedup();
            for host in hosts.into_iter().filter(|host| *host != gateway) {
                desired.push(RouteOp {
                    network: IpAddr::V4(host),
                    prefix: 32,
                    target: Target::Gateway {
                        address: IpAddr::V4(gateway),
                    },
                    optional: true,
                });
            }
        }

        let (keep, stale): (Vec<RouteOp>, Vec<RouteOp>) = installed
            .drain(..)
            .partition(|have| desired.iter().any(|want| same_route(have, want)));
        routes::remove(&*self.runner, &stale);
        let fresh: Vec<RouteOp> = desired
            .iter()
            .filter(|want| !keep.iter().any(|have| same_route(have, want)))
            .cloned()
            .collect();
        let added = routes::apply(&*self.runner, &fresh).unwrap_or_default();
        let mut now = keep;
        now.extend(added);
        *installed = now;
        self.save(interface.as_deref().unwrap_or(""), &installed)?;

        let pinned = installed
            .iter()
            .filter(|op| op.prefix < 32 && matches!(op.target, Target::Interface { .. }))
            .map(|op| format!("{}/{}", op.network, op.prefix))
            .collect();
        let bypassed = installed
            .iter()
            .filter(|op| matches!(op.target, Target::Gateway { .. }))
            .count() as u32;
        Ok(TailscaleProtectResult {
            interface,
            pinned,
            bypassed,
        })
    }

    /// Hand every route back. `true` when there was something to remove.
    pub fn release(&self) -> Result<bool, Error> {
        let mut installed = self.installed.lock().unwrap_or_else(|e| e.into_inner());
        let had = !installed.is_empty();
        routes::remove(&*self.runner, &installed);
        installed.clear();
        self.save("", &installed)?;
        Ok(had)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysexec::fake::FakeRunner;
    use std::sync::Arc;

    const IFCONFIG_OUT: &str = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
\tinet 127.0.0.1 netmask 0xff000000\n\
en0: flags=8863<UP> mtu 1500\n\
\tinet 10.228.40.5 netmask 0xffffff00 broadcast 10.228.40.255\n\
utun10: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n\
\tinet 169.254.10.2 --> 169.254.10.1 netmask 0xffffff00\n\
utun12: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280\n\
\tinet6 fe80::1%utun12 prefixlen 64 scopeid 0x1c\n\
\tinet 100.115.39.70 --> 100.115.39.70 netmask 0xffffffff\n\
\tinet6 fd7a:115c:a1e0::c82f:2747 prefixlen 128\n";

    const UPLINK: &str = "gateway: 10.228.40.1\n interface: en0\n";

    fn self_ips() -> Vec<IpAddr> {
        vec![
            "100.115.39.70".parse().unwrap(),
            "fd7a:115c:a1e0::c82f:2747".parse().unwrap(),
        ]
    }

    fn params(endpoints: &[&str]) -> TailscaleProtectParams {
        TailscaleProtectParams {
            self_ips: self_ips(),
            endpoints: endpoints.iter().map(|ip| ip.parse().unwrap()).collect(),
        }
    }

    /// A runner that is shared with the test so calls can be inspected.
    struct Shared(Arc<FakeRunner>);
    impl Runner for Shared {
        fn run(&self, program: &str, args: &[String]) -> io::Result<String> {
            self.0.run(program, args)
        }
    }

    fn guard(dir: &std::path::Path) -> (TailscaleGuard, Arc<FakeRunner>) {
        let runner = Arc::new(FakeRunner::default());
        runner.reply("ifconfig", IFCONFIG_OUT);
        runner.reply("route -n get default", UPLINK);
        // Tailscale's own routes win by default.
        runner.reply(
            "route -n get 100.64.0.1",
            "interface: utun12\n mask: 255.192.0.0\n",
        );
        runner.reply(
            "route -n get -inet6 fd7a:115c:a1e0::1",
            "interface: utun12\n",
        );
        let guard = TailscaleGuard::new(
            Box::new(Shared(runner.clone())),
            Journal::named(dir, "tailscale.json"),
        );
        (guard, runner)
    }

    fn mutations(runner: &FakeRunner) -> Vec<String> {
        runner
            .calls()
            .into_iter()
            .filter(|call| call.starts_with("route -n add") || call.starts_with("route -n delete"))
            .collect()
    }

    #[test]
    fn the_interface_is_found_by_tailscales_own_address() {
        assert_eq!(
            tailscale_interface(IFCONFIG_OUT, &self_ips()).as_deref(),
            Some("utun12")
        );
        // Another tunnel's addresses never qualify.
        assert_eq!(
            tailscale_interface(IFCONFIG_OUT, &["100.99.1.1".parse().unwrap()]),
            None
        );
        // Not a utun: not Tailscale's.
        assert_eq!(
            tailscale_interface(IFCONFIG_OUT, &["10.228.40.5".parse().unwrap()]),
            None
        );
    }

    #[test]
    fn routes_tailscale_already_wins_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, runner) = guard(dir.path());
        let result = guard.protect(&params(&[])).unwrap();
        assert_eq!(result.interface.as_deref(), Some("utun12"));
        assert!(result.pinned.is_empty());
        assert!(mutations(&runner).is_empty());
    }

    #[test]
    fn a_prefix_another_route_wins_is_pinned_and_released() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, runner) = guard(dir.path());
        // A pushed route took the tailnet range.
        let runner2 = Arc::new(FakeRunner::default());
        runner2.reply("ifconfig", IFCONFIG_OUT);
        runner2.reply("route -n get default", UPLINK);
        runner2.reply(
            "route -n get 100.64.0.1",
            "interface: utun9\n mask: 255.192.0.0\n",
        );
        runner2.reply(
            "route -n get -inet6 fd7a:115c:a1e0::1",
            "interface: utun12\n",
        );
        let stolen = TailscaleGuard::new(
            Box::new(Shared(runner2.clone())),
            Journal::named(dir.path(), "tailscale-2.json"),
        );
        let result = stolen.protect(&params(&[])).unwrap();
        assert_eq!(result.pinned, ["100.64.0.0/10"]);
        assert_eq!(
            mutations(&runner2),
            ["route -n add -net 100.64.0.0 -netmask 255.192.0.0 -interface utun12"]
        );
        assert!(stolen.release().unwrap());
        assert!(mutations(&runner2)
            .last()
            .unwrap()
            .starts_with("route -n delete -net 100.64.0.0"));
        assert!(!stolen.release().unwrap());
        // The first guard never saw a conflict.
        guard.protect(&params(&[])).unwrap();
        assert!(mutations(&runner).is_empty());
    }

    #[test]
    fn a_shorter_winning_route_does_not_count_as_ours() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, runner) = guard(dir.path());
        // Same interface name but a /2: the tailnet range is not what wins.
        let broken = Arc::new(FakeRunner::default());
        broken.reply("ifconfig", IFCONFIG_OUT);
        broken.reply("route -n get default", UPLINK);
        broken.reply(
            "route -n get 100.64.0.1",
            "interface: utun12\n mask: 192.0.0.0\n",
        );
        broken.reply(
            "route -n get -inet6 fd7a:115c:a1e0::1",
            "interface: utun12\n",
        );
        let g = TailscaleGuard::new(
            Box::new(Shared(broken.clone())),
            Journal::named(dir.path(), "t3.json"),
        );
        assert_eq!(g.protect(&params(&[])).unwrap().pinned, ["100.64.0.0/10"]);
        drop((guard, runner));
    }

    #[test]
    fn endpoints_bypass_through_the_gateway_and_private_ones_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, runner) = guard(dir.path());
        let result = guard
            .protect(&params(&[
                "203.0.113.7",
                "203.0.113.7",
                "192.168.1.9",
                "100.79.1.1",
                "127.0.0.1",
                "10.228.40.1",
                "2001:db8::1",
            ]))
            .unwrap();
        assert_eq!(result.bypassed, 1);
        assert_eq!(
            mutations(&runner),
            ["route -n add -host 203.0.113.7 -gateway 10.228.40.1"]
        );
        // Asking again changes nothing; a different set swaps only the difference.
        guard.protect(&params(&["203.0.113.7"])).unwrap();
        assert_eq!(mutations(&runner).len(), 1);
        let result = guard.protect(&params(&["198.51.100.4"])).unwrap();
        assert_eq!(result.bypassed, 1);
        let calls = mutations(&runner);
        assert!(calls[1].starts_with("route -n delete -host 203.0.113.7"));
        assert_eq!(
            calls[2],
            "route -n add -host 198.51.100.4 -gateway 10.228.40.1"
        );
    }

    #[test]
    fn a_changed_gateway_replaces_the_bypass() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, runner) = guard(dir.path());
        guard.protect(&params(&["203.0.113.7"])).unwrap();
        // Wi-Fi changed: the same host must now go via the new router.
        let moved = Arc::new(FakeRunner::default());
        moved.reply("ifconfig", IFCONFIG_OUT);
        moved.reply(
            "route -n get default",
            "gateway: 172.20.0.1\n interface: en0\n",
        );
        moved.reply(
            "route -n get 100.64.0.1",
            "interface: utun12\n mask: 255.192.0.0\n",
        );
        moved.reply(
            "route -n get -inet6 fd7a:115c:a1e0::1",
            "interface: utun12\n",
        );
        let g = TailscaleGuard::new(
            Box::new(Shared(moved.clone())),
            Journal::named(dir.path(), "t4.json"),
        );
        g.protect(&params(&["203.0.113.7"])).unwrap();
        assert_eq!(
            mutations(&moved),
            ["route -n add -host 203.0.113.7 -gateway 172.20.0.1"]
        );
        drop(runner);
    }

    #[test]
    fn a_default_route_owned_by_a_tunnel_skips_the_bypass_only() {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(FakeRunner::default());
        runner.reply("ifconfig", IFCONFIG_OUT);
        runner.reply(
            "route -n get default",
            "gateway: 10.0.0.1\n interface: utun4\n",
        );
        runner.reply(
            "route -n get 100.64.0.1",
            "interface: utun12\n mask: 255.192.0.0\n",
        );
        runner.reply(
            "route -n get -inet6 fd7a:115c:a1e0::1",
            "interface: utun12\n",
        );
        let guard = TailscaleGuard::new(
            Box::new(Shared(runner.clone())),
            Journal::named(dir.path(), "tailscale.json"),
        );
        let result = guard.protect(&params(&["203.0.113.7"])).unwrap();
        assert_eq!(result.bypassed, 0);
        assert!(mutations(&runner).is_empty());
    }

    #[test]
    fn tailscale_still_starting_gets_its_bypass_but_no_pins() {
        let dir = tempfile::tempdir().unwrap();
        // Its utun exists but carries no address yet.
        let runner = Arc::new(FakeRunner::default());
        runner.reply(
            "ifconfig",
            "utun11: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280\n",
        );
        runner.reply("route -n get default", UPLINK);
        let guard = TailscaleGuard::new(
            Box::new(Shared(runner.clone())),
            Journal::named(dir.path(), "tailscale.json"),
        );
        let result = guard.protect(&params(&["176.98.188.76"])).unwrap();
        assert_eq!(result.interface, None);
        assert!(result.pinned.is_empty());
        assert_eq!(result.bypassed, 1);
        assert_eq!(
            mutations(&runner),
            ["route -n add -host 176.98.188.76 -gateway 10.228.40.1"]
        );
    }

    #[test]
    fn a_dead_helpers_routes_are_undone_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, _) = guard(dir.path());
        guard.protect(&params(&["203.0.113.7"])).unwrap();
        let fresh = Arc::new(FakeRunner::default());
        let restarted = TailscaleGuard::new(
            Box::new(Shared(fresh.clone())),
            Journal::named(dir.path(), "tailscale.json"),
        );
        assert!(restarted.recover().unwrap());
        assert!(mutations(&fresh)[0].starts_with("route -n delete -host 203.0.113.7"));
        assert!(!restarted.recover().unwrap());
    }

    #[test]
    fn the_journal_holds_only_what_was_installed() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, runner) = guard(dir.path());
        // A host that already has a route: the add fails and is not ours.
        runner.fail("route -n add -host 198.51.100.4");
        let result = guard
            .protect(&params(&["203.0.113.7", "198.51.100.4"]))
            .unwrap();
        assert_eq!(result.bypassed, 1);
        let journal = Journal::named(dir.path(), "tailscale.json");
        let record = journal.load().unwrap().unwrap();
        assert_eq!(record.routes.len(), 1);
        assert_eq!(
            record.routes[0].network,
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        guard.release().unwrap();
        assert_eq!(journal.load().unwrap(), None);
    }

    #[test]
    fn foreign_addresses_and_oversized_requests_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (guard, runner) = guard(dir.path());
        let bad = |ips: &[&str]| TailscaleProtectParams {
            self_ips: ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            endpoints: Vec::new(),
        };
        assert!(guard.protect(&bad(&[])).is_err());
        assert!(guard.protect(&bad(&["192.168.1.2"])).is_err());
        assert!(guard.protect(&bad(&["100.115.39.70", "8.8.8.8"])).is_err());
        let many = TailscaleProtectParams {
            self_ips: self_ips(),
            endpoints: (0..=MAX_ENDPOINTS as u32)
                .map(|n| IpAddr::V4(Ipv4Addr::from(0xCB00_7100 + n)))
                .collect(),
        };
        assert!(guard.protect(&many).is_err());
        assert!(runner.calls().is_empty());
    }
}
