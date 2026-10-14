//! System DNS for the tunnel: point the uplink's network service at Xray's
//! resolver on the tunnel gateway, remembering exactly what was there.

use crate::sysexec::{Runner, IPCONFIG, NETWORKSETUP};
use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;

/// What the service had before; `servers` empty means "automatic (DHCP)".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub service: String,
    pub servers: Vec<IpAddr>,
}

/// `networksetup -listnetworkserviceorder` → the service whose device is
/// `device`. Disabled services are listed with a leading `*` and skipped.
pub fn service_for_device(order: &str, device: &str) -> Option<String> {
    let mut current: Option<String> = None;
    for line in order.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('(') {
            if let Some((index, name)) = rest.split_once(')') {
                if index.chars().all(|c| c.is_ascii_digit() || c == '*') {
                    let name = name.trim();
                    current = (!index.contains('*')).then(|| name.to_string());
                    continue;
                }
            }
            // "(Hardware Port: Wi-Fi, Device: en0)"
            if let (Some(service), Some(pos)) = (&current, rest.find("Device:")) {
                let dev = rest[pos + "Device:".len()..]
                    .trim()
                    .trim_end_matches(')')
                    .trim();
                if dev == device {
                    return Some(service.clone());
                }
            }
        }
    }
    None
}

fn parse_servers(output: &str) -> Vec<IpAddr> {
    // "There aren't any DNS Servers set on Wi-Fi." parses to nothing.
    output
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

pub fn snapshot(runner: &dyn Runner, device: &str) -> io::Result<Snapshot> {
    let order = runner.run(NETWORKSETUP, &["-listnetworkserviceorder".into()])?;
    let service = service_for_device(&order, device)
        .ok_or_else(|| io::Error::other("no network service for the uplink interface"))?;
    let current = runner.run(NETWORKSETUP, &["-getdnsservers".into(), service.clone()])?;
    Ok(Snapshot {
        service,
        servers: parse_servers(&current),
    })
}

const MAX_LOCAL_RESOLVERS: usize = 4;

fn usable_resolver(ip: &IpAddr) -> bool {
    let tunnel = IpAddr::V4(crate::tun::GATEWAY);
    !(ip.is_loopback()
        || ip.is_unspecified()
        || *ip == tunnel
        || matches!(ip, IpAddr::V4(v4) if v4.is_link_local()))
}

/// Resolvers of the local network, which keep serving the names the profile
/// routes direct and the network's own domains: the ones set by hand on the
/// service first, then the ones DHCP handed out on the uplink (a corporate
/// resolver is usually only the latter). Read before the system DNS is
/// switched.
pub fn local_resolvers(
    runner: &dyn Runner,
    device: &str,
    snapshot: Option<&Snapshot>,
) -> Vec<IpAddr> {
    let mut found: Vec<IpAddr> = snapshot
        .map(|snapshot| snapshot.servers.clone())
        .unwrap_or_default();
    if let Ok(output) = runner.run(
        IPCONFIG,
        &[
            "getoption".into(),
            device.into(),
            "domain_name_server".into(),
        ],
    ) {
        found.extend(
            output
                .split(|c: char| c.is_whitespace() || matches!(c, ',' | '{' | '}'))
                .filter_map(|token| token.parse::<IpAddr>().ok()),
        );
    }
    found.retain(usable_resolver);
    let mut unique: Vec<IpAddr> = Vec::new();
    for ip in found {
        if !unique.contains(&ip) {
            unique.push(ip);
        }
    }
    unique.truncate(MAX_LOCAL_RESOLVERS);
    unique
}

const MAX_SEARCH_DOMAINS: usize = 8;

fn plausible_domain(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 253
        && token.contains(|c: char| c.is_ascii_alphabetic())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// The network's own domains (manual search domains of the service, DHCP
/// search/domain name): names under them live on the local network and must
/// resolve through its resolvers, not the profile's public ones.
pub fn search_domains(runner: &dyn Runner, device: &str, service: Option<&str>) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut collect = |output: io::Result<String>| {
        for token in output
            .unwrap_or_default()
            .split(|c: char| c.is_whitespace() || matches!(c, ',' | '{' | '}'))
        {
            // "There aren't any Search Domains set on X." has no such token.
            let token = token.trim_matches('.').to_ascii_lowercase();
            if plausible_domain(&token) && token.contains('.') && !found.contains(&token) {
                found.push(token);
            }
        }
    };
    if let Some(service) = service {
        collect(runner.run(NETWORKSETUP, &["-getsearchdomains".into(), service.into()]));
    }
    for option in ["search_domain", "domain_name"] {
        collect(runner.run(
            IPCONFIG,
            &["getoption".into(), device.into(), option.into()],
        ));
    }
    found.truncate(MAX_SEARCH_DOMAINS);
    found
}

fn set(runner: &dyn Runner, service: &str, servers: &[IpAddr]) -> io::Result<()> {
    let mut args = vec!["-setdnsservers".to_string(), service.to_string()];
    if servers.is_empty() {
        args.push("Empty".into());
    } else {
        args.extend(servers.iter().map(IpAddr::to_string));
    }
    runner.run(NETWORKSETUP, &args).map(|_| ())
}

pub fn apply(runner: &dyn Runner, snapshot: &Snapshot, servers: &[IpAddr]) -> io::Result<()> {
    set(runner, &snapshot.service, servers)
}

pub fn restore(runner: &dyn Runner, snapshot: &Snapshot) -> io::Result<()> {
    set(runner, &snapshot.service, &snapshot.servers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysexec::fake::FakeRunner;

    const ORDER: &str = "An asterisk (*) denotes that a network service is disabled.\n(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(*2) Old Ethernet\n(Hardware Port: Ethernet, Device: en5)\n\n(3) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n";

    #[test]
    fn service_is_found_by_device_and_disabled_ones_are_skipped() {
        assert_eq!(service_for_device(ORDER, "en0").as_deref(), Some("Wi-Fi"));
        assert_eq!(
            service_for_device(ORDER, "bridge0").as_deref(),
            Some("Thunderbolt Bridge")
        );
        assert_eq!(service_for_device(ORDER, "en5"), None);
        assert_eq!(service_for_device(ORDER, "en9"), None);
    }

    #[test]
    fn snapshot_distinguishes_automatic_from_explicit() {
        let runner = FakeRunner::default();
        runner.reply("networksetup -listnetworkserviceorder", ORDER);
        runner.reply(
            "networksetup -getdnsservers",
            "There aren't any DNS Servers set on Wi-Fi.\n",
        );
        let auto = snapshot(&runner, "en0").unwrap();
        assert_eq!(auto.servers, Vec::<IpAddr>::new());

        let runner = FakeRunner::default();
        runner.reply("networksetup -listnetworkserviceorder", ORDER);
        runner.reply(
            "networksetup -getdnsservers",
            "1.1.1.1\n2606:4700:4700::1111\n",
        );
        let explicit = snapshot(&runner, "en0").unwrap();
        assert_eq!(explicit.servers.len(), 2);
    }

    #[test]
    fn search_domains_come_from_the_service_and_dhcp_without_noise() {
        let runner = FakeRunner::default();
        runner.reply(
            "networksetup -getsearchdomains Wi-Fi",
            "agtuvsn.local\nagni.loc\n",
        );
        runner.reply(
            "ipconfig getoption en0 search_domain",
            "{agtuvsn.local, corp.example}\n",
        );
        let found = search_domains(&runner, "en0", Some("Wi-Fi"));
        assert_eq!(found, ["agtuvsn.local", "agni.loc", "corp.example"]);

        let none = FakeRunner::default();
        none.reply(
            "networksetup -getsearchdomains Wi-Fi",
            "There aren't any Search Domains set on Wi-Fi.\n",
        );
        assert!(search_domains(&none, "en0", Some("Wi-Fi")).is_empty());
    }

    #[test]
    fn explicit_resolvers_win_and_dhcp_ones_fill_in() {
        let runner = FakeRunner::default();
        runner.reply("ipconfig getoption en0 domain_name_server", "10.228.32.2\n");
        let none = Snapshot {
            service: "Wi-Fi".into(),
            servers: vec![],
        };
        assert_eq!(
            local_resolvers(&runner, "en0", Some(&none)),
            ["10.228.32.2".parse::<IpAddr>().unwrap()]
        );
        let explicit = Snapshot {
            service: "Wi-Fi".into(),
            servers: vec!["192.168.7.1".parse().unwrap()],
        };
        // Explicit ones first; the DHCP resolver (often the corporate one) follows.
        assert_eq!(
            local_resolvers(&runner, "en0", Some(&explicit)),
            [
                "192.168.7.1".parse::<IpAddr>().unwrap(),
                "10.228.32.2".parse::<IpAddr>().unwrap()
            ]
        );
        // Without a snapshot (service not found) DHCP is still consulted.
        assert_eq!(local_resolvers(&runner, "en0", None).len(), 1);
    }

    #[test]
    fn tunnel_loopback_and_link_local_resolvers_are_not_local_network() {
        let runner = FakeRunner::default();
        runner.reply(
            "ipconfig getoption en0 domain_name_server",
            "{127.0.0.1, 169.254.10.1, 169.254.5.5, 198.18.0.2}\n",
        );
        assert_eq!(
            local_resolvers(&runner, "en0", None),
            ["198.18.0.2".parse::<IpAddr>().unwrap()]
        );
        let failing = FakeRunner::default();
        failing.fail("ipconfig");
        assert!(local_resolvers(&failing, "en0", None).is_empty());
    }

    #[test]
    fn apply_and_restore_issue_the_right_commands() {
        let runner = FakeRunner::default();
        let auto = Snapshot {
            service: "Wi-Fi".into(),
            servers: vec![],
        };
        apply(&runner, &auto, &["169.254.10.1".parse().unwrap()]).unwrap();
        restore(&runner, &auto).unwrap();
        let explicit = Snapshot {
            service: "Wi-Fi".into(),
            servers: vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        };
        restore(&runner, &explicit).unwrap();
        assert_eq!(
            runner.calls(),
            [
                "networksetup -setdnsservers Wi-Fi 169.254.10.1",
                "networksetup -setdnsservers Wi-Fi Empty",
                "networksetup -setdnsservers Wi-Fi 1.1.1.1 8.8.8.8",
            ]
        );
    }
}
