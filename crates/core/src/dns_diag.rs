//! The system's DNS resolver configuration (macOS `scutil --dns`) as data, and
//! which resolver answers a given name. Pure: the caller runs `scutil` and
//! hands over its text, so the rules are tested on any OS.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// One `resolver #N` block.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolver {
    pub index: u32,
    /// The domain this resolver is for; `None` for the default resolver.
    pub domain: Option<String>,
    pub search_domains: Vec<String>,
    pub nameservers: Vec<IpAddr>,
    pub port: Option<u16>,
    /// Set for the "scoped queries" section: bound to one interface.
    pub scoped: bool,
    pub interface: Option<String>,
    pub if_index: Option<u32>,
    /// Added by a VPN or profile next to the default resolver.
    pub supplemental: bool,
    pub mdns: bool,
    pub reachable: bool,
    pub order: Option<u32>,
    pub timeout: Option<u32>,
    pub flags: Vec<String>,
}

/// Both sections of `scutil --dns`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsConfig {
    /// "DNS configuration": what ordinary queries are matched against.
    pub resolvers: Vec<Resolver>,
    /// "DNS configuration (for scoped queries)": per-interface resolvers.
    pub scoped: Vec<Resolver>,
}

pub fn parse_scutil_dns(text: &str) -> DnsConfig {
    let mut config = DnsConfig::default();
    let mut scoped_section = false;
    let mut current: Option<Resolver> = None;
    let finish = |current: &mut Option<Resolver>, scoped: bool, config: &mut DnsConfig| {
        if let Some(resolver) = current.take() {
            if scoped {
                config.scoped.push(resolver);
            } else {
                config.resolvers.push(resolver);
            }
        }
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("DNS configuration") {
            finish(&mut current, scoped_section, &mut config);
            scoped_section = trimmed.contains("scoped");
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("resolver #") {
            finish(&mut current, scoped_section, &mut config);
            current = Some(Resolver {
                index: rest.trim().parse().unwrap_or(0),
                scoped: scoped_section,
                ..Default::default()
            });
            continue;
        }
        let (Some(resolver), Some((key, value))) = (current.as_mut(), trimmed.split_once(" : "))
        else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key.split('[').next().unwrap_or(key) {
            "domain" => resolver.domain = Some(value.to_ascii_lowercase()),
            "search domain" => resolver.search_domains.push(value.to_ascii_lowercase()),
            "nameserver" => {
                if let Ok(address) = value.parse() {
                    resolver.nameservers.push(address);
                }
            }
            "port" => resolver.port = value.parse().ok(),
            "order" => resolver.order = value.parse().ok(),
            "timeout" => resolver.timeout = value.parse().ok(),
            "options" => resolver.mdns |= value.split_whitespace().any(|o| o == "mdns"),
            "if_index" => {
                // `13 (en7)`
                let (number, name) = value.split_once(' ').unwrap_or((value, ""));
                resolver.if_index = number.parse().ok();
                let name = name.trim().trim_start_matches('(').trim_end_matches(')');
                resolver.interface = (!name.is_empty()).then(|| name.to_string());
            }
            "flags" => {
                resolver.flags = value.split(',').map(|f| f.trim().to_string()).collect();
                resolver.supplemental = resolver.flags.iter().any(|f| f == "Supplemental");
            }
            "reach" => {
                resolver.reachable =
                    value.contains("Reachable") && !value.contains("Not Reachable");
            }
            _ => {}
        }
    }
    finish(&mut current, scoped_section, &mut config);
    config
}

/// A resolver that can answer unicast queries.
fn usable(resolver: &&Resolver) -> bool {
    !resolver.nameservers.is_empty() && !resolver.mdns
}

/// The resolver ordinary (unscoped) queries use when no domain matches.
pub fn default_resolver(config: &DnsConfig) -> Option<&Resolver> {
    config
        .resolvers
        .iter()
        .filter(usable)
        .filter(|r| r.domain.is_none())
        .min_by_key(|r| r.order.unwrap_or(0))
}

/// The resolver the system asks for `name`: the one whose domain is the
/// longest suffix of the name (lowest `order` on a tie), else the default.
pub fn resolver_for<'a>(config: &'a DnsConfig, name: &str) -> Option<&'a Resolver> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    config
        .resolvers
        .iter()
        .filter(usable)
        .filter_map(|resolver| {
            let domain = resolver.domain.as_deref()?;
            let inside = name == domain || name.ends_with(&format!(".{domain}"));
            inside.then_some((domain.len(), resolver))
        })
        .max_by(|(a_len, a), (b_len, b)| {
            a_len.cmp(b_len).then(
                b.order
                    .unwrap_or(u32::MAX)
                    .cmp(&a.order.unwrap_or(u32::MAX)),
            )
        })
        .map(|(_, resolver)| resolver)
        .or_else(|| default_resolver(config))
}

/// Where a probe goes: the server, its port and the resolver entry behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub server: IpAddr,
    pub port: u16,
    /// The system resolver that matched, when the server was not given.
    pub resolver_index: Option<u32>,
    pub resolver_domain: Option<String>,
}

/// An explicit server wins (port 53). Otherwise the server is the one the
/// system would ask for `hostname`: the first nameserver of its resolver.
pub fn choose_target(
    config: &DnsConfig,
    hostname: &str,
    explicit: Option<IpAddr>,
) -> Option<ProbeTarget> {
    if let Some(server) = explicit {
        return Some(ProbeTarget {
            server,
            port: 53,
            resolver_index: None,
            resolver_domain: None,
        });
    }
    let resolver = resolver_for(config, hostname)?;
    Some(ProbeTarget {
        server: *resolver.nameservers.first()?,
        port: resolver.port.unwrap_or(53),
        resolver_index: Some(resolver.index),
        resolver_domain: resolver.domain.clone(),
    })
}

/// The interface and gateway the route table sends traffic for `server` to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbePath {
    pub interface_name: String,
    pub gateway: Option<IpAddr>,
}

pub fn path_to(server: IpAddr, routes: &[crate::models::RouteEntry]) -> Option<ProbePath> {
    let route = crate::explorer::longest_prefix_match(server, routes)?;
    Some(ProbePath {
        interface_name: route.interface_name.clone(),
        gateway: route.gateway,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
DNS configuration

resolver #1
  search domain[0] : corp.example
  search domain[1] : lan.example
  nameserver[0] : 169.254.10.1
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

resolver #2
  domain   : lab.internal
  nameserver[0] : 10.85.255.254
  port     : 53
  flags    : Supplemental, Request A records
  reach    : 0x00000002 (Reachable)
  order    : 105001

resolver #3
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

resolver #4
  domain   : deep.lab.internal
  nameserver[0] : 10.99.0.53
  nameserver[1] : fd00::53
  port     : 5353
  flags    : Supplemental, Request A records
  reach    : 0x00000002 (Reachable)
  order    : 105000

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : lan.example
  nameserver[0] : 169.254.10.1
  if_index : 13 (en7)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  nameserver[0] : 10.228.32.2
  if_index : 15 (en0)
  flags    : Scoped, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)
";

    #[test]
    fn both_sections_are_parsed_into_resolvers() {
        let config = parse_scutil_dns(SAMPLE);
        assert_eq!(config.resolvers.len(), 4);
        assert_eq!(config.scoped.len(), 2);
        let first = &config.resolvers[0];
        assert_eq!(first.index, 1);
        assert_eq!(first.domain, None);
        assert_eq!(first.search_domains, ["corp.example", "lan.example"]);
        assert_eq!(
            first.nameservers,
            ["169.254.10.1".parse::<IpAddr>().unwrap()]
        );
        assert!(!first.supplemental && first.reachable);
        assert_eq!(first.order, None);
    }

    #[test]
    fn supplemental_resolvers_carry_domain_port_and_order() {
        let config = parse_scutil_dns(SAMPLE);
        let lab = &config.resolvers[1];
        assert_eq!(lab.domain.as_deref(), Some("lab.internal"));
        assert!(lab.supplemental);
        assert_eq!(lab.port, Some(53));
        assert_eq!(lab.order, Some(105001));
        let deep = &config.resolvers[3];
        assert_eq!(deep.port, Some(5353));
        assert_eq!(deep.nameservers.len(), 2);
    }

    #[test]
    fn mdns_resolvers_and_unreachable_ones_are_marked() {
        let config = parse_scutil_dns(SAMPLE);
        let local = &config.resolvers[2];
        assert!(local.mdns && !local.reachable);
        assert!(local.nameservers.is_empty());
        assert_eq!(local.timeout, Some(5));
    }

    #[test]
    fn scoped_resolvers_name_their_interface() {
        let config = parse_scutil_dns(SAMPLE);
        assert_eq!(config.scoped[0].interface.as_deref(), Some("en7"));
        assert_eq!(config.scoped[0].if_index, Some(13));
        assert!(config.scoped[0].scoped);
        assert_eq!(config.scoped[1].interface.as_deref(), Some("en0"));
        assert!(config.scoped[1]
            .flags
            .iter()
            .any(|f| f == "Request AAAA records"));
        assert!(config.resolvers.iter().all(|r| !r.scoped));
    }

    #[test]
    fn garbage_and_empty_text_give_an_empty_config() {
        assert_eq!(parse_scutil_dns(""), DnsConfig::default());
        let junk = parse_scutil_dns("no resolvers here\n  nameserver[0] : 1.1.1.1\n");
        assert!(junk.resolvers.is_empty() && junk.scoped.is_empty());
        // A bad address is skipped, not fatal.
        let bad = parse_scutil_dns(
            "resolver #1\n  nameserver[0] : not-an-ip\n  nameserver[1] : 9.9.9.9\n",
        );
        assert_eq!(
            bad.resolvers[0].nameservers,
            ["9.9.9.9".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn the_longest_matching_supplemental_domain_answers_first() {
        let config = parse_scutil_dns(SAMPLE);
        let pick = |name: &str| resolver_for(&config, name).map(|r| (r.index, r.domain.clone()));
        assert_eq!(
            pick("db.deep.lab.internal"),
            Some((4, Some("deep.lab.internal".into())))
        );
        assert_eq!(
            pick("host.lab.internal"),
            Some((2, Some("lab.internal".into())))
        );
        assert_eq!(pick("lab.internal"), Some((2, Some("lab.internal".into()))));
        // A name that merely ends with the same letters is not in the domain.
        assert_eq!(pick("notlab.internal"), Some((1, None)));
        assert_eq!(pick("example.com"), Some((1, None)));
        assert_eq!(pick("EXAMPLE.com."), Some((1, None)));
    }

    #[test]
    fn the_default_resolver_is_the_unscoped_one_without_a_domain() {
        let config = parse_scutil_dns(SAMPLE);
        assert_eq!(default_resolver(&config).unwrap().index, 1);
        assert!(default_resolver(&DnsConfig::default()).is_none());
    }

    #[test]
    fn a_resolver_without_nameservers_is_never_chosen_for_a_query() {
        let config = parse_scutil_dns(SAMPLE);
        // `.local` is answered by mDNS and has no unicast server to probe.
        assert_eq!(
            resolver_for(&config, "printer.local").map(|r| r.index),
            Some(1)
        );
    }

    fn route(
        destination: &str,
        prefix: u8,
        interface: &str,
        gateway: Option<&str>,
    ) -> crate::models::RouteEntry {
        crate::models::RouteEntry {
            destination: destination.parse().unwrap(),
            prefix_len: prefix,
            gateway: gateway.map(|g| g.parse().unwrap()),
            interface_index: 1,
            interface_name: interface.into(),
            metric: 0,
        }
    }

    #[test]
    fn without_a_given_server_the_matching_resolver_decides_server_and_port() {
        let config = parse_scutil_dns(SAMPLE);
        let target = choose_target(&config, "api.deep.lab.internal", None).unwrap();
        assert_eq!(target.server, "10.99.0.53".parse::<IpAddr>().unwrap());
        assert_eq!(target.port, 5353);
        assert_eq!(target.resolver_index, Some(4));
        assert_eq!(target.resolver_domain.as_deref(), Some("deep.lab.internal"));
        let default = choose_target(&config, "example.com", None).unwrap();
        assert_eq!((default.resolver_index, default.port), (Some(1), 53));
        assert_eq!(default.resolver_domain, None);
    }

    #[test]
    fn a_given_server_is_used_as_is_on_port_53() {
        let target = choose_target(
            &DnsConfig::default(),
            "x.com",
            Some("1.1.1.1".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(target.server.to_string(), "1.1.1.1");
        assert_eq!((target.port, target.resolver_index), (53, None));
        assert!(choose_target(&DnsConfig::default(), "x.com", None).is_none());
    }

    #[test]
    fn the_path_to_a_server_is_the_longest_matching_route() {
        let routes = [
            route("0.0.0.0", 0, "en0", Some("192.168.1.1")),
            route("10.0.0.0", 8, "utun5", None),
        ];
        let tunnel = path_to("10.85.255.254".parse().unwrap(), &routes).unwrap();
        assert_eq!(
            (tunnel.interface_name.as_str(), tunnel.gateway),
            ("utun5", None)
        );
        let uplink = path_to("1.1.1.1".parse().unwrap(), &routes).unwrap();
        assert_eq!(uplink.interface_name, "en0");
        assert_eq!(uplink.gateway, Some("192.168.1.1".parse().unwrap()));
        assert!(path_to("1.1.1.1".parse().unwrap(), &[]).is_none());
    }
}
