//! Happ/Incy routing-profile import.
//!
//! Happ exports routing profiles as a single JSON object (frequently
//! base64/base64url-encoded or wrapped in a `happ://routing/<payload>` /
//! `incy://routing/<payload>` deep link). The format is informal and
//! unversioned: key casing varies between producers (`Geoipurl`,
//! `geoipURL`), booleans may arrive as `"true"` strings, and fields carry
//! overlapping representations of the same resolver. This module is the
//! compat boundary: it normalizes all of that into our per-profile model
//! and reports what could not be represented as warnings instead of
//! silently dropping it.

use crate::models::{
    DomainPolicy, DomainRouteTarget, XrayDnsConfig, XrayDnsQueryStrategy, XrayDnsRoute,
    XrayDnsServer, XrayDomainMatcher, XrayDomainStrategy,
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::io;

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

/// Routing fields recovered from a Happ profile. `None`/empty means the
/// source did not mention the setting — callers leave the existing profile
/// value untouched.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HappRoutingImport {
    /// Profile `Name`, surfaced for display only — never renames the
    /// existing profile.
    pub name: Option<String>,
    /// Ordered policies: `RouteOrder` decides the bucket order, sites and
    /// ip lists merge into one selector list per target.
    pub domain_policies: Vec<DomainPolicy>,
    pub private_lan_direct: Option<bool>,
    pub domain_strategy: Option<XrayDomainStrategy>,
    pub domain_matcher: Option<XrayDomainMatcher>,
    pub dns: XrayDnsConfig,
    pub geoip_url: Option<String>,
    pub geosite_url: Option<String>,
    /// Non-fatal quirks: unsupported or conflicting source settings.
    pub warnings: Vec<String>,
}

/// Parse a Happ routing profile. Accepts raw JSON, base64/base64url
/// (padded or not) and `happ://`/`incy://` routing deep links.
pub fn parse_happ_routing(input: &str) -> io::Result<HappRoutingImport> {
    let payload = extract_payload(input)?;
    let value = decode_payload(&payload)?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid_input("happ routing profile must be a JSON object"))?;
    import_object(object)
}

/// Strip an optional deep-link wrapper, returning the embedded payload.
fn extract_payload(input: &str) -> io::Result<String> {
    let trimmed = input.trim();
    let Some(pos) = trimmed.find("://") else {
        return Ok(trimmed.to_string());
    };
    let scheme = trimmed[..pos].to_ascii_lowercase();
    let rest = trimmed[pos + 3..].trim_start_matches('/');
    let Some(after) = rest.strip_prefix("routing") else {
        return Ok(trimmed.to_string());
    };
    if !matches!(scheme.as_str(), "happ" | "incy") {
        return Ok(trimmed.to_string());
    }
    let mut after = after.trim_start_matches('/');
    if let Some(rest) = after.strip_prefix("add") {
        after = rest.trim_start_matches('/');
    }
    let after = after.trim();
    if matches!(after.to_ascii_lowercase().as_str(), "off" | "0" | "false") {
        return Err(invalid_input(
            "happ routing link disables routing, nothing to import",
        ));
    }
    if after.starts_with("http://") || after.starts_with("https://") {
        return Err(invalid_input(
            "happ routing link points at a remote profile; paste the exported JSON instead",
        ));
    }
    if after.is_empty() {
        return Err(invalid_input("happ routing link carries no payload"));
    }
    Ok(after.to_string())
}

fn decode_payload(payload: &str) -> io::Result<Value> {
    use base64::Engine;
    if let Ok(value) = serde_json::from_str::<Value>(payload) {
        return Ok(value);
    }
    let engines = [
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::STANDARD,
    ];
    for engine in engines {
        if let Ok(bytes) = engine.decode(payload.trim()) {
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                return Ok(value);
            }
        }
    }
    Err(invalid_input(
        "payload is neither a JSON object nor base64-encoded one",
    ))
}

/// Case-insensitive field lookup: producers emit `Geoipurl`, `geoipURL`
/// and other casings for the same field.
fn get<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value)
}

fn as_str(value: &Value) -> Option<&str> {
    value.as_str().map(str::trim).filter(|s| !s.is_empty())
}

/// Happ booleans arrive as `true`, `"true"`, `1` or missing.
fn as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        Value::Number(n) => n.as_u64().map(|n| n != 0),
        _ => None,
    }
}

/// Selector lists are arrays of strings; tolerate a bare string (one
/// selector per line) since hand-edited exports show up in the wild.
fn as_selector_list(value: Option<&Value>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    match value {
        Value::Array(items) => items.iter().filter_map(as_str).map(String::from).collect(),
        Value::String(text) => text.lines().map(str::trim).filter(|l| !l.is_empty()).fold(
            Vec::new(),
            |mut acc, line| {
                acc.push(line.to_string());
                acc
            },
        ),
        _ => Vec::new(),
    }
}

/// `RouteOrder` is `"block-proxy-direct"` style text (occasionally an
/// array). Unknown or missing tokens keep their default tail order; a
/// fully unrecognized value falls back to block → proxy → direct.
fn route_order(value: Option<&Value>, warnings: &mut Vec<String>) -> [DomainRouteTarget; 3] {
    use DomainRouteTarget::*;
    const DEFAULT: [DomainRouteTarget; 3] = [Block, Proxy, Direct];
    let token = |raw: &str| match raw.trim().to_ascii_lowercase().as_str() {
        "block" => Some(Block),
        "proxy" => Some(Proxy),
        "direct" => Some(Direct),
        _ => None,
    };
    let mut tokens: Vec<String> = match value {
        Some(Value::String(text)) => text
            .split(['-', ',', ' '])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect(),
        Some(Value::Array(items)) => items.iter().filter_map(as_str).map(String::from).collect(),
        _ => Vec::new(),
    };
    if tokens.is_empty() {
        return DEFAULT;
    }
    let mut order = Vec::new();
    for raw in tokens.drain(..) {
        match token(&raw) {
            Some(target) if !order.contains(&target) => order.push(target),
            Some(_) => {}
            None => warnings.push(format!("routeOrder entry '{raw}' is not recognized")),
        }
    }
    for target in DEFAULT {
        if !order.contains(&target) {
            order.push(target);
        }
    }
    [order[0], order[1], order[2]]
}

fn parse_domain_strategy(
    value: Option<&Value>,
    warnings: &mut Vec<String>,
) -> Option<XrayDomainStrategy> {
    let raw = value.and_then(as_str)?;
    match raw
        .to_ascii_lowercase()
        .replace(['_', '-', ' '], "")
        .as_str()
    {
        "asis" => Some(XrayDomainStrategy::AsIs),
        "ipifnonmatch" => Some(XrayDomainStrategy::IpIfNonMatch),
        "ipondemand" => Some(XrayDomainStrategy::IpOnDemand),
        _ => {
            warnings.push(format!("DomainStrategy '{raw}' is not recognized"));
            None
        }
    }
}

fn parse_domain_matcher(
    value: Option<&Value>,
    warnings: &mut Vec<String>,
) -> Option<XrayDomainMatcher> {
    let raw = value.and_then(as_str)?;
    match raw.to_ascii_lowercase().as_str() {
        "mph" => Some(XrayDomainMatcher::Mph),
        "hybrid" => Some(XrayDomainMatcher::Hybrid),
        "linear" => Some(XrayDomainMatcher::Linear),
        _ => {
            warnings.push(format!("domainMatcher '{raw}' is not recognized"));
            None
        }
    }
}

/// DNS type tokens seen in exports: `DoH`, `DoT`, `UDP`, `TCP`, `DoU`,
/// plus the literal schemes when the domain field already holds a URL.
fn resolver_scheme(dns_type: Option<&str>) -> &'static str {
    match dns_type
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("doh") | Some("https") | Some("https+local") => "https",
        Some("dot") | Some("tls") => "tls",
        Some("tcp") => "tcp",
        Some("quic") | Some("quic+local") => "quic+local",
        _ => "udp",
    }
}

/// One resolver definition collapses three overlapping Happ fields:
/// `RemoteDns` (a bare string carrying its own scheme), `RemoteDNSType` +
/// `RemoteDNSDomain` (a URL), and `RemoteDNSIP` (a bare host).
fn resolver_address(
    bare: Option<&Value>,
    dns_type: Option<&Value>,
    domain: Option<&Value>,
    ip: Option<&Value>,
) -> Option<String> {
    if let Some(text) = bare.and_then(as_str) {
        return Some(text.to_string());
    }
    let scheme = resolver_scheme(dns_type.and_then(as_str));
    if let Some(domain) = domain.and_then(as_str) {
        if domain.contains("://") {
            return Some(domain.to_string());
        }
        return match scheme {
            "udp" => Some(domain.to_string()),
            _ => Some(format!("{scheme}://{domain}")),
        };
    }
    ip.and_then(as_str).map(|ip| match scheme {
        "https" => format!("https://{ip}/dns-query"),
        "udp" => ip.to_string(),
        _ => format!("{scheme}://{ip}"),
    })
}

/// `DnsHosts` maps a hostname to one IP string, a comma-separated list or
/// an array of addresses.
fn parse_dns_hosts(
    value: Option<&Value>,
    hosts: &mut std::collections::BTreeMap<String, Vec<String>>,
) {
    let Some(object) = value.and_then(Value::as_object) else {
        return;
    };
    for (name, entry) in object {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let addresses: Vec<String> = match entry {
            Value::String(text) => text
                .split(',')
                .map(str::trim)
                .filter(|a| !a.is_empty())
                .map(String::from)
                .collect(),
            Value::Array(items) => items.iter().filter_map(as_str).map(String::from).collect(),
            _ => Vec::new(),
        };
        if !addresses.is_empty() {
            hosts.insert(name.to_string(), addresses);
        }
    }
}

fn parse_query_strategy(value: Option<&Value>) -> Option<XrayDnsQueryStrategy> {
    let raw = value.and_then(as_str)?;
    match raw
        .to_ascii_lowercase()
        .replace(['_', '-', ' '], "")
        .as_str()
    {
        "useip" | "auto" | "ip" => Some(XrayDnsQueryStrategy::UseIp),
        "useipv4" | "ipv4" => Some(XrayDnsQueryStrategy::UseIpv4),
        "useipv6" | "ipv6" => Some(XrayDnsQueryStrategy::UseIpv6),
        _ => None,
    }
}

fn import_object(object: &Map<String, Value>) -> io::Result<HappRoutingImport> {
    let mut warnings = Vec::new();
    let mut import = HappRoutingImport {
        name: get(object, "Name").and_then(as_str).map(String::from),
        warnings: Vec::new(),
        ..HappRoutingImport::default()
    };

    let order = route_order(get(object, "RouteOrder"), &mut warnings);
    let buckets = [
        (DomainRouteTarget::Block, "BlockSites", "BlockIp"),
        (DomainRouteTarget::Proxy, "ProxySites", "ProxyIp"),
        (DomainRouteTarget::Direct, "DirectSites", "DirectIp"),
    ];
    for target in order {
        let (_, sites_key, ip_key) = buckets
            .iter()
            .find(|(bucket, _, _)| *bucket == target)
            .expect("route order covers every target");
        let mut selectors = as_selector_list(get(object, sites_key));
        selectors.extend(as_selector_list(get(object, ip_key)));
        if !selectors.is_empty() {
            import.domain_policies.push(DomainPolicy {
                domains: selectors,
                target,
            });
        }
    }

    import.domain_strategy = parse_domain_strategy(get(object, "DomainStrategy"), &mut warnings);
    import.domain_matcher = parse_domain_matcher(get(object, "domainMatcher"), &mut warnings);
    import.private_lan_direct = get(object, "bypassPrivateIPs").and_then(as_bool);
    if get(object, "GlobalProxy").and_then(as_bool) == Some(false) {
        warnings.push(
            "GlobalProxy is off; unmatched traffic still goes through the profile's proxy"
                .to_string(),
        );
    }

    for (bare, kind, domain_key, ip_key, route) in [
        (
            get(object, "RemoteDns"),
            "remote",
            "RemoteDNSDomain",
            "RemoteDNSIP",
            XrayDnsRoute::Proxy,
        ),
        (
            get(object, "DomesticDns"),
            "domestic",
            "DomesticDNSDomain",
            "DomesticDNSIP",
            XrayDnsRoute::Direct,
        ),
    ] {
        let dns_type = get(
            object,
            if kind == "remote" {
                "RemoteDNSType"
            } else {
                "DomesticDNSType"
            },
        );
        if let Some(address) =
            resolver_address(bare, dns_type, get(object, domain_key), get(object, ip_key))
        {
            import.dns.servers.push(XrayDnsServer {
                address,
                port: None,
                domains: Vec::new(),
                skip_fallback: false,
                route,
            });
        }
    }

    parse_dns_hosts(get(object, "DnsHosts"), &mut import.dns.hosts);
    import.dns.fake_dns = get(object, "FakeDNS")
        .or_else(|| get(object, "enableFakeDNS"))
        .and_then(as_bool)
        .unwrap_or(false);
    import.dns.query_strategy = parse_query_strategy(get(object, "queryStrategy"))
        .or_else(|| parse_query_strategy(get(object, "preferredIPType")));

    for (field, key) in [
        ("remoteDnsAddresses", "remoteDnsAddresses"),
        ("domesticDnsAddresses", "domesticDnsAddresses"),
    ] {
        if get(object, key)
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty())
        {
            warnings.push(format!(
                "{field} per-domain DNS overrides are not supported"
            ));
        }
    }

    for (target, key) in [
        (&mut import.geoip_url, "Geoipurl"),
        (&mut import.geosite_url, "Geositeurl"),
    ] {
        if let Some(url) = get(object, key).and_then(as_str) {
            if url.starts_with("https://") || url.starts_with("http://") {
                *target = Some(url.to_string());
            } else {
                warnings.push(format!("{key} '{url}' is not an http(s) URL, skipped"));
            }
        }
    }

    if import.domain_policies.is_empty()
        && import.dns.is_empty()
        && import.domain_strategy.is_none()
        && import.geoip_url.is_none()
        && import.geosite_url.is_none()
        && import.private_lan_direct.is_none()
    {
        return Err(invalid_input(
            "no recognizable Happ routing fields in the payload",
        ));
    }
    import.warnings = warnings;
    Ok(import)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::XrayDnsQueryStrategy;
    use base64::Engine;

    const ROSCOMVPN: &str = r##"{
        "id": "7d9faac0-02e7-4513-8f76-44a0874ec1ae",
        "Name": "RoscomVPN",
        "type": "GLOBAL",
        "GlobalProxy": true,
        "RemoteDNSType": "DoH",
        "RemoteDNSDomain": "https://8.8.8.8/dns-query",
        "RemoteDNSIP": "8.8.8.8",
        "DomesticDNSType": "DoH",
        "DomesticDNSDomain": "https://77.88.8.8/dns-query",
        "DomesticDNSIP": "77.88.8.8",
        "FakeDNS": false,
        "DnsHosts": {
            "lkfl2.nalog.ru": "213.24.64.175",
            "lknpd.nalog.ru": "213.24.64.181"
        },
        "RemoteDns": "8.8.8.8",
        "DomesticDns": "77.88.8.8",
        "Geoipurl": "https://cdn.example.test/geoip.dat",
        "Geositeurl": "https://cdn.example.test/geosite.dat",
        "GeoipHash": "0ff7bd",
        "DirectSites": ["geosite:private", "# custom", "domain:ozon.ru"],
        "ProxySites": ["geosite:youtube", "geosite:telegram"],
        "BlockSites": ["geosite:category-ads"],
        "DirectIp": ["geoip:private", "100.125.55.11"],
        "DomainStrategy": "IPIfNonMatch",
        "RouteOrder": "block-proxy-direct",
        "bypassPrivateIPs": true,
        "isEditable": true,
        "sortOrder": 0
    }"##;

    #[test]
    fn full_profile_maps_every_bucket() {
        let import = parse_happ_routing(ROSCOMVPN).unwrap();
        assert_eq!(import.name.as_deref(), Some("RoscomVPN"));
        assert_eq!(import.domain_policies.len(), 3);
        // RouteOrder block-proxy-direct pins the bucket order.
        assert_eq!(import.domain_policies[0].target, DomainRouteTarget::Block);
        assert_eq!(import.domain_policies[0].domains, ["geosite:category-ads"]);
        assert_eq!(import.domain_policies[1].target, DomainRouteTarget::Proxy);
        assert_eq!(
            import.domain_policies[1].domains,
            ["geosite:youtube", "geosite:telegram"]
        );
        assert_eq!(import.domain_policies[2].target, DomainRouteTarget::Direct);
        // Sites and ip lists merge; comments survive verbatim.
        assert_eq!(
            import.domain_policies[2].domains,
            [
                "geosite:private",
                "# custom",
                "domain:ozon.ru",
                "geoip:private",
                "100.125.55.11"
            ]
        );
        assert_eq!(
            import.domain_strategy,
            Some(XrayDomainStrategy::IpIfNonMatch)
        );
        assert_eq!(import.private_lan_direct, Some(true));
        assert_eq!(import.dns.servers.len(), 2);
        // Bare `RemoteDns`/`DomesticDns` strings win over the typed fields.
        assert_eq!(import.dns.servers[0].address, "8.8.8.8");
        assert_eq!(import.dns.servers[0].route, XrayDnsRoute::Proxy);
        assert_eq!(import.dns.servers[1].address, "77.88.8.8");
        assert_eq!(import.dns.servers[1].route, XrayDnsRoute::Direct);
        assert_eq!(
            import.dns.hosts["lkfl2.nalog.ru"],
            vec!["213.24.64.175".to_string()]
        );
        assert!(!import.dns.fake_dns);
        assert_eq!(
            import.geoip_url.as_deref(),
            Some("https://cdn.example.test/geoip.dat")
        );
        assert_eq!(
            import.geosite_url.as_deref(),
            Some("https://cdn.example.test/geosite.dat")
        );
        assert!(import.warnings.is_empty());
    }

    #[test]
    fn keys_match_case_insensitively() {
        let import = parse_happ_routing(
            r#"{"geoipURL":"https://a.test/geoip.dat","GEOSITEURL":"https://a.test/geosite.dat","domainstrategy":"asis","fakedns":"true"}"#,
        )
        .unwrap();
        assert_eq!(
            import.geoip_url.as_deref(),
            Some("https://a.test/geoip.dat")
        );
        assert_eq!(import.domain_strategy, Some(XrayDomainStrategy::AsIs));
        assert!(import.dns.fake_dns);
    }

    #[test]
    fn route_order_permutation_orders_policies() {
        let import = parse_happ_routing(
            r#"{"DirectSites":["a.ru"],"ProxySites":["b.ru"],"BlockSites":["c.ru"],"RouteOrder":"direct-block-proxy"}"#,
        )
        .unwrap();
        let targets: Vec<_> = import.domain_policies.iter().map(|p| p.target).collect();
        assert_eq!(
            targets,
            [
                DomainRouteTarget::Direct,
                DomainRouteTarget::Block,
                DomainRouteTarget::Proxy
            ]
        );
        // Empty buckets emit no policy.
        assert_eq!(import.domain_policies.len(), 3);
    }

    #[test]
    fn typed_dns_fields_build_resolver_addresses() {
        let import = parse_happ_routing(
            r#"{
                "RemoteDNSType": "DoH", "RemoteDNSIP": "8.8.8.8",
                "DomesticDNSType": "DoT", "DomesticDNSIP": "77.88.8.8",
                "FakeDNS": "true"
            }"#,
        )
        .unwrap();
        assert_eq!(import.dns.servers[0].address, "https://8.8.8.8/dns-query");
        assert_eq!(import.dns.servers[1].address, "tls://77.88.8.8");
        assert!(import.dns.fake_dns);
    }

    #[test]
    fn resolver_domain_holds_full_url() {
        let import = parse_happ_routing(
            r#"{"RemoteDNSType":"DoH","RemoteDNSDomain":"https://dns.example.test/query"}"#,
        )
        .unwrap();
        assert_eq!(
            import.dns.servers[0].address,
            "https://dns.example.test/query"
        );
    }

    #[test]
    fn base64_and_deeplink_inputs_decode() {
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"BlockSites":["ads.ru"]}"#);
        let import = parse_happ_routing(&encoded).unwrap();
        assert_eq!(import.domain_policies[0].domains, ["ads.ru"]);
        let import = parse_happ_routing(&format!("incy://routing/{encoded}")).unwrap();
        assert_eq!(import.domain_policies[0].domains, ["ads.ru"]);
        let import = parse_happ_routing(&format!("happ://routing/add/{encoded}")).unwrap();
        assert_eq!(import.domain_policies[0].domains, ["ads.ru"]);
        assert!(parse_happ_routing("incy://routing/off").is_err());
        assert!(parse_happ_routing("incy://routing/https://a.test/r.json").is_err());
    }

    #[test]
    fn global_proxy_off_and_dns_address_maps_warn() {
        let import = parse_happ_routing(
            r#"{"GlobalProxy":"false","ProxySites":["a.ru"],"remoteDnsAddresses":{"x.ru":"1.2.3.4"}}"#,
        )
        .unwrap();
        assert_eq!(import.warnings.len(), 2);
        assert!(import.warnings.iter().any(|w| w.contains("GlobalProxy")));
        assert!(import
            .warnings
            .iter()
            .any(|w| w.contains("remoteDnsAddresses")));
    }

    #[test]
    fn query_strategy_accepts_both_field_names() {
        let import =
            parse_happ_routing(r#"{"queryStrategy":"UseIPv4","BlockSites":["a.ru"]}"#).unwrap();
        assert_eq!(
            import.dns.query_strategy,
            Some(XrayDnsQueryStrategy::UseIpv4)
        );
        let import =
            parse_happ_routing(r#"{"preferredIPType":"IPv6","BlockSites":["a.ru"]}"#).unwrap();
        assert_eq!(
            import.dns.query_strategy,
            Some(XrayDnsQueryStrategy::UseIpv6)
        );
    }

    #[test]
    fn garbage_and_empty_profiles_error() {
        assert!(parse_happ_routing("").is_err());
        assert!(parse_happ_routing("not json").is_err());
        assert!(parse_happ_routing("[1,2]").is_err());
        assert!(parse_happ_routing(r#"{"isEditable":true}"#).is_err());
    }

    #[test]
    fn single_string_lists_and_array_route_order() {
        let import = parse_happ_routing(
            r#"{"DirectSites":"a.ru\nb.ru","RouteOrder":["direct","proxy","block"]}"#,
        )
        .unwrap();
        assert_eq!(import.domain_policies[0].target, DomainRouteTarget::Direct);
        assert_eq!(import.domain_policies[0].domains, ["a.ru", "b.ru"]);
    }
}
