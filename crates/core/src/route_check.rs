//! Offline route-decision simulator. Given a profile's domain policies and
//! DNS options plus a target host/IP, replays the rule chain that
//! [`crate::xray::apply_profile_routing`] would generate and reports which
//! rule decides the traffic. `geosite:`/`geoip:` selectors are resolved
//! against parsed `geosite.dat`/`geoip.dat` assets when the caller has them
//! on disk; `regexp:` selectors and missing assets degrade the step to
//! `Unknown` and the verdict to `Probable`.

use std::io;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::models::{DomainPolicy, DomainRouteTarget, XrayDnsRoute, XrayDomainStrategy};
use crate::xray::ProfileRoutingOptions;

fn invalid_input(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.to_string())
}

// ---------------------------------------------------------------------------
// Target parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RouteCheckTargetKind {
    Domain,
    Ip,
}

#[derive(Debug)]
enum RouteTarget {
    Domain(String),
    Ip(IpAddr),
}

/// Normalize `host`, `host:port`, `scheme://host/path` or a bare IP into a
/// routable target. Anything else is rejected.
fn parse_target(raw: &str) -> io::Result<(RouteTarget, Option<u16>)> {
    let input = raw.trim();
    if input.is_empty() {
        return Err(invalid_input("route check target is empty"));
    }
    // Drop scheme and everything past the authority.
    let after_scheme = input
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(input);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    // Drop userinfo.
    let authority = authority.rsplit('@').next().unwrap_or(authority).trim();
    if authority.is_empty() {
        return Err(invalid_input("route check target has no host"));
    }

    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        // Bracketed IPv6, optional :port.
        let Some((host, tail)) = inner.split_once(']') else {
            return Err(invalid_input("route check target has a malformed bracket"));
        };
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(
                p.trim()
                    .parse::<u16>()
                    .map_err(|_| invalid_input("route check target has an invalid port"))?,
            ),
            None => None,
        };
        (host.to_string(), port)
    } else if authority.matches(':').count() == 1 {
        let (host, p) = authority.split_once(':').unwrap();
        let port = p
            .trim()
            .parse::<u16>()
            .map_err(|_| invalid_input("route check target has an invalid port"))?;
        (host.trim().to_string(), Some(port))
    } else {
        (authority.to_string(), None)
    };

    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return Err(invalid_input("route check target has no host"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok((RouteTarget::Ip(ip), port));
    }
    // Xray compares domains case-insensitively.
    let host = host.to_ascii_lowercase();
    if host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*'))
    {
        return Err(invalid_input("route check target is not a valid hostname"));
    }
    Ok((RouteTarget::Domain(host), port))
}

// ---------------------------------------------------------------------------
// Geo assets: minimal protobuf readers for geosite.dat / geoip.dat
// ---------------------------------------------------------------------------

fn pb_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

enum PbField<'a> {
    Varint(u64),
    Len(&'a [u8]),
}

/// Step over one protobuf field; supports varint/len-delim/fixed wire types.
fn pb_field<'a>(buf: &'a [u8], pos: &mut usize) -> Option<(u32, PbField<'a>)> {
    let tag = pb_varint(buf, pos)?;
    let field = u32::try_from(tag >> 3).ok()?;
    match tag & 0x7 {
        0 => pb_varint(buf, pos).map(PbField::Varint).map(|v| (field, v)),
        1 => {
            let end = pos.checked_add(8)?;
            let _ = buf.get(*pos..end)?;
            *pos = end;
            Some((field, PbField::Varint(0)))
        }
        2 => {
            let len = usize::try_from(pb_varint(buf, pos)?).ok()?;
            let end = pos.checked_add(len)?;
            let data = buf.get(*pos..end)?;
            *pos = end;
            Some((field, PbField::Len(data)))
        }
        5 => {
            let end = pos.checked_add(4)?;
            let _ = buf.get(*pos..end)?;
            *pos = end;
            Some((field, PbField::Varint(0)))
        }
        _ => None,
    }
}

fn pb_str<'a>(field: PbField<'a>) -> Option<&'a str> {
    match field {
        PbField::Len(data) => std::str::from_utf8(data).ok(),
        PbField::Varint(_) => None,
    }
}

/// `geosite.dat` domain-record types (`GeoSite.Domain.Type`).
const GEO_DOMAIN_PLAIN: u64 = 0;
const GEO_DOMAIN_REGEX: u64 = 1;
const GEO_DOMAIN_ROOT: u64 = 2;
const GEO_DOMAIN_FULL: u64 = 3;

#[derive(Debug)]
struct GeoDomain {
    kind: u64,
    value: String,
    /// Attribute keys carrying a truthy value (lowercased).
    attrs: Vec<String>,
}

#[derive(Debug)]
struct GeoSiteEntry {
    category: String,
    domains: Vec<GeoDomain>,
}

/// Parsed `geosite.dat` (`GeoSiteList`).
#[derive(Debug, Default)]
pub struct GeoSiteDb {
    entries: Vec<GeoSiteEntry>,
}

impl GeoSiteDb {
    pub fn parse(dat: &[u8]) -> io::Result<Self> {
        let mut entries = Vec::new();
        let mut pos = 0;
        while let Some((field, value)) = pb_field(dat, &mut pos) {
            if field != 1 {
                continue;
            }
            let PbField::Len(body) = value else { continue };
            entries.push(Self::parse_entry(body)?);
        }
        Ok(Self { entries })
    }

    fn parse_entry(buf: &[u8]) -> io::Result<GeoSiteEntry> {
        let mut category = String::new();
        let mut domains = Vec::new();
        let mut pos = 0;
        while let Some((field, value)) = pb_field(buf, &mut pos) {
            match (field, value) {
                (1, f) => category = pb_str(f).unwrap_or_default().to_ascii_lowercase(),
                (2, PbField::Len(body)) => domains.push(Self::parse_domain(body)),
                _ => {}
            }
        }
        Ok(GeoSiteEntry { category, domains })
    }

    fn parse_domain(buf: &[u8]) -> GeoDomain {
        let mut kind = 0u64;
        let mut value = String::new();
        let mut attrs = Vec::new();
        let mut pos = 0;
        while let Some((field, raw)) = pb_field(buf, &mut pos) {
            match (field, raw) {
                (1, PbField::Varint(v)) => kind = v,
                (2, f) => value = pb_str(f).unwrap_or_default().to_ascii_lowercase(),
                (3, PbField::Len(body)) => {
                    if let Some(attr) = Self::parse_attr(body) {
                        attrs.push(attr);
                    }
                }
                _ => {}
            }
        }
        GeoDomain { kind, value, attrs }
    }

    /// `GeoSite.Domain.Attribute { key = 1; bool_value = 2; int_value = 3 }` —
    /// keeps only truthy attributes, as Xray does.
    fn parse_attr(buf: &[u8]) -> Option<String> {
        let mut key = String::new();
        let mut truthy = false;
        let mut pos = 0;
        while let Some((field, raw)) = pb_field(buf, &mut pos) {
            match (field, raw) {
                (1, f) => key = pb_str(f).unwrap_or_default().to_ascii_lowercase(),
                (2 | 3, PbField::Varint(v)) => truthy |= v != 0,
                _ => {}
            }
        }
        if key.is_empty() || !truthy {
            return None;
        }
        Some(key)
    }

    /// Evaluate `host` against `category[@attr]`. `Regex` records cannot be
    /// evaluated locally — they turn the lookup `Unknown` unless a literal
    /// record already matched.
    fn lookup(&self, category: &str, attr: Option<&str>, host: &str) -> SelectorEval {
        let category = category.to_ascii_lowercase();
        let Some(entry) = self.entries.iter().find(|e| e.category == category) else {
            return SelectorEval::Unknown("geo-category-missing");
        };
        let mut saw_regex = false;
        for record in &entry.domains {
            if let Some(attr) = attr {
                if !attr_glob(attr, &record.attrs) {
                    continue;
                }
            }
            let hit = match record.kind {
                GEO_DOMAIN_FULL => host == record.value,
                GEO_DOMAIN_ROOT => domain_suffix_match(host, &record.value),
                GEO_DOMAIN_PLAIN => host.contains(&record.value),
                GEO_DOMAIN_REGEX => {
                    saw_regex = true;
                    false
                }
                _ => false,
            };
            if hit {
                return SelectorEval::Match;
            }
        }
        if saw_regex {
            return SelectorEval::Unknown("geo-regex-records");
        }
        SelectorEval::Miss
    }
}

/// `category@attr` attribute matching: `*` works as a glob over attribute
/// keys (Xray accepts literal keys; the wider form is a tolerated extension
/// our selector validator already allows).
fn attr_glob(pattern: &str, attrs: &[String]) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    attrs.iter().any(|attr| glob_match(&pattern, attr))
}

fn glob_match(pattern: &str, value: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == value;
    }
    let mut rest = value;
    let mut anchor_start = !pattern.starts_with('*');
    for part in pattern.split('*').filter(|p| !p.is_empty()) {
        if anchor_start {
            let Some(stripped) = rest.strip_prefix(part) else {
                return false;
            };
            rest = stripped;
        } else if let Some(index) = rest.find(part) {
            rest = &rest[index + part.len()..];
        } else {
            return false;
        }
        anchor_start = false;
    }
    pattern.ends_with('*') || rest.is_empty() || {
        // `foo*bar` consumed everything iff `bar` ended the string.
        let last = pattern.rsplit('*').next().unwrap_or_default();
        !last.is_empty() && value.ends_with(last)
    }
}

/// Parsed `geoip.dat` (`GeoIPList`): country code → CIDRs.
#[derive(Debug, Default)]
pub struct GeoIpDb {
    entries: Vec<(String, Vec<IpNet>)>,
}

impl GeoIpDb {
    pub fn parse(dat: &[u8]) -> io::Result<Self> {
        let mut entries = Vec::new();
        let mut pos = 0;
        while let Some((field, value)) = pb_field(dat, &mut pos) {
            if field != 1 {
                continue;
            }
            let PbField::Len(body) = value else { continue };
            entries.push(Self::parse_entry(body));
        }
        Ok(Self { entries })
    }

    /// `GeoIP { country_code = 1; cidr = 2; reverse_match = 3 }` —
    /// reverse-match lists are skipped (rare, and unsupported by our
    /// selector surface anyway).
    fn parse_entry(buf: &[u8]) -> (String, Vec<IpNet>) {
        let mut code = String::new();
        let mut cidrs = Vec::new();
        let mut reverse = false;
        let mut pos = 0;
        while let Some((field, raw)) = pb_field(buf, &mut pos) {
            match (field, raw) {
                (1, f) => code = pb_str(f).unwrap_or_default().to_ascii_lowercase(),
                (2, PbField::Len(body)) => {
                    if let Some(net) = Self::parse_cidr(body) {
                        cidrs.push(net);
                    }
                }
                (3, PbField::Varint(v)) => reverse = v != 0,
                _ => {}
            }
        }
        if reverse {
            cidrs.clear();
        }
        (code, cidrs)
    }

    /// `CIDR { ip = 1; prefix = 2 }` — raw 4/16-byte network address.
    fn parse_cidr(buf: &[u8]) -> Option<IpNet> {
        let mut ip: Option<IpAddr> = None;
        let mut prefix = 0u64;
        let mut pos = 0;
        while let Some((field, raw)) = pb_field(buf, &mut pos) {
            match (field, raw) {
                (1, PbField::Len(bytes)) => {
                    ip = match bytes.len() {
                        4 => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
                        16 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
                        _ => None,
                    };
                }
                (2, PbField::Varint(v)) => prefix = v,
                _ => {}
            }
        }
        let ip = ip?;
        IpNet::new(ip, u8::try_from(prefix).ok()?).ok()
    }

    fn lookup(&self, code: &str, ip: IpAddr) -> SelectorEval {
        let code = code.to_ascii_lowercase();
        let Some((_, cidrs)) = self
            .entries
            .iter()
            .find(|(candidate, _)| candidate == &code)
        else {
            return SelectorEval::Unknown("geo-category-missing");
        };
        if cidrs.iter().any(|net| net.contains(&ip)) {
            SelectorEval::Match
        } else {
            SelectorEval::Miss
        }
    }
}

/// Geo databases the caller could load — `None` entries make the matching
/// selector evaluate to `Unknown`.
#[derive(Debug, Default)]
pub struct GeoDbs<'a> {
    pub geo_site: Option<&'a GeoSiteDb>,
    pub geo_ip: Option<&'a GeoIpDb>,
}

// ---------------------------------------------------------------------------
// Selector evaluation (mirrors Xray matcher semantics)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectorEval {
    Match,
    Miss,
    Unknown(&'static str),
}

/// `domain:` / bare-name semantics: the host equals the pattern or sits in
/// its subtree.
fn domain_suffix_match(host: &str, pattern: &str) -> bool {
    host == pattern
        || host
            .strip_suffix(pattern)
            .is_some_and(|rest| rest.ends_with('.'))
}

fn eval_domain_selector(selector: &str, host: &str, geo: &GeoDbs) -> SelectorEval {
    if let Some(value) = selector.strip_prefix("domain:") {
        return domain_suffix_match(host, &value.to_ascii_lowercase()).into();
    }
    if let Some(value) = selector.strip_prefix("full:") {
        return (host == value.to_ascii_lowercase()).into();
    }
    if let Some(value) = selector.strip_prefix("keyword:") {
        return host.contains(&value.to_ascii_lowercase()).into();
    }
    if selector.starts_with("regexp:") {
        return SelectorEval::Unknown("regexp-unsupported");
    }
    if let Some(category) = selector.strip_prefix("geosite:") {
        let (name, attr) = match category.split_once('@') {
            Some((name, attr)) => (name, Some(attr)),
            None => (category, None),
        };
        return match geo.geo_site {
            Some(db) => db.lookup(name, attr, host),
            None => SelectorEval::Unknown("geo-asset-missing"),
        };
    }
    // A bare name is a root-domain matcher in Xray.
    domain_suffix_match(host, &selector.to_ascii_lowercase()).into()
}

fn eval_ip_selector(selector: &str, ip: IpAddr, geo: &GeoDbs) -> SelectorEval {
    if let Some(code) = selector.strip_prefix("geoip:") {
        return match geo.geo_ip {
            Some(db) => db.lookup(code, ip),
            None => SelectorEval::Unknown("geo-asset-missing"),
        };
    }
    if let Ok(literal) = selector.parse::<IpAddr>() {
        return (literal == ip).into();
    }
    if let Ok(net) = IpNet::from_str(selector) {
        return net.contains(&ip).into();
    }
    SelectorEval::Miss
}

impl From<bool> for SelectorEval {
    fn from(hit: bool) -> Self {
        if hit {
            SelectorEval::Match
        } else {
            SelectorEval::Miss
        }
    }
}

// ---------------------------------------------------------------------------
// Check result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RouteCheckOutbound {
    Proxy,
    Direct,
    Block,
    /// Port-53 capture into the configured DNS resolvers.
    Dns,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RouteCheckSource {
    /// Built-in `:53 → dns-out` capture rule.
    DnsCapture,
    /// A profile domain policy decided the target.
    Policy,
    /// A DNS resolver's own address pinned to an outbound.
    ResolverPin,
    /// Built-in multicast block rule.
    Multicast,
    /// `privateLanDirect` static private-range rule.
    PrivateLan,
    /// No rule matched; traffic follows the first outbound (proxy).
    Default,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RouteCheckCertainty {
    /// Every evaluated selector produced a definite answer.
    Certain,
    /// One or more selectors could not be evaluated (missing geo assets,
    /// `regexp:`, or a resolved-IP recheck under a non-AsIs strategy).
    Probable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteCheckStep {
    /// Human-readable rule origin, e.g. `block rules #1` or `resolver 1.1.1.1`.
    pub label: String,
    /// The deciding/unevaluated selector, when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    pub outcome: RouteCheckStepOutcome,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RouteCheckStepOutcome {
    Match,
    Miss,
    /// Selector could not be evaluated locally (geo assets, `regexp:`).
    Unknown,
    /// Selector family does not apply to this target kind.
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteCheckResult {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub target_kind: RouteCheckTargetKind,
    pub outbound: RouteCheckOutbound,
    pub source: RouteCheckSource,
    /// Index into `domainPolicies` when `source` is `policy`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_selector: Option<String>,
    pub certainty: RouteCheckCertainty,
    pub steps: Vec<RouteCheckStep>,
    pub notes: Vec<String>,
}

const MULTICAST_NETS: &[&str] = &["224.0.0.0/4", "ff00::/8"];

const PRIVATE_NETS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
];

fn any_net_contains(nets: &[&str], ip: IpAddr) -> bool {
    nets.iter()
        .filter_map(|net| IpNet::from_str(net).ok())
        .any(|net| net.contains(&ip))
}

/// Replay the generated routing chain for `target`. `policies` and `options`
/// are the same profile fields `apply_profile_routing` consumes — block →
/// proxy → direct ordering is the caller's responsibility (the form already
/// serializes rules in that order).
pub fn check_route(
    policies: &[DomainPolicy],
    options: &ProfileRoutingOptions,
    target: &str,
    geo: &GeoDbs,
) -> io::Result<RouteCheckResult> {
    let (target, port) = parse_target(target)?;
    let dns_active = !options.dns.is_empty();

    let (kind, target_label) = match &target {
        RouteTarget::Domain(host) => (RouteCheckTargetKind::Domain, host.clone()),
        RouteTarget::Ip(ip) => (RouteCheckTargetKind::Ip, ip.to_string()),
    };

    let mut steps: Vec<RouteCheckStep> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut saw_unknown = false;

    let mut note = |reason: &'static str| {
        let text = match reason {
            "geo-asset-missing" => {
                "geoip/geosite selectors could not be evaluated: no geo assets on disk"
            }
            "geo-category-missing" => "a geo category is absent from the loaded geo assets",
            "geo-regex-records" => "a geo category contains regex records that were not evaluated",
            "regexp-unsupported" => "regexp: selectors are not evaluated locally",
            "resolved-ip-recheck" => {
                "domainStrategy resolves unmatched names, so IP rules may still decide this target"
            }
            _ => return,
        };
        if !notes.iter().any(|n| n == text) {
            notes.push(text.to_string());
        }
    };

    let mut verdict: Option<(
        RouteCheckOutbound,
        RouteCheckSource,
        Option<usize>,
        Option<String>,
    )> = None;

    // 1. DNS capture: the generated chain starts with `port:53 → dns-out`
    // whenever the profile configures split DNS.
    if dns_active {
        let hit = port == Some(53);
        steps.push(RouteCheckStep {
            label: "dns capture (port 53)".to_string(),
            selector: Some("port:53".to_string()),
            outcome: if hit {
                RouteCheckStepOutcome::Match
            } else {
                RouteCheckStepOutcome::Miss
            },
        });
        if hit {
            verdict = Some((
                RouteCheckOutbound::Dns,
                RouteCheckSource::DnsCapture,
                None,
                Some("port:53".to_string()),
            ));
        }
    }

    // 2. Domain policies, in generated order (domain rule before ip rule —
    // same verdict at policy granularity).
    let resolves = matches!(
        options.domain_strategy,
        Some(XrayDomainStrategy::IpIfNonMatch | XrayDomainStrategy::IpOnDemand)
    );
    if verdict.is_none() {
        for (index, policy) in policies.iter().enumerate() {
            let mut policy_hit: Option<String> = None;
            let mut policy_unknown = false;
            for selector in &policy.domains {
                let selector = selector.trim();
                if selector.is_empty() || selector.starts_with('#') {
                    continue;
                }
                let is_ip_selector = matches!(
                    crate::xray::classify_routing_selector(selector),
                    Ok(Some(("ip", _)))
                );
                let outcome = match (&target, is_ip_selector) {
                    (RouteTarget::Domain(host), false) => eval_domain_selector(selector, host, geo),
                    (RouteTarget::Domain(_), true) => {
                        if resolves {
                            SelectorEval::Unknown("resolved-ip-recheck")
                        } else {
                            SelectorEval::Miss
                        }
                    }
                    (RouteTarget::Ip(ip), true) => eval_ip_selector(selector, *ip, geo),
                    (RouteTarget::Ip(_), false) => {
                        // geosite/domain selectors cannot match a literal IP.
                        SelectorEval::Miss
                    }
                };
                match outcome {
                    SelectorEval::Match => {
                        policy_hit = Some(selector.to_string());
                        break;
                    }
                    SelectorEval::Unknown(reason) => {
                        policy_unknown = true;
                        note(reason);
                    }
                    SelectorEval::Miss => {}
                }
            }
            let label = format!(
                "{} rules #{}",
                match policy.target {
                    DomainRouteTarget::Proxy => "proxy",
                    DomainRouteTarget::Direct => "direct",
                    DomainRouteTarget::Block => "block",
                },
                index + 1
            );
            if let Some(selector) = policy_hit {
                steps.push(RouteCheckStep {
                    label,
                    selector: Some(selector.clone()),
                    outcome: RouteCheckStepOutcome::Match,
                });
                let outbound = match policy.target {
                    DomainRouteTarget::Proxy => RouteCheckOutbound::Proxy,
                    DomainRouteTarget::Direct => RouteCheckOutbound::Direct,
                    DomainRouteTarget::Block => RouteCheckOutbound::Block,
                };
                verdict = Some((
                    outbound,
                    RouteCheckSource::Policy,
                    Some(index),
                    Some(selector),
                ));
                break;
            }
            if policy_unknown {
                saw_unknown = true;
            }
            steps.push(RouteCheckStep {
                label,
                selector: None,
                outcome: if policy_unknown {
                    RouteCheckStepOutcome::Unknown
                } else {
                    RouteCheckStepOutcome::Miss
                },
            });
        }
    }

    // 3. Resolver pins keep each DNS server reachable on its own side.
    if verdict.is_none() {
        for server in &options.dns.servers {
            let tag = match server.route {
                XrayDnsRoute::Proxy => RouteCheckOutbound::Proxy,
                XrayDnsRoute::Direct => RouteCheckOutbound::Direct,
                XrayDnsRoute::None => continue,
            };
            let Some((kind_flag, value)) = crate::xray::dns_server_route_target(&server.address)
            else {
                continue;
            };
            let outcome = match (&target, kind_flag) {
                (RouteTarget::Domain(host), "domain") => {
                    domain_suffix_match(host, &value.to_ascii_lowercase()).into()
                }
                (RouteTarget::Ip(ip), "ip") => eval_ip_selector(&value, *ip, geo),
                // A domain resolver can still intercept a domain target
                // after strategy resolution.
                (RouteTarget::Domain(_), "ip") => {
                    if resolves {
                        SelectorEval::Unknown("resolved-ip-recheck")
                    } else {
                        SelectorEval::Miss
                    }
                }
                (RouteTarget::Ip(_), "domain") => SelectorEval::Miss,
                _ => SelectorEval::Miss,
            };
            if let SelectorEval::Unknown(reason) = outcome {
                note(reason);
                saw_unknown = true;
            }
            steps.push(RouteCheckStep {
                label: format!("resolver pin {}", server.address.trim()),
                selector: Some(value),
                outcome: match outcome {
                    SelectorEval::Match => RouteCheckStepOutcome::Match,
                    SelectorEval::Miss => RouteCheckStepOutcome::Miss,
                    SelectorEval::Unknown(_) => RouteCheckStepOutcome::Unknown,
                },
            });
            if outcome == SelectorEval::Match {
                verdict = Some((
                    tag,
                    RouteCheckSource::ResolverPin,
                    None,
                    Some(server.address.trim().to_string()),
                ));
                break;
            }
        }
    }

    // 4. Built-in rules, emitted only when some rule surface exists.
    let rules_emitted = !policies.is_empty() || options.private_lan_direct || dns_active;
    if verdict.is_none() && rules_emitted {
        if let RouteTarget::Ip(ip) = target {
            if any_net_contains(MULTICAST_NETS, ip) {
                steps.push(RouteCheckStep {
                    label: "multicast".to_string(),
                    selector: Some("224.0.0.0/4, ff00::/8".to_string()),
                    outcome: RouteCheckStepOutcome::Match,
                });
                verdict = Some((
                    RouteCheckOutbound::Block,
                    RouteCheckSource::Multicast,
                    None,
                    Some("multicast".to_string()),
                ));
            }
        }
    }
    if verdict.is_none() && options.private_lan_direct {
        if let RouteTarget::Ip(ip) = target {
            if any_net_contains(PRIVATE_NETS, ip) {
                steps.push(RouteCheckStep {
                    label: "private LAN".to_string(),
                    selector: Some("private ranges".to_string()),
                    outcome: RouteCheckStepOutcome::Match,
                });
                verdict = Some((
                    RouteCheckOutbound::Direct,
                    RouteCheckSource::PrivateLan,
                    None,
                    Some("privateLanDirect".to_string()),
                ));
            }
        }
    }

    // 5. Nothing matched — the first outbound (proxy) takes it.
    if verdict.is_none() {
        steps.push(RouteCheckStep {
            label: "default".to_string(),
            selector: None,
            outcome: RouteCheckStepOutcome::Match,
        });
        verdict = Some((
            RouteCheckOutbound::Proxy,
            RouteCheckSource::Default,
            None,
            None,
        ));
    }

    if resolves && kind == RouteCheckTargetKind::Domain {
        note("resolved-ip-recheck");
    }
    // DNS static hosts can still rewrite the answer a resolver returns —
    // routing itself is unaffected, but the flag helps debugging.
    if let RouteTarget::Domain(host) = &target {
        for (name, _) in options
            .dns
            .hosts
            .iter()
            .filter(|(name, _)| domain_suffix_match(host, &name.to_ascii_lowercase()))
        {
            notes.push(format!(
                "dns hosts entry `{name}` rewrites resolution of this target"
            ));
        }
    }

    let (outbound, source, policy_index, matched_selector) = verdict.unwrap();
    Ok(RouteCheckResult {
        target: target_label,
        port,
        target_kind: kind,
        outbound,
        source,
        policy_index,
        matched_selector,
        certainty: if saw_unknown {
            RouteCheckCertainty::Probable
        } else {
            RouteCheckCertainty::Certain
        },
        steps,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{XrayDnsConfig, XrayDnsServer};

    fn policies(spec: &[(&[&str], DomainRouteTarget)]) -> Vec<DomainPolicy> {
        spec.iter()
            .map(|(selectors, target)| DomainPolicy {
                domains: selectors.iter().map(|s| s.to_string()).collect(),
                target: *target,
            })
            .collect()
    }

    fn check(
        policies: &[DomainPolicy],
        options: &ProfileRoutingOptions,
        target: &str,
    ) -> RouteCheckResult {
        check_route(policies, options, target, &GeoDbs::default()).unwrap()
    }

    #[test]
    fn bare_domain_default_routes_proxy() {
        let result = check(&[], &ProfileRoutingOptions::default(), "example.com");
        assert_eq!(result.outbound, RouteCheckOutbound::Proxy);
        assert_eq!(result.source, RouteCheckSource::Default);
        assert_eq!(result.target_kind, RouteCheckTargetKind::Domain);
        assert_eq!(result.certainty, RouteCheckCertainty::Certain);
    }

    #[test]
    fn domain_policy_subdomain_match() {
        let list = policies(&[(&["domain:example.com"], DomainRouteTarget::Direct)]);
        let result = check(&list, &ProfileRoutingOptions::default(), "a.b.example.com");
        assert_eq!(result.outbound, RouteCheckOutbound::Direct);
        assert_eq!(result.source, RouteCheckSource::Policy);
        assert_eq!(result.policy_index, Some(0));
        assert_eq!(
            result.matched_selector.as_deref(),
            Some("domain:example.com")
        );
    }

    #[test]
    fn first_policy_wins() {
        let list = policies(&[
            (&["blocked.test"], DomainRouteTarget::Block),
            (&["blocked.test"], DomainRouteTarget::Proxy),
        ]);
        let result = check(&list, &ProfileRoutingOptions::default(), "blocked.test");
        assert_eq!(result.outbound, RouteCheckOutbound::Block);
    }

    #[test]
    fn full_and_keyword_semantics() {
        let list = policies(&[
            (&["full:exact.test"], DomainRouteTarget::Direct),
            (&["keyword:partial"], DomainRouteTarget::Block),
        ]);
        let exact = check(&list, &ProfileRoutingOptions::default(), "exact.test");
        assert_eq!(exact.outbound, RouteCheckOutbound::Direct);
        let miss = check(&list, &ProfileRoutingOptions::default(), "sub.exact.test");
        assert_eq!(miss.outbound, RouteCheckOutbound::Proxy); // full: did not match
        let partial = check(
            &list,
            &ProfileRoutingOptions::default(),
            "some.partial.host",
        );
        assert_eq!(partial.outbound, RouteCheckOutbound::Block);
    }

    #[test]
    fn ip_target_uses_ip_selectors() {
        let list = policies(&[
            (&["10.20.0.0/16"], DomainRouteTarget::Direct),
            (&["8.8.8.8"], DomainRouteTarget::Block),
        ]);
        let hit = check(&list, &ProfileRoutingOptions::default(), "10.20.3.4");
        assert_eq!(hit.outbound, RouteCheckOutbound::Direct);
        let literal = check(&list, &ProfileRoutingOptions::default(), "8.8.8.8");
        assert_eq!(literal.outbound, RouteCheckOutbound::Block);
        let miss = check(&list, &ProfileRoutingOptions::default(), "9.9.9.9");
        assert_eq!(miss.outbound, RouteCheckOutbound::Proxy);
    }

    #[test]
    fn ip_selectors_skip_domain_targets_under_asis() {
        let list = policies(&[(&["0.0.0.0/0"], DomainRouteTarget::Direct)]);
        let options = ProfileRoutingOptions {
            domain_strategy: Some(XrayDomainStrategy::AsIs),
            ..ProfileRoutingOptions::default()
        };
        let result = check(&list, &options, "anything.test");
        // IP rules never see unresolved names under AsIs.
        assert_eq!(result.outbound, RouteCheckOutbound::Proxy);
        assert_eq!(result.certainty, RouteCheckCertainty::Certain);
    }

    #[test]
    fn resolving_strategy_degrades_certainty_for_domain_targets() {
        let list = policies(&[(&["1.2.3.4"], DomainRouteTarget::Block)]);
        let options = ProfileRoutingOptions {
            domain_strategy: Some(XrayDomainStrategy::IpIfNonMatch),
            ..ProfileRoutingOptions::default()
        };
        let result = check(&list, &options, "maybe-blocked.test");
        assert_eq!(result.outbound, RouteCheckOutbound::Proxy);
        assert_eq!(result.certainty, RouteCheckCertainty::Probable);
        assert!(result.notes.iter().any(|n| n.contains("resolv")));
    }

    #[test]
    fn dns_capture_takes_port_53() {
        let options = ProfileRoutingOptions {
            dns: XrayDnsConfig {
                servers: vec![XrayDnsServer {
                    address: "8.8.8.8".into(),
                    port: None,
                    domains: vec![],
                    skip_fallback: false,
                    route: XrayDnsRoute::None,
                }],
                ..XrayDnsConfig::default()
            },
            ..ProfileRoutingOptions::default()
        };
        let result = check(&[], &options, "dns.test:53");
        assert_eq!(result.outbound, RouteCheckOutbound::Dns);
        assert_eq!(result.source, RouteCheckSource::DnsCapture);
    }

    #[test]
    fn resolver_pin_routes_resolver_host() {
        let options = ProfileRoutingOptions {
            dns: XrayDnsConfig {
                servers: vec![XrayDnsServer {
                    address: "https://dns.remote.example/dns-query".into(),
                    port: None,
                    domains: vec![],
                    skip_fallback: false,
                    route: XrayDnsRoute::Proxy,
                }],
                ..XrayDnsConfig::default()
            },
            ..ProfileRoutingOptions::default()
        };
        let result = check(&[], &options, "dns.remote.example");
        assert_eq!(result.outbound, RouteCheckOutbound::Proxy);
        assert_eq!(result.source, RouteCheckSource::ResolverPin);
    }

    #[test]
    fn private_lan_direct_catches_ip_targets() {
        let options = ProfileRoutingOptions {
            private_lan_direct: true,
            ..ProfileRoutingOptions::default()
        };
        let result = check(&[], &options, "192.168.1.20");
        assert_eq!(result.outbound, RouteCheckOutbound::Direct);
        assert_eq!(result.source, RouteCheckSource::PrivateLan);
        let other = check(&[], &options, "8.8.8.8");
        assert_eq!(other.outbound, RouteCheckOutbound::Proxy);
    }

    #[test]
    fn multicast_blocked_when_rules_exist() {
        let list = policies(&[(&["example.com"], DomainRouteTarget::Direct)]);
        let result = check(&list, &ProfileRoutingOptions::default(), "224.0.0.251");
        assert_eq!(result.outbound, RouteCheckOutbound::Block);
        assert_eq!(result.source, RouteCheckSource::Multicast);
        // Without any rule surface no multicast rule is emitted.
        let empty = check(&[], &ProfileRoutingOptions::default(), "224.0.0.251");
        assert_eq!(empty.outbound, RouteCheckOutbound::Proxy);
    }

    #[test]
    fn geosite_without_assets_is_probable() {
        let list = policies(&[
            (&["geosite:cn"], DomainRouteTarget::Direct),
            (&["later.test"], DomainRouteTarget::Block),
        ]);
        let result = check(&list, &ProfileRoutingOptions::default(), "later.test");
        assert_eq!(result.outbound, RouteCheckOutbound::Block);
        assert_eq!(result.certainty, RouteCheckCertainty::Probable);
        assert!(result.notes.iter().any(|n| n.contains("geo")));
    }

    #[test]
    fn geoip_without_assets_is_probable() {
        let list = policies(&[(&["geoip:cn"], DomainRouteTarget::Direct)]);
        let result = check(&list, &ProfileRoutingOptions::default(), "1.2.3.4");
        assert_eq!(result.outbound, RouteCheckOutbound::Proxy);
        assert_eq!(result.certainty, RouteCheckCertainty::Probable);
    }

    #[test]
    fn url_and_port_forms_parse() {
        let (target, port) = parse_target("https://User@Example.COM:8443/some/path").unwrap();
        assert_eq!(port, Some(8443));
        match target {
            RouteTarget::Domain(host) => assert_eq!(host, "example.com"),
            _ => panic!("expected domain"),
        }
        let (target, port) = parse_target("[::1]:53").unwrap();
        match target {
            RouteTarget::Ip(ip) => assert_eq!(ip.to_string(), "::1"),
            _ => panic!("expected ip"),
        }
        assert_eq!(port, Some(53));
        let (target, _) = parse_target("10.0.0.1").unwrap();
        assert!(matches!(target, RouteTarget::Ip(_)));
        assert!(parse_target("").is_err());
        assert!(parse_target("https://").is_err());
        assert!(parse_target("host:not-a-port").is_err());
    }

    // -- geo database parsing ------------------------------------------------

    /// Tiny protobuf encoder for synthetic geosite/geoip fixtures.
    fn pb_push_varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn pb_field_len(out: &mut Vec<u8>, field: u32, data: &[u8]) {
        pb_push_varint(out, (u64::from(field) << 3) | 2);
        pb_push_varint(out, data.len() as u64);
        out.extend_from_slice(data);
    }

    fn pb_field_varint(out: &mut Vec<u8>, field: u32, v: u64) {
        pb_push_varint(out, u64::from(field) << 3);
        pb_push_varint(out, v);
    }

    fn geo_domain(kind: u64, value: &str, attrs: &[(&str, u64)]) -> Vec<u8> {
        let mut buf = Vec::new();
        pb_field_varint(&mut buf, 1, kind);
        pb_field_len(&mut buf, 2, value.as_bytes());
        for (key, truthy) in attrs {
            let mut attr = Vec::new();
            pb_field_len(&mut attr, 1, key.as_bytes());
            pb_field_varint(&mut attr, 2, *truthy);
            pb_field_len(&mut buf, 3, &attr);
        }
        buf
    }

    fn geo_site_entry(category: &str, domains: Vec<Vec<u8>>) -> Vec<u8> {
        let mut buf = Vec::new();
        pb_field_len(&mut buf, 1, category.as_bytes());
        for domain in domains {
            pb_field_len(&mut buf, 2, &domain);
        }
        buf
    }

    fn geo_ip_entry(code: &str, cidrs: Vec<(Vec<u8>, u64)>) -> Vec<u8> {
        let mut buf = Vec::new();
        pb_field_len(&mut buf, 1, code.as_bytes());
        for (ip, prefix) in cidrs {
            let mut cidr = Vec::new();
            pb_field_len(&mut cidr, 1, &ip);
            pb_field_varint(&mut cidr, 2, prefix);
            pb_field_len(&mut buf, 2, &cidr);
        }
        buf
    }

    fn sample_geo_site() -> GeoSiteDb {
        let mut dat = Vec::new();
        // `cn`: root-domain + full + plain + a regex record + attr records.
        pb_field_len(
            &mut dat,
            1,
            &geo_site_entry(
                "CN",
                vec![
                    geo_domain(GEO_DOMAIN_ROOT, "qq.com", &[]),
                    geo_domain(GEO_DOMAIN_FULL, "full.only", &[]),
                    geo_domain(GEO_DOMAIN_PLAIN, "keywordbit", &[]),
                    geo_domain(GEO_DOMAIN_REGEX, "^rx-", &[]),
                    geo_domain(GEO_DOMAIN_ROOT, "cdn.only", &[("cdn", 1), ("dead", 0)]),
                ],
            ),
        );
        let db = GeoSiteDb::parse(&dat).unwrap();
        assert_eq!(db.entries.len(), 1);
        assert_eq!(db.entries[0].domains.len(), 5);
        db
    }

    #[test]
    fn geosite_lookup_matches_records() {
        let db = sample_geo_site();
        let geo = GeoDbs {
            geo_site: Some(&db),
            geo_ip: None,
        };
        let list = policies(&[(&["geosite:cn"], DomainRouteTarget::Direct)]);
        let opts = ProfileRoutingOptions::default();

        let hit = check_route(&list, &opts, "weixin.qq.com", &geo).unwrap();
        assert_eq!(hit.outbound, RouteCheckOutbound::Direct);
        let full = check_route(&list, &opts, "full.only", &geo).unwrap();
        assert_eq!(full.outbound, RouteCheckOutbound::Direct);
        let full_miss = check_route(&list, &opts, "sub.full.only", &geo).unwrap();
        // `full.only` missed but the regex record stays unevaluated.
        assert_eq!(full_miss.certainty, RouteCheckCertainty::Probable);
        let keyword = check_route(&list, &opts, "x.keywordbit.y", &geo).unwrap();
        assert_eq!(keyword.outbound, RouteCheckOutbound::Direct);
    }

    #[test]
    fn geosite_attr_filtering() {
        let db = sample_geo_site();
        let geo = GeoDbs {
            geo_site: Some(&db),
            geo_ip: None,
        };
        let opts = ProfileRoutingOptions::default();
        let attr_list = policies(&[(&["geosite:cn@cdn"], DomainRouteTarget::Direct)]);
        // `cdn.only` carries attr `cdn=1` — the filter admits it.
        let hit = check_route(&attr_list, &opts, "www.cdn.only", &geo).unwrap();
        assert_eq!(hit.outbound, RouteCheckOutbound::Direct);
        // `qq.com` has no attrs — filtered out; regex record still unknown.
        let miss = check_route(&attr_list, &opts, "qq.com", &geo).unwrap();
        assert_eq!(miss.outbound, RouteCheckOutbound::Proxy);
        // Category absent from the db → probable.
        let ghost = policies(&[(&["geosite:ghost"], DomainRouteTarget::Direct)]);
        let result = check_route(&ghost, &opts, "qq.com", &geo).unwrap();
        assert_eq!(result.certainty, RouteCheckCertainty::Probable);
    }

    #[test]
    fn geoip_lookup_matches_cidrs() {
        let mut dat = Vec::new();
        pb_field_len(
            &mut dat,
            1,
            &geo_ip_entry(
                "PRIVATE",
                vec![(vec![10, 0, 0, 0], 8), (vec![192, 168, 0, 0], 16)],
            ),
        );
        pb_field_len(
            &mut dat,
            1,
            &geo_ip_entry("CN", vec![(vec![1, 2, 3, 0], 24)]),
        );
        let db = GeoIpDb::parse(&dat).unwrap();
        let geo = GeoDbs {
            geo_site: None,
            geo_ip: Some(&db),
        };
        let list = policies(&[(&["geoip:private"], DomainRouteTarget::Direct)]);
        let opts = ProfileRoutingOptions::default();
        let hit = check_route(&list, &opts, "10.9.9.9", &geo).unwrap();
        assert_eq!(hit.outbound, RouteCheckOutbound::Direct);
        let cn = policies(&[(&["geoip:cn"], DomainRouteTarget::Block)]);
        let hit = check_route(&cn, &opts, "1.2.3.99", &geo).unwrap();
        assert_eq!(hit.outbound, RouteCheckOutbound::Block);
        let miss = check_route(&cn, &opts, "8.8.8.8", &geo).unwrap();
        assert_eq!(miss.outbound, RouteCheckOutbound::Proxy);
        assert_eq!(miss.certainty, RouteCheckCertainty::Certain);
    }

    #[test]
    fn dns_hosts_note_flags_static_override() {
        let options = ProfileRoutingOptions {
            dns: XrayDnsConfig {
                hosts: [("pinned.test".to_string(), vec!["1.1.1.1".to_string()])]
                    .into_iter()
                    .collect(),
                ..XrayDnsConfig::default()
            },
            ..ProfileRoutingOptions::default()
        };
        let result = check(&[], &options, "www.pinned.test");
        assert!(result.notes.iter().any(|n| n.contains("hosts entry")));
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("cdn", "cdn"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("cd*", "cdn"));
        assert!(glob_match("*dn", "cdn"));
        assert!(glob_match("c*n", "cdn"));
        assert!(!glob_match("cdn", "cdn2"));
        assert!(!glob_match("cd*", "xcdn"));
    }
}
