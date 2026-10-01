use crate::validate::{full_coverage, validate_owner};
use net_manager_core::daemon_protocol::XrayConnectParams;
use net_manager_core::models::PolicyRoute;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;

pub const MAX_XRAY_CONFIG_BYTES: usize = 512 * 1024;

pub struct XrayPlan {
    pub profile_id: String,
    pub name: String,
    pub config: String,
    pub routes: Vec<PolicyRoute>,
    pub address: ipnet::IpNet,
    pub mtu: u32,
    pub dns_servers: Vec<IpAddr>,
    pub dns_domains: Vec<String>,
    /// Additional hosts that get a physical-gateway host route when their
    /// family is fully captured (see [`dns_bypass_addrs`]): upstream DNS
    /// resolvers chosen in the profile, which may be literal IPs or names.
    pub dns_bypass: Vec<String>,
    pub full_ipv4: bool,
    pub full_ipv6: bool,
    pub mark: u32,
    /// Upstream host of the first outbound (literal IP or hostname). Kernel
    /// must keep a direct route to it outside the tunnel, otherwise the
    /// tunnel would try to carry its own server traffic.
    pub server_host: Option<String>,
    /// Inline caller-provided `geoip.dat`/`geosite.dat` contents; decoded
    /// into the root-owned staging dir before spawn (the sandboxed unit
    /// cannot see caller paths).
    pub geo_assets: Option<net_manager_core::daemon_protocol::XrayGeoAssets>,
}

impl std::fmt::Debug for XrayPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XrayPlan")
            .field("profile_id", &self.profile_id)
            .field("name", &self.name)
            .field("config", &"[REDACTED]")
            .field("routes", &self.routes)
            .field("address", &self.address)
            .field("mtu", &self.mtu)
            .field("dns_servers", &self.dns_servers)
            .field("dns_domains", &self.dns_domains)
            .field("dns_bypass", &self.dns_bypass)
            .field("full_ipv4", &self.full_ipv4)
            .field("full_ipv6", &self.full_ipv6)
            .field("mark", &self.mark)
            .field("server_host", &self.server_host)
            .field("geo_assets", &self.geo_assets.is_some())
            .finish()
    }
}

fn rejected() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "unsupported generated Xray TUN config",
    )
}

fn object<'a>(value: &'a Value, allowed: &[&str]) -> io::Result<&'a Map<String, Value>> {
    let map = value.as_object().ok_or_else(rejected)?;
    if map.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(rejected());
    }
    Ok(map)
}

fn string(value: &Value) -> io::Result<&str> {
    value
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(rejected)
}

fn port(value: &Value) -> io::Result<()> {
    if value
        .as_u64()
        .is_some_and(|port| (1..=65535).contains(&port))
    {
        Ok(())
    } else {
        Err(rejected())
    }
}

fn one(value: &Value) -> io::Result<&Value> {
    let array = value.as_array().ok_or_else(rejected)?;
    if array.len() != 1 {
        return Err(rejected());
    }
    Ok(&array[0])
}

fn validate_generated(config: &Value) -> io::Result<()> {
    let root = object(
        config,
        &["log", "inbounds", "outbounds", "routing", "dns", "fakedns"],
    )?;
    if let Some(log) = root.get("log") {
        object(log, &["loglevel"])?;
        if !matches!(log["loglevel"].as_str(), Some("warning" | "error" | "none")) {
            return Err(rejected());
        }
    }
    if let Some(dns) = root.get("dns") {
        validate_dns(dns)?;
    }
    if let Some(fakedns) = root.get("fakedns") {
        validate_fakedns(fakedns)?;
    }
    let inbounds = root
        .get("inbounds")
        .and_then(Value::as_array)
        .ok_or_else(rejected)?;
    if inbounds.is_empty() || inbounds.len() > 2 {
        return Err(rejected());
    }
    for inbound in inbounds {
        let map = object(inbound, &["tag", "listen", "port", "protocol", "settings"])?;
        if inbound["listen"] != "127.0.0.1" {
            return Err(rejected());
        }
        port(&inbound["port"])?;
        string(&inbound["tag"])?;
        match string(&inbound["protocol"])? {
            "socks" => {
                if let Some(settings) = map.get("settings") {
                    object(settings, &["udp"])?;
                    if settings["udp"] != true {
                        return Err(rejected());
                    }
                }
            }
            "http" if !map.contains_key("settings") => {}
            _ => return Err(rejected()),
        }
    }
    let outbounds = root
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or_else(rejected)?;
    if outbounds.len() < 2 || outbounds.len() > 4 {
        return Err(rejected());
    }
    let mut tags = HashSet::new();
    for (index, outbound) in outbounds.iter().enumerate() {
        let map = object(outbound, &["tag", "protocol", "settings", "streamSettings"])?;
        let tag = string(&outbound["tag"])?;
        if !tags.insert(tag) {
            return Err(rejected());
        }
        match string(&outbound["protocol"])? {
            "vless" if index == 0 => {
                let settings = object(&outbound["settings"], &["vnext"])?;
                let server = one(settings.get("vnext").ok_or_else(rejected)?)?;
                object(server, &["address", "port", "users"])?;
                string(&server["address"])?;
                port(&server["port"])?;
                let user = one(&server["users"])?;
                object(user, &["id", "encryption", "flow"])?;
                string(&user["id"])?;
                if user["encryption"] != "none" {
                    return Err(rejected());
                }
                if !user["flow"].is_null() {
                    string(&user["flow"])?;
                }
                validate_vless_stream(&outbound["streamSettings"])?;
            }
            "hysteria" if index == 0 => {
                object(&outbound["settings"], &["version", "address", "port"])?;
                if outbound["settings"]["version"] != 2 {
                    return Err(rejected());
                }
                string(&outbound["settings"]["address"])?;
                port(&outbound["settings"]["port"])?;
                validate_hysteria_stream(&outbound["streamSettings"])?;
            }
            "freedom" | "blackhole" | "dns"
                if index > 0
                    && !map.contains_key("settings")
                    && !map.contains_key("streamSettings") => {}
            _ => return Err(rejected()),
        }
    }
    if outbounds[1]["protocol"] != "freedom" {
        return Err(rejected());
    }
    let routing = object(
        &config["routing"],
        &["domainStrategy", "domainMatcher", "rules"],
    )?;
    if let Some(strategy) = routing.get("domainStrategy") {
        if !matches!(
            strategy.as_str(),
            Some("AsIs" | "IPIfNonMatch" | "IPOnDemand")
        ) {
            return Err(rejected());
        }
    }
    if let Some(matcher) = routing.get("domainMatcher") {
        if !matches!(matcher.as_str(), Some("mph" | "hybrid" | "linear")) {
            return Err(rejected());
        }
    }
    let rules = config["routing"]["rules"].as_array().ok_or_else(rejected)?;
    if rules.len() > 64 {
        return Err(rejected());
    }
    for rule in rules {
        object(
            rule,
            &["type", "domain", "ip", "port", "network", "outboundTag"],
        )?;
        if rule["type"] != "field" || !tags.contains(string(&rule["outboundTag"])?) {
            return Err(rejected());
        }
        if let Some(rule_port) = rule.get("port") {
            match rule_port {
                Value::String(list) => {
                    if list.len() > 128
                        || !list.split(',').all(|item| {
                            let mut bounds = item.splitn(2, '-');
                            bounds.all(|bound| bound.parse::<u16>().is_ok() && bound.len() <= 5)
                        })
                    {
                        return Err(rejected());
                    }
                }
                Value::Number(_) => port(rule_port)?,
                _ => return Err(rejected()),
            }
        }
        if let Some(network) = rule.get("network") {
            if !matches!(network.as_str(), Some("tcp" | "udp" | "tcp,udp")) {
                return Err(rejected());
            }
        }
        for key in ["domain", "ip"] {
            if let Some(items) = rule.get(key) {
                let items = items.as_array().ok_or_else(rejected)?;
                if items.is_empty() || items.len() > 128 {
                    return Err(rejected());
                }
                for item in items {
                    routing_selector(key, string(item)?)?;
                }
            }
        }
    }
    Ok(())
}

/// The generated `dns` section: resolver entries may be bare address strings
/// or `{address, port, domains, skipFallback}` objects; hosts map names to
/// one or more literal addresses.
fn validate_dns(dns: &Value) -> io::Result<()> {
    let dns = object(dns, &["hosts", "servers", "queryStrategy"])?;
    if let Some(query) = dns.get("queryStrategy") {
        string(query)?;
    }
    if let Some(hosts) = dns.get("hosts") {
        let hosts = hosts.as_object().ok_or_else(rejected)?;
        if hosts.len() > 128 {
            return Err(rejected());
        }
        for (name, value) in hosts {
            if name.is_empty() || name.len() > 253 {
                return Err(rejected());
            }
            match value {
                Value::String(entry) if !entry.is_empty() && entry.len() <= 256 => {}
                Value::Array(entries) => {
                    if entries.is_empty() || entries.len() > 8 {
                        return Err(rejected());
                    }
                    for entry in entries {
                        string(entry)?;
                    }
                }
                _ => return Err(rejected()),
            }
        }
    }
    if let Some(servers) = dns.get("servers") {
        let servers = servers.as_array().ok_or_else(rejected)?;
        if servers.is_empty() || servers.len() > 16 {
            return Err(rejected());
        }
        for server in servers {
            match server {
                Value::String(address) => {
                    if address.is_empty() || address.len() > 256 {
                        return Err(rejected());
                    }
                }
                Value::Object(_) => {
                    let entry = object(
                        server,
                        &[
                            "address",
                            "port",
                            "domains",
                            "skipFallback",
                            "queryStrategy",
                        ],
                    )?;
                    string(&entry["address"])?;
                    if let Some(server_port) = entry.get("port") {
                        port(server_port)?;
                    }
                    if let Some(domains) = entry.get("domains") {
                        let domains = domains.as_array().ok_or_else(rejected)?;
                        if domains.is_empty() || domains.len() > 64 {
                            return Err(rejected());
                        }
                        for domain in domains {
                            string(domain)?;
                        }
                    }
                    if let Some(skip) = entry.get("skipFallback") {
                        if !skip.is_boolean() {
                            return Err(rejected());
                        }
                    }
                    if let Some(query) = entry.get("queryStrategy") {
                        string(query)?;
                    }
                }
                _ => return Err(rejected()),
            }
        }
    }
    Ok(())
}

fn validate_fakedns(fakedns: &Value) -> io::Result<()> {
    let pools = fakedns.as_array().ok_or_else(rejected)?;
    if pools.is_empty() || pools.len() > 4 {
        return Err(rejected());
    }
    for pool in pools {
        let pool = object(pool, &["ipPool", "poolSize"])?;
        let cidr = string(&pool["ipPool"])?;
        if cidr.parse::<ipnet::IpNet>().is_err() {
            return Err(rejected());
        }
        if pool["poolSize"]
            .as_u64()
            .is_none_or(|size| size == 0 || size > 65535)
        {
            return Err(rejected());
        }
    }
    Ok(())
}

/// Root Xray resolves `ext:`-style selectors to files next to its assets, so
/// accept only the selector forms the app generates.
fn routing_selector(key: &str, item: &str) -> io::Result<()> {
    let valid = if key == "ip" {
        match item.strip_prefix("geoip:") {
            // Country codes dominate, but profiles may load a custom geoip.dat
            // defining arbitrary categories (e.g. `direct`); Xray resolves the
            // code against the staged asset at start and fails loudly if absent.
            Some(code) => {
                !code.is_empty()
                    && code.len() <= 64
                    && code
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            }
            None => item.parse::<IpAddr>().is_ok() || item.parse::<ipnet::IpNet>().is_ok(),
        }
    } else {
        match item.split_once(':') {
            Some(("geosite", category)) => {
                // `geosite:category@attr` filters on asset attributes (the
                // `*` wildcard is allowed inside the attribute only).
                let mut parts = category.splitn(2, '@');
                let (name, attr) = (parts.next().unwrap_or_default(), parts.next());
                !name.is_empty()
                    && name.len() <= 64
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                    && attr.is_none_or(|attr| {
                        !attr.is_empty()
                            && attr.len() <= 64
                            && attr.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric()
                                    || byte == b'-'
                                    || byte == b'_'
                                    || byte == b'*'
                            })
                    })
            }
            Some(("domain" | "full" | "keyword" | "regexp", value)) => !value.is_empty(),
            Some(_) => false,
            None => !item.contains(['/', '\\']),
        }
    };
    if valid {
        Ok(())
    } else {
        Err(rejected())
    }
}

fn validate_vless_stream(stream: &Value) -> io::Result<()> {
    object(
        stream,
        &[
            "network",
            "security",
            "wsSettings",
            "grpcSettings",
            "xhttpSettings",
            "httpupgradeSettings",
            "tlsSettings",
            "realitySettings",
        ],
    )?;
    if !matches!(
        stream["network"].as_str(),
        Some("tcp" | "raw" | "ws" | "grpc" | "xhttp" | "httpupgrade")
    ) || !matches!(
        stream["security"].as_str(),
        Some("none" | "tls" | "reality")
    ) {
        return Err(rejected());
    }
    for (key, allowed) in [
        ("wsSettings", &["path", "headers"][..]),
        ("grpcSettings", &["serviceName"][..]),
        ("xhttpSettings", &["path", "host"][..]),
        ("httpupgradeSettings", &["path", "host"][..]),
        ("tlsSettings", &["serverName", "fingerprint", "alpn"][..]),
        (
            "realitySettings",
            &[
                "serverName",
                "fingerprint",
                "publicKey",
                "shortId",
                "spiderX",
            ][..],
        ),
    ] {
        if let Some(value) = stream.get(key) {
            let map = object(value, allowed)?;
            for (field, value) in map {
                if key == "wsSettings" && field == "headers" {
                    object(value, &["Host"])?;
                    string(&value["Host"])?;
                } else if key == "tlsSettings" && field == "alpn" {
                    let items = value.as_array().ok_or_else(rejected)?;
                    if items.is_empty() || items.len() > 8 {
                        return Err(rejected());
                    }
                    for item in items {
                        string(item)?;
                    }
                } else {
                    string(value)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_hysteria_stream(stream: &Value) -> io::Result<()> {
    object(
        stream,
        &[
            "network",
            "security",
            "tlsSettings",
            "hysteriaSettings",
            "finalmask",
        ],
    )?;
    if stream["network"] != "hysteria" || stream["security"] != "tls" {
        return Err(rejected());
    }
    let tls = object(
        &stream["tlsSettings"],
        &["serverName", "pinnedPeerCertSha256"],
    )?;
    for value in tls.values() {
        string(value)?;
    }
    object(&stream["hysteriaSettings"], &["version", "auth"])?;
    if stream["hysteriaSettings"]["version"] != 2 {
        return Err(rejected());
    }
    string(&stream["hysteriaSettings"]["auth"])?;
    if let Some(mask) = stream.get("finalmask") {
        object(mask, &["udp", "quicParams"])?;
        if let Some(udp) = mask.get("udp") {
            let item = one(udp)?;
            object(item, &["type", "settings"])?;
            if item["type"] != "salamander" {
                return Err(rejected());
            }
            object(&item["settings"], &["password"])?;
            string(&item["settings"]["password"])?;
        }
        if let Some(quic) = mask.get("quicParams") {
            object(quic, &["udpHop"])?;
            object(&quic["udpHop"], &["ports"])?;
            string(&quic["udpHop"]["ports"])?;
        }
    }
    Ok(())
}

pub fn prepare_xray(uid: u32, params: XrayConnectParams, mark: u32) -> io::Result<XrayPlan> {
    validate_owner(&format!("xray:{}", params.profile_id)).map_err(|_| rejected())?;
    if mark == 0
        || params.config.len() > MAX_XRAY_CONFIG_BYTES
        || params.routes.len() > 64
        || params.dns_servers.len() > 8
        || params.dns_domains.len() > 16
    {
        return Err(rejected());
    }
    let mut seen = HashSet::new();
    for route in &params.routes {
        if route.via.is_some()
            || route.destination.trunc() != route.destination
            || !seen.insert(route.destination)
        {
            return Err(rejected());
        }
    }
    if (seen.contains(&"0.0.0.0/1".parse().unwrap())
        && seen.contains(&"128.0.0.0/1".parse().unwrap()))
        || (seen.contains(&"::/1".parse().unwrap()) && seen.contains(&"8000::/1".parse().unwrap()))
    {
        return Err(rejected());
    }
    if params
        .dns_servers
        .iter()
        .any(|ip| ip.is_unspecified() || ip.is_multicast())
        || (!params.dns_domains.is_empty() && params.dns_servers.is_empty())
        || params.dns_domains.iter().any(|domain| {
            domain.is_empty() || domain.len() > 253 || domain.chars().any(char::is_control)
        })
        || params.dns_bypass.len() > 16
        || params.dns_bypass.iter().any(|host| {
            host.is_empty()
                || host.len() > 253
                || host
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '@' | '%'))
        })
    {
        return Err(rejected());
    }
    let full_ipv4 = params
        .routes
        .iter()
        .any(|r| r.destination.to_string() == "0.0.0.0/0");
    let full_ipv6 = params
        .routes
        .iter()
        .any(|r| r.destination.to_string() == "::/0");
    let (covers_ipv4, covers_ipv6) = full_coverage(params.routes.iter().map(|r| r.destination));
    if (covers_ipv4 && !full_ipv4) || (covers_ipv6 && !full_ipv6) {
        return Err(rejected());
    }
    for server in &params.dns_servers {
        if !params
            .routes
            .iter()
            .any(|route| route.destination.contains(server))
        {
            return Err(rejected());
        }
    }
    let mut config: Value = serde_json::from_str(&params.config).map_err(|_| rejected())?;
    validate_generated(&config)?;
    // `validate_generated` guarantees the shape of outbounds[0]; extracting
    // the upstream host here lets the daemon install a direct bypass route
    // before any tunnel routes land.
    let server_host = match config["outbounds"][0]["protocol"].as_str() {
        Some("vless") => config["outbounds"][0]["settings"]["vnext"][0]["address"].as_str(),
        Some("hysteria") => config["outbounds"][0]["settings"]["address"].as_str(),
        _ => None,
    }
    .map(str::to_owned);
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in uid.to_le_bytes().iter().chain(params.profile_id.as_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let (name, _) = crate::link_names::tunnel_link_names(
        "xray-",
        uid,
        &params.profile_id,
        params.interface_name.as_deref(),
    );
    // Build an address within 198.18.0.0/15 without accepting a caller IP.
    let host = (hash as u32) & 0x1ffff;
    let address: ipnet::IpNet = format!(
        "198.{}.{}.{}/32",
        18 + (host >> 16),
        (host >> 8) & 255,
        host & 255
    )
    .parse()
    .map_err(|_| rejected())?;
    let mtu = 1500;
    let mut dest_override = vec!["http", "tls", "quic"];
    // Fake-IP answers need the sniffing stage to keep the fake destination so
    // routing can match it against domain policies.
    if config["fakedns"]
        .as_array()
        .is_some_and(|pools| !pools.is_empty())
    {
        dest_override.push("fakedns");
    }
    config["inbounds"] = json!([
        {
            "tag": "tun-in",
            "protocol": "tun",
            "settings": { "name": name, "mtu": mtu },
            // TUN traffic arrives as bare IP packets; sniffing recovers the TLS
            // SNI / HTTP Host so domain and geosite routing rules can match.
            "sniffing": { "enabled": true, "destOverride": dest_override },
        },
    ]);
    config["log"] = json!({"loglevel":"warning"});
    for outbound in config["outbounds"].as_array_mut().ok_or_else(rejected)? {
        if outbound["protocol"] != "blackhole" {
            if outbound["streamSettings"].is_null() {
                outbound["streamSettings"] = json!({});
            }
            outbound["streamSettings"]["sockopt"] = json!({"mark": mark});
        }
    }
    Ok(XrayPlan {
        profile_id: params.profile_id,
        name,
        config: serde_json::to_string(&config).map_err(|_| rejected())?,
        routes: params.routes,
        address,
        mtu,
        dns_servers: params.dns_servers,
        dns_domains: params.dns_domains,
        dns_bypass: params.dns_bypass,
        full_ipv4,
        full_ipv6,
        mark,
        server_host,
        geo_assets: params.geo_assets,
    })
}

/// DNS resolvers whose family is fully captured by the tunnel need a direct
/// host route through the physical gateway: without it, resolver queries
/// (e.g. systemd-resolved resolving the VPN server host) re-enter the TUN
/// and loop. Split-tunnel profiles intentionally resolve those servers
/// *inside* the tunnel, so they are bypassed only under full coverage.
pub fn dns_bypass_addrs(dns_servers: &[IpAddr], full_ipv4: bool, full_ipv6: bool) -> Vec<IpAddr> {
    dns_servers
        .iter()
        .copied()
        .filter(|ip| match ip {
            IpAddr::V4(_) => full_ipv4,
            IpAddr::V6(_) => full_ipv6,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::XrayConnectParams;
    use net_manager_core::models::PolicyRoute;
    use serde_json::{json, Value};

    fn params() -> XrayConnectParams {
        XrayConnectParams {
            profile_id: "home".into(),
            config: json!({
                "inbounds": [{"tag":"socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 1080, "settings":{"udp":true}}],
                "outbounds": [
                    {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address":"example.test","port":443,"users":[{"id":"SECRET-UUID","encryption":"none"}]}]}, "streamSettings":{"network":"tcp","security":"none"}},
                    {"tag": "direct", "protocol": "freedom"},
                    {"tag": "blocked", "protocol": "blackhole"}
                ],
                "routing": {"rules": []}
            }).to_string(),
            routes: vec![PolicyRoute {
                destination: "10.20.0.0/16".parse().unwrap(),
                metric: 5,
                via: None,
            }],
            dns_servers: vec![],
            dns_domains: vec![],
            dns_bypass: vec![],
            interface_name: None,
            geo_assets: None,
        }
    }

    #[test]
    fn plan_replaces_user_inbounds_and_marks_every_dialling_outbound() {
        let plan = prepare_xray(1000, params(), 51820).unwrap();
        assert!(plan.name.starts_with("xray-"));
        assert!(plan.name.len() <= 15);
        // The deterministic hash name is hex-only and stable per (uid, profile).
        assert!(plan.name[5..].chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(plan.name, prepare_xray(1000, params(), 51820).unwrap().name);
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        assert_eq!(config["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(config["inbounds"][0]["protocol"], "tun");
        assert_eq!(config["inbounds"][0]["settings"]["name"], plan.name);
        assert_eq!(config["inbounds"][0]["settings"]["mtu"], 1500);
        for index in [0, 1] {
            assert_eq!(
                config["outbounds"][index]["streamSettings"]["sockopt"]["mark"],
                51820
            );
        }
        assert!(config["outbounds"][2]["streamSettings"].is_null());
        assert!(!plan.config.contains("\"protocol\":\"socks\""));
        assert!(!format!("{plan:?}").contains("SECRET-UUID"));
    }

    #[test]
    fn plan_extracts_server_host_for_bypass_routes() {
        let plan = prepare_xray(1000, params(), 51820).unwrap();
        assert_eq!(plan.server_host.as_deref(), Some("example.test"));

        let mut hysteria = params();
        hysteria.config = json!({
            "inbounds": [{"tag":"socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 1080, "settings":{"udp":true}}],
            "outbounds": [
                {"tag": "proxy", "protocol": "hysteria", "settings": {"version": 2, "address": "hy.example.test", "port": 443}, "streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"hy.example.test"},"hysteriaSettings":{"version":2,"auth":"SECRET-PASS"}}},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "blocked", "protocol": "blackhole"}
            ],
            "routing": {"rules": []}
        })
        .to_string();
        let plan = prepare_xray(1000, hysteria, 51820).unwrap();
        assert_eq!(plan.server_host.as_deref(), Some("hy.example.test"));
        assert!(!format!("{plan:?}").contains("SECRET-PASS"));
    }

    #[test]
    fn dns_bypass_addrs_keeps_only_fully_captured_families() {
        let dns: Vec<IpAddr> = vec![
            "1.1.1.1".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];
        assert_eq!(
            dns_bypass_addrs(&dns, true, false),
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(dns_bypass_addrs(&dns, true, true).len(), 2);
        assert!(dns_bypass_addrs(&dns, false, false).is_empty());
    }

    #[test]
    fn plan_names_tun_after_sanitized_interface_hint() {
        let mut hinted = params();
        hinted.interface_name = Some("NL Home!".into());
        let plan = prepare_xray(1000, hinted, 51820).unwrap();
        assert_eq!(plan.name, "xray-nl-home");
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        assert_eq!(config["inbounds"][0]["settings"]["name"], "xray-nl-home");
    }

    #[test]
    fn plan_enables_traffic_sniffing_on_the_tun_inbound() {
        let plan = prepare_xray(1000, params(), 51820).unwrap();
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        let sniffing = &config["inbounds"][0]["sniffing"];
        // TUN traffic arrives as bare IP packets; sniffing exposes the TLS/HTTP
        // hostname so domain/geosite routing rules can match.
        assert_eq!(sniffing["enabled"], true);
        assert_eq!(sniffing["destOverride"], json!(["http", "tls", "quic"]));
    }

    #[test]
    fn plan_rejects_untrusted_config_without_echoing_secrets() {
        let mut input = params();
        input.config = "{SECRET-CONFIG".into();
        let err = prepare_xray(1000, input, 51820).unwrap_err();
        assert!(!err.to_string().contains("SECRET-CONFIG"));

        let mut input = params();
        input.config =
            json!({"outbounds":[{"protocol":"freedom","settings":{"redirect":"127.0.0.1:22"}}]})
                .to_string();
        assert!(prepare_xray(1000, input, 51820).is_err());
    }

    #[test]
    fn real_generated_vless_and_hysteria_schemas_are_accepted() {
        for uri in [
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=ws&security=tls&sni=node.test&path=%2Fapi&host=front.test&alpn=h2%2Chttp%2F1.1",
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=raw&security=reality&sni=node.test&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&spx=%2Fcrawl",
            "hy2://password@node.test:443,8443-8444?sni=node.test&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&obfs=salamander&obfs-password=mask",
        ] {
            let generated = net_manager_core::xray::generate_share_link_config(uri, 10808).unwrap();
            let mut input = params();
            input.config = generated.to_string();
            assert!(prepare_xray(1000, input, 51820).is_ok(), "generated schema was rejected");
        }
    }

    #[test]
    fn routing_selectors_cannot_load_arbitrary_asset_files() {
        let with_rule = |rule: Value| {
            let mut config: Value = serde_json::from_str(&params().config).unwrap();
            config["routing"]["rules"] = json!([rule]);
            let mut input = params();
            input.config = config.to_string();
            prepare_xray(1000, input, 51820)
        };
        for rule in [
            json!({"type":"field","domain":["ext:geosite.dat:cn"],"outboundTag":"proxy"}),
            json!({"type":"field","domain":["ext-domain:custom.dat:ads"],"outboundTag":"proxy"}),
            json!({"type":"field","domain":["geosite:../../etc/shadow"],"outboundTag":"proxy"}),
            json!({"type":"field","domain":["../../etc/shadow"],"outboundTag":"proxy"}),
            json!({"type":"field","ip":["ext:../../etc/shadow:tag"],"outboundTag":"direct"}),
            json!({"type":"field","ip":["ext-ip:geoip.dat:cn"],"outboundTag":"direct"}),
            json!({"type":"field","ip":["example.test"],"outboundTag":"direct"}),
        ] {
            assert!(with_rule(rule.clone()).is_err(), "{rule}");
        }
        for rule in [
            json!({"type":"field","domain":["example.com","domain:a.test","full:b.test","keyword:ads","regexp:^c\\.test$","geosite:category-ads_all"],"outboundTag":"proxy"}),
            json!({"type":"field","ip":["geoip:private","geoip:us","geoip:direct","geoip:custom_cat","10.0.0.0/8","::1/128","192.0.2.1"],"outboundTag":"direct"}),
        ] {
            assert!(with_rule(rule.clone()).is_ok(), "{rule}");
        }
    }

    #[test]
    fn def1_style_routes_cannot_bypass_full_tunnel_marking() {
        let mut input = params();
        input.routes = ["0.0.0.0/1", "128.0.0.0/1"]
            .into_iter()
            .map(|destination| PolicyRoute {
                destination: destination.parse().unwrap(),
                metric: 5,
                via: None,
            })
            .collect();
        assert!(prepare_xray(1000, input, 51820).is_err());
    }

    #[test]
    fn noncanonical_full_coverage_cannot_bypass_full_tunnel_marking() {
        let mut input = params();
        input.routes = ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"]
            .into_iter()
            .map(|destination| PolicyRoute {
                destination: destination.parse().unwrap(),
                metric: 5,
                via: None,
            })
            .collect();
        assert!(prepare_xray(1000, input, 51820).is_err());
    }

    #[test]
    fn plan_accepts_generated_split_dns_and_strategy_sections() {
        // Mirror of what `apply_profile_routing` emits for a profile with
        // xrayDns + strategy overrides — the daemon must not reject it.
        let mut input = params();
        input.config = json!({
            "inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"udp":true}}],
            "outbounds":[
                {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"proxy.test","port":443,"users":[{"id":"SECRET-ID","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}},
                {"tag":"direct","protocol":"freedom"},
                {"tag":"blocked","protocol":"blackhole"},
                {"tag":"dns-out","protocol":"dns"}
            ],
            "dns":{
                "hosts":{"domain:ads.test":["127.0.0.1"]},
                "servers":[
                    "fakedns",
                    {"address":"https://1.1.1.1/dns-query","domains":["geosite:category-ru@attr"],"skipFallback":true},
                    "udp://9.9.9.9:53"
                ],
                "queryStrategy":"UseIPv4"
            },
            "fakedns":[{"ipPool":"198.18.0.0/16","poolSize":65535}],
            "routing":{
                "domainStrategy":"IPIfNonMatch",
                "domainMatcher":"mph",
                "rules":[
                    {"type":"field","port":"53","outboundTag":"dns-out"},
                    {"type":"field","ip":["1.1.1.1"],"outboundTag":"direct"},
                    {"type":"field","domain":["geosite:category-ru@attr"],"outboundTag":"proxy"},
                    {"type":"field","network":"udp","domain":["ntp.test"],"outboundTag":"blocked"}
                ]
            }
        })
        .to_string();
        let plan = prepare_xray(1000, input, 51820).unwrap();
        let config: Value = serde_json::from_str(&plan.config).unwrap();
        assert_eq!(
            config["inbounds"][0]["sniffing"]["destOverride"],
            json!(["http", "tls", "quic", "fakedns"])
        );
        assert_eq!(config["outbounds"][3]["protocol"], "dns");
        assert_eq!(
            config["outbounds"][3]["streamSettings"]["sockopt"]["mark"],
            51820
        );
    }

    #[test]
    fn plan_rejects_malformed_dns_sections() {
        let with_dns = |dns: Value| {
            let mut config: Value = serde_json::from_str(&params().config).unwrap();
            config["dns"] = dns;
            let mut input = params();
            input.config = config.to_string();
            prepare_xray(1000, input, 51820)
        };
        assert!(with_dns(json!({"servers": [{"address": "ok.test", "exec": "sh"}]})).is_err());
        assert!(with_dns(json!({"servers": [{"address": "ok.test", "port": 99999}]})).is_err());
        assert!(with_dns(json!({"hosts": {"x.test": 42}})).is_err());
        let mut config: Value = serde_json::from_str(&params().config).unwrap();
        config["fakedns"] = json!([{"ipPool": "not-a-cidr", "poolSize": 16}]);
        let mut input = params();
        input.config = config.to_string();
        assert!(prepare_xray(1000, input, 51820).is_err());
    }
    #[test]
    fn dns_bypass_hosts_are_carried_into_the_plan() {
        let mut input = params();
        input.dns_bypass = vec!["8.8.8.8".into(), "dns.example.test".into()];
        let plan = prepare_xray(1000, input, 51820).unwrap();
        assert_eq!(plan.dns_bypass, ["8.8.8.8", "dns.example.test"]);

        let mut input = params();
        input.dns_bypass = vec!["1.1.1.1".into(); 17];
        assert!(prepare_xray(1000, input, 51820).is_err());
        let mut input = params();
        input.dns_bypass = vec!["bad host/name".into()];
        assert!(prepare_xray(1000, input, 51820).is_err());
    }
}
