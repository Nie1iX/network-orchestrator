use crate::models::{DomainPolicy, DomainRouteTarget};
use ipnet::IpNet;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVless {
    pub name: Option<String>,
    pub id: String,
    pub address: String,
    pub port: u16,
    pub network: String,
    pub security: String,
    pub flow: Option<String>,
    pub sni: Option<String>,
    pub fingerprint: Option<String>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub service_name: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub spider_x: Option<String>,
}

pub fn parse_vless_url(uri: &str) -> io::Result<ParsedVless> {
    let url = Url::parse(uri.trim()).map_err(|_| invalid_input("invalid vless url"))?;
    if url.scheme() != "vless" {
        return Err(invalid_input(format!(
            "unsupported scheme '{}', expected vless",
            url.scheme()
        )));
    }
    let id = percent_decode(url.username());
    if id.trim().is_empty() {
        return Err(invalid_input("vless url must contain a nonblank user id"));
    }
    let address = url
        .host_str()
        .map(str::to_string)
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| invalid_input("vless url must contain a host"))?;

    let mut network = "tcp".to_string();
    let mut security = "none".to_string();
    let mut flow = None;
    let mut sni = None;
    let mut fingerprint = None;
    let mut public_key = None;
    let mut short_id = None;
    let mut path = None;
    let mut host = None;
    let mut service_name = None;
    let mut alpn = None;
    let mut spider_x = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "type" => network = value.into_owned(),
            "security" => security = value.into_owned(),
            "flow" => flow = Some(value.into_owned()),
            "sni" => sni = Some(value.into_owned()),
            "fp" => fingerprint = Some(value.into_owned()),
            "pbk" => public_key = Some(value.into_owned()),
            "sid" => short_id = Some(value.into_owned()),
            "path" => path = Some(value.into_owned()),
            "host" => host = Some(value.into_owned()),
            "serviceName" => service_name = Some(value.into_owned()),
            "alpn" => {
                alpn = Some(
                    value
                        .split(',')
                        .map(str::trim)
                        .map(str::to_string)
                        .collect(),
                )
            }
            "spx" => spider_x = Some(value.into_owned()),
            "allowInsecure" if value != "0" => {
                return Err(invalid_input(
                    "allowInsecure is unsupported by Xray 26.3.27",
                ))
            }
            _ => {}
        }
    }
    if !matches!(
        network.as_str(),
        "tcp" | "raw" | "ws" | "grpc" | "xhttp" | "httpupgrade"
    ) {
        return Err(invalid_input("unsupported transport type"));
    }
    if !matches!(security.as_str(), "none" | "tls" | "reality") {
        return Err(invalid_input("unsupported security"));
    }
    let port = match url.port() {
        Some(0) => return Err(invalid_input("vless url port must be nonzero")),
        Some(port) => port,
        None if security == "tls" || security == "reality" => 443,
        None => {
            return Err(invalid_input(
                "vless url requires an explicit port unless security is tls or reality",
            ))
        }
    };
    if security == "reality"
        && (sni.as_deref().map(str::trim).unwrap_or("").is_empty()
            || public_key
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty())
    {
        return Err(invalid_input(
            "reality security requires nonblank sni and pbk",
        ));
    }
    let name = url
        .fragment()
        .map(percent_decode)
        .filter(|name| !name.trim().is_empty());
    Ok(ParsedVless {
        name,
        id,
        address,
        port,
        network,
        security,
        flow,
        sni,
        fingerprint,
        public_key,
        short_id,
        path,
        host,
        service_name,
        alpn,
        spider_x,
    })
}

pub fn generate_vless_config(uri: &str, socks_port: u16) -> io::Result<Value> {
    if socks_port == 0 {
        return Err(invalid_input("socks port must be nonzero"));
    }
    let parsed = parse_vless_url(uri)?;
    let mut user = json!({
        "id": parsed.id,
        "encryption": "none",
    });
    if let Some(flow) = &parsed.flow {
        user["flow"] = json!(flow);
    }
    let mut stream = json!({
        "network": parsed.network,
        "security": parsed.security,
    });
    match parsed.network.as_str() {
        "ws" => {
            let mut ws = Map::new();
            if let Some(path) = &parsed.path {
                ws.insert("path".into(), json!(path));
            }
            if let Some(host) = &parsed.host {
                ws.insert("headers".into(), json!({ "Host": host }));
            }
            if !ws.is_empty() {
                stream["wsSettings"] = Value::Object(ws);
            }
        }
        "grpc" => {
            if let Some(service_name) = &parsed.service_name {
                stream["grpcSettings"] = json!({ "serviceName": service_name });
            }
        }
        "xhttp" | "httpupgrade" => {
            let mut settings = Map::new();
            if let Some(path) = &parsed.path {
                settings.insert("path".into(), json!(path));
            }
            if let Some(host) = &parsed.host {
                settings.insert("host".into(), json!(host));
            }
            if !settings.is_empty() {
                let key = if parsed.network == "xhttp" {
                    "xhttpSettings"
                } else {
                    "httpupgradeSettings"
                };
                stream[key] = Value::Object(settings);
            }
        }
        _ => {}
    }
    match parsed.security.as_str() {
        "tls" => {
            let mut tls = Map::new();
            if let Some(sni) = &parsed.sni {
                tls.insert("serverName".into(), json!(sni));
            }
            if let Some(fingerprint) = &parsed.fingerprint {
                tls.insert("fingerprint".into(), json!(fingerprint));
            }
            if let Some(alpn) = &parsed.alpn {
                tls.insert("alpn".into(), json!(alpn));
            }
            stream["tlsSettings"] = Value::Object(tls);
        }
        "reality" => {
            let mut reality = Map::new();
            if let Some(sni) = &parsed.sni {
                reality.insert("serverName".into(), json!(sni));
            }
            if let Some(fingerprint) = &parsed.fingerprint {
                reality.insert("fingerprint".into(), json!(fingerprint));
            }
            if let Some(public_key) = &parsed.public_key {
                reality.insert("publicKey".into(), json!(public_key));
            }
            if let Some(short_id) = &parsed.short_id {
                reality.insert("shortId".into(), json!(short_id));
            }
            if let Some(spider_x) = &parsed.spider_x {
                reality.insert("spiderX".into(), json!(spider_x));
            }
            stream["realitySettings"] = Value::Object(reality);
        }
        _ => {}
    }
    Ok(config_with_proxy(
        json!({
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": parsed.address,
                    "port": parsed.port,
                    "users": [user],
                }],
            },
            "streamSettings": stream,
        }),
        socks_port,
    ))
}

pub fn generate_share_link_config(uri: &str, socks_port: u16) -> io::Result<Value> {
    match uri.trim().split_once("://").map(|(scheme, _)| scheme) {
        Some("vless") => generate_vless_config(uri, socks_port),
        Some("hysteria2" | "hy2") => generate_hysteria2_config(uri, socks_port),
        _ => Err(invalid_input("unsupported share link scheme")),
    }
}

pub fn generate_share_link_config_with_http(
    uri: &str,
    socks_port: u16,
    http_port: u16,
) -> io::Result<Value> {
    if http_port == 0 || http_port == socks_port {
        return Err(invalid_input(
            "HTTP proxy port must be nonzero and differ from SOCKS port",
        ));
    }
    let mut config = generate_share_link_config(uri, socks_port)?;
    config["inbounds"].as_array_mut().unwrap().push(json!({
        "tag": "http-in",
        "listen": "127.0.0.1",
        "port": http_port,
        "protocol": "http",
    }));
    Ok(config)
}

pub fn share_link_name(uri: &str) -> Option<String> {
    uri.rsplit_once('#')
        .map(|(_, fragment)| percent_decode(fragment))
        .filter(|name| !name.trim().is_empty())
}

fn generate_hysteria2_config(uri: &str, socks_port: u16) -> io::Result<Value> {
    if socks_port == 0 {
        return Err(invalid_input("socks port must be nonzero"));
    }
    let uri = uri.trim();
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| invalid_input("invalid hysteria2 url"))?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .ok_or_else(|| invalid_input("hysteria2 url must contain auth"))?;
    let port_spec = if host_port.starts_with('[') {
        host_port.rsplit_once("]:").map(|(_, port)| port)
    } else {
        host_port.rsplit_once(':').map(|(_, port)| port)
    };
    let mut hop_ports = None;
    let normalized;
    if let Some(port_spec) = port_spec.filter(|port| port.contains([',', '-'])) {
        let first = validate_hysteria_ports(port_spec)?;
        let port_start = authority
            .rfind(':')
            .ok_or_else(|| invalid_input("invalid hysteria2 port"))?;
        normalized = format!(
            "{scheme}://{}:{first}{}",
            &authority[..port_start],
            &rest[authority_end..]
        );
        hop_ports = Some(port_spec);
    } else {
        normalized = uri.to_string();
    }
    let url = Url::parse(&normalized).map_err(|_| invalid_input("invalid hysteria2 url"))?;
    let auth = percent_decode(url.username());
    let auth = match url.password() {
        Some(password) => format!("{auth}:{}", percent_decode(password)),
        None => auth,
    };
    if auth.is_empty() {
        return Err(invalid_input("hysteria2 url must contain auth"));
    }
    let address = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| invalid_input("hysteria2 url must contain a host"))?;
    let port = url.port().unwrap_or(443);
    if port == 0 {
        return Err(invalid_input("hysteria2 port must be nonzero"));
    }
    if !matches!(url.path(), "" | "/") {
        return Err(invalid_input("unsupported hysteria2 url path"));
    }
    let mut sni = None;
    let mut pin = None;
    let mut obfs = None;
    let mut obfs_password = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "sni" => sni = Some(value.into_owned()),
            "pinSHA256" => {
                let normalized_pin = value.replace(':', "");
                if normalized_pin.len() != 64
                    || !normalized_pin.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(invalid_input("invalid pinSHA256"));
                }
                pin = Some(normalized_pin);
            }
            "obfs" => obfs = Some(value.into_owned()),
            "obfs-password" => obfs_password = Some(value.into_owned()),
            "insecure" | "allowInsecure" if value == "0" => {}
            "insecure" | "allowInsecure" => {
                return Err(invalid_input("insecure TLS is unsupported by Xray 26.3.27"))
            }
            _ => return Err(invalid_input("unsupported hysteria2 option")),
        }
    }
    let mut tls = Map::new();
    if let Some(sni) = sni {
        tls.insert("serverName".into(), json!(sni));
    }
    if let Some(pin) = pin {
        tls.insert("pinnedPeerCertSha256".into(), json!(pin));
    }
    let mut stream = json!({
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": Value::Object(tls),
        "hysteriaSettings": {"version": 2, "auth": auth},
    });
    let mut finalmask = Map::new();
    match (obfs.as_deref(), obfs_password) {
        (Some("salamander"), Some(password)) if !password.is_empty() => {
            finalmask.insert(
                "udp".into(),
                json!([{"type": "salamander", "settings": {"password": password}}]),
            );
        }
        (None, None) => {}
        _ => return Err(invalid_input("unsupported hysteria2 obfuscation")),
    }
    if let Some(ports) = hop_ports {
        finalmask.insert("quicParams".into(), json!({"udpHop": {"ports": ports}}));
    }
    if !finalmask.is_empty() {
        stream["finalmask"] = Value::Object(finalmask);
    }
    Ok(config_with_proxy(
        json!({
            "tag": "proxy",
            "protocol": "hysteria",
            "settings": {"version": 2, "address": address, "port": port},
            "streamSettings": stream,
        }),
        socks_port,
    ))
}

fn validate_hysteria_ports(ports: &str) -> io::Result<u16> {
    let mut first = None;
    for part in ports.split(',') {
        let (start, end) = part.split_once('-').unwrap_or((part, part));
        let start = start
            .parse::<u16>()
            .map_err(|_| invalid_input("invalid hysteria2 port range"))?;
        let end = end
            .parse::<u16>()
            .map_err(|_| invalid_input("invalid hysteria2 port range"))?;
        if start == 0 || end < start {
            return Err(invalid_input("invalid hysteria2 port range"));
        }
        first.get_or_insert(start);
    }
    first.ok_or_else(|| invalid_input("invalid hysteria2 port range"))
}

fn config_with_proxy(proxy: Value, socks_port: u16) -> Value {
    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": { "udp": true },
        }],
        "outbounds": [
            proxy,
            {
                "tag": "direct",
                "protocol": "freedom",
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [],
        },
    })
}

pub fn apply_domain_policies(base: &Value, policies: &[DomainPolicy]) -> io::Result<Value> {
    apply_profile_routing(base, policies, false)
}

pub fn validate_routing_policy_selectors(policies: &[DomainPolicy]) -> io::Result<()> {
    for policy in policies {
        if policy.domains.is_empty() {
            return Err(invalid_input("routing rule must contain selectors"));
        }
        for selector in &policy.domains {
            classify_routing_selector(selector)?;
        }
    }
    Ok(())
}

/// Returns `Ok(None)` for comments (`# …`) and blank selectors so the UI can
/// keep annotation lines inside routing lists.
fn classify_routing_selector(selector: &str) -> io::Result<Option<(&'static str, String)>> {
    let selector = selector.trim();
    if selector.is_empty() || selector.starts_with('#') {
        return Ok(None);
    }
    if let Some(category) = selector.strip_prefix("geosite:") {
        if category.is_empty()
            || category.len() > 64
            || !category
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(invalid_input("invalid geosite category"));
        }
        return Ok(Some(("domain", selector.to_string())));
    }
    if let Some(code) = selector.strip_prefix("geoip:") {
        // Countries are the common case, but profiles may ship custom
        // geoip.dat files defining arbitrary categories (e.g. `direct`) —
        // Xray resolves the code against the actually loaded asset.
        if code.is_empty()
            || code.len() > 64
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(invalid_input("invalid geoip code"));
        }
        return Ok(Some(("ip", selector.to_string())));
    }
    if let Ok(ip) = selector.parse::<IpAddr>() {
        return Ok(Some(("ip", ip.to_string())));
    }
    if let Ok(net) = IpNet::from_str(selector) {
        return Ok(Some(("ip", net.to_string())));
    }
    Ok(Some(("domain", selector.to_string())))
}

pub fn apply_profile_routing(
    base: &Value,
    policies: &[DomainPolicy],
    private_lan_direct: bool,
) -> io::Result<Value> {
    if policies.is_empty() && !private_lan_direct {
        return Ok(base.clone());
    }
    validate_routing_policy_selectors(policies)?;
    let mut doc = base.clone();
    let root = doc
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config root must be an object"))?;
    let outbounds = root
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid_data("xray config outbounds must be an array"))?;

    let needs_proxy = policies
        .iter()
        .any(|policy| policy.target == DomainRouteTarget::Proxy);
    let needs_direct = private_lan_direct
        || policies
            .iter()
            .any(|policy| policy.target == DomainRouteTarget::Direct);
    let needs_block = policies
        .iter()
        .any(|policy| policy.target == DomainRouteTarget::Block);

    let mut counts: HashMap<String, usize> = HashMap::new();
    for tag in outbounds
        .iter()
        .filter_map(|outbound| outbound["tag"].as_str())
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
    {
        *counts.entry(tag.to_string()).or_default() += 1;
    }
    let mut used: HashSet<String> = counts.keys().cloned().collect();

    let proxy_tag = if needs_proxy {
        let index = outbounds
            .iter()
            .position(|outbound| match outbound["protocol"].as_str() {
                Some(protocol) => {
                    !protocol.trim().is_empty()
                        && !matches!(protocol, "freedom" | "blackhole" | "dns")
                }
                None => false,
            })
            .ok_or_else(|| invalid_data("no eligible proxy outbound for domain policy"))?;
        Some(resolve_outbound_tag(
            &mut outbounds[index],
            "network-orchestrator-proxy",
            &counts,
            &mut used,
        ))
    } else {
        None
    };

    let direct_tag = if needs_direct {
        let index = match outbounds
            .iter()
            .position(|outbound| outbound["protocol"].as_str() == Some("freedom"))
        {
            Some(index) => index,
            None => {
                outbounds.push(json!({ "protocol": "freedom" }));
                outbounds.len() - 1
            }
        };
        Some(resolve_outbound_tag(
            &mut outbounds[index],
            "network-orchestrator-direct",
            &counts,
            &mut used,
        ))
    } else {
        None
    };

    let block_tag = if needs_block {
        let index = match outbounds
            .iter()
            .position(|outbound| outbound["protocol"].as_str() == Some("blackhole"))
        {
            Some(index) => index,
            None => {
                outbounds.push(json!({ "protocol": "blackhole" }));
                outbounds.len() - 1
            }
        };
        Some(resolve_outbound_tag(
            &mut outbounds[index],
            "network-orchestrator-block",
            &counts,
            &mut used,
        ))
    } else {
        None
    };

    let routing = root.entry("routing").or_insert_with(|| json!({}));
    let routing = routing
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config routing must be an object"))?;
    let rules = routing.entry("rules").or_insert_with(|| json!([]));
    let rules = rules
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config routing.rules must be an array"))?;

    let mut merged = Vec::new();
    for policy in policies {
        let tag = match policy.target {
            DomainRouteTarget::Proxy => proxy_tag.as_deref().unwrap_or_default(),
            DomainRouteTarget::Direct => direct_tag.as_deref().unwrap_or_default(),
            DomainRouteTarget::Block => block_tag.as_deref().unwrap_or_default(),
        };
        let mut domains = Vec::new();
        let mut ips = Vec::new();
        for selector in &policy.domains {
            let Some((kind, value)) = classify_routing_selector(selector)? else {
                continue;
            };
            if kind == "ip" {
                ips.push(value);
            } else {
                domains.push(value);
            }
        }
        if !domains.is_empty() {
            merged.push(json!({"type": "field", "domain": domains, "outboundTag": tag}));
        }
        if !ips.is_empty() {
            merged.push(json!({"type": "field", "ip": ips, "outboundTag": tag}));
        }
    }
    if private_lan_direct {
        merged.push(json!({
            "type": "field",
            "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"],
            "outboundTag": direct_tag.as_deref().unwrap_or_default(),
        }));
    }
    merged.append(rules);
    *rules = merged;
    Ok(doc)
}

/// Replace the SOCKS inbound in an Xray config with a TUN inbound (Wintun on
/// Windows). If no inbound exists, a TUN inbound is added. The TUN interface
/// captures all IP traffic at the interface level, making Xray a full-tunnel
/// backend. The `interface_name` and `ip` parameters configure the TUN
/// adapter; if `None`, sensible defaults are used.
pub fn apply_tun_inbound(
    base: &Value,
    interface_name: Option<&str>,
    ip: Option<&str>,
) -> io::Result<Value> {
    let mut doc = base.clone();
    let root = doc
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config root must be an object"))?;
    let inbounds = root
        .entry("inbounds")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config inbounds must be an array"))?;

    // Remove existing SOCKS inbound(s) — TUN mode replaces system-proxy-based
    // traffic capture with interface-level capture.
    inbounds.retain(|inbound| inbound["protocol"].as_str() != Some("socks"));

    let tun_inbound = json!({
        "tag": "tun-in",
        "protocol": "tun",
        "settings": {
            "interfaceName": interface_name.unwrap_or("xray-tun"),
            "ip": ip.unwrap_or("172.19.0.1/30"),
            "mtu": 1500,
        },
        // TUN traffic arrives as bare IP packets; sniffing recovers the TLS
        // SNI / HTTP Host so domain and geosite routing rules can match.
        "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls", "quic"],
        },
    });
    inbounds.insert(0, tun_inbound);
    Ok(doc)
}

/// Check whether an Xray config has a TUN inbound.
pub fn has_tun_inbound(config: &Value) -> bool {
    config["inbounds"]
        .as_array()
        .map(|inbounds| {
            inbounds
                .iter()
                .any(|inbound| inbound["protocol"].as_str() == Some("tun"))
        })
        .unwrap_or(false)
}

fn resolve_outbound_tag(
    outbound: &mut Value,
    base_tag: &str,
    counts: &HashMap<String, usize>,
    used: &mut HashSet<String>,
) -> String {
    if let Some(tag) = outbound["tag"]
        .as_str()
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
    {
        if counts.get(tag) == Some(&1) {
            return tag.to_string();
        }
    }
    let mut candidate = base_tag.to_string();
    let mut suffix = 2;
    while used.contains(&candidate) {
        candidate = format!("{base_tag}-{suffix}");
        suffix += 1;
    }
    used.insert(candidate.clone());
    outbound["tag"] = json!(candidate.clone());
    candidate
}

pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = char::from(bytes[index + 1]).to_digit(16);
            let low = char::from(bytes[index + 2]).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                decoded.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DomainRouteTarget;
    use serde_json::json;

    const WS_TLS_URL: &str = "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls&sni=edge.example.com&fp=chrome&path=%2Fapi%2Fws&host=cdn.example.com#My%20Node%20%F0%9F%9A%80";

    #[test]
    fn parses_tls_websocket_url() {
        let parsed = parse_vless_url(WS_TLS_URL).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("My Node 🚀"));
        assert_eq!(parsed.id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(parsed.address, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.network, "ws");
        assert_eq!(parsed.security, "tls");
        assert_eq!(parsed.sni.as_deref(), Some("edge.example.com"));
        assert_eq!(parsed.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(parsed.path.as_deref(), Some("/api/ws"));
        assert_eq!(parsed.host.as_deref(), Some("cdn.example.com"));
        assert!(parsed.flow.is_none());
        assert!(parsed.service_name.is_none());
    }

    #[test]
    fn parses_reality_grpc_url() {
        let parsed = parse_vless_url(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@node.test:8443?type=grpc&security=reality&sni=www.microsoft.com&pbk=PUBLIC_KEY&sid=0123ab&serviceName=grpcsvc&flow=xtls-rprx-vision",
        )
        .unwrap();
        assert_eq!(parsed.network, "grpc");
        assert_eq!(parsed.security, "reality");
        assert_eq!(parsed.port, 8443);
        assert_eq!(parsed.service_name.as_deref(), Some("grpcsvc"));
        assert_eq!(parsed.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(parsed.public_key.as_deref(), Some("PUBLIC_KEY"));
        assert_eq!(parsed.short_id.as_deref(), Some("0123ab"));
        assert!(parsed.name.is_none());
    }

    #[test]
    fn reality_requires_sni_and_public_key() {
        for uri in [
            "vless://id@node.test:443?security=reality&pbk=KEY",
            "vless://id@node.test:443?security=reality&sni=site.com",
            "vless://id@node.test:443?security=reality&sni=%20&pbk=KEY",
            "vless://id@node.test:443?security=reality&sni=site.com&pbk=%20",
        ] {
            assert_eq!(
                parse_vless_url(uri).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{uri}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_transport_and_security() {
        for uri in [
            "vless://id@node.test:443?type=h2&security=tls&sni=x",
            "vless://id@node.test:443?type=ws&security=auto",
            "vless://id@node.test:443?type=tcp&security=xtls",
        ] {
            assert_eq!(
                parse_vless_url(uri).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{uri}"
            );
        }
    }

    #[test]
    fn rejects_missing_id_host_and_port() {
        for uri in [
            "vless://@node.test:443?security=tls&sni=x",
            "vless://id@:443?security=tls&sni=x",
            "vless://id@node.test?security=none",
            "vless://id@node.test:0?security=tls&sni=x",
            "not-a-url",
            "vmess://id@node.test:443",
        ] {
            assert_eq!(
                parse_vless_url(uri).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{uri}"
            );
        }
    }

    #[test]
    fn tls_and_reality_default_to_port_443() {
        let parsed = parse_vless_url("vless://id@node.test?security=tls&sni=x").unwrap();
        assert_eq!(parsed.port, 443);
        let parsed =
            parse_vless_url("vless://id@node.test?security=reality&sni=x&pbk=KEY").unwrap();
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn generated_config_shape_for_ws_tls() {
        let config = generate_vless_config(WS_TLS_URL, 10808).unwrap();
        assert_eq!(config["log"]["loglevel"], "warning");
        assert_eq!(config["inbounds"][0]["tag"], "socks-in");
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["port"], 10808);
        assert_eq!(config["inbounds"][0]["protocol"], "socks");
        assert_eq!(config["inbounds"][0]["settings"]["udp"], true);

        let proxy = &config["outbounds"][0];
        assert_eq!(proxy["tag"], "proxy");
        assert_eq!(proxy["protocol"], "vless");
        let vnext = &proxy["settings"]["vnext"][0];
        assert_eq!(vnext["address"], "example.com");
        assert_eq!(vnext["port"], 443);
        let user = &vnext["users"][0];
        assert_eq!(user["id"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(user["encryption"], "none");
        assert!(user.get("flow").is_none());

        let stream = &proxy["streamSettings"];
        assert_eq!(stream["network"], "ws");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["wsSettings"]["path"], "/api/ws");
        assert_eq!(stream["wsSettings"]["headers"]["Host"], "cdn.example.com");
        assert_eq!(stream["tlsSettings"]["serverName"], "edge.example.com");
        assert_eq!(stream["tlsSettings"]["fingerprint"], "chrome");

        assert_eq!(config["outbounds"][1]["tag"], "direct");
        assert_eq!(config["outbounds"][1]["protocol"], "freedom");
        assert_eq!(config["routing"]["domainStrategy"], "AsIs");
        assert_eq!(config["routing"]["rules"], json!([]));
    }

    #[test]
    fn generated_share_link_has_distinct_loopback_socks_and_http_inbounds() {
        let config = generate_share_link_config_with_http(WS_TLS_URL, 10808, 10809).unwrap();
        assert_eq!(config["inbounds"].as_array().unwrap().len(), 2);
        assert_eq!(config["inbounds"][0]["protocol"], "socks");
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["port"], 10808);
        assert_eq!(config["inbounds"][1]["tag"], "http-in");
        assert_eq!(config["inbounds"][1]["protocol"], "http");
        assert_eq!(config["inbounds"][1]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][1]["port"], 10809);
    }

    #[test]
    fn generated_share_link_rejects_duplicate_or_zero_http_port() {
        for http_port in [0, 10808] {
            assert_eq!(
                generate_share_link_config_with_http(WS_TLS_URL, 10808, http_port)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn generated_config_includes_flow_only_when_present() {
        let with_flow = generate_vless_config(
            "vless://id@node.test:443?security=reality&sni=x&pbk=KEY&flow=xtls-rprx-vision",
            10808,
        )
        .unwrap();
        assert_eq!(
            with_flow["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );

        let without_flow = generate_vless_config(
            "vless://id@node.test:443?security=reality&sni=x&pbk=KEY",
            10808,
        )
        .unwrap();
        assert!(
            without_flow["outbounds"][0]["settings"]["vnext"][0]["users"][0]
                .get("flow")
                .is_none()
        );
    }

    #[test]
    fn generated_config_rejects_zero_socks_port() {
        assert_eq!(
            generate_vless_config(WS_TLS_URL, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn reality_grpc_stream_settings() {
        let config = generate_vless_config(
            "vless://id@node.test:443?type=grpc&security=reality&sni=x&pbk=KEY&sid=ff&serviceName=svc",
            10808,
        )
        .unwrap();
        let stream = &config["outbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "grpc");
        assert_eq!(stream["security"], "reality");
        assert_eq!(stream["grpcSettings"]["serviceName"], "svc");
        assert_eq!(stream["realitySettings"]["serverName"], "x");
        assert_eq!(stream["realitySettings"]["publicKey"], "KEY");
        assert_eq!(stream["realitySettings"]["shortId"], "ff");
    }

    #[test]
    fn vless_new_transports_keep_decoded_path_host_and_alpn() {
        for (network, settings) in [
            ("raw", None),
            ("xhttp", Some("xhttpSettings")),
            ("httpupgrade", Some("httpupgradeSettings")),
        ] {
            let uri = format!("vless://id@node.test:443?type={network}&security=tls&sni=node.test&path=%2Fhello%3Ftoken%3Da%252Fb&host=front.test&alpn=h2%2Chttp%2F1.1");
            let config = generate_vless_config(&uri, 10808).unwrap();
            let stream = &config["outbounds"][0]["streamSettings"];
            assert_eq!(stream["network"], network);
            assert_eq!(stream["tlsSettings"]["alpn"], json!(["h2", "http/1.1"]));
            if let Some(settings) = settings {
                assert_eq!(stream[settings]["path"], "/hello?token=a%2Fb");
                assert_eq!(stream[settings]["host"], "front.test");
            }
        }
    }

    #[test]
    fn vless_reality_spider_x_is_decoded() {
        let config = generate_vless_config("vless://id@node.test:443?type=raw&security=reality&sni=node.test&pbk=KEY&spx=%2Fcrawl%3Fq%3D1", 10808).unwrap();
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["realitySettings"]["spiderX"],
            "/crawl?q=1"
        );
    }

    #[test]
    fn vless_rejects_removed_insecure_setting_without_leaking_uri() {
        let uri = "vless://sensitive-id@node.test:443?security=tls&allowInsecure=1#private-name";
        let err = generate_vless_config(uri, 10808).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let message = err.to_string();
        assert!(!message.contains("sensitive-id"));
        assert!(!message.contains("private-name"));
        assert!(!message.contains(uri));
    }

    #[test]
    fn hysteria2_share_link_generates_auth_tls_obfs_and_port_hopping() {
        let uri = "hysteria2://my%40secret@node.test:443,8443-8444/?sni=front.test&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&obfs=salamander&obfs-password=mask%40secret#Private";
        let config = generate_share_link_config(uri, 10808).unwrap();
        let proxy = &config["outbounds"][0];
        assert_eq!(proxy["protocol"], "hysteria");
        assert_eq!(
            proxy["settings"],
            json!({"version": 2, "address": "node.test", "port": 443})
        );
        let stream = &proxy["streamSettings"];
        assert_eq!(stream["network"], "hysteria");
        assert_eq!(stream["security"], "tls");
        assert_eq!(
            stream["hysteriaSettings"],
            json!({"version": 2, "auth": "my@secret"})
        );
        assert_eq!(stream["tlsSettings"]["serverName"], "front.test");
        assert_eq!(
            stream["tlsSettings"]["pinnedPeerCertSha256"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            stream["finalmask"]["udp"][0],
            json!({"type": "salamander", "settings": {"password": "mask@secret"}})
        );
        assert_eq!(
            stream["finalmask"]["quicParams"]["udpHop"]["ports"],
            "443,8443-8444"
        );
    }

    #[test]
    fn hy2_alias_defaults_to_port_443() {
        let config =
            generate_share_link_config("hy2://pass%3Aword@node.test?sni=front.test", 10808)
                .unwrap();
        let proxy = &config["outbounds"][0];
        assert_eq!(proxy["settings"]["port"], 443);
        assert_eq!(
            proxy["streamSettings"]["hysteriaSettings"]["auth"],
            "pass:word"
        );
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
    }

    #[test]
    fn hysteria2_rejects_unsupported_options_without_leaking_secrets() {
        for uri in [
            "hy2://private-password@node.test?insecure=1",
            "hy2://private-password@node.test?allowInsecure=1",
            "hy2://private-password@node.test?obfs=gecko&obfs-password=secret",
            "hy2://private-password@node.test?ech=secret",
            "hy2://private-password@node.test:443,0",
        ] {
            let err = generate_share_link_config(uri, 10808).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            let message = err.to_string();
            assert!(!message.contains("private-password"));
            assert!(!message.contains("secret"));
            assert!(!message.contains(uri));
        }
    }

    #[test]
    fn generated_share_configs_pass_pinned_xray_test_when_requested() {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let Ok(binary) = std::env::var("XRAY_TEST_BINARY") else {
            return;
        };
        let uris = [
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=raw&security=tls&sni=node.test",
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=raw&security=reality&sni=node.test&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&spx=%2Fcrawl",
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=xhttp&security=tls&sni=node.test&path=%2Fapi&host=front.test",
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=httpupgrade&security=tls&sni=node.test&path=%2Fapi&host=front.test",
            "hy2://password@node.test:443,8443-8444?sni=node.test&pinSHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&obfs=salamander&obfs-password=mask",
        ];
        let mut configs: Vec<_> = uris
            .iter()
            .map(|uri| generate_share_link_config_with_http(uri, 10808, 10809).unwrap())
            .collect();
        if std::env::var_os("XRAY_LOCATION_ASSET").is_some() {
            let policies = [
                DomainPolicy {
                    domains: vec!["geosite:cn".into()],
                    target: DomainRouteTarget::Direct,
                },
                DomainPolicy {
                    domains: vec!["geoip:cn".into()],
                    target: DomainRouteTarget::Block,
                },
            ];
            configs.push(apply_profile_routing(&configs[0], &policies, true).unwrap());
        }
        for (index, config) in configs.iter().enumerate() {
            let path = std::env::temp_dir().join(format!(
                "net-manager-xray-test-{}-{index}.json",
                std::process::id()
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&path).unwrap();
            file.write_all(&serde_json::to_vec(&config).unwrap())
                .unwrap();
            drop(file);
            let result = std::process::Command::new(&binary)
                .args(["run", "-test", "-config"])
                .arg(&path)
                .output();
            std::fs::remove_file(&path).unwrap();
            assert!(
                result.unwrap().status.success(),
                "Xray rejected generated config {index}"
            );
        }
    }

    #[test]
    fn empty_policies_return_unchanged_clone() {
        let base = json!({"anything": [1, 2, 3]});
        let result = apply_domain_policies(&base, &[]).unwrap();
        assert_eq!(result, base);
    }

    #[test]
    fn geo_rules_precede_private_lan_preset_and_existing_rules() {
        let mut base = generate_share_link_config_with_http(WS_TLS_URL, 10808, 10809).unwrap();
        base["routing"]["rules"] =
            json!([{"type":"field","domain":["domain:existing.test"],"outboundTag":"proxy"}]);
        let policies = [
            DomainPolicy {
                domains: vec!["geosite:cn".into()],
                target: DomainRouteTarget::Direct,
            },
            DomainPolicy {
                domains: vec!["geoip:us".into()],
                target: DomainRouteTarget::Block,
            },
        ];
        let config = apply_profile_routing(&base, &policies, true).unwrap();
        let rules = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0]["domain"], json!(["geosite:cn"]));
        assert_eq!(rules[0]["outboundTag"], "direct");
        assert_eq!(rules[1]["ip"], json!(["geoip:us"]));
        assert!(rules[1].get("domain").is_none());
        let block = rules[1]["outboundTag"].as_str().unwrap();
        assert_eq!(
            config["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|outbound| outbound["tag"] == block)
                .unwrap()["protocol"],
            "blackhole"
        );
        assert_eq!(rules[2]["ip"][0], "10.0.0.0/8");
        assert_eq!(rules[2]["outboundTag"], "direct");
        assert_eq!(rules[3]["domain"], json!(["domain:existing.test"]));
    }

    #[test]
    fn comments_and_blank_selectors_are_ignored() {
        let policies = [DomainPolicy {
            domains: vec![
                "# custom".into(),
                "".into(),
                "   ".into(),
                "domain:example.com".into(),
            ],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base_config(), &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["domain"], json!(["domain:example.com"]));
        assert_eq!(rules[0]["outboundTag"], "direct");
    }

    #[test]
    fn comment_only_policy_emits_no_rule() {
        let policies = [DomainPolicy {
            domains: vec!["# just a note".into()],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base_config(), &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert!(rules.iter().all(|rule| rule["domain"]
            .as_array()
            .map(|d| !d.iter().any(|v| v == "# just a note"))
            .unwrap_or(true)));
    }

    #[test]
    fn bare_ip_and_cidr_selectors_go_to_ip_rules() {
        let policies = [DomainPolicy {
            domains: vec![
                "203.0.113.10".into(),
                "198.51.100.0/24".into(),
                "2001:db8::/32".into(),
            ],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base_config(), &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        let ip_rule = rules
            .iter()
            .find(|rule| rule.get("ip").is_some())
            .expect("ip rule emitted");
        assert_eq!(
            ip_rule["ip"],
            json!(["203.0.113.10", "198.51.100.0/24", "2001:db8::/32"])
        );
        assert_eq!(ip_rule["outboundTag"], "direct");
    }

    #[test]
    fn invalid_geo_selectors_do_not_leak_input() {
        for selector in [
            "geosite:secret/../cn",
            "geoip:secret/../cn",
            "geoip:",
            "geosite:",
        ] {
            let policies = [DomainPolicy {
                domains: vec![selector.into()],
                target: DomainRouteTarget::Proxy,
            }];
            let err = apply_profile_routing(&base_config(), &policies, false).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(!err.to_string().contains("secret"));
            assert!(!err.to_string().contains(selector));
        }
    }

    fn base_config() -> Value {
        generate_vless_config(WS_TLS_URL, 10808).unwrap()
    }

    #[test]
    fn policies_prepend_rules_and_map_outbound_tags() {
        let mut base = base_config();
        base["routing"]["rules"] =
            json!([{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]);
        let policies = [
            DomainPolicy {
                domains: vec![" ads.example ".into(), "tracker.io".into()],
                target: DomainRouteTarget::Direct,
            },
            DomainPolicy {
                domains: vec!["example.com".into()],
                target: DomainRouteTarget::Proxy,
            },
        ];
        let result = apply_domain_policies(&base, &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(
            rules[0],
            json!({"type": "field", "domain": ["ads.example", "tracker.io"], "outboundTag": "direct"})
        );
        assert_eq!(
            rules[1],
            json!({"type": "field", "domain": ["example.com"], "outboundTag": "proxy"})
        );
        assert_eq!(rules[2]["ip"], json!(["geoip:private"]));
    }

    #[test]
    fn policies_do_not_mutate_input() {
        let base = base_config();
        let snapshot = base.clone();
        let policies = [DomainPolicy {
            domains: vec!["example.com".into()],
            target: DomainRouteTarget::Direct,
        }];
        apply_domain_policies(&base, &policies).unwrap();
        assert_eq!(base, snapshot);
    }

    #[test]
    fn missing_outbound_tags_are_assigned_uniquely() {
        let mut base = base_config();
        base["outbounds"][0].as_object_mut().unwrap().remove("tag");
        base["outbounds"][1].as_object_mut().unwrap().remove("tag");
        base["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"tag": "network-orchestrator-proxy", "protocol": "blackhole"}));

        let policies = [
            DomainPolicy {
                domains: vec!["a.com".into()],
                target: DomainRouteTarget::Proxy,
            },
            DomainPolicy {
                domains: vec!["b.com".into()],
                target: DomainRouteTarget::Direct,
            },
        ];
        let result = apply_domain_policies(&base, &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], "network-orchestrator-proxy-2");
        assert_eq!(rules[1]["outboundTag"], "network-orchestrator-direct");
        assert_eq!(
            result["outbounds"][0]["tag"],
            "network-orchestrator-proxy-2"
        );
        assert_eq!(result["outbounds"][1]["tag"], "network-orchestrator-direct");
    }

    #[test]
    fn direct_outbound_injected_when_absent() {
        let mut base = base_config();
        base["outbounds"]
            .as_array_mut()
            .unwrap()
            .retain(|o| o["protocol"] != "freedom");
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base, &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], "network-orchestrator-direct");
        let injected = result["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["protocol"] == "freedom")
            .unwrap();
        assert_eq!(injected["tag"], "network-orchestrator-direct");
    }

    #[test]
    fn proxy_policy_without_proxy_outbound_rejects() {
        let base = json!({
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": []}
        });
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Proxy,
        }];
        assert_eq!(
            apply_domain_policies(&base, &policies).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn malformed_routing_or_rules_rejects() {
        for bad in [
            json!({"outbounds": [{"protocol": "vless"}], "routing": "nope"}),
            json!({"outbounds": [{"protocol": "vless"}], "routing": {"rules": "nope"}}),
        ] {
            let policies = [DomainPolicy {
                domains: vec!["a.com".into()],
                target: DomainRouteTarget::Proxy,
            }];
            assert_eq!(
                apply_domain_policies(&bad, &policies).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{bad}"
            );
        }
    }

    #[test]
    fn outbound_without_protocol_is_not_eligible_proxy() {
        let base = json!({
            "outbounds": [
                {"tag": "no-protocol"},
                {"tag": "null-protocol", "protocol": null},
                {"tag": "blank-protocol", "protocol": "   "},
                {"tag": "direct", "protocol": "freedom"}
            ],
            "routing": {"rules": []}
        });
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Proxy,
        }];
        assert_eq!(
            apply_domain_policies(&base, &policies).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn injected_direct_tag_avoids_occupied_base_tag() {
        let base = json!({
            "outbounds": [
                {"tag": "network-orchestrator-direct", "protocol": "blackhole"},
                {"tag": "p", "protocol": "vless"}
            ]
        });
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base, &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], "network-orchestrator-direct-2");
        let injected = result["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["protocol"] == "freedom")
            .unwrap();
        assert_eq!(injected["tag"], "network-orchestrator-direct-2");
        assert_eq!(result["outbounds"][0]["tag"], "network-orchestrator-direct");
    }

    #[test]
    fn duplicate_selected_tag_is_reassigned() {
        let base = json!({
            "outbounds": [
                {"tag": "dup", "protocol": "vless"},
                {"tag": "dup", "protocol": "vless"}
            ]
        });
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Proxy,
        }];
        let result = apply_domain_policies(&base, &policies).unwrap();
        let rules = result["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outboundTag"], "network-orchestrator-proxy");
        assert_eq!(result["outbounds"][0]["tag"], "network-orchestrator-proxy");
        assert_eq!(result["outbounds"][1]["tag"], "dup");
    }

    #[test]
    fn routing_created_when_absent() {
        let base = json!({"outbounds": [{"tag": "p", "protocol": "vless"}]});
        let policies = [DomainPolicy {
            domains: vec!["a.com".into()],
            target: DomainRouteTarget::Proxy,
        }];
        let result = apply_domain_policies(&base, &policies).unwrap();
        assert_eq!(
            result["routing"]["rules"][0],
            json!({"type": "field", "domain": ["a.com"], "outboundTag": "p"})
        );
    }

    #[test]
    fn apply_tun_inbound_replaces_socks_with_tun() {
        let base = json!({
            "inbounds": [{"tag": "socks-in", "protocol": "socks", "port": 10808}],
            "outbounds": [{"tag": "proxy", "protocol": "vless"}],
        });
        let result = apply_tun_inbound(&base, None, None).unwrap();
        assert_eq!(result["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(result["inbounds"][0]["protocol"], "tun");
        assert_eq!(result["inbounds"][0]["tag"], "tun-in");
        assert_eq!(
            result["inbounds"][0]["settings"]["interfaceName"],
            "xray-tun"
        );
        assert_eq!(result["inbounds"][0]["settings"]["ip"], "172.19.0.1/30");
        assert_eq!(result["inbounds"][0]["settings"]["mtu"], 1500);
        // Outbounds preserved.
        assert_eq!(result["outbounds"][0]["tag"], "proxy");
    }

    #[test]
    fn apply_tun_inbound_enables_traffic_sniffing() {
        let base = json!({"outbounds": [{"tag": "proxy", "protocol": "vless"}]});
        let result = apply_tun_inbound(&base, None, None).unwrap();
        // Without sniffing, TUN traffic only carries destination IPs and
        // domain/geosite routing rules can never match.
        assert_eq!(result["inbounds"][0]["sniffing"]["enabled"], true);
        assert_eq!(
            result["inbounds"][0]["sniffing"]["destOverride"],
            json!(["http", "tls", "quic"])
        );
    }

    #[test]
    fn apply_tun_inbound_uses_custom_interface_and_ip() {
        let base = json!({"outbounds": [{"tag": "proxy", "protocol": "vless"}]});
        let result = apply_tun_inbound(&base, Some("my-tun"), Some("10.5.0.1/24")).unwrap();
        assert_eq!(result["inbounds"][0]["settings"]["interfaceName"], "my-tun");
        assert_eq!(result["inbounds"][0]["settings"]["ip"], "10.5.0.1/24");
    }

    #[test]
    fn apply_tun_inbound_adds_inbound_when_none_exists() {
        let base = json!({"outbounds": [{"tag": "proxy", "protocol": "vless"}]});
        let result = apply_tun_inbound(&base, None, None).unwrap();
        assert_eq!(result["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(result["inbounds"][0]["protocol"], "tun");
    }

    #[test]
    fn has_tun_inbound_detects_tun_protocol() {
        let with_tun = json!({"inbounds": [{"protocol": "tun"}]});
        assert!(has_tun_inbound(&with_tun));
        let with_socks = json!({"inbounds": [{"protocol": "socks"}]});
        assert!(!has_tun_inbound(&with_socks));
        let no_inbounds = json!({"outbounds": []});
        assert!(!has_tun_inbound(&no_inbounds));
    }

    #[test]
    fn percent_decode_does_not_panic_on_non_ascii_after_percent() {
        assert_eq!(percent_decode("Speed 5%-Москва"), "Speed 5%-Москва");
        assert_eq!(percent_decode("%М"), "%М");
        assert_eq!(
            share_link_name("vless://id@example.com:443#Speed 5%-Москва").as_deref(),
            Some("Speed 5%-Москва")
        );
    }

    #[test]
    fn percent_decode_handles_trailing_and_invalid_escapes() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("a%4"), "a%4");
        assert_eq!(percent_decode("%+1"), "%+1");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("a%41"), "aA");
        assert_eq!(percent_decode("%D0%9C%D0%BE"), "Мо");
        assert_eq!(percent_decode("%FF"), "\u{FFFD}");
    }
}
