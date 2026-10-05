use crate::models::{
    DomainPolicy, DomainRouteTarget, XrayDnsConfig, XrayDnsRoute, XrayDnsServer, XrayDomainMatcher,
    XrayDomainStrategy,
};
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

/// Subscription entries that arrive as complete Xray JSON configs (Remnawave
/// and similar panels serve this format to v2rayN) are stored next to share
/// links as `xray-json:<base64url>` so switching, refresh and naming reuse the
/// share-link paths unchanged.
pub const XRAY_JSON_PREFIX: &str = "xray-json:";
/// Only routing-relevant sections survive; `log` (arbitrary file paths), `api`,
/// `stats`, `inbounds` and anything else from the untrusted panel is dropped.
const XRAY_JSON_KEEP: [&str; 6] = [
    "outbounds",
    "routing",
    "dns",
    "policy",
    "observatory",
    "burstObservatory",
];

pub fn xray_json_entry(config: &Value) -> io::Result<String> {
    use base64::Engine;
    let object = config
        .as_object()
        .ok_or_else(|| invalid_input("xray config must be an object"))?;
    if object
        .get("outbounds")
        .and_then(Value::as_array)
        .is_none_or(|outbounds| outbounds.is_empty())
    {
        return Err(invalid_input("xray config has no outbounds"));
    }
    let mut kept = Map::new();
    for key in XRAY_JSON_KEEP {
        if let Some(value) = object.get(key) {
            kept.insert(key.into(), value.clone());
        }
    }
    if let Some(remarks) = object.get("remarks").and_then(Value::as_str) {
        kept.insert("remarks".into(), json!(remarks));
    }
    let bytes = serde_json::to_vec(&Value::Object(kept))
        .map_err(|_| invalid_input("xray config could not be encoded"))?;
    Ok(format!(
        "{XRAY_JSON_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    ))
}

fn decode_xray_json_entry(uri: &str) -> io::Result<Map<String, Value>> {
    use base64::Engine;
    let encoded = uri
        .trim()
        .strip_prefix(XRAY_JSON_PREFIX)
        .ok_or_else(|| invalid_input("not an xray-json entry"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| invalid_input("invalid xray-json entry"))?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(invalid_input("invalid xray-json entry")),
    }
}

fn generate_xray_json_config(uri: &str, socks_port: u16) -> io::Result<Value> {
    if socks_port == 0 {
        return Err(invalid_input("socks port must be nonzero"));
    }
    let entry = decode_xray_json_entry(uri)?;
    let mut config = Map::new();
    for key in XRAY_JSON_KEEP {
        if let Some(value) = entry.get(key) {
            config.insert(key.into(), value.clone());
        }
    }
    if config
        .get("outbounds")
        .and_then(Value::as_array)
        .is_none_or(|outbounds| outbounds.is_empty())
    {
        return Err(invalid_input("xray config has no outbounds"));
    }
    config.insert("log".into(), json!({ "loglevel": "warning" }));
    config.insert(
        "inbounds".into(),
        json!([{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": { "udp": true },
        }]),
    );
    Ok(Value::Object(config))
}

pub fn generate_share_link_config(uri: &str, socks_port: u16) -> io::Result<Value> {
    if uri.trim().starts_with(XRAY_JSON_PREFIX) {
        return generate_xray_json_config(uri, socks_port);
    }
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

/// Short protocol label for an endpoint, e.g. `VLESS · Reality` or
/// `Hysteria2`; for full Xray JSON entries it is read from the first outbound.
pub fn endpoint_protocol(uri: &str) -> Option<String> {
    let name = |scheme: &str| match scheme {
        "vless" => "VLESS".to_string(),
        "hy2" | "hysteria2" => "Hysteria2".to_string(),
        "trojan" => "Trojan".to_string(),
        "vmess" => "VMess".to_string(),
        "ss" | "shadowsocks" => "Shadowsocks".to_string(),
        other => other.to_uppercase(),
    };
    let mut label;
    let (security, transport) = if uri.trim().starts_with(XRAY_JSON_PREFIX) {
        let entry = decode_xray_json_entry(uri).ok()?;
        let outbound = entry.get("outbounds")?.as_array()?.first()?.clone();
        label = name(outbound.get("protocol")?.as_str()?);
        let stream = outbound
            .get("streamSettings")
            .cloned()
            .unwrap_or(Value::Null);
        (
            stream["security"].as_str().map(str::to_string),
            stream["network"].as_str().map(str::to_string),
        )
    } else {
        let url = reqwest::Url::parse(uri.trim()).ok()?;
        label = name(url.scheme());
        let query = |key: &str| {
            url.query_pairs()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.into_owned())
        };
        (query("security"), query("type"))
    };
    match security.as_deref() {
        Some("reality") => label.push_str(" · Reality"),
        Some("tls") => label.push_str(" · TLS"),
        _ => {}
    }
    if let Some(transport) = transport.filter(|t| t != "tcp" && t != "none" && t != "raw") {
        label.push_str(&format!(" · {}", transport.to_uppercase()));
    }
    Some(label)
}

pub fn share_link_name(uri: &str) -> Option<String> {
    if uri.trim().starts_with(XRAY_JSON_PREFIX) {
        return decode_xray_json_entry(uri)
            .ok()
            .and_then(|entry| entry.get("remarks")?.as_str().map(str::to_string))
            .filter(|name| !name.trim().is_empty());
    }
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

/// Profile-level routing/DNS options applied alongside the domain policy
/// lists: strategy, matcher, split DNS, static hosts and fake-DNS capture.
#[derive(Debug, Default)]
pub struct ProfileRoutingOptions {
    pub private_lan_direct: bool,
    /// `routing.domainStrategy` override (`None` keeps the base value).
    pub domain_strategy: Option<XrayDomainStrategy>,
    /// `routing.domainMatcher` override.
    pub domain_matcher: Option<XrayDomainMatcher>,
    /// Profile `dns` section policy.
    pub dns: XrayDnsConfig,
}

pub fn apply_domain_policies(base: &Value, policies: &[DomainPolicy]) -> io::Result<Value> {
    apply_profile_routing(base, policies, &ProfileRoutingOptions::default())
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
pub(crate) fn classify_routing_selector(
    selector: &str,
) -> io::Result<Option<(&'static str, String)>> {
    let selector = selector.trim();
    if selector.is_empty() || selector.starts_with('#') {
        return Ok(None);
    }
    if let Some(category) = selector.strip_prefix("geosite:") {
        // `category@attr` filters records by attribute (`@cn`, `*`
        // wildcards allowed); a single `@` separates name and attribute.
        let (name, attr) = match category.split_once('@') {
            Some((name, attr)) => (name, Some(attr)),
            None => (category, None),
        };
        let valid_name = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        let valid_attr = attr.is_none_or(|attr| {
            !attr.is_empty()
                && attr.len() <= 32
                && attr.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*' | b'.')
                })
        });
        if !valid_name || !valid_attr {
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

const DNS_SCHEMES: &[&str] = &["udp", "tcp", "tls", "https", "https+local", "quic+local"];

pub fn validate_dns_config(dns: &XrayDnsConfig) -> io::Result<()> {
    for server in &dns.servers {
        let address = server.address.trim();
        if address.is_empty()
            || address.len() > 256
            || !address.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(invalid_input("invalid dns server address"));
        }
        match address {
            "localhost" => {}
            "fakedns" if dns.fake_dns => {}
            "fakedns" => return Err(invalid_input("fakedns server requires fakeDns")),
            _ => {
                if let Some((scheme, _)) = address.split_once("://") {
                    if !DNS_SCHEMES.contains(&scheme) {
                        return Err(invalid_input("unsupported dns server scheme"));
                    }
                }
                if dns_server_host(address).is_none() {
                    return Err(invalid_input("invalid dns server address"));
                }
            }
        }
        if server.port == Some(0) {
            return Err(invalid_input("dns server port must be nonzero"));
        }
        for selector in &server.domains {
            // dns.servers `domains` takes domain matchers only — geosite
            // categories and literal domain forms, never IP selectors.
            if matches!(classify_routing_selector(selector)?, Some(("ip", _))) {
                return Err(invalid_input("dns server domains must be domain selectors"));
            }
        }
    }
    for (name, values) in &dns.hosts {
        let name = name.trim();
        if name.is_empty() || name.len() > 253 || !name.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(invalid_input("invalid dns hosts entry"));
        }
        if values.is_empty() {
            return Err(invalid_input("dns hosts entry must map to an address"));
        }
        for value in values {
            let value = value.trim();
            let ok = value.parse::<IpAddr>().is_ok()
                || (!value.is_empty()
                    && value.len() <= 253
                    && value.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*')
                    }));
            if !ok {
                return Err(invalid_input("invalid dns hosts value"));
            }
        }
    }
    Ok(())
}

/// Host part of a DNS server entry, dropping scheme/userinfo/port/path.
/// `udp://` and bare values share the same `host[:port]` shape.
fn dns_server_host(address: &str) -> Option<&str> {
    let rest = match address.split_once("://") {
        Some((_, rest)) => rest,
        None => address,
    };
    let host = rest.split(['/', '?', '#']).next()?.trim();
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = if let Some(inner) = host.strip_prefix('[') {
        inner.split(']').next()?
    } else if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or(host)
    } else {
        host
    };
    (!host.is_empty()).then_some(host)
}

/// Resolver hosts that must stay reachable through the physical uplink when
/// the tunnel fully captures their family — every configured resolver that
/// is not pinned to the proxy outbound (a `Proxy` resolver is meant to be
/// reached *inside* the tunnel, so bypassing it would defeat the point).
/// Returned as a deduped list of literal IPs or resolvable names.
pub fn dns_bypass_hosts(dns: &XrayDnsConfig) -> Vec<String> {
    let mut hosts = Vec::new();
    for server in &dns.servers {
        if matches!(server.route, crate::models::XrayDnsRoute::Proxy) {
            continue;
        }
        let Some(host) = dns_server_host(&server.address) else {
            continue;
        };
        if matches!(host, "localhost" | "fakedns") || hosts.iter().any(|item| item == host) {
            continue;
        }
        hosts.push(host.to_string());
    }
    hosts
}

/// The routable destination of a DNS server entry: `None` for
/// `localhost`/`fakedns`, which Xray handles internally.
pub(crate) fn dns_server_route_target(address: &str) -> Option<(&'static str, String)> {
    let host = dns_server_host(address)?;
    if matches!(host, "localhost" | "fakedns") {
        return None;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(("ip", ip.to_string()));
    }
    Some(("domain", host.to_string()))
}

/// Block-target selectors that can also be null-routed through the DNS
/// `hosts` table — plain names and `domain:`/`full:` literals only (a
/// geosite/keyword/regexp matcher cannot be expressed as a hosts key).
fn dns_hosts_key(selector: &str) -> Option<String> {
    let selector = selector.trim();
    if selector.is_empty() || selector.starts_with('#') {
        return None;
    }
    for prefix in ["domain:", "full:"] {
        if let Some(rest) = selector.strip_prefix(prefix) {
            let rest = rest.trim();
            return (!rest.is_empty()).then(|| rest.to_string());
        }
    }
    if selector.contains(':') || selector.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(selector.to_string())
}

fn dns_server_entry(server: &XrayDnsServer, policies: &[DomainPolicy]) -> Value {
    let mut entry = Map::new();
    entry.insert("address".into(), json!(server.address.trim()));
    if let Some(port) = server.port {
        entry.insert("port".into(), json!(port));
    }
    let mut domains = server.domains.clone();
    // Split-DNS default: a resolver pinned to an outbound also answers the
    // domains routed through it — remote/proxy lists and domestic/direct
    // lists stay on their own resolver.
    if domains.is_empty() {
        let target = match server.route {
            XrayDnsRoute::Proxy => Some(DomainRouteTarget::Proxy),
            XrayDnsRoute::Direct => Some(DomainRouteTarget::Direct),
            XrayDnsRoute::None => None,
        };
        if let Some(target) = target {
            for policy in policies.iter().filter(|policy| policy.target == target) {
                for selector in &policy.domains {
                    if let Ok(Some(("domain", value))) = classify_routing_selector(selector) {
                        domains.push(value);
                    }
                }
            }
        }
    }
    if !domains.is_empty() {
        entry.insert("domains".into(), json!(domains));
    }
    if server.skip_fallback {
        entry.insert("skipFallback".into(), json!(true));
    }
    Value::Object(entry)
}

fn dns_servers_json(dns: &XrayDnsConfig, policies: &[DomainPolicy]) -> Vec<Value> {
    let mut servers = Vec::new();
    if dns.fake_dns {
        servers.push(json!("fakedns"));
    }
    for server in &dns.servers {
        servers.push(dns_server_entry(server, policies));
    }
    // Xray walks servers in order and domain-bound entries only answer
    // their own list — when nothing is left as a catch-all, mirror the
    // first proxy-routed (else first) server as a bare fallback.
    let has_catch_all = servers
        .iter()
        .any(|s| s.as_str().is_some() || s.get("domains").is_none());
    if !has_catch_all {
        let catch_all = dns
            .servers
            .iter()
            .find(|server| server.route == XrayDnsRoute::Proxy)
            .or_else(|| dns.servers.first());
        if let Some(catch_all) = catch_all {
            servers.insert(
                usize::from(dns.fake_dns),
                json!({"address": catch_all.address.trim()}),
            );
        }
    }
    servers
}

pub fn apply_profile_routing(
    base: &Value,
    policies: &[DomainPolicy],
    options: &ProfileRoutingOptions,
) -> io::Result<Value> {
    let dns_active = !options.dns.is_empty();
    let rules_active = !policies.is_empty() || options.private_lan_direct || dns_active;
    if !rules_active && options.domain_strategy.is_none() && options.domain_matcher.is_none() {
        return Ok(base.clone());
    }
    validate_routing_policy_selectors(policies)?;
    validate_dns_config(&options.dns)?;
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
        .any(|policy| policy.target == DomainRouteTarget::Proxy)
        || options
            .dns
            .servers
            .iter()
            .any(|server| server.route == XrayDnsRoute::Proxy);
    let needs_direct = options.private_lan_direct
        || policies
            .iter()
            .any(|policy| policy.target == DomainRouteTarget::Direct)
        || options
            .dns
            .servers
            .iter()
            .any(|server| server.route == XrayDnsRoute::Direct);
    // Any customised rule set also drops multicast, so the blackhole
    // outbound is always required once rules are emitted.
    let needs_block = rules_active;

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

    let dns_tag = if dns_active {
        let index = match outbounds
            .iter()
            .position(|outbound| outbound["protocol"].as_str() == Some("dns"))
        {
            Some(index) => index,
            None => {
                outbounds.push(json!({ "protocol": "dns" }));
                outbounds.len() - 1
            }
        };
        Some(resolve_outbound_tag(
            &mut outbounds[index],
            "dns-out",
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
    if let Some(strategy) = options.domain_strategy {
        routing.insert("domainStrategy".into(), json!(strategy.as_xray_str()));
    }
    if let Some(matcher) = options.domain_matcher {
        routing.insert("domainMatcher".into(), json!(matcher.as_xray_str()));
    }
    let rules = routing.entry("rules").or_insert_with(|| json!([]));
    let rules = rules
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config routing.rules must be an array"))?;

    let mut merged = Vec::new();
    // DNS capture comes first: port-53 traffic is answered by the dns
    // outbound so static hosts / split resolvers / fake-DNS apply even to
    // plain system resolvers (TUN mode).
    if let Some(tag) = dns_tag.as_deref() {
        merged.push(json!({"type": "field", "port": "53", "outboundTag": tag}));
    }
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
    // Keep each resolver reachable on its own side of the tunnel: the
    // resolver pinned to `proxy` must not resolve via the local network and
    // vice versa.
    for server in &options.dns.servers {
        let tag = match server.route {
            XrayDnsRoute::Proxy => proxy_tag.as_deref().unwrap_or_default(),
            XrayDnsRoute::Direct => direct_tag.as_deref().unwrap_or_default(),
            XrayDnsRoute::None => continue,
        };
        match dns_server_route_target(&server.address) {
            Some(("ip", value)) => {
                merged.push(json!({"type": "field", "ip": [value], "outboundTag": tag}));
            }
            Some(("domain", value)) => {
                merged.push(json!({"type": "field", "domain": [value], "outboundTag": tag}));
            }
            _ => {}
        }
    }
    // Multicast is never routed through the tunnel — emit only when some
    // other rule set exists so a comment-only policy stays a no-op.
    if !merged.is_empty() || options.private_lan_direct {
        merged.push(json!({
            "type": "field",
            "ip": ["224.0.0.0/4", "ff00::/8"],
            "outboundTag": block_tag.as_deref().unwrap_or_default(),
        }));
    }
    if options.private_lan_direct {
        merged.push(json!({
            "type": "field",
            "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"],
            "outboundTag": direct_tag.as_deref().unwrap_or_default(),
        }));
    }
    merged.append(rules);
    *rules = merged;

    if dns_active {
        let mut hosts = Map::new();
        // Blocked literal domains are also null-routed at the resolver —
        // a client ignoring routing still gets a dead answer.
        for policy in policies
            .iter()
            .filter(|policy| policy.target == DomainRouteTarget::Block)
        {
            for selector in &policy.domains {
                if let Some(host) = dns_hosts_key(selector) {
                    hosts.entry(host).or_insert_with(|| json!(["127.0.0.1"]));
                }
            }
        }
        // Explicit host overrides win over the generated null routes.
        for (name, values) in &options.dns.hosts {
            hosts.insert(name.clone(), json!(values));
        }
        let mut dns_obj = Map::new();
        if !hosts.is_empty() {
            dns_obj.insert("hosts".into(), Value::Object(hosts));
        }
        let servers = dns_servers_json(&options.dns, policies);
        if !servers.is_empty() {
            dns_obj.insert("servers".into(), json!(servers));
        }
        if let Some(strategy) = options.dns.query_strategy {
            dns_obj.insert("queryStrategy".into(), json!(strategy.as_xray_str()));
        }
        root.insert("dns".into(), Value::Object(dns_obj));

        if options.dns.fake_dns {
            root.insert(
                "fakedns".into(),
                json!([{ "ipPool": "198.18.0.0/16", "poolSize": 65535 }]),
            );
            // Sniffing must translate fake pool answers back to the real
            // name on every inbound that sees them.
            if let Some(inbounds) = root.get_mut("inbounds").and_then(Value::as_array_mut) {
                for inbound in inbounds.iter_mut() {
                    let sniffing = inbound
                        .as_object_mut()
                        .map(|obj| obj.entry("sniffing").or_insert_with(|| json!({})))
                        .and_then(|s| s.as_object_mut());
                    let Some(sniffing) = sniffing else { continue };
                    sniffing.insert("enabled".into(), json!(true));
                    let overrides = sniffing.entry("destOverride").or_insert_with(|| json!([]));
                    if let Some(list) = overrides.as_array_mut() {
                        if !list.iter().any(|v| v == "fakedns") {
                            list.push(json!("fakedns"));
                        }
                    }
                }
            }
        }
    }
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

    // TUN traffic arrives as bare IP packets; sniffing recovers the TLS
    // SNI / HTTP Host so domain and geosite routing rules can match. With
    // fake-DNS enabled it also translates pool answers back to real names.
    let mut dest_override = vec!["http", "tls", "quic"];
    if base["fakedns"]
        .as_array()
        .is_some_and(|fakedns| !fakedns.is_empty())
    {
        dest_override.push("fakedns");
    }

    let tun_inbound = json!({
        "tag": "tun-in",
        "protocol": "tun",
        "settings": {
            "interfaceName": interface_name.unwrap_or("xray-tun"),
            "ip": ip.unwrap_or("172.19.0.1/30"),
            "mtu": 1500,
        },
        "sniffing": {
            "enabled": true,
            "destOverride": dest_override,
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
    #[test]
    fn endpoint_protocol_labels_links_and_json_entries() {
        assert_eq!(
            endpoint_protocol("vless://id@h:443?security=reality&type=grpc#A").as_deref(),
            Some("VLESS · Reality · GRPC")
        );
        assert_eq!(
            endpoint_protocol("hy2://p@h:443#B").as_deref(),
            Some("Hysteria2")
        );
        let entry = xray_json_entry(&json!({
            "remarks": "NL",
            "outbounds": [{"protocol": "vless", "streamSettings": {"network": "xhttp", "security": "reality"}}]
        }))
        .unwrap();
        assert_eq!(
            endpoint_protocol(&entry).as_deref(),
            Some("VLESS · Reality · XHTTP")
        );
    }

    /// Opt-in pipeline probe: XRAY_PANEL_CONFIG=<managed config>,
    /// XRAY_PROFILES=<profiles.json>, XRAY_PROFILE_ID=<id>, XRAY_PROC_OUT=<out>
    /// applies `apply_profile_routing` exactly like the TUN connect path and
    /// writes the wire-format config to XRAY_PROC_OUT for daemon-side tests.
    /// Skips silently unless all four vars are set.
    #[test]
    fn env_gated_apply_profile_routing_dumps_wire_config() {
        let (Ok(config_path), Ok(profiles_path), Ok(profile_id), Ok(out_path)) = (
            std::env::var("XRAY_PANEL_CONFIG"),
            std::env::var("XRAY_PROFILES"),
            std::env::var("XRAY_PROFILE_ID"),
            std::env::var("XRAY_PROC_OUT"),
        ) else {
            return;
        };
        let base: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&config_path).expect("read panel config"),
        )
        .expect("parse panel config");
        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&profiles_path).expect("read profiles"))
                .expect("parse profiles");
        let profiles: Vec<crate::models::Profile> =
            serde_json::from_value(document["profiles"].clone()).expect("parse profile list");
        let profile = profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .expect("profile id");
        let processed = apply_profile_routing(
            &base,
            &profile.domain_policies,
            &ProfileRoutingOptions {
                private_lan_direct: profile.private_lan_direct,
                domain_strategy: profile.xray_domain_strategy,
                domain_matcher: profile.xray_domain_matcher,
                dns: profile.xray_dns.clone(),
            },
        )
        .expect("apply_profile_routing");
        std::fs::write(
            &out_path,
            serde_json::to_string(&processed).expect("encode processed config"),
        )
        .expect("write processed config");
    }

    /// Opt-in: XRAY_TEST_BIN=/path/to/xray validates a panel-style JSON entry.
    #[test]
    fn xray_accepts_generated_panel_json_config_when_binary_supplied() {
        let Ok(binary) = std::env::var("XRAY_TEST_BIN") else {
            return;
        };
        let panel = json!({
            "remarks": "🇳🇱 Netherlands",
            "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
            "inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks"}],
            "outbounds": [
                {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "nl.example.test", "port": 443, "users": [{"id": "00000000-0000-4000-8000-000000000000", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
                 "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "www.example.test", "fingerprint": "chrome", "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "shortId": "0123"}}},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}
            ],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"}
            ]}
        });
        let entry = xray_json_entry(&panel).unwrap();
        let config = generate_share_link_config_with_http(&entry, 20808, 20809).unwrap();
        let mut child = std::process::Command::new(&binary)
            .args(["run", "-test", "-config", "stdin:"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(config.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    fn panel_config(name: &str) -> Value {
        json!({
            "remarks": name,
            "log": {"loglevel": "debug", "access": "/tmp/stolen.log"},
            "api": {"tag": "api", "services": ["HandlerService"]},
            "stats": {},
            "inbounds": [{"tag": "socks", "port": 10808, "listen": "0.0.0.0", "protocol": "socks"}],
            "outbounds": [
                {"tag": "proxy", "protocol": "vless", "settings": {"vnext": []}},
                {"tag": "direct", "protocol": "freedom"},
            ],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]},
            "dns": {"servers": ["1.1.1.1"]},
        })
    }

    #[test]
    fn xray_json_entry_keeps_its_remarks_as_the_endpoint_name() {
        let entry = xray_json_entry(&panel_config("🇳🇱 Netherlands")).unwrap();
        assert!(entry.starts_with(XRAY_JSON_PREFIX));
        assert!(!entry.contains('#') && !entry.contains('\n'));
        assert_eq!(share_link_name(&entry).as_deref(), Some("🇳🇱 Netherlands"));
        assert!(xray_json_entry(&json!({"remarks": "x"})).is_err());
    }

    #[test]
    fn xray_json_entry_config_uses_our_listeners_and_drops_unsafe_sections() {
        let entry = xray_json_entry(&panel_config("DE")).unwrap();
        let config = generate_share_link_config_with_http(&entry, 20808, 20809).unwrap();
        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[0]["listen"], "127.0.0.1");
        assert_eq!(inbounds[0]["port"], 20808);
        assert_eq!(inbounds[1]["port"], 20809);
        assert_eq!(config["log"], json!({"loglevel": "warning"}));
        for dropped in ["api", "stats", "remarks"] {
            assert!(config.get(dropped).is_none(), "{dropped} kept");
        }
        assert_eq!(config["outbounds"][0]["tag"], "proxy");
        assert_eq!(config["routing"]["domainStrategy"], "IPIfNonMatch");
        assert_eq!(config["dns"]["servers"][0], "1.1.1.1");
    }

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
            configs.push(
                apply_profile_routing(
                    &configs[0],
                    &policies,
                    &ProfileRoutingOptions {
                        private_lan_direct: true,
                        ..ProfileRoutingOptions::default()
                    },
                )
                .unwrap(),
            );
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
        let config = apply_profile_routing(
            &base,
            &policies,
            &ProfileRoutingOptions {
                private_lan_direct: true,
                ..ProfileRoutingOptions::default()
            },
        )
        .unwrap();
        let rules = config["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 5);
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
        assert_eq!(rules[2]["ip"], json!(["224.0.0.0/4", "ff00::/8"]));
        assert_eq!(rules[2]["outboundTag"], block);
        assert_eq!(rules[3]["ip"][0], "10.0.0.0/8");
        assert_eq!(rules[3]["outboundTag"], "direct");
        assert_eq!(rules[4]["domain"], json!(["domain:existing.test"]));
    }

    #[test]
    fn geosite_attribute_selectors_are_domain_rules() {
        let policies = [DomainPolicy {
            domains: vec!["geosite:category-ru@cdn".into(), "geosite:cn@*".into()],
            target: DomainRouteTarget::Direct,
        }];
        let result = apply_domain_policies(&base_config(), &policies).unwrap();
        assert_eq!(
            result["routing"]["rules"][0]["domain"],
            json!(["geosite:category-ru@cdn", "geosite:cn@*"])
        );
        for bad in ["geosite:@cn", "geosite:cat@", "geosite:a@b@c"] {
            let policies = [DomainPolicy {
                domains: vec![bad.into()],
                target: DomainRouteTarget::Direct,
            }];
            assert_eq!(
                apply_domain_policies(&base_config(), &policies)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "accepted {bad}"
            );
        }
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
            let err =
                apply_profile_routing(&base_config(), &policies, &ProfileRoutingOptions::default())
                    .unwrap_err();
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
        assert_eq!(rules.len(), 4);
        assert_eq!(
            rules[0],
            json!({"type": "field", "domain": ["ads.example", "tracker.io"], "outboundTag": "direct"})
        );
        assert_eq!(
            rules[1],
            json!({"type": "field", "domain": ["example.com"], "outboundTag": "proxy"})
        );
        assert_eq!(rules[2]["ip"], json!(["224.0.0.0/4", "ff00::/8"]));
        assert_eq!(rules[3]["ip"], json!(["geoip:private"]));
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

    fn dns_options(dns: XrayDnsConfig) -> ProfileRoutingOptions {
        ProfileRoutingOptions {
            dns,
            ..ProfileRoutingOptions::default()
        }
    }

    fn dns_server(address: &str, route: XrayDnsRoute) -> XrayDnsServer {
        XrayDnsServer {
            address: address.into(),
            port: None,
            domains: Vec::new(),
            skip_fallback: false,
            route,
        }
    }

    #[test]
    fn domain_strategy_and_matcher_override_base_values() {
        let config = apply_profile_routing(
            &base_config(),
            &[],
            &ProfileRoutingOptions {
                domain_strategy: Some(XrayDomainStrategy::IpIfNonMatch),
                domain_matcher: Some(XrayDomainMatcher::Mph),
                ..ProfileRoutingOptions::default()
            },
        )
        .unwrap();
        assert_eq!(config["routing"]["domainStrategy"], "IPIfNonMatch");
        assert_eq!(config["routing"]["domainMatcher"], "mph");
        // No rule set configured → no rules, no extra outbounds.
        assert_eq!(config["routing"]["rules"], json!([]));
    }

    #[test]
    fn split_dns_emits_section_servers_and_route_rules() {
        let mut dns = XrayDnsConfig {
            servers: vec![
                dns_server("https://8.8.8.8/dns-query", XrayDnsRoute::Proxy),
                dns_server("https://77.88.8.8/dns-query", XrayDnsRoute::Direct),
            ],
            query_strategy: Some(crate::models::XrayDnsQueryStrategy::UseIpv4),
            ..XrayDnsConfig::default()
        };
        dns.hosts
            .insert("lk.nalog.ru".into(), vec!["213.24.64.1".into()]);
        let config = apply_profile_routing(&base_config(), &[], &dns_options(dns)).unwrap();

        let rules = config["routing"]["rules"].as_array().unwrap();
        // port-53 capture, remote DNS → proxy, domestic DNS → direct,
        // multicast block.
        assert_eq!(rules[0]["port"], "53");
        let dns_tag = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["protocol"] == "dns")
            .unwrap()["tag"]
            .clone();
        assert_eq!(rules[0]["outboundTag"], dns_tag);
        assert_eq!(rules[1]["ip"], json!(["8.8.8.8"]));
        assert_eq!(rules[1]["outboundTag"], "proxy");
        assert_eq!(rules[2]["ip"], json!(["77.88.8.8"]));
        assert_eq!(rules[2]["outboundTag"], "direct");
        assert_eq!(rules[3]["ip"], json!(["224.0.0.0/4", "ff00::/8"]));

        assert_eq!(
            config["dns"]["hosts"]["lk.nalog.ru"],
            json!(["213.24.64.1"])
        );
        assert_eq!(config["dns"]["queryStrategy"], "UseIPv4");
        let servers = config["dns"]["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0]["address"], "https://8.8.8.8/dns-query");
        assert_eq!(servers[1]["address"], "https://77.88.8.8/dns-query");
    }

    #[test]
    fn route_bound_dns_servers_autobind_policy_domains() {
        let policies = [DomainPolicy {
            domains: vec!["geosite:youtube".into(), "domain:example.com".into()],
            target: DomainRouteTarget::Proxy,
        }];
        let dns = XrayDnsConfig {
            servers: vec![dns_server(
                "https://dns.google/dns-query",
                XrayDnsRoute::Proxy,
            )],
            ..XrayDnsConfig::default()
        };
        let config = apply_profile_routing(&base_config(), &policies, &dns_options(dns)).unwrap();
        let servers = config["dns"]["servers"].as_array().unwrap();
        // Bare catch-all comes first, then the domain-bound entry.
        assert_eq!(servers.len(), 2);
        assert_eq!(
            servers[0],
            json!({"address": "https://dns.google/dns-query"})
        );
        assert_eq!(servers[0].get("domains"), None);
        assert_eq!(
            servers[1]["domains"],
            json!(["geosite:youtube", "domain:example.com"])
        );
        // The resolver host itself is pinned to the proxy outbound.
        let rules = config["routing"]["rules"].as_array().unwrap();
        let dns_rule = rules
            .iter()
            .find(|rule| rule["domain"] == json!(["dns.google"]))
            .expect("dns server route rule");
        assert_eq!(dns_rule["outboundTag"], "proxy");
    }

    #[test]
    fn block_domains_are_null_routed_through_dns_hosts() {
        let policies = [DomainPolicy {
            domains: vec![
                "domain:ads.example".into(),
                "geosite:category-ads".into(),
                "full:telemetry.example".into(),
            ],
            target: DomainRouteTarget::Block,
        }];
        let mut dns = XrayDnsConfig {
            servers: vec![dns_server("8.8.8.8", XrayDnsRoute::None)],
            ..XrayDnsConfig::default()
        };
        // An explicit hosts entry beats the generated null route.
        dns.hosts
            .insert("telemetry.example".into(), vec!["10.0.0.7".into()]);
        let config = apply_profile_routing(&base_config(), &policies, &dns_options(dns)).unwrap();
        let hosts = &config["dns"]["hosts"];
        assert_eq!(hosts["ads.example"], json!(["127.0.0.1"]));
        assert_eq!(hosts["telemetry.example"], json!(["10.0.0.7"]));
        // geosite categories cannot be expressed as hosts keys.
        assert!(hosts.get("geosite:category-ads").is_none());
    }

    #[test]
    fn fake_dns_emits_section_and_sniffing_override() {
        let dns = XrayDnsConfig {
            fake_dns: true,
            servers: vec![dns_server("1.1.1.1", XrayDnsRoute::None)],
            ..XrayDnsConfig::default()
        };
        let config = apply_profile_routing(&base_config(), &[], &dns_options(dns)).unwrap();
        assert_eq!(config["fakedns"][0]["ipPool"], "198.18.0.0/16");
        assert_eq!(config["dns"]["servers"][0], json!("fakedns"));
        let sniffing = &config["inbounds"][0]["sniffing"];
        assert_eq!(sniffing["enabled"], true);
        assert!(sniffing["destOverride"]
            .as_array()
            .unwrap()
            .contains(&json!("fakedns")));

        // TUN inbound picks up the fakedns override too.
        let tun = apply_tun_inbound(&config, None, None).unwrap();
        let overrides = tun["inbounds"][0]["sniffing"]["destOverride"]
            .as_array()
            .unwrap();
        for expected in ["http", "tls", "quic", "fakedns"] {
            assert!(overrides.contains(&json!(expected)));
        }
    }

    #[test]
    fn dns_validation_rejects_bad_servers() {
        for bad in [
            // Unknown scheme.
            "quic://dns.example",
            // Empty host after scheme.
            "https://",
            // fakedns entry without the fakedns section enabled.
            "fakedns",
        ] {
            let dns = XrayDnsConfig {
                servers: vec![dns_server(bad, XrayDnsRoute::None)],
                ..XrayDnsConfig::default()
            };
            assert_eq!(
                apply_profile_routing(&base_config(), &[], &dns_options(dns))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "accepted {bad}"
            );
        }
        let mut server = dns_server("1.1.1.1", XrayDnsRoute::None);
        server.port = Some(0);
        let dns = XrayDnsConfig {
            servers: vec![server],
            ..XrayDnsConfig::default()
        };
        assert_eq!(
            apply_profile_routing(&base_config(), &[], &dns_options(dns))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        // IP selectors are meaningless in dns.servers `domains`.
        let mut server = dns_server("1.1.1.1", XrayDnsRoute::None);
        server.domains = vec!["geoip:cn".into()];
        let dns = XrayDnsConfig {
            servers: vec![server],
            ..XrayDnsConfig::default()
        };
        assert_eq!(
            apply_profile_routing(&base_config(), &[], &dns_options(dns))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn dns_server_host_extracts_routable_host() {
        assert_eq!(dns_server_host("8.8.8.8"), Some("8.8.8.8"));
        assert_eq!(dns_server_host("8.8.8.8:53"), Some("8.8.8.8"));
        assert_eq!(
            dns_server_host("https://dns.google/dns-query"),
            Some("dns.google")
        );
        assert_eq!(
            dns_server_host("tls://one.one.one:853"),
            Some("one.one.one")
        );
        assert_eq!(
            dns_server_host("udp://[2001:db8::1]:53"),
            Some("2001:db8::1")
        );
        assert_eq!(dns_server_host("::1"), Some("::1"));
        assert_eq!(dns_server_host("https://"), None);
        assert_eq!(dns_server_route_target("localhost"), None);
        assert_eq!(dns_server_route_target("fakedns"), None);
        assert_eq!(
            dns_server_route_target("https://1.1.1.1/dns-query"),
            Some(("ip", "1.1.1.1".to_string()))
        );
        assert_eq!(
            dns_server_route_target("dns.google"),
            Some(("domain", "dns.google".to_string()))
        );
    }

    #[test]
    fn dns_bypass_hosts_skip_proxy_routed_and_internal_resolvers() {
        use crate::models::{XrayDnsConfig, XrayDnsRoute, XrayDnsServer};
        let server = |address: &str, route: XrayDnsRoute| XrayDnsServer {
            address: address.to_string(),
            route,
            domains: Vec::new(),
            port: None,
            skip_fallback: false,
        };
        let dns = XrayDnsConfig {
            servers: vec![
                server("udp://9.9.9.9:53", XrayDnsRoute::Direct),
                server("https://dns.resolver.test/dns-query", XrayDnsRoute::Direct),
                server("udp://8.8.4.4", XrayDnsRoute::Proxy),
                server("localhost", XrayDnsRoute::Direct),
                server("fakedns", XrayDnsRoute::Direct),
                server("udp://9.9.9.9:53", XrayDnsRoute::Direct),
            ],
            ..XrayDnsConfig::default()
        };
        assert_eq!(dns_bypass_hosts(&dns), ["9.9.9.9", "dns.resolver.test"]);
        assert!(dns_bypass_hosts(&XrayDnsConfig::default()).is_empty());
    }
}
