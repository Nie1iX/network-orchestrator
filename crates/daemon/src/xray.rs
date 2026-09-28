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
    pub full_ipv4: bool,
    pub full_ipv6: bool,
    pub mark: u32,
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
            .field("full_ipv4", &self.full_ipv4)
            .field("full_ipv6", &self.full_ipv6)
            .field("mark", &self.mark)
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
    let root = object(config, &["log", "inbounds", "outbounds", "routing"])?;
    if let Some(log) = root.get("log") {
        object(log, &["loglevel"])?;
        if !matches!(log["loglevel"].as_str(), Some("warning" | "error" | "none")) {
            return Err(rejected());
        }
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
    if outbounds.len() < 2 || outbounds.len() > 3 {
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
            "freedom" | "blackhole"
                if index > 0
                    && !map.contains_key("settings")
                    && !map.contains_key("streamSettings") => {}
            _ => return Err(rejected()),
        }
    }
    if outbounds[1]["protocol"] != "freedom" {
        return Err(rejected());
    }
    let routing = object(&config["routing"], &["domainStrategy", "rules"])?;
    if let Some(strategy) = routing.get("domainStrategy") {
        if strategy != "AsIs" {
            return Err(rejected());
        }
    }
    let rules = config["routing"]["rules"].as_array().ok_or_else(rejected)?;
    if rules.len() > 64 {
        return Err(rejected());
    }
    for rule in rules {
        object(rule, &["type", "domain", "ip", "outboundTag"])?;
        if rule["type"] != "field" || !tags.contains(string(&rule["outboundTag"])?) {
            return Err(rejected());
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

/// Root Xray resolves `ext:`-style selectors to files next to its assets, so
/// accept only the selector forms the app generates.
fn routing_selector(key: &str, item: &str) -> io::Result<()> {
    let valid = if key == "ip" {
        match item.strip_prefix("geoip:") {
            Some(country) => {
                country == "private"
                    || (country.len() == 2
                        && country.bytes().all(|byte| byte.is_ascii_alphabetic()))
            }
            None => item.parse::<IpAddr>().is_ok() || item.parse::<ipnet::IpNet>().is_ok(),
        }
    } else {
        match item.split_once(':') {
            Some(("geosite", category)) => {
                !category.is_empty()
                    && category.len() <= 64
                    && category
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
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
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in uid.to_le_bytes().iter().chain(params.profile_id.as_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let name = format!("xray-{:010x}", hash & 0xffffffffff);
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
    config["inbounds"] =
        json!([{ "tag": "tun-in", "protocol": "tun", "settings": { "name": name, "mtu": mtu } }]);
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
        full_ipv4,
        full_ipv6,
        mark,
    })
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
        }
    }

    #[test]
    fn plan_replaces_user_inbounds_and_marks_every_dialling_outbound() {
        let plan = prepare_xray(1000, params(), 51820).unwrap();
        assert!(plan.name.starts_with("xray-"));
        assert!(plan.name.len() <= 15);
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
            json!({"type":"field","ip":["geoip:private","geoip:us","10.0.0.0/8","::1/128","192.0.2.1"],"outboundTag":"direct"}),
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
}
