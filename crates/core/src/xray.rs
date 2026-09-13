use crate::models::{DomainPolicy, DomainRouteTarget};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::io;
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
}

pub fn parse_vless_url(uri: &str) -> io::Result<ParsedVless> {
    let url =
        Url::parse(uri.trim()).map_err(|err| invalid_input(format!("invalid vless url: {err}")))?;
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
            _ => {}
        }
    }
    if !matches!(network.as_str(), "tcp" | "ws" | "grpc") {
        return Err(invalid_input(format!(
            "unsupported transport type '{network}'"
        )));
    }
    if !matches!(security.as_str(), "none" | "tls" | "reality") {
        return Err(invalid_input(format!("unsupported security '{security}'")));
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
            stream["realitySettings"] = Value::Object(reality);
        }
        _ => {}
    }
    Ok(json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": { "udp": true },
        }],
        "outbounds": [
            {
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
            },
            {
                "tag": "direct",
                "protocol": "freedom",
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [],
        },
    }))
}

pub fn apply_domain_policies(base: &Value, policies: &[DomainPolicy]) -> io::Result<Value> {
    if policies.is_empty() {
        return Ok(base.clone());
    }
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
    let needs_direct = policies
        .iter()
        .any(|policy| policy.target == DomainRouteTarget::Direct);

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

    let routing = root.entry("routing").or_insert_with(|| json!({}));
    let routing = routing
        .as_object_mut()
        .ok_or_else(|| invalid_data("xray config routing must be an object"))?;
    let rules = routing.entry("rules").or_insert_with(|| json!([]));
    let rules = rules
        .as_array_mut()
        .ok_or_else(|| invalid_data("xray config routing.rules must be an array"))?;

    let generated: Vec<Value> = policies
        .iter()
        .map(|policy| {
            let tag = match policy.target {
                DomainRouteTarget::Proxy => proxy_tag.as_deref().unwrap_or_default(),
                DomainRouteTarget::Direct => direct_tag.as_deref().unwrap_or_default(),
            };
            json!({
                "type": "field",
                "domain": policy
                    .domains
                    .iter()
                    .map(|domain| domain.trim().to_string())
                    .collect::<Vec<_>>(),
                "outboundTag": tag,
            })
        })
        .collect();
    let mut merged = generated;
    merged.append(rules);
    *rules = merged;
    Ok(doc)
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

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = &input[index + 1..index + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                decoded.push(byte);
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
    fn empty_policies_return_unchanged_clone() {
        let base = json!({"anything": [1, 2, 3]});
        let result = apply_domain_policies(&base, &[]).unwrap();
        assert_eq!(result, base);
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
}
