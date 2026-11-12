use net_manager_core::daemon_protocol::MihomoConnectParams;
use net_manager_core::models::PolicyRoute;
use serde_json::{json, Value};
use std::{collections::HashSet, io, net::IpAddr};

pub struct MihomoPlan {
    pub profile_id: String,
    pub name: String,
    pub config: String,
    pub routes: Vec<PolicyRoute>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_domains: Vec<String>,
    pub server_hosts: Vec<String>,
    pub full_ipv4: bool,
    pub full_ipv6: bool,
    pub group_selections: std::collections::BTreeMap<String, String>,
}

pub fn prepare_mihomo(uid: u32, params: MihomoConnectParams, mark: u32) -> io::Result<MihomoPlan> {
    let rejected = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported Mihomo TUN request",
        )
    };
    crate::validate::validate_owner(&format!("mihomo:{}", params.profile_id))
        .map_err(|_| rejected())?;
    net_manager_core::models::validate_secondary(params.role, &params.routes, &params.dns_domains)
        .map_err(|_| rejected())?;
    if mark == 0
        || params.config.len() > 4 * 1024 * 1024
        || params.routes.len() > 64
        || params.dns_servers.len() > 8
        || params.dns_domains.len() > 16
        || params.group_selections.len() > 64
        || params.group_selections.iter().any(|(group, member)| {
            group.is_empty()
                || member.is_empty()
                || group.len() > 512
                || member.len() > 512
                || group.chars().any(char::is_control)
                || member.chars().any(char::is_control)
        })
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
    if params.dns_servers.iter().any(|ip| {
        ip.is_unspecified()
            || ip.is_multicast()
            || !params
                .routes
                .iter()
                .any(|route| route.destination.contains(ip))
    }) || (!params.dns_domains.is_empty() && params.dns_servers.is_empty())
        || params.dns_domains.iter().any(|domain| {
            domain.is_empty() || domain.len() > 253 || domain.chars().any(char::is_control)
        })
    {
        return Err(rejected());
    }
    let net = |s: &str| s.parse::<ipnet::IpNet>().unwrap();
    let full_ipv4 = seen.contains(&net("0.0.0.0/0"))
        || (seen.contains(&net("0.0.0.0/1")) && seen.contains(&net("128.0.0.0/1")));
    let full_ipv6 = seen.contains(&net("::/0"))
        || (seen.contains(&net("::/1")) && seen.contains(&net("8000::/1")));
    let (covers_ipv4, covers_ipv6) =
        net_manager_core::connect_plan::full_coverage(params.routes.iter().map(|r| r.destination));
    if (covers_ipv4 && !full_ipv4) || (covers_ipv6 && !full_ipv6) {
        return Err(rejected());
    }
    let mut config: Value = serde_json::from_str(&params.config).map_err(|_| rejected())?;
    net_manager_core::mihomo::validate_config(&config).map_err(|_| rejected())?;
    let (name, _) = crate::link_names::tunnel_link_names(
        "mh-",
        uid,
        &params.profile_id,
        params.interface_name.as_deref(),
    );
    let root = config.as_object_mut().ok_or_else(rejected)?;
    let mut server_hosts = Vec::new();
    root.insert("routing-mark".into(), json!(mark));
    if let Some(proxies) = root.get_mut("proxies").and_then(Value::as_array_mut) {
        for proxy in proxies {
            if let Some(host) = proxy.get("server").and_then(Value::as_str) {
                if !server_hosts.iter().any(|known| known == host) {
                    server_hosts.push(host.to_owned());
                }
            }
            if let Some(proxy) = proxy.as_object_mut() {
                proxy.insert("routing-mark".into(), json!(mark));
            }
        }
    }
    if let Some(providers) = root.get_mut("proxy-providers") {
        for provider in providers.as_object_mut().ok_or_else(rejected)?.values_mut() {
            let provider = provider.as_object_mut().ok_or_else(rejected)?;
            if provider.get("type").and_then(Value::as_str) != Some("inline")
                || provider
                    .get("override")
                    .and_then(Value::as_object)
                    .is_some_and(|options| {
                        options.keys().any(|key| {
                            !matches!(key.as_str(), "additional-prefix" | "additional-suffix")
                        })
                    })
                || provider.contains_key("dialer-proxy")
                || provider.contains_key("url")
                || provider.contains_key("path")
            {
                return Err(rejected());
            }
            for proxy in provider
                .get_mut("payload")
                .and_then(Value::as_array_mut)
                .ok_or_else(rejected)?
            {
                if let Some(host) = proxy.get("server").and_then(Value::as_str) {
                    if !server_hosts.iter().any(|known| known == host) {
                        server_hosts.push(host.to_owned());
                    }
                }
                proxy
                    .as_object_mut()
                    .ok_or_else(rejected)?
                    .insert("routing-mark".into(), json!(mark));
            }
        }
    }
    let dns = root.entry("dns").or_insert_with(|| json!({}));
    dns.as_object_mut()
        .ok_or_else(rejected)?
        .insert("enable".into(), json!(true));
    // Mihomo installs an IPv6 gateway route even with auto-route disabled.
    // Keep it out of the daemon's scoped policy table.
    let native_table = mark.checked_add(128).ok_or_else(rejected)?;
    root.insert("tun".into(), json!({"enable":true,"device":name,"stack":"gvisor","auto-route":false,"auto-redirect":false,"auto-detect-interface":false,"dns-hijack":["any:53","tcp://any:53"],"mtu":1500,"iproute2-table-index":native_table}));
    Ok(MihomoPlan {
        profile_id: params.profile_id,
        name,
        config: serde_json::to_string(&config).map_err(|_| rejected())?,
        routes: params.routes,
        dns_servers: params.dns_servers,
        dns_domains: params.dns_domains,
        server_hosts,
        full_ipv4,
        full_ipv6,
        group_selections: params.group_selections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::MihomoConnectParams;

    fn params() -> MihomoConnectParams {
        serde_json::from_value(serde_json::json!({
            "profileId": "home", "config": "{\"proxies\":[],\"proxy-groups\":[],\"rules\":[\"MATCH,DIRECT\"]}",
            "routes": [{"destination":"0.0.0.0/0","metric":10}]
        })).unwrap()
    }

    #[test]
    fn plan_forces_daemon_owned_tun_and_mark() {
        let plan = prepare_mihomo(1000, params(), 51820).unwrap();
        let config: serde_json::Value = serde_json::from_str(&plan.config).unwrap();
        assert_eq!(config["routing-mark"], 51820);
        assert_eq!(config["tun"]["device"], plan.name);
        assert_eq!(config["tun"]["auto-route"], false);
        assert_eq!(config["tun"]["auto-redirect"], false);
        assert_eq!(config["tun"]["stack"], "gvisor");
        assert_eq!(config["tun"]["iproute2-table-index"], 51948);
        let next = prepare_mihomo(1000, params(), 51821).unwrap();
        let next_config: serde_json::Value = serde_json::from_str(&next.config).unwrap();
        assert_eq!(next_config["tun"]["iproute2-table-index"], 51949);
    }

    #[test]
    fn rejects_runtime_proxy_provider_downloads() {
        let mut p = params();
        let mut value: Value = serde_json::from_str(&p.config).unwrap();
        value["proxy-providers"] =
            json!({"remote":{"type":"http","url":"https://example.invalid/proxies"}});
        p.config = value.to_string();
        assert!(prepare_mihomo(1000, p, 51820).is_err());
    }

    #[test]
    fn plan_rejects_duplicate_and_noncanonical_routes() {
        let mut p = params();
        p.routes.push(p.routes[0].clone());
        assert!(prepare_mihomo(1000, p, 51820).is_err());
    }

    #[test]
    fn secondary_cannot_request_default_capture() {
        let mut p = params();
        p.role = net_manager_core::models::TunnelRole::Secondary;
        assert!(prepare_mihomo(1000, p, 51820).is_err());
    }
}
