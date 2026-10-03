//! Kernel routing inventory (`ip route`/`ip rule` equivalent) plus the
//! manual edit and explainability surface, read/driven through the
//! privileged daemon's rtnetlink socket. Linux only — other platforms
//! report `available: false` or return the daemon error.

#[cfg(target_os = "linux")]
use net_manager_core::daemon_protocol::{
    method, NetDnsProbeParams, NetIntentDelParams, NetRouteDelParams, NetRuleDelParams,
};
use net_manager_core::daemon_protocol::{
    NetDnsProbeResult, NetDnsStatusResult, NetEditResult, NetExplainResult, NetIntentListResult,
    NetIntentResult, NetIntentSetParams, NetRouteAddParams, NetRuleAddParams, NetTablesResult,
    SystemRoute, SystemRule,
};

#[cfg(target_os = "linux")]
async fn request<P: serde::Serialize, T: serde::de::DeserializeOwned>(
    method_name: &'static str,
    params: P,
) -> Result<T, String> {
    crate::daemon_client::DaemonClient::system()
        .request::<P, T>(method_name, params)
        .await
        .map_err(|e| crate::daemon_client::user_message(&e))
}

#[tauri::command]
pub(crate) async fn get_net_tables() -> Result<NetTablesResult, String> {
    #[cfg(target_os = "linux")]
    {
        request(method::NET_TABLES, serde_json::Value::Null).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(NetTablesResult {
            routes: Vec::new(),
            rules: Vec::new(),
            available: false,
        })
    }
}

/// `net.route.add`: install a daemon-owned unicast route (journaled under
/// the `manual` owner, reconciled, reverted by its removal).
#[tauri::command]
pub(crate) async fn net_route_add(params: NetRouteAddParams) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        request::<_, serde_json::Value>(method::NET_ROUTE_ADD, &params).await?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = params;
        Err("route editing is not supported on this platform".into())
    }
}

/// `net.route.del`: remove a route exactly as `get_net_tables` reported
/// it. Foreign routes are suppressed (journaled, restored on revert);
/// tunnel-owned routes are refused by the daemon.
#[tauri::command]
pub(crate) async fn net_route_del(route: SystemRoute) -> Result<NetEditResult, String> {
    #[cfg(target_os = "linux")]
    {
        request(method::NET_ROUTE_DEL, NetRouteDelParams { route }).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = route;
        Err("route editing is not supported on this platform".into())
    }
}

/// `net.rule.add`: install a daemon-owned `lookup` policy rule.
#[tauri::command]
pub(crate) async fn net_rule_add(params: NetRuleAddParams) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        request::<_, serde_json::Value>(method::NET_RULE_ADD, &params).await?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = params;
        Err("rule editing is not supported on this platform".into())
    }
}

/// `net.rule.del`: remove a policy rule; foreign rules are suppressed
/// (journaled for restore), priority 0 is refused.
#[tauri::command]
pub(crate) async fn net_rule_del(rule: SystemRule) -> Result<NetEditResult, String> {
    #[cfg(target_os = "linux")]
    {
        request(method::NET_RULE_DEL, NetRuleDelParams { rule }).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = rule;
        Err("rule editing is not supported on this platform".into())
    }
}

/// `net.explain`: per-owner reconciliation status of every journaled
/// intent (effective / deferred / conflicted / missing / suppressed).
#[tauri::command]
pub(crate) async fn net_explain() -> Result<NetExplainResult, String> {
    #[cfg(target_os = "linux")]
    {
        request(method::NET_EXPLAIN, serde_json::Value::Null).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(NetExplainResult {
            entries: Vec::new(),
            available: false,
        })
    }
}

/// `net.dns.status`: per-link resolver inventory (systemd-resolved) plus
/// the /etc/resolv.conf stub view.
#[tauri::command]
pub(crate) async fn net_dns_status() -> Result<NetDnsStatusResult, String> {
    #[cfg(target_os = "linux")]
    {
        request(method::NET_DNS_STATUS, serde_json::Value::Null).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(NetDnsStatusResult {
            links: Vec::new(),
            available: false,
            resolv_conf: Vec::new(),
        })
    }
}

/// `net.dns.probe`: one real DNS query to the selected resolver plus the
/// egress route the kernel picked for it.
#[tauri::command]
pub(crate) async fn net_dns_probe(
    hostname: String,
    server: Option<String>,
    family: Option<String>,
) -> Result<NetDnsProbeResult, String> {
    #[cfg(target_os = "linux")]
    {
        use net_manager_core::daemon_protocol::IpFamily;
        let server = match server.as_deref().map(str::trim) {
            Some("") | None => None,
            Some(text) => Some(
                text.parse()
                    .map_err(|_| "invalid resolver address".to_string())?,
            ),
        };
        let family = match family.as_deref() {
            Some("ipv6") => Some(IpFamily::Ipv6),
            _ => Some(IpFamily::Ipv4),
        };
        request(
            method::NET_DNS_PROBE,
            NetDnsProbeParams {
                hostname,
                server,
                family,
            },
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (hostname, server, family);
        Err("DNS probing is not supported on this platform".into())
    }
}

/// `net.intent.list`: stored routing intents with their live status.
#[tauri::command]
pub(crate) async fn net_intent_list() -> Result<NetIntentListResult, String> {
    #[cfg(target_os = "linux")]
    {
        request(method::NET_INTENT_LIST, serde_json::Value::Null).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(NetIntentListResult {
            intents: Vec::new(),
        })
    }
}

/// `net.intent.set`: upsert a routing intent — destinations routed via an
/// interface or pinned to the physical uplink, enforced by reconcile.
#[tauri::command]
pub(crate) async fn net_intent_set(params: NetIntentSetParams) -> Result<NetIntentResult, String> {
    #[cfg(target_os = "linux")]
    {
        request(method::NET_INTENT_SET, &params).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = params;
        Err("routing intents are not supported on this platform".into())
    }
}

/// `net.intent.del`: remove the intent and withdraw its routes.
#[tauri::command]
pub(crate) async fn net_intent_del(id: String) -> Result<NetIntentResult, String> {
    #[cfg(target_os = "linux")]
    {
        request(method::NET_INTENT_DEL, NetIntentDelParams { id }).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = id;
        Err("routing intents are not supported on this platform".into())
    }
}
