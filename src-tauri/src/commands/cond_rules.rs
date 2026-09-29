use net_manager_core::daemon_protocol::{
    CondRulesListResult, CondRulesPutResult, CondRulesRemoveResult, ConditionalRouteRule,
};

#[cfg(target_os = "linux")]
use net_manager_core::daemon_protocol::{method, CondRulesPutParams, CondRulesRemoveParams};

/// Per-user conditional rules with live evaluation status. Linux daemon
/// only; other platforms report an empty list.
#[tauri::command]
pub(crate) async fn list_conditional_rules() -> Result<CondRulesListResult, String> {
    #[cfg(target_os = "linux")]
    {
        crate::daemon_client::DaemonClient::system()
            .request(method::COND_RULES_LIST, serde_json::Value::Null)
            .await
            .map_err(|err| crate::daemon_client::user_message(&err))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(CondRulesListResult { rules: Vec::new() })
    }
}

/// Create or replace a rule; the daemon re-evaluates it immediately and
/// returns the fresh status.
#[tauri::command]
pub(crate) async fn put_conditional_rule(
    rule: ConditionalRouteRule,
) -> Result<CondRulesPutResult, String> {
    #[cfg(target_os = "linux")]
    {
        crate::daemon_client::DaemonClient::system()
            .request(method::COND_RULES_PUT, CondRulesPutParams { rule })
            .await
            .map_err(|err| crate::daemon_client::user_message(&err))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = rule;
        Err("conditional rules are available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn remove_conditional_rule(
    rule_id: String,
) -> Result<CondRulesRemoveResult, String> {
    #[cfg(target_os = "linux")]
    {
        crate::daemon_client::DaemonClient::system()
            .request(method::COND_RULES_REMOVE, CondRulesRemoveParams { rule_id })
            .await
            .map_err(|err| crate::daemon_client::user_message(&err))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = rule_id;
        Err("conditional rules are available on Linux only".into())
    }
}
