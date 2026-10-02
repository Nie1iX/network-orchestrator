//! Kernel routing inventory (`ip route`/`ip rule` equivalent) read through
//! the privileged daemon's rtnetlink socket: routes across every table plus
//! all policy rules. Linux only — other platforms report `available: false`.

use net_manager_core::daemon_protocol::NetTablesResult;

#[tauri::command]
pub(crate) async fn get_net_tables() -> Result<NetTablesResult, String> {
    #[cfg(target_os = "linux")]
    {
        use net_manager_core::daemon_protocol::method;
        let client = crate::daemon_client::DaemonClient::system();
        client
            .request(method::NET_TABLES, serde_json::Value::Null)
            .await
            .map_err(|e| crate::daemon_client::user_message(&e))
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
