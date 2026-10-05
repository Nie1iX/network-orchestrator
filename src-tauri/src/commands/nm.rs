//! NetworkManager-backed external connections. NM owns profile lifecycle
//! and secrets; the app lists VPN/WireGuard profiles and toggles them so
//! routing orchestration can target their interfaces. Linux only.

use net_manager_core::daemon_protocol::NmListResult;
#[cfg(target_os = "linux")]
use tauri::Emitter;

#[tauri::command]
pub(crate) async fn nm_list_connections() -> Result<NmListResult, String> {
    #[cfg(target_os = "linux")]
    {
        use net_manager_core::daemon_protocol::method;
        let client = crate::daemon_client::DaemonClient::system();
        client
            .request(method::NM_LIST, serde_json::Value::Null)
            .await
            .map_err(|e| crate::daemon_client::user_message(&e))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(NmListResult {
            connections: Vec::new(),
            available: false,
        })
    }
}

#[tauri::command]
pub(crate) async fn nm_set_active(
    uuid: String,
    active: bool,
    app: tauri::AppHandle,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use net_manager_core::daemon_protocol::{method, NmSetActiveParams};
        let client = crate::daemon_client::DaemonClient::system();
        let _: serde_json::Value = client
            .request(method::NM_SET_ACTIVE, NmSetActiveParams { uuid, active })
            .await
            .map_err(|e| crate::daemon_client::user_message(&e))?;
        let _ = app.emit("route-changed", ());
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (uuid, active, app);
        Err("NetworkManager connections are only supported on Linux".into())
    }
}
