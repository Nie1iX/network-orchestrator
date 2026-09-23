use net_manager_core::explorer;
use net_manager_core::models::*;
use std::net::IpAddr;

#[tauri::command]
pub(crate) async fn get_interfaces() -> Result<Vec<NetworkInterface>, String> {
    explorer::list_interfaces().map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn get_routes() -> Result<Vec<RouteEntry>, String> {
    explorer::list_routes().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn lookup_destination(dest: String) -> Result<RouteLookupResult, String> {
    let ip: IpAddr = dest
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    explorer::lookup_route(ip).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn set_interface_state(name: String, up: bool) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use net_manager_core::daemon_protocol::{method, LinkSetStateParams};
        let client = crate::daemon_client::DaemonClient::system();
        let _: serde_json::Value = client
            .request(method::LINK_SET_STATE, LinkSetStateParams { name, up })
            .await
            .map_err(|e| crate::daemon_client::user_message(&e))?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        explorer::set_interface_state(&name, up).map_err(|e| e.to_string())
    }
}
