use net_manager_core::explorer;
use net_manager_core::models::*;
use std::net::IpAddr;
use tauri::Manager;

#[tauri::command]
async fn get_interfaces() -> Result<Vec<NetworkInterface>, String> {
    explorer::list_interfaces().map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_routes() -> Result<Vec<RouteEntry>, String> {
    explorer::list_routes().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn lookup_destination(dest: String) -> Result<RouteLookupResult, String> {
    let ip: IpAddr = dest
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    explorer::lookup_route(ip).await.map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let handle = app.handle().clone();
            explorer::spawn_route_watcher(move || {
                let _ = handle.emit("route-changed", ());
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_interfaces,
            get_routes,
            lookup_destination
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
