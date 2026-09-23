#[cfg(target_os = "linux")]
mod auto_connect;
mod commands;
#[cfg(target_os = "linux")]
mod daemon_client;
mod elevation;
mod lifecycle;
mod route_runtime;
mod state;
#[cfg(test)]
mod test_support;
#[cfg(target_os = "linux")]
mod tray;

#[cfg(target_os = "linux")]
use auto_connect::get_auto_connect_result;
use commands::*;
use net_manager_core::explorer;
use tauri::{Emitter, Manager};

#[cfg(target_os = "linux")]
use tray::{get_login_autostart, set_login_autostart};

#[cfg(not(target_os = "linux"))]
#[tauri::command]
fn get_login_autostart() -> Result<bool, String> {
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
fn set_login_autostart(_enabled: bool) -> Result<bool, String> {
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
fn get_auto_connect_result() -> Option<serde_json::Value> {
    None
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            app.manage(state::build_state(data_dir)?);
            #[cfg(target_os = "linux")]
            {
                app.handle().plugin(tauri_plugin_autostart::init(
                    tauri_plugin_autostart::MacosLauncher::LaunchAgent,
                    None,
                ))?;
                match tray::install(app) {
                    Ok(true) => {
                        tauri::async_runtime::spawn(tray::refresh_loop(app.handle().clone()));
                    }
                    Ok(false) => {}
                    Err(err) => eprintln!("network-orchestrator: tray unavailable: {err}"),
                }
            }
            #[cfg(target_os = "linux")]
            app.manage(auto_connect::AutoConnectStatus::default());
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                #[cfg(target_os = "linux")]
                auto_connect::start(handle.clone()).await;
                commands::profiles::run_subscription_refresh_loop(handle).await;
            });
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(explorer::route_watcher_loop(move || {
                let _ = handle.emit("route-changed", ());
            }));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_interfaces,
            get_routes,
            parse_bulk_cidrs,
            lookup_destination,
            set_interface_state,
            get_always_on_profiles,
            set_always_on_profile,
            remove_always_on_profile,
            resume_always_on,
            get_profiles,
            save_profile,
            save_vless_profile,
            save_wireguard_profile,
            import_configs_batch,
            import_subscription,
            refresh_subscription,
            set_subscription_refresh_interval,
            measure_subscription_endpoint_delay,
            get_subscription_endpoints,
            switch_subscription_endpoint,
            delete_profile,
            connect_profile,
            connect_openvpn_with_credentials,
            disconnect_profile,
            probe_openvpn_routes,
            inspect_profile_by_id,
            inspect_profiles,
            diagnose_profile,
            get_tunnel_statuses,
            get_recovery_report,
            cleanup_recovery,
            is_elevated,
            daemon_status,
            restart_elevated,
            discover_wireguard_configs,
            get_route_map,
            get_backend_availability,
            set_backend_executable,
            reset_backend_executable,
            install_managed_xray,
            cancel_managed_xray_install,
            remove_managed_xray,
            get_managed_xray_offer,
            get_platform_capabilities,
            get_auto_connect_result,
            get_login_autostart,
            set_login_autostart
        ])
        .on_window_event(lifecycle::handle_window_event)
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(lifecycle::handle_run_event);
}
