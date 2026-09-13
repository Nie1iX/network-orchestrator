mod commands;
mod elevation;
mod lifecycle;
mod state;
#[cfg(test)]
mod test_support;

use commands::*;
use net_manager_core::explorer;
use tauri::{Emitter, Manager};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            app.manage(state::build_state(data_dir)?);
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(explorer::route_watcher_loop(move || {
                let _ = handle.emit("route-changed", ());
            }));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_interfaces,
            get_routes,
            lookup_destination,
            set_interface_state,
            get_profiles,
            save_profile,
            save_vless_profile,
            delete_profile,
            connect_profile,
            disconnect_profile,
            inspect_profile_by_id,
            inspect_profiles,
            diagnose_profile,
            get_tunnel_statuses,
            get_recovery_report,
            cleanup_recovery,
            is_elevated,
            restart_elevated,
            get_route_map,
            get_backend_availability
        ])
        .on_window_event(lifecycle::handle_window_event)
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(lifecycle::handle_run_event);
}
