use crate::state::AppState;
use tauri::State;

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn probe_current_path(
    state: State<'_, AppState>,
    target: String,
) -> Result<net_manager_engine::network_probe::NetworkPathProbe, String> {
    let root = state.data_dir().to_path_buf();
    let proxy_url = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        crate::daemon_client::DaemonClient::system().engine_observation(move |engine| {
            net_manager_engine::network_probe::proxy::current_user_proxy(&engine, &root)
        }),
    )
    .await
    .map_err(|_| "Timed out inspecting the current user proxy.".to_string())??;
    net_manager_engine::network_probe::probe_current_path(&target, proxy_url.as_deref()).await
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn probe_current_path(
    _state: State<'_, AppState>,
    _target: String,
) -> Result<(), String> {
    Err("Current-path probing is unsupported on this platform.".into())
}
