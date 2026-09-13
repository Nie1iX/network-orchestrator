use crate::elevation;
use crate::state::AppState;
use std::sync::atomic::Ordering;
use tauri::State;

#[tauri::command]
pub(crate) async fn is_elevated() -> Result<bool, String> {
    elevation::is_elevated().map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn restart_elevated(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if elevation::is_elevated().map_err(|e| e.to_string())? {
        return Ok(());
    }
    elevation::restart_elevated().map_err(|e| e.to_string())?;
    state.cleanup_complete.store(true, Ordering::SeqCst);
    app.exit(0);
    Ok(())
}
