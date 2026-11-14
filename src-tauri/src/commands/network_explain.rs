use net_manager_core::route_check::RouteCheckResult;
use tauri::State;

use crate::state::AppState;

#[cfg(target_os = "linux")]
#[tauri::command]
pub(crate) async fn explain_profile_document(
    id: String,
    document: serde_json::Value,
    expected_revision: String,
    target: String,
    state: State<'_, AppState>,
) -> Result<RouteCheckResult, String> {
    super::profiles::linux_profiles_operation(state.inner(), move |service| {
        service.explain_document_route(&id, document, &expected_revision, &target)
    })
    .await
}

#[cfg(not(target_os = "linux"))]
#[tauri::command]
pub(crate) async fn explain_profile_document(
    _id: String,
    _document: serde_json::Value,
    _expected_revision: String,
    _target: String,
    _state: State<'_, AppState>,
) -> Result<RouteCheckResult, String> {
    Err("Offline profile explanation is not supported on this platform".into())
}
