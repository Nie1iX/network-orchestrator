use net_manager_core::happ_routing::HappRoutingImport;

/// Preview a pasted Happ/Incy routing-profile export. Pure parse — the
/// modal applies the returned fields to its form state and the normal
/// `save_profile` path persists them.
#[tauri::command]
pub(crate) fn parse_happ_routing(payload: String) -> Result<HappRoutingImport, String> {
    net_manager_core::happ_routing::parse_happ_routing(&payload)
        .map_err(|err| format!("invalid Happ routing profile: {err}"))
}
