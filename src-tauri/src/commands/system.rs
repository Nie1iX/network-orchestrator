use crate::elevation;
use crate::state::AppState;
use net_manager_core::models::{BackendAvailability, TunnelBackend};
use net_manager_core::vpn;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use tauri::State;

#[tauri::command]
pub(crate) async fn is_elevated() -> Result<bool, String> {
    elevation::is_elevated().map_err(|e| e.to_string())
}

fn backend_entry(
    backend: TunnelBackend,
    resolved: Result<PathBuf, std::io::Error>,
) -> BackendAvailability {
    match resolved {
        Ok(path) => BackendAvailability {
            backend,
            available: true,
            path: Some(path),
            message: "executable found".to_string(),
        },
        Err(err) => BackendAvailability {
            backend,
            available: false,
            path: None,
            message: format!("executable not found: {err}"),
        },
    }
}

pub(crate) fn collect_backend_availability() -> Vec<BackendAvailability> {
    vec![
        backend_entry(
            TunnelBackend::WireGuard,
            vpn::resolve_wireguard_executable(None),
        ),
        backend_entry(
            TunnelBackend::OpenVpn,
            vpn::resolve_openvpn_executable(None),
        ),
        backend_entry(TunnelBackend::Xray, vpn::resolve_xray_executable(None)),
    ]
}

#[tauri::command]
pub(crate) async fn get_backend_availability() -> Vec<BackendAvailability> {
    collect_backend_availability()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn backend_entry_maps_found_and_missing() {
        let found = backend_entry(
            TunnelBackend::WireGuard,
            Ok(PathBuf::from(r"C:\tools\wireguard.exe")),
        );
        assert!(found.available);
        assert_eq!(
            found.path.unwrap(),
            PathBuf::from(r"C:\tools\wireguard.exe")
        );

        let missing = backend_entry(
            TunnelBackend::Xray,
            Err(io::Error::new(io::ErrorKind::NotFound, "xray.exe missing")),
        );
        assert!(!missing.available);
        assert!(missing.path.is_none());
        assert!(missing.message.contains("xray.exe missing"));
    }
}
