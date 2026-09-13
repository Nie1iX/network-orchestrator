mod elevation;

use net_manager_core::analysis;
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::explorer;
use net_manager_core::models::*;
use net_manager_core::policy::PolicyManager;
use net_manager_core::profiles::{ProfileDocument, ProfileStore};
use net_manager_core::route_state::{
    AppliedRouteDocument, AppliedRouteStore, APPLIED_ROUTE_DOCUMENT_VERSION,
};
use net_manager_core::vpn::{self, TunnelManager};
use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{Emitter, Manager, State};

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

#[tauri::command]
async fn set_interface_state(name: String, up: bool) -> Result<(), String> {
    explorer::set_interface_state(&name, up).map_err(|e| e.to_string())
}

struct RuntimeState {
    tunnels: TunnelManager,
    policies: PolicyManager,
}

struct AppState {
    profiles: ProfileStore,
    config_vault: ConfigVault,
    applied_routes: AppliedRouteStore,
    shutting_down: AtomicBool,
    cleanup_complete: AtomicBool,
    runtime: tokio::sync::Mutex<RuntimeState>,
}

fn persist_applied_routes(
    store: &AppliedRouteStore,
    policies: &PolicyManager,
) -> Result<(), String> {
    let document = AppliedRouteDocument {
        version: APPLIED_ROUTE_DOCUMENT_VERSION,
        profiles: policies.snapshot(),
    };
    store.save(&document).map_err(|e| e.to_string())
}

fn find_profile(store: &ProfileStore, id: &str) -> Result<Profile, String> {
    store
        .load()
        .map_err(|e| e.to_string())?
        .profiles
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| format!("profile '{id}' not found"))
}

fn existing_profile_for_update<'a>(
    document: &'a ProfileDocument,
    incoming_id: &str,
) -> Option<&'a Profile> {
    document.profiles.iter().find(|p| p.id == incoming_id)
}

fn has_target_interface(profile: &Profile, interfaces: &[NetworkInterface]) -> bool {
    interfaces.iter().any(|iface| {
        matches!(iface.state, InterfaceState::Up)
            && (iface.friendly_name == profile.interface_name
                || iface.name == profile.interface_name)
    })
}

const AUTO_SOCKS_PORT_START: u16 = 10808;
const AUTO_SOCKS_PORT_END: u16 = 10999;

fn select_available_socks_port(
    used: &HashSet<u16>,
    available: impl Fn(u16) -> bool,
) -> Result<u16, String> {
    (AUTO_SOCKS_PORT_START..=AUTO_SOCKS_PORT_END)
        .find(|port| !used.contains(port) && available(*port))
        .ok_or_else(|| {
            format!(
                "no available SOCKS5 port in automatic range {AUTO_SOCKS_PORT_START}-{AUTO_SOCKS_PORT_END}"
            )
        })
}

fn profile_listener_ports(profiles: &[Profile], exclude_id: &str) -> HashSet<u16> {
    let mut ports = HashSet::new();
    for profile in profiles {
        if profile.id == exclude_id {
            continue;
        }
        if let Some(port) = profile.xray_socks_port {
            ports.insert(port);
        }
        if let Ok(analysis) = analysis::analyze_profile(profile) {
            for listener in &analysis.listeners {
                if matches!(
                    listener.address.as_str(),
                    "127.0.0.1" | "0.0.0.0" | "::" | ""
                ) {
                    ports.insert(listener.port);
                }
            }
        }
    }
    ports
}

fn loopback_port_available(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

fn rewrite_generated_socks_port(
    vault: &ConfigVault,
    profile: &mut Profile,
    new_port: u16,
) -> Result<PathBuf, String> {
    if profile.backend != TunnelBackend::Xray
        || profile.xray_socks_port.is_none()
        || !vault.is_managed_profile_path(&profile.id, &profile.config_path)
    {
        return Err("profile does not use a managed generated Xray config".into());
    }
    let text = std::fs::read_to_string(&profile.config_path).map_err(|e| e.to_string())?;
    let mut doc: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let inbounds = doc
        .get_mut("inbounds")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "generated config has no inbounds array".to_string())?;
    let inbound = inbounds
        .iter_mut()
        .find(|i| i.get("tag").and_then(|t| t.as_str()) == Some("socks-in"))
        .ok_or_else(|| "generated config has no 'socks-in' inbound".to_string())?;
    inbound["port"] = serde_json::json!(new_port);
    let body = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
    let import = vault
        .store_xray_config(&profile.id, &body)
        .map_err(|e| e.to_string())?;
    profile.config_path = import.config_path.clone();
    profile.xray_socks_port = Some(new_port);
    Ok(import.config_path)
}

fn remove_managed_revision(
    vault: &ConfigVault,
    profile_id: &str,
    path: &Path,
    action: &str,
) -> Result<(), String> {
    if !vault.is_managed_profile_path(profile_id, path) {
        return Ok(());
    }
    vault.remove_revision_for_config(path).map_err(|err| {
        format!(
            "{action}, but managed config cleanup failed for '{}': {err}",
            path.display()
        )
    })
}

fn validate_managed_save_path(
    vault: &ConfigVault,
    stored: Option<&Profile>,
    profile: &Profile,
) -> Result<(), String> {
    if !vault.is_managed_path(&profile.config_path) {
        return Ok(());
    }
    if !vault.is_managed_profile_path(&profile.id, &profile.config_path) {
        return Err(format!(
            "config path '{}' is managed by a different profile",
            profile.config_path.display()
        ));
    }
    if let Some(existing) = stored {
        if existing.config_path == profile.config_path && existing.backend != profile.backend {
            return Err(
                "changing backend requires selecting or importing a new source config".into(),
            );
        }
    }
    Ok(())
}

fn cleanup_stale_routes_before_connect(
    state: &AppState,
    runtime: &mut RuntimeState,
    profile: &Profile,
) -> Result<(), String> {
    if runtime.tunnels.status(profile).state == TunnelState::Running {
        return Err(
            std::io::Error::new(ErrorKind::AlreadyExists, "profile is already running").to_string(),
        );
    }
    if runtime.policies.has_applied_profile(&profile.id) {
        runtime
            .policies
            .remove_profile(&profile.id)
            .map_err(|err| format!("failed to clean previously applied routes: {err}"))?;
        persist_applied_routes(&state.applied_routes, &runtime.policies).map_err(|err| {
            format!("stale routes were cleaned, but registry update failed: {err}")
        })?;
    }
    Ok(())
}

async fn cleanup_all(state: &AppState) -> Result<(), String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let mut runtime = state.runtime.lock().await;
    let mut errors: Vec<String> = Vec::new();
    for id in runtime.policies.applied_profile_ids() {
        if let Err(err) = runtime.policies.remove_profile(&id) {
            errors.push(format!("routes for '{id}': {err}"));
        }
    }
    if let Err(err) = persist_applied_routes(&state.applied_routes, &runtime.policies) {
        errors.push(format!("applied route registry: {err}"));
    }
    for profile in &profiles {
        if runtime.tunnels.status(profile).state == TunnelState::Running {
            if let Err(err) = runtime.tunnels.disconnect(profile) {
                errors.push(format!("tunnel '{}': {err}", profile.id));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn build_profile_inspection(
    candidate: &Profile,
    others: &[Profile],
    os_routes: &[RouteEntry],
    vault: &ConfigVault,
) -> Result<ProfileInspection, String> {
    let mut analysis = analysis::analyze_profile(candidate).map_err(|e| e.to_string())?;
    let mut conflicts = Vec::new();
    for other in others {
        match analysis::analyze_profile(other) {
            Ok(other_analysis) => conflicts.extend(analysis::conflicts_between(
                &analysis,
                &other_analysis,
                false,
            )),
            Err(_) => analysis.warnings.push(format!(
                "could not analyze profile '{}' ('{}') for conflicts",
                other.name, other.id
            )),
        }
    }
    conflicts.extend(analysis::warnings_against_os_routes(&analysis, os_routes));
    Ok(ProfileInspection {
        analysis,
        conflicts,
        managed_config: vault.is_managed_profile_path(&candidate.id, &candidate.config_path),
    })
}

fn unknown_route_conflicts(
    candidate: &ConfigAnalysis,
    other: &Profile,
    other_analysis: &ConfigAnalysis,
) -> Vec<ProfileConflict> {
    let mut conflicts = Vec::new();
    if !other_analysis.route_knowledge_complete
        && (!candidate.os_routes.is_empty() || !candidate.route_knowledge_complete)
    {
        conflicts.push(ProfileConflict {
            kind: ConflictKind::RouteOverlap,
            message: format!(
                "cannot verify route conflicts with active profile '{}' because its effective routes are not fully known",
                other.name
            ),
            other_profile_id: Some(other.id.clone()),
            blocking: true,
        });
    } else if !candidate.route_knowledge_complete && !other_analysis.os_routes.is_empty() {
        conflicts.push(ProfileConflict {
            kind: ConflictKind::RouteOverlap,
            message: format!(
                "candidate routes are not fully known and may conflict with routes of active profile '{}'",
                other.name
            ),
            other_profile_id: Some(other.id.clone()),
            blocking: true,
        });
    }
    conflicts
}

fn active_profile_conflicts(
    tunnels: &mut TunnelManager,
    candidate_id: &str,
    candidate: &ConfigAnalysis,
    profiles: &[Profile],
) -> Result<Vec<ProfileConflict>, String> {
    let mut conflicts = Vec::new();
    for other in profiles {
        if other.id == candidate_id {
            continue;
        }
        if tunnels.status(other).state != TunnelState::Running {
            continue;
        }
        let other_analysis = analysis::analyze_profile(other).map_err(|_| {
            format!(
                "cannot verify conflicts with active profile '{}'",
                other.name
            )
        })?;
        conflicts.extend(unknown_route_conflicts(candidate, other, &other_analysis));
        conflicts.extend(analysis::conflicts_between(
            candidate,
            &other_analysis,
            true,
        ));
    }
    Ok(conflicts)
}

#[tauri::command]
async fn get_profiles(state: State<'_, AppState>) -> Result<Vec<Profile>, String> {
    state
        .profiles
        .load()
        .map(|doc| doc.profiles)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn save_profile(
    mut profile: Profile,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let document = state.profiles.load().map_err(|e| e.to_string())?;
    let stored = existing_profile_for_update(&document, &profile.id).cloned();
    if let Some(existing) = &stored {
        let mut runtime = state.runtime.lock().await;
        if runtime.tunnels.status(existing).state == TunnelState::Running {
            return Err(format!(
                "profile '{}' is running; disconnect before editing",
                profile.id
            ));
        }
    }
    validate_managed_save_path(&state.config_vault, stored.as_ref(), &profile)?;
    let imported = if state.config_vault.is_managed_path(&profile.config_path) {
        None
    } else {
        let import = state
            .config_vault
            .import(&profile.id, profile.backend, &profile.config_path)
            .map_err(|e| e.to_string())?;
        profile.config_path = import.config_path.clone();
        Some(import.config_path)
    };
    let new_path = profile.config_path.clone();
    let doc = match state.profiles.upsert(profile) {
        Ok(doc) => doc,
        Err(err) => {
            if let Some(path) = imported {
                let _ = state.config_vault.remove_revision_for_config(&path);
            }
            return Err(err.to_string());
        }
    };
    if let Some(existing) = stored {
        if existing.config_path != new_path {
            remove_managed_revision(
                &state.config_vault,
                &existing.id,
                &existing.config_path,
                "profile saved",
            )?;
        }
    }
    Ok(doc.profiles)
}

#[tauri::command]
async fn delete_profile(id: String, state: State<'_, AppState>) -> Result<Vec<Profile>, String> {
    let profile = find_profile(&state.profiles, &id)?;
    {
        let mut runtime = state.runtime.lock().await;
        if runtime.tunnels.status(&profile).state == TunnelState::Running {
            return Err(format!(
                "profile '{id}' is running; disconnect before deleting"
            ));
        }
        if runtime.policies.has_applied_profile(&id) {
            return Err(format!(
                "profile '{id}' has applied routes; disconnect before deleting"
            ));
        }
    }
    let doc = state.profiles.delete(&id).map_err(|e| e.to_string())?;
    state
        .config_vault
        .remove_profile(&id)
        .map_err(|err| format!("profile deleted, but managed config cleanup failed: {err}"))?;
    Ok(doc.profiles)
}

#[tauri::command]
async fn connect_profile(
    id: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<TunnelStatus, String> {
    let mut profile = find_profile(&state.profiles, &id)?;
    let mut profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let mut runtime = state.runtime.lock().await;
    cleanup_stale_routes_before_connect(&state, &mut runtime, &profile)?;
    let mut port_notice: Option<String> = None;
    if profile.backend == TunnelBackend::Xray {
        if let Some(port) = profile.xray_socks_port {
            if !loopback_port_available(port) {
                let used = profile_listener_ports(&profiles, &id);
                let new_port = select_available_socks_port(&used, loopback_port_available)?;
                let old_path = profile.config_path.clone();
                rewrite_generated_socks_port(&state.config_vault, &mut profile, new_port)?;
                match state.profiles.upsert(profile.clone()) {
                    Ok(_) => {
                        if let Some(stored) = profiles.iter_mut().find(|p| p.id == id) {
                            *stored = profile.clone();
                        }
                        remove_managed_revision(
                            &state.config_vault,
                            &profile.id,
                            &old_path,
                            "connection started",
                        )?;
                        port_notice = Some(format!(
                            "SOCKS5 port changed from {port} to {new_port} because the previous port is occupied."
                        ));
                    }
                    Err(err) => {
                        let _ = state
                            .config_vault
                            .remove_revision_for_config(&profile.config_path);
                        return Err(err.to_string());
                    }
                }
            }
        }
    }
    let candidate_analysis = analysis::analyze_profile(&profile)
        .map_err(|e| format!("cannot analyze profile config: {e}"))?;
    let conflicts =
        active_profile_conflicts(&mut runtime.tunnels, &id, &candidate_analysis, &profiles)?;
    if !conflicts.is_empty() {
        let joined = conflicts
            .iter()
            .map(|c| c.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "connection blocked by active profile conflict: {joined}"
        ));
    }
    let mut status = runtime
        .tunnels
        .connect(&profile)
        .map_err(|e| e.to_string())?;
    if let Some(notice) = port_notice {
        status.message = Some(notice);
    }

    if !profile.routes.is_empty() {
        let mut matched_interfaces: Option<Vec<NetworkInterface>> = None;
        let mut list_error: Option<String> = None;
        for _ in 0..40 {
            match explorer::list_interfaces() {
                Ok(interfaces) => {
                    if has_target_interface(&profile, &interfaces) {
                        matched_interfaces = Some(interfaces);
                        break;
                    }
                }
                Err(e) => {
                    list_error = Some(e.to_string());
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        if let Some(err) = list_error {
            let mut message = format!("failed to enumerate interfaces: {err}");
            if let Err(cleanup) = runtime.tunnels.disconnect(&profile) {
                message.push_str(&format!("; cleanup disconnect failed: {cleanup}"));
            }
            return Err(message);
        }
        let Some(interfaces) = matched_interfaces else {
            let mut message = format!(
                "timed out waiting for interface '{}' to come up",
                profile.interface_name
            );
            if let Err(cleanup) = runtime.tunnels.disconnect(&profile) {
                message.push_str(&format!("; cleanup disconnect failed: {cleanup}"));
            }
            return Err(message);
        };
        if let Err(err) = runtime.policies.apply_profile(&profile, &interfaces) {
            let mut message = err.to_string();
            if let Err(cleanup) = runtime.tunnels.disconnect(&profile) {
                message.push_str(&format!("; cleanup disconnect failed: {cleanup}"));
            }
            return Err(message);
        }
        if let Err(err) = persist_applied_routes(&state.applied_routes, &runtime.policies) {
            let mut message = format!("failed to persist applied routes: {err}");
            if let Err(cleanup) = runtime.policies.remove_profile(&id) {
                message.push_str(&format!("; route rollback failed: {cleanup}"));
            }
            if let Err(cleanup) = runtime.tunnels.disconnect(&profile) {
                message.push_str(&format!("; cleanup disconnect failed: {cleanup}"));
            }
            return Err(message);
        }
    }

    let _ = app.emit("route-changed", ());
    Ok(status)
}

#[tauri::command]
async fn disconnect_profile(
    id: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<TunnelStatus, String> {
    let profile = find_profile(&state.profiles, &id)?;
    let mut runtime = state.runtime.lock().await;
    if let Err(err) = runtime.policies.remove_profile(&id) {
        if err.kind() != ErrorKind::NotFound {
            return Err(err.to_string());
        }
    }
    let persist_result = persist_applied_routes(&state.applied_routes, &runtime.policies);
    let status = runtime.tunnels.disconnect(&profile);
    match (status, persist_result) {
        (Ok(status), Ok(())) => {
            let _ = app.emit("route-changed", ());
            Ok(status)
        }
        (Ok(_), Err(persist_err)) => {
            Err(format!("failed to persist applied routes: {persist_err}"))
        }
        (Err(status_err), Ok(())) => Err(status_err.to_string()),
        (Err(status_err), Err(persist_err)) => Err(format!(
            "failed to persist applied routes: {persist_err}; tunnel disconnect failed: {status_err}"
        )),
    }
}

#[tauri::command]
async fn save_vless_profile(
    mut profile: Profile,
    vless_url: String,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    if profile.backend != TunnelBackend::Xray {
        return Err("vless import requires an Xray profile".into());
    }
    let document = state.profiles.load().map_err(|e| e.to_string())?;
    let socks_port = match profile.xray_socks_port {
        Some(port) if port != 0 => port,
        _ => {
            let used = profile_listener_ports(&document.profiles, &profile.id);
            select_available_socks_port(&used, loopback_port_available)?
        }
    };
    profile.xray_socks_port = Some(socks_port);
    let stored = existing_profile_for_update(&document, &profile.id).cloned();
    if let Some(existing) = &stored {
        let mut runtime = state.runtime.lock().await;
        if runtime.tunnels.status(existing).state == TunnelState::Running {
            return Err(format!(
                "profile '{}' is running; disconnect before editing",
                profile.id
            ));
        }
    }
    let config = net_manager_core::xray::generate_vless_config(vless_url.trim(), socks_port)
        .map_err(|e| format!("invalid VLESS URL: {e}"))?;
    let body = serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?;
    let import = state
        .config_vault
        .store_xray_config(&profile.id, &body)
        .map_err(|e| e.to_string())?;
    profile.config_path = import.config_path.clone();
    let doc = match state.profiles.upsert(profile) {
        Ok(doc) => doc,
        Err(err) => {
            let _ = state
                .config_vault
                .remove_revision_for_config(&import.config_path);
            return Err(err.to_string());
        }
    };
    if let Some(existing) = stored {
        if existing.config_path != import.config_path {
            remove_managed_revision(
                &state.config_vault,
                &existing.id,
                &existing.config_path,
                "profile saved",
            )?;
        }
    }
    Ok(doc.profiles)
}

#[tauri::command]
async fn is_elevated() -> Result<bool, String> {
    elevation::is_elevated().map_err(|e| e.to_string())
}

#[tauri::command]
async fn restart_elevated(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if elevation::is_elevated().map_err(|e| e.to_string())? {
        return Ok(());
    }
    elevation::restart_elevated().map_err(|e| e.to_string())?;
    state.cleanup_complete.store(true, Ordering::SeqCst);
    app.exit(0);
    Ok(())
}

struct DiagnosticsInput {
    profile: Profile,
    status: TunnelStatus,
    managed: bool,
    inspection: Option<ProfileInspection>,
    inspection_error: Option<String>,
    executable: Result<PathBuf, String>,
    interfaces: Result<Vec<NetworkInterface>, String>,
    os_routes: Result<Vec<RouteEntry>, String>,
    owned_routes: Option<Vec<AppliedRoute>>,
}

fn diag_check(name: &str, level: DiagnosticLevel, message: String) -> DiagnosticCheck {
    DiagnosticCheck {
        name: name.to_string(),
        level,
        message,
    }
}

fn applied_route_present(applied: &AppliedRoute, entry: &RouteEntry) -> bool {
    applied.interface_index == entry.interface_index
        && entry.destination == applied.destination.network()
        && entry.prefix_len == applied.destination.prefix_len()
}

fn resolve_backend_executable(profile: &Profile) -> Result<PathBuf, String> {
    match profile.backend {
        TunnelBackend::WireGuard => {
            vpn::resolve_wireguard_executable(None).map_err(|e| e.to_string())
        }
        TunnelBackend::OpenVpn => vpn::resolve_openvpn_executable(None).map_err(|e| e.to_string()),
        TunnelBackend::Xray => vpn::resolve_xray_executable(None).map_err(|e| e.to_string()),
    }
}

fn build_diagnostics(input: &DiagnosticsInput) -> Vec<DiagnosticCheck> {
    let mut checks = Vec::new();
    let profile = &input.profile;

    checks.push(match &input.inspection {
        None => diag_check(
            "Configuration",
            DiagnosticLevel::Error,
            format!(
                "configuration could not be read or analyzed: {}",
                input.inspection_error.as_deref().unwrap_or("unknown error")
            ),
        ),
        Some(_) if input.managed => diag_check(
            "Configuration",
            DiagnosticLevel::Healthy,
            "configuration is stored in managed storage".to_string(),
        ),
        Some(_) => diag_check(
            "Configuration",
            DiagnosticLevel::Warning,
            "Resave this profile to import it into managed storage".to_string(),
        ),
    });

    checks.push(match &input.executable {
        Ok(path) => diag_check(
            "Backend executable",
            DiagnosticLevel::Healthy,
            format!("found {}", path.display()),
        ),
        Err(err) => diag_check("Backend executable", DiagnosticLevel::Error, err.clone()),
    });

    const STATUS_NOTE: &str = "process/service state only, not handshake verification";
    checks.push(match input.status.state {
        TunnelState::Running => diag_check(
            "Tunnel status",
            DiagnosticLevel::Healthy,
            format!("running ({STATUS_NOTE})"),
        ),
        TunnelState::Stopped => diag_check(
            "Tunnel status",
            DiagnosticLevel::Warning,
            format!("stopped ({STATUS_NOTE})"),
        ),
        TunnelState::Failed => diag_check(
            "Tunnel status",
            DiagnosticLevel::Error,
            format!(
                "failed: {} ({STATUS_NOTE})",
                input.status.message.as_deref().unwrap_or("unknown error")
            ),
        ),
    });

    match &input.inspection {
        None => checks.push(diag_check(
            "Static analysis",
            DiagnosticLevel::Warning,
            "static analysis unavailable".to_string(),
        )),
        Some(inspection) => {
            let warning_count = inspection.analysis.warnings.len();
            let conflict_count = inspection.conflicts.len();
            let incomplete = !inspection.analysis.route_knowledge_complete;
            if warning_count + conflict_count == 0 && !incomplete {
                checks.push(diag_check(
                    "Static analysis",
                    DiagnosticLevel::Healthy,
                    "no warnings or conflicts".to_string(),
                ));
            } else {
                let mut details: Vec<String> = inspection.analysis.warnings.clone();
                details.extend(inspection.conflicts.iter().map(|c| c.message.clone()));
                if incomplete {
                    details.push("effective routes are not fully known".to_string());
                }
                checks.push(diag_check(
                    "Static analysis",
                    DiagnosticLevel::Warning,
                    format!(
                        "{warning_count} warning(s), {conflict_count} conflict(s): {}",
                        details.join("; ")
                    ),
                ));
            }
        }
    }

    if !profile.routes.is_empty() {
        let check = match &input.interfaces {
            Err(err) => diag_check(
                "Target interface",
                DiagnosticLevel::Error,
                format!("cannot list interfaces: {err}"),
            ),
            Ok(interfaces) => match interfaces.iter().find(|i| {
                i.friendly_name == profile.interface_name || i.name == profile.interface_name
            }) {
                Some(i) if matches!(i.state, InterfaceState::Up) => diag_check(
                    "Target interface",
                    DiagnosticLevel::Healthy,
                    format!("interface '{}' is up", profile.interface_name),
                ),
                Some(_) => diag_check(
                    "Target interface",
                    DiagnosticLevel::Error,
                    format!("interface '{}' is not up", profile.interface_name),
                ),
                None => diag_check(
                    "Target interface",
                    DiagnosticLevel::Error,
                    format!("interface '{}' not found", profile.interface_name),
                ),
            },
        };
        checks.push(check);
    }

    if profile.routes.is_empty() {
        checks.push(diag_check(
            "Applied routes",
            DiagnosticLevel::Healthy,
            "No app-managed routes".to_string(),
        ));
    } else {
        let check = match &input.owned_routes {
            None => diag_check(
                "Applied routes",
                if input.status.state == TunnelState::Running {
                    DiagnosticLevel::Error
                } else {
                    DiagnosticLevel::Warning
                },
                "app-managed routes not applied".to_string(),
            ),
            Some(routes) => match &input.os_routes {
                Err(err) => diag_check(
                    "Applied routes",
                    DiagnosticLevel::Error,
                    format!("cannot list OS routes: {err}"),
                ),
                Ok(entries) => {
                    let missing: Vec<String> = routes
                        .iter()
                        .filter(|r| !entries.iter().any(|e| applied_route_present(r, e)))
                        .map(|r| r.destination.to_string())
                        .collect();
                    if missing.is_empty() {
                        diag_check(
                            "Applied routes",
                            DiagnosticLevel::Healthy,
                            format!("{} managed route(s) present", routes.len()),
                        )
                    } else {
                        diag_check(
                            "Applied routes",
                            DiagnosticLevel::Error,
                            format!("missing OS routes: {}", missing.join(", ")),
                        )
                    }
                }
            },
        };
        checks.push(check);
    }

    if let Some(inspection) = &input.inspection {
        if inspection.analysis.endpoints.is_empty() {
            checks.push(diag_check(
                "Endpoints",
                DiagnosticLevel::Warning,
                "no remote endpoints discovered in config".to_string(),
            ));
        } else {
            let list = inspection
                .analysis
                .endpoints
                .iter()
                .map(|e| match e.port {
                    Some(port) => format!("{}:{port}", e.address),
                    None => e.address.clone(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            checks.push(diag_check(
                "Endpoints",
                DiagnosticLevel::Healthy,
                format!(
                    "{} endpoint(s): {list}",
                    inspection.analysis.endpoints.len()
                ),
            ));
        }
        if profile.backend == TunnelBackend::Xray {
            if inspection.analysis.listeners.is_empty() {
                checks.push(diag_check(
                    "Listeners",
                    DiagnosticLevel::Warning,
                    "no inbound listeners discovered".to_string(),
                ));
            } else {
                let list = inspection
                    .analysis
                    .listeners
                    .iter()
                    .map(|l| format!("{}:{}", l.address, l.port))
                    .collect::<Vec<_>>()
                    .join(", ");
                checks.push(diag_check(
                    "Listeners",
                    DiagnosticLevel::Healthy,
                    format!("listeners: {list}"),
                ));
            }
        }
    }

    checks
}

#[tauri::command]
async fn inspect_profiles(state: State<'_, AppState>) -> Result<Vec<ProfileInspection>, String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let os_routes = explorer::list_routes().await.map_err(|e| e.to_string())?;
    let mut inspections = Vec::with_capacity(profiles.len());
    for profile in &profiles {
        let others: Vec<Profile> = profiles
            .iter()
            .filter(|o| o.id != profile.id)
            .cloned()
            .collect();
        inspections.push(build_profile_inspection(
            profile,
            &others,
            &os_routes,
            &state.config_vault,
        )?);
    }
    Ok(inspections)
}

#[tauri::command]
async fn diagnose_profile(
    id: String,
    state: State<'_, AppState>,
) -> Result<ProfileDiagnostics, String> {
    let profile = find_profile(&state.profiles, &id)?;
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let others: Vec<Profile> = profiles
        .iter()
        .filter(|o| o.id != profile.id)
        .cloned()
        .collect();
    let os_routes = explorer::list_routes().await.map_err(|e| e.to_string());
    let interfaces = explorer::list_interfaces().map_err(|e| e.to_string());
    let empty_routes: &[RouteEntry] = &[];
    let routes_ref = os_routes.as_deref().unwrap_or(empty_routes);
    let (inspection, inspection_error) =
        match build_profile_inspection(&profile, &others, routes_ref, &state.config_vault) {
            Ok(inspection) => (Some(inspection), None),
            Err(err) => (None, Some(err)),
        };
    let executable = resolve_backend_executable(&profile);
    let mut runtime = state.runtime.lock().await;
    let status = runtime.tunnels.status(&profile);
    let owned_routes = if runtime.policies.has_applied_profile(&id) {
        Some(runtime.policies.applied_for(&id).to_vec())
    } else {
        None
    };
    drop(runtime);
    let managed = state
        .config_vault
        .is_managed_profile_path(&profile.id, &profile.config_path);
    let checks = build_diagnostics(&DiagnosticsInput {
        profile: profile.clone(),
        status: status.clone(),
        managed,
        inspection: inspection.clone(),
        inspection_error,
        executable,
        interfaces,
        os_routes,
        owned_routes,
    });
    Ok(ProfileDiagnostics {
        profile_id: profile.id,
        status,
        inspection,
        checks,
    })
}

#[tauri::command]
async fn inspect_profile_by_id(
    id: String,
    state: State<'_, AppState>,
) -> Result<ProfileInspection, String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let candidate = profiles
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| format!("profile '{id}' not found"))?;
    let others: Vec<Profile> = profiles.into_iter().filter(|p| p.id != id).collect();
    let os_routes = explorer::list_routes().await.map_err(|e| e.to_string())?;
    build_profile_inspection(&candidate, &others, &os_routes, &state.config_vault)
}

#[tauri::command]
async fn get_tunnel_statuses(state: State<'_, AppState>) -> Result<Vec<TunnelStatus>, String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let mut runtime = state.runtime.lock().await;
    Ok(profiles
        .iter()
        .map(|profile| runtime.tunnels.status(profile))
        .collect())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let store = ProfileStore::new(data_dir.join("profiles.json"));
            let applied_routes = AppliedRouteStore::new(data_dir.join("applied-routes.json"));
            let mut policies = PolicyManager::new();
            policies.restore(applied_routes.load()?.profiles)?;
            app.manage(AppState {
                profiles: store,
                config_vault: ConfigVault::new(data_dir.join("configs")),
                applied_routes,
                shutting_down: AtomicBool::new(false),
                cleanup_complete: AtomicBool::new(false),
                runtime: tokio::sync::Mutex::new(RuntimeState {
                    tunnels: TunnelManager::new(),
                    policies,
                }),
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
            is_elevated,
            restart_elevated
        ])
        .on_window_event(|window, event| {
            let tauri::WindowEvent::CloseRequested { api, .. } = event else {
                return;
            };
            if window.label() != "main" {
                return;
            }
            let Some(state) = window.try_state::<AppState>() else {
                return;
            };
            if state.cleanup_complete.load(Ordering::SeqCst) {
                return;
            }
            api.prevent_close();
            if state.shutting_down.swap(true, Ordering::SeqCst) {
                return;
            }
            let window = window.clone();
            tauri::async_runtime::spawn(async move {
                let state = window.state::<AppState>();
                match cleanup_all(&state).await {
                    Ok(()) => {
                        state.cleanup_complete.store(true, Ordering::SeqCst);
                        let _ = window.close();
                    }
                    Err(err) => {
                        state.shutting_down.store(false, Ordering::SeqCst);
                        let _ = window.emit("shutdown-failed", err);
                    }
                }
            });
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            let tauri::RunEvent::ExitRequested { api, .. } = event else {
                return;
            };
            let Some(state) = app.try_state::<AppState>() else {
                return;
            };
            if state.cleanup_complete.load(Ordering::SeqCst) {
                return;
            }
            api.prevent_exit();
            if state.shutting_down.swap(true, Ordering::SeqCst) {
                return;
            }
            let handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let state = handle.state::<AppState>();
                match cleanup_all(&state).await {
                    Ok(()) => {
                        state.cleanup_complete.store(true, Ordering::SeqCst);
                        handle.exit(0);
                    }
                    Err(err) => {
                        state.shutting_down.store(false, Ordering::SeqCst);
                        let _ = handle.emit("shutdown-failed", err);
                    }
                }
            });
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-app-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn iface(name: &str, friendly_name: &str, state: InterfaceState) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            friendly_name: friendly_name.into(),
            kind: InterfaceKind::Other("test".into()),
            state,
            addresses: vec![],
            dns_servers: vec![],
            dns_suffix: None,
            mtu: None,
            if_index: 1,
            physical: true,
            mac: None,
            gateway: None,
            rx_bytes: None,
            tx_bytes: None,
            link_speed_mbps: None,
            category: InterfaceCategory::Physical,
            description: String::new(),
            if_type: 6,
            tunnel_type: None,
        }
    }

    fn profile(interface_name: &str) -> Profile {
        Profile {
            id: "p1".into(),
            name: "P1".into(),
            backend: TunnelBackend::WireGuard,
            config_path: PathBuf::from(r"C:\configs\p1.conf"),
            interface_name: interface_name.into(),
            routes: vec![],
            auto_connect: false,
            domain_policies: vec![],
            xray_socks_port: None,
        }
    }

    #[test]
    fn update_status_check_selects_stored_profile_backend() {
        let mut stored = profile("wg-work");
        stored.backend = TunnelBackend::WireGuard;
        let document = ProfileDocument {
            version: 1,
            profiles: vec![stored.clone()],
        };
        let mut incoming = stored.clone();
        incoming.backend = TunnelBackend::OpenVpn;

        let selected = existing_profile_for_update(&document, &incoming.id).unwrap();

        assert_eq!(selected.backend, TunnelBackend::WireGuard);
        assert_eq!(selected, &stored);
    }

    #[test]
    fn update_status_check_returns_none_for_new_profile() {
        let document = ProfileDocument {
            version: 1,
            profiles: vec![profile("wg-work")],
        };
        assert!(existing_profile_for_update(&document, "other-id").is_none());
    }

    #[test]
    fn target_interface_matches_exact_friendly_or_raw_name() {
        let p = profile("wg-work");
        let interfaces = vec![
            iface("if0", "wg-work", InterfaceState::Up),
            iface("if1", "other", InterfaceState::Up),
        ];
        assert!(has_target_interface(&p, &interfaces));

        let p_raw = profile("if1");
        assert!(has_target_interface(&p_raw, &interfaces));
    }

    #[test]
    fn target_interface_rejects_down_state() {
        let p = profile("wg-work");
        let interfaces = vec![iface("if0", "wg-work", InterfaceState::Down)];
        assert!(!has_target_interface(&p, &interfaces));
    }

    #[test]
    fn target_interface_rejects_substring_matches() {
        let p = profile("wg-work");
        let interfaces = vec![
            iface("wg-work-extra", "wg", InterfaceState::Up),
            iface("xwg-work", "my-wg-work-tunnel", InterfaceState::Up),
        ];
        assert!(!has_target_interface(&p, &interfaces));
    }

    fn os_route(dest: &str, prefix_len: u8) -> RouteEntry {
        RouteEntry {
            destination: dest.parse().unwrap(),
            prefix_len,
            gateway: None,
            interface_index: 5,
            interface_name: "Ethernet".into(),
            metric: 10,
        }
    }

    #[test]
    fn build_profile_inspection_reports_conflicts_warnings_and_managed_flag() {
        let dir = unique_dir("inspect");
        let vault = ConfigVault::new(dir.join("configs"));
        let a_cfg = dir.join("a.conf");
        fs::write(&a_cfg, "[Peer]\nAllowedIPs=10.0.0.0/24\n").unwrap();
        let b_cfg = dir.join("b.conf");
        fs::write(&b_cfg, "[Peer]\nAllowedIPs=10.0.0.0/8\n").unwrap();

        let mut candidate = profile("wg-a");
        candidate.id = "a".into();
        candidate.config_path = a_cfg;
        let mut other = profile("wg-b");
        other.id = "b".into();
        other.config_path = b_cfg;
        let mut broken = profile("wg-broken");
        broken.id = "broken".into();
        broken.name = "Broken One".into();
        broken.config_path = dir.join("missing.conf");

        let os = vec![os_route("0.0.0.0", 0), os_route("10.0.0.0", 16)];
        let inspection =
            build_profile_inspection(&candidate, &[other, broken], &os, &vault).unwrap();

        assert!(!inspection.managed_config);
        assert!(inspection.conflicts.iter().any(|c| {
            c.kind == ConflictKind::RouteOverlap
                && c.other_profile_id.as_deref() == Some("b")
                && !c.blocking
        }));
        assert!(inspection
            .conflicts
            .iter()
            .any(|c| { c.other_profile_id.is_none() && c.message.contains("10.0.0.0/24") }));
        assert!(inspection
            .analysis
            .warnings
            .iter()
            .any(|w| w.contains("Broken One") && w.contains("broken")));

        let stored = vault.store_xray_config("managed", b"{}").unwrap();
        let mut managed = profile("xray-1");
        managed.id = "managed".into();
        managed.backend = TunnelBackend::Xray;
        managed.config_path = stored.config_path;
        let inspection = build_profile_inspection(&managed, &[], &[], &vault).unwrap();
        assert!(inspection.managed_config);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn validate_managed_save_path_rejects_foreign_and_backend_swap() {
        let dir = unique_dir("managed-save");
        let vault = ConfigVault::new(dir.join("configs"));
        let source = dir.join("src.conf");
        fs::write(&source, b"[Interface]\n").unwrap();
        let import = vault
            .import("owner", TunnelBackend::WireGuard, &source)
            .unwrap();

        let mut incoming = profile("wg");
        incoming.id = "owner".into();
        incoming.config_path = import.config_path.clone();
        let stored = incoming.clone();

        assert!(
            validate_managed_save_path(&vault, Some(&stored), &incoming).is_ok(),
            "same profile, same backend, own managed path"
        );

        let mut foreign = incoming.clone();
        foreign.id = "other".into();
        let err = validate_managed_save_path(&vault, None, &foreign).unwrap_err();
        assert!(err.contains("different profile"), "{err}");

        let mut swapped = incoming.clone();
        swapped.backend = TunnelBackend::OpenVpn;
        let err = validate_managed_save_path(&vault, Some(&stored), &swapped).unwrap_err();
        assert!(err.contains("new source config"), "{err}");

        let mut external = profile("ext");
        external.config_path = dir.join("external.conf");
        assert!(validate_managed_save_path(&vault, None, &external).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn active_profile_conflicts_skips_non_running_profiles() {
        let mut tunnels = TunnelManager::new();
        let candidate = ConfigAnalysis {
            profile_id: "a".into(),
            os_routes: vec![AnalyzedRoute {
                destination: "10.0.0.0/8".parse().unwrap(),
                source: "test".into(),
            }],
            internal_routes: vec![],
            listeners: vec![],
            endpoints: vec![],
            domain_patterns: vec![],
            warnings: vec![],
            route_knowledge_complete: true,
        };
        let mut other = profile("wg-b");
        other.id = "b".into();
        other.config_path = PathBuf::from("nonexistent.conf");

        let conflicts = active_profile_conflicts(&mut tunnels, "a", &candidate, &[other]).unwrap();
        assert!(conflicts.is_empty());

        let same = active_profile_conflicts(&mut tunnels, "a", &candidate, &[candidate_profile()])
            .unwrap();
        assert!(same.is_empty());
    }

    fn candidate_profile() -> Profile {
        let mut p = profile("wg-a");
        p.id = "a".into();
        p
    }

    struct NoopExecutor;

    impl net_manager_core::policy::RouteExecutor for NoopExecutor {
        fn add_route(&mut self, _route: &AppliedRoute) -> std::io::Result<()> {
            Ok(())
        }

        fn remove_route(&mut self, _route: &AppliedRoute) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn persist_applied_routes_writes_registry_snapshot() {
        let dir = unique_dir("persist");
        let store = AppliedRouteStore::new(dir.join("applied-routes.json"));
        let mut policies = PolicyManager::with_executor(Box::new(NoopExecutor));
        let mut p = profile("wg-work");
        p.routes.push(PolicyRoute {
            destination: "10.5.0.0/24".parse().unwrap(),
            metric: 3,
        });
        policies
            .apply_profile(&p, &[iface("if0", "wg-work", InterfaceState::Up)])
            .unwrap();

        persist_applied_routes(&store, &policies).unwrap();

        let doc = store.load().unwrap();
        assert_eq!(doc.version, APPLIED_ROUTE_DOCUMENT_VERSION);
        assert_eq!(doc.profiles.len(), 1);
        assert_eq!(doc.profiles[0].profile_id, "p1");
        assert_eq!(doc.profiles[0].routes.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn vless_generation_errors_do_not_leak_uri() {
        let sentinel = "SENTINEL-UUID-7777";
        let err = net_manager_core::xray::generate_vless_config(
            &format!("vless://{sentinel}@:443?security=tls&sni=x"),
            10808,
        )
        .unwrap_err();
        assert!(!err.to_string().contains(sentinel));
        assert!(net_manager_core::xray::generate_vless_config(
            "vless://id@node.test:443?security=tls&sni=x",
            0,
        )
        .is_err());
    }

    fn app_state(dir: &Path) -> AppState {
        AppState {
            profiles: ProfileStore::new(dir.join("profiles.json")),
            config_vault: ConfigVault::new(dir.join("configs")),
            applied_routes: AppliedRouteStore::new(dir.join("applied-routes.json")),
            shutting_down: AtomicBool::new(false),
            cleanup_complete: AtomicBool::new(false),
            runtime: tokio::sync::Mutex::new(RuntimeState {
                tunnels: TunnelManager::new(),
                policies: PolicyManager::with_executor(Box::new(NoopExecutor)),
            }),
        }
    }

    #[tokio::test]
    async fn cleanup_all_removes_owned_routes_and_persists_empty_registry() {
        let dir = unique_dir("cleanup-all");
        let state = app_state(&dir);
        {
            let mut runtime = state.runtime.lock().await;
            runtime
                .policies
                .restore(vec![
                    AppliedProfileRoutes {
                        profile_id: "z".into(),
                        routes: vec![],
                    },
                    AppliedProfileRoutes {
                        profile_id: "a".into(),
                        routes: vec![AppliedRoute {
                            destination: "10.3.0.0/24".parse().unwrap(),
                            interface_index: 4,
                            metric: 10,
                        }],
                    },
                ])
                .unwrap();
        }
        cleanup_all(&state).await.unwrap();
        let runtime = state.runtime.lock().await;
        assert!(runtime.policies.applied_profile_ids().is_empty());
        drop(runtime);
        let loaded = state.applied_routes.load().unwrap();
        assert!(loaded.profiles.is_empty());
    }

    #[tokio::test]
    async fn cleanup_stale_clears_tracked_routes_and_persists_registry() {
        let dir = unique_dir("cleanup-stale");
        let state = app_state(&dir);
        let mut runtime = state.runtime.lock().await;
        runtime
            .policies
            .restore(vec![AppliedProfileRoutes {
                profile_id: "p1".into(),
                routes: vec![AppliedRoute {
                    destination: "10.4.0.0/24".parse().unwrap(),
                    interface_index: 5,
                    metric: 11,
                }],
            }])
            .unwrap();
        let p = profile("wg-p1");
        cleanup_stale_routes_before_connect(&state, &mut runtime, &p).unwrap();
        assert!(!runtime.policies.has_applied_profile("p1"));
        let loaded = state.applied_routes.load().unwrap();
        assert!(loaded.profiles.is_empty());
    }

    fn route_entry(dest: &str, prefix: u8, if_index: u32, metric: u32) -> RouteEntry {
        RouteEntry {
            destination: dest.parse().unwrap(),
            prefix_len: prefix,
            gateway: None,
            interface_index: if_index,
            interface_name: "if0".into(),
            metric,
        }
    }

    fn inspection_for(p: &Profile, managed: bool) -> ProfileInspection {
        ProfileInspection {
            analysis: ConfigAnalysis {
                profile_id: p.id.clone(),
                os_routes: vec![],
                internal_routes: vec![],
                listeners: vec![],
                endpoints: vec![],
                domain_patterns: vec![],
                warnings: vec![],
                route_knowledge_complete: true,
            },
            conflicts: vec![],
            managed_config: managed,
        }
    }

    fn diag_input(p: &Profile) -> DiagnosticsInput {
        DiagnosticsInput {
            profile: p.clone(),
            status: TunnelStatus {
                profile_id: p.id.clone(),
                state: TunnelState::Running,
                message: None,
            },
            managed: true,
            inspection: Some(inspection_for(p, true)),
            inspection_error: None,
            executable: Ok(PathBuf::from(r"C:\tools\wg.exe")),
            interfaces: Ok(vec![iface("if0", "if0", InterfaceState::Up)]),
            os_routes: Ok(vec![]),
            owned_routes: None,
        }
    }

    fn check_named<'a>(checks: &'a [DiagnosticCheck], name: &str) -> &'a DiagnosticCheck {
        checks.iter().find(|c| c.name == name).unwrap()
    }

    fn blank_analysis(id: &str) -> ConfigAnalysis {
        ConfigAnalysis {
            profile_id: id.into(),
            os_routes: vec![],
            internal_routes: vec![],
            listeners: vec![],
            endpoints: vec![],
            domain_patterns: vec![],
            warnings: vec![],
            route_knowledge_complete: true,
        }
    }

    #[test]
    fn unknown_route_conflicts_cover_uncertainty_both_directions() {
        let mut other = profile("ovpn-b");
        other.id = "b".into();
        other.name = "B".into();

        let mut complete_with_route = blank_analysis("a");
        complete_with_route.os_routes.push(AnalyzedRoute {
            destination: "10.0.0.0/8".parse().unwrap(),
            source: "test".into(),
        });
        let mut incomplete_other = blank_analysis("b");
        incomplete_other.route_knowledge_complete = false;

        let conflicts = unknown_route_conflicts(&complete_with_route, &other, &incomplete_other);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].blocking);
        assert!(conflicts[0].message.contains("'B'"));
        assert!(conflicts[0]
            .message
            .contains("effective routes are not fully known"));

        let mut incomplete_candidate = blank_analysis("a");
        incomplete_candidate.route_knowledge_complete = false;
        let mut known_other = blank_analysis("b");
        known_other.os_routes.push(AnalyzedRoute {
            destination: "10.0.0.0/8".parse().unwrap(),
            source: "test".into(),
        });
        let conflicts = unknown_route_conflicts(&incomplete_candidate, &other, &known_other);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].message.contains("not fully known"));
        assert!(conflicts[0].message.contains("'B'"));

        let mut both_incomplete_other = blank_analysis("b");
        both_incomplete_other.route_knowledge_complete = false;
        both_incomplete_other.os_routes.push(AnalyzedRoute {
            destination: "10.0.0.0/8".parse().unwrap(),
            source: "test".into(),
        });
        let conflicts =
            unknown_route_conflicts(&incomplete_candidate, &other, &both_incomplete_other);
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0]
            .message
            .contains("effective routes are not fully known"));
    }

    #[test]
    fn unknown_route_conflicts_skip_complete_candidate_without_routes() {
        let mut other = profile("ovpn-b");
        other.id = "b".into();
        other.name = "B".into();
        let candidate = blank_analysis("a");
        let mut incomplete_other = blank_analysis("b");
        incomplete_other.route_knowledge_complete = false;

        assert!(unknown_route_conflicts(&candidate, &other, &incomplete_other).is_empty());

        let mut known_other = blank_analysis("b");
        known_other.os_routes.push(AnalyzedRoute {
            destination: "10.0.0.0/8".parse().unwrap(),
            source: "test".into(),
        });
        assert!(unknown_route_conflicts(&candidate, &other, &known_other).is_empty());
    }

    #[test]
    fn foreign_managed_path_inspection_not_managed() {
        let dir = unique_dir("foreign-managed");
        let vault = ConfigVault::new(dir.join("configs"));
        let foreign_rev = vault.root().join("other").join("rev-1");
        fs::create_dir_all(&foreign_rev).unwrap();
        fs::write(foreign_rev.join("client.ovpn"), "[Interface]\n").unwrap();
        let mut p = profile("wg-c1");
        p.id = "c1".into();
        p.config_path = foreign_rev.join("client.ovpn");

        let inspection = build_profile_inspection(&p, &[], &[], &vault).unwrap();
        assert!(!inspection.managed_config);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn select_available_socks_port_skips_used_and_unavailable() {
        let used: HashSet<u16> = [10808, 10809].into_iter().collect();
        let port = select_available_socks_port(&used, |p| p != 10810).unwrap();
        assert_eq!(port, 10811);
        assert_eq!(
            select_available_socks_port(&HashSet::new(), |_| true).unwrap(),
            AUTO_SOCKS_PORT_START
        );
    }

    #[test]
    fn select_available_socks_port_errors_when_exhausted() {
        let err = select_available_socks_port(&HashSet::new(), |_| false).unwrap_err();
        assert!(err.contains("10808"), "{err}");
    }

    #[test]
    fn profile_listener_ports_collects_metadata_and_loopback_listeners() {
        let dir = unique_dir("listener-ports");
        let cfg = dir.join("other.json");
        fs::write(
            &cfg,
            r#"{"inbounds":[
                {"tag":"a","listen":"0.0.0.0","port":2080,"protocol":"socks"},
                {"tag":"b","listen":"192.168.1.5","port":2090,"protocol":"socks"}
            ]}"#,
        )
        .unwrap();
        let mut other = profile("x-other");
        other.id = "other".into();
        other.backend = TunnelBackend::Xray;
        other.config_path = cfg;
        other.xray_socks_port = Some(10809);
        let mut me = profile("x-me");
        me.id = "me".into();
        me.xray_socks_port = Some(10810);

        let used = profile_listener_ports(&[other, me], "me");
        assert!(used.contains(&10809));
        assert!(used.contains(&2080));
        assert!(!used.contains(&2090));
        assert!(!used.contains(&10810));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rewrite_generated_socks_port_creates_revision_and_rejects_ineligible() {
        let dir = unique_dir("rewrite-socks");
        let vault = ConfigVault::new(dir.join("configs"));
        let mut p = profile("x-gen");
        p.id = "gen".into();
        p.backend = TunnelBackend::Xray;
        p.xray_socks_port = Some(10808);
        let body = br#"{"inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":10808,"protocol":"socks"}]}"#;
        let import = vault.store_xray_config("gen", body).unwrap();
        p.config_path = import.config_path.clone();

        let new_path = rewrite_generated_socks_port(&vault, &mut p, 10950).unwrap();
        assert_ne!(new_path, import.config_path);
        assert_eq!(p.config_path, new_path);
        assert_eq!(p.xray_socks_port, Some(10950));
        assert!(import.config_path.exists());
        let text = fs::read_to_string(&new_path).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["inbounds"][0]["port"], 10950);
        assert_eq!(doc["inbounds"][0]["tag"], "socks-in");

        let mut bad = p.clone();
        fs::write(&new_path, "{oops").unwrap();
        assert!(rewrite_generated_socks_port(&vault, &mut bad, 10960).is_err());
        assert_eq!(bad.config_path, new_path);
        assert_eq!(bad.xray_socks_port, Some(10950));

        let mut ext = profile("x-ext");
        ext.backend = TunnelBackend::Xray;
        ext.xray_socks_port = Some(10808);
        let before = ext.config_path.clone();
        assert!(rewrite_generated_socks_port(&vault, &mut ext, 10960).is_err());
        assert_eq!(ext.config_path, before);
        assert_eq!(ext.xray_socks_port, Some(10808));

        let mut no_port = ext.clone();
        no_port.xray_socks_port = None;
        assert!(rewrite_generated_socks_port(&vault, &mut no_port, 10960).is_err());
        assert!(no_port.xray_socks_port.is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn diagnostics_static_analysis_marks_incomplete_route_knowledge() {
        let p = profile("wg-p1");
        let mut input = diag_input(&p);
        let mut inspection = inspection_for(&p, true);
        inspection.analysis.route_knowledge_complete = false;
        input.inspection = Some(inspection);
        let checks = build_diagnostics(&input);
        let static_check = check_named(&checks, "Static analysis");
        assert_eq!(static_check.level, DiagnosticLevel::Warning);
        assert!(static_check.message.contains("not fully known"));
    }

    #[test]
    fn diagnostics_healthy_managed_static() {
        let p = profile("wg-p1");
        let checks = build_diagnostics(&diag_input(&p));
        assert_eq!(
            check_named(&checks, "Configuration").level,
            DiagnosticLevel::Healthy
        );
        let exe = check_named(&checks, "Backend executable");
        assert_eq!(exe.level, DiagnosticLevel::Healthy);
        assert!(exe.message.contains("wg.exe"));
        let status = check_named(&checks, "Tunnel status");
        assert_eq!(status.level, DiagnosticLevel::Healthy);
        assert!(status.message.contains("not handshake verification"));
        assert_eq!(
            check_named(&checks, "Static analysis").level,
            DiagnosticLevel::Healthy
        );
        let applied = check_named(&checks, "Applied routes");
        assert_eq!(applied.level, DiagnosticLevel::Healthy);
        assert_eq!(applied.message, "No app-managed routes");
        assert!(checks.iter().all(|c| c.name != "Target interface"));
    }

    #[test]
    fn diagnostics_running_with_missing_applied_routes_is_error() {
        let mut p = profile("wg-p1");
        p.interface_name = "if0".into();
        p.routes = vec![PolicyRoute {
            destination: "10.9.0.0/24".parse().unwrap(),
            metric: 5,
        }];
        let mut input = diag_input(&p);
        input.owned_routes = Some(vec![AppliedRoute {
            destination: "10.9.0.0/24".parse().unwrap(),
            interface_index: 7,
            metric: 5,
        }]);
        let checks = build_diagnostics(&input);
        let applied = check_named(&checks, "Applied routes");
        assert_eq!(applied.level, DiagnosticLevel::Error);
        assert!(
            applied.message.contains("10.9.0.0/24"),
            "{}",
            applied.message
        );
    }

    #[test]
    fn diagnostics_applied_route_match_ignores_metric() {
        let mut p = profile("wg-p1");
        p.interface_name = "if0".into();
        p.routes = vec![PolicyRoute {
            destination: "10.9.0.0/24".parse().unwrap(),
            metric: 5,
        }];
        let mut input = diag_input(&p);
        input.owned_routes = Some(vec![AppliedRoute {
            destination: "10.9.0.0/24".parse().unwrap(),
            interface_index: 7,
            metric: 99,
        }]);
        input.os_routes = Ok(vec![route_entry("10.9.0.0", 24, 7, 1)]);
        let checks = build_diagnostics(&input);
        assert_eq!(
            check_named(&checks, "Applied routes").level,
            DiagnosticLevel::Healthy
        );
        input.os_routes = Ok(vec![route_entry("10.9.0.0", 24, 8, 1)]);
        let checks = build_diagnostics(&input);
        assert_eq!(
            check_named(&checks, "Applied routes").level,
            DiagnosticLevel::Error
        );
    }

    #[test]
    fn diagnostics_xray_lists_endpoints_and_listeners() {
        let mut p = profile("x1");
        p.backend = TunnelBackend::Xray;
        let mut input = diag_input(&p);
        let mut inspection = inspection_for(&p, true);
        inspection.analysis.endpoints = vec![RemoteEndpoint {
            address: "node.test".into(),
            port: Some(443),
            protocol: "vless".into(),
        }];
        inspection.analysis.listeners = vec![LocalListener {
            address: "127.0.0.1".into(),
            port: 10808,
            protocol: "socks".into(),
        }];
        input.inspection = Some(inspection);
        let checks = build_diagnostics(&input);
        let endpoints = check_named(&checks, "Endpoints");
        assert_eq!(endpoints.level, DiagnosticLevel::Healthy);
        assert!(endpoints.message.contains("node.test:443"));
        let listeners = check_named(&checks, "Listeners");
        assert_eq!(listeners.level, DiagnosticLevel::Healthy);
        assert!(listeners.message.contains("127.0.0.1:10808"));
    }
}
