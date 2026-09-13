use crate::commands::profiles::{
    loopback_port_available, profile_listener_ports, remove_managed_revision,
    rewrite_generated_socks_port, select_available_socks_port,
};
use crate::state::{find_profile, persist_applied_routes, AppState, RuntimeState};
use net_manager_core::analysis;
use net_manager_core::explorer;
use net_manager_core::models::*;
use net_manager_core::vpn::TunnelManager;
use std::io::ErrorKind;
use tauri::{Emitter, State};

fn has_target_interface(profile: &Profile, interfaces: &[NetworkInterface]) -> bool {
    interfaces.iter().any(|iface| {
        matches!(iface.state, InterfaceState::Up)
            && (iface.friendly_name == profile.interface_name
                || iface.name == profile.interface_name)
    })
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
pub(crate) async fn connect_profile(
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
pub(crate) async fn disconnect_profile(
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
pub(crate) async fn get_tunnel_statuses(
    state: State<'_, AppState>,
) -> Result<Vec<TunnelStatus>, String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let mut runtime = state.runtime.lock().await;
    Ok(profiles
        .iter()
        .map(|profile| runtime.tunnels.status(profile))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

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

    #[test]
    fn active_profile_conflicts_skips_non_running_profiles() {
        let mut tunnels = TunnelManager::new();
        let candidate = ConfigAnalysis {
            profile_id: "a".into(),
            os_routes: vec![AnalyzedRoute {
                metric: None,
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
        other.config_path = std::path::PathBuf::from("nonexistent.conf");

        let conflicts = active_profile_conflicts(&mut tunnels, "a", &candidate, &[other]).unwrap();
        assert!(conflicts.is_empty());

        let same = active_profile_conflicts(&mut tunnels, "a", &candidate, &[candidate_profile()])
            .unwrap();
        assert!(same.is_empty());
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

    #[test]
    fn unknown_route_conflicts_cover_uncertainty_both_directions() {
        let mut other = profile("ovpn-b");
        other.id = "b".into();
        other.name = "B".into();

        let mut complete_with_route = blank_analysis("a");
        complete_with_route.os_routes.push(AnalyzedRoute {
            metric: None,
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
            metric: None,
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
            metric: None,
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
            metric: None,
            destination: "10.0.0.0/8".parse().unwrap(),
            source: "test".into(),
        });
        assert!(unknown_route_conflicts(&candidate, &other, &known_other).is_empty());
    }
}
