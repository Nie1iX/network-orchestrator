use crate::state::{find_profile, AppState};
use net_manager_core::analysis;
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::explorer;
use net_manager_core::models::*;
use std::path::PathBuf;
use tauri::State;

pub(crate) struct DiagnosticsInput {
    pub(crate) profile: Profile,
    pub(crate) status: TunnelStatus,
    pub(crate) managed: bool,
    pub(crate) inspection: Option<ProfileInspection>,
    pub(crate) inspection_error: Option<String>,
    pub(crate) executable: Result<PathBuf, String>,
    pub(crate) interfaces: Result<Vec<NetworkInterface>, String>,
    pub(crate) os_routes: Result<Vec<RouteEntry>, String>,
    pub(crate) owned_routes: Option<Vec<AppliedRoute>>,
    pub(crate) protocol_health: ProtocolHealth,
    pub(crate) proxy_owner: Option<String>,
}

fn diag_check(name: &str, level: DiagnosticLevel, message: String) -> DiagnosticCheck {
    DiagnosticCheck {
        name: name.to_string(),
        level,
        message,
    }
}

pub(crate) fn applied_route_present(applied: &AppliedRoute, entry: &RouteEntry) -> bool {
    applied.interface_index == entry.interface_index
        && entry.destination == applied.destination.network()
        && entry.prefix_len == applied.destination.prefix_len()
}

fn resolve_backend_executable(state: &AppState, profile: &Profile) -> Result<PathBuf, String> {
    if profile.backend == TunnelBackend::None {
        return Ok(PathBuf::new());
    }
    state
        .resolve_backend_executable(profile.backend)
        .map(|resolved| resolved.path)
        .map_err(|e| e.to_string())
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
        Some(_) if input.managed => {
            let dpapi_protected = profile
                .config_path
                .file_name()
                .map(|name| {
                    name.to_string_lossy()
                        .to_lowercase()
                        .ends_with(".json.dpapi")
                })
                .unwrap_or(false);
            diag_check(
                "Configuration",
                DiagnosticLevel::Healthy,
                if dpapi_protected {
                    "managed configuration is DPAPI protected".to_string()
                } else {
                    "configuration is stored in managed storage".to_string()
                },
            )
        }
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

    let health = &input.protocol_health;
    checks.push(diag_check(
        "Protocol health",
        match health.state {
            ProtocolHealthState::Healthy => DiagnosticLevel::Healthy,
            ProtocolHealthState::Degraded => DiagnosticLevel::Warning,
            ProtocolHealthState::Failed => DiagnosticLevel::Error,
            ProtocolHealthState::Unknown => DiagnosticLevel::Warning,
        },
        health.summary.clone(),
    ));
    if let Some(tail) = health.log_tail.as_ref().filter(|t| !t.trim().is_empty()) {
        checks.push(diag_check(
            "Runtime log",
            if matches!(
                health.state,
                ProtocolHealthState::Failed | ProtocolHealthState::Degraded
            ) {
                DiagnosticLevel::Warning
            } else {
                DiagnosticLevel::Healthy
            },
            tail.clone(),
        ));
    }

    if !health.pushed_routes.is_empty() {
        let list = health
            .pushed_routes
            .iter()
            .map(|r| r.destination.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        checks.push(diag_check(
            "Pushed routes",
            DiagnosticLevel::Healthy,
            format!(
                "{} server-pushed route(s): {list}",
                health.pushed_routes.len()
            ),
        ));
    }

    if profile.use_system_proxy || input.proxy_owner.is_some() {
        let check = match &input.proxy_owner {
            Some(owner) if owner == &profile.id => {
                if input.status.state == TunnelState::Running {
                    diag_check(
                        "System proxy",
                        DiagnosticLevel::Healthy,
                        "system proxy is applied for this profile (127.0.0.1 SOCKS5)".to_string(),
                    )
                } else {
                    diag_check(
                        "System proxy",
                        DiagnosticLevel::Error,
                        "stale ownership: system proxy still applied while the profile is not running".to_string(),
                    )
                }
            }
            Some(owner) => diag_check(
                "System proxy",
                DiagnosticLevel::Error,
                format!("system proxy is owned by another profile '{owner}'"),
            ),
            None if profile.use_system_proxy => diag_check(
                "System proxy",
                DiagnosticLevel::Warning,
                "system proxy is configured but not currently applied".to_string(),
            ),
            None => diag_check(
                "System proxy",
                DiagnosticLevel::Warning,
                "stale system proxy record without a known owner".to_string(),
            ),
        };
        checks.push(check);
    }

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

#[tauri::command]
pub(crate) async fn inspect_profiles(
    state: State<'_, AppState>,
) -> Result<Vec<ProfileInspection>, String> {
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
pub(crate) async fn diagnose_profile(
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
    let executable = resolve_backend_executable(&state, &profile);
    let mut runtime = state.runtime.lock().await;
    let status = runtime.tunnels.status(&profile);
    let protocol_health = runtime.tunnels.protocol_health(&profile);
    let owned_routes = if runtime.policies.has_applied_profile(&id) {
        Some(runtime.policies.applied_for(&id).to_vec())
    } else {
        None
    };
    let proxy_owner = runtime.proxy.ownership().map(|o| o.profile_id.clone());
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
        protocol_health,
        proxy_owner,
    });
    Ok(ProfileDiagnostics {
        profile_id: profile.id,
        status,
        inspection,
        checks,
    })
}

#[tauri::command]
pub(crate) async fn inspect_profile_by_id(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use std::fs;

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
    fn diagnostics_maps_system_proxy_states() {
        let mut p = profile("xray-p1");
        p.backend = TunnelBackend::Xray;
        p.use_system_proxy = true;
        p.xray_socks_port = Some(10808);

        let mut input = diag_input(&p);
        input.proxy_owner = Some(p.id.clone());
        let checks = build_diagnostics(&input);
        assert_eq!(
            check_named(&checks, "System proxy").level,
            DiagnosticLevel::Healthy
        );

        let mut stale = diag_input(&p);
        stale.status.state = TunnelState::Stopped;
        stale.proxy_owner = Some(p.id.clone());
        let checks = build_diagnostics(&stale);
        let check = check_named(&checks, "System proxy");
        assert_eq!(check.level, DiagnosticLevel::Error);
        assert!(check.message.contains("stale"));

        let mut other = diag_input(&p);
        other.proxy_owner = Some("other-id".into());
        let checks = build_diagnostics(&other);
        let check = check_named(&checks, "System proxy");
        assert_eq!(check.level, DiagnosticLevel::Error);
        assert!(check.message.contains("other-id"));

        let checks = build_diagnostics(&diag_input(&p));
        let check = check_named(&checks, "System proxy");
        assert_eq!(check.level, DiagnosticLevel::Warning);
        assert!(check.message.contains("not currently applied"));

        let plain = profile("wg-p1");
        let checks = build_diagnostics(&diag_input(&plain));
        assert!(checks.iter().all(|c| c.name != "System proxy"));
    }

    #[test]
    fn diagnostics_maps_protocol_health_and_runtime_log() {
        let p = profile("xray-p1");
        let mut input = diag_input(&p);
        input.protocol_health = ProtocolHealth {
            state: ProtocolHealthState::Degraded,
            summary: "process running; connection not confirmed".into(),
            last_handshake_unix: None,
            rx_bytes: None,
            tx_bytes: None,
            log_tail: Some("redacted tail".into()),
            pushed_routes: Vec::new(),
        };
        let checks = build_diagnostics(&input);
        let health = check_named(&checks, "Protocol health");
        assert_eq!(health.level, DiagnosticLevel::Warning);
        assert_eq!(health.message, "process running; connection not confirmed");
        let log = check_named(&checks, "Runtime log");
        assert_eq!(log.level, DiagnosticLevel::Warning);
        assert_eq!(log.message, "redacted tail");

        input.protocol_health = ProtocolHealth {
            state: ProtocolHealthState::Healthy,
            summary: "ok".into(),
            last_handshake_unix: None,
            rx_bytes: None,
            tx_bytes: None,
            log_tail: None,
            pushed_routes: Vec::new(),
        };
        let checks = build_diagnostics(&input);
        assert_eq!(
            check_named(&checks, "Protocol health").level,
            DiagnosticLevel::Healthy
        );
        assert!(checks.iter().all(|c| c.name != "Runtime log"));
    }

    #[test]
    fn diagnostics_reports_dpapi_protected_managed_config() {
        let mut p = profile("xray-p1");
        p.config_path = PathBuf::from(r"C:\vault\xray-p1\rev-1\config.json.dpapi");
        let checks = build_diagnostics(&diag_input(&p));
        assert_eq!(
            check_named(&checks, "Configuration").message,
            "managed configuration is DPAPI protected"
        );
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
