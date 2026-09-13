use crate::commands::diagnostics::applied_route_present;
use crate::lifecycle::cleanup_all;
use crate::state::AppState;
use net_manager_core::explorer;
use net_manager_core::models::*;
use tauri::{Emitter, State};

pub(crate) fn build_recovery_report(
    profiles: &[Profile],
    statuses: &[(String, TunnelStatus)],
    ownership: &[AppliedProfileRoutes],
    os_routes: &[RouteEntry],
) -> RecoveryReport {
    let mut issues = Vec::new();
    for (profile_id, status) in statuses {
        let Some(profile) = profiles.iter().find(|p| &p.id == profile_id) else {
            continue;
        };
        if profile.backend != TunnelBackend::WireGuard {
            continue;
        }
        match status.state {
            TunnelState::Running => issues.push(RecoveryIssue {
                kind: RecoveryIssueKind::SurvivingWireGuardService,
                profile_id: Some(profile_id.clone()),
                message: format!(
                    "WireGuard tunnel service for profile '{}' ('{}') may still be installed",
                    profile.id, profile.name
                ),
            }),
            TunnelState::Failed => issues.push(RecoveryIssue {
                kind: RecoveryIssueKind::StatusCheckFailed,
                profile_id: Some(profile_id.clone()),
                message: format!(
                    "status check failed for profile '{}' ('{}'): {}",
                    profile.id,
                    profile.name,
                    status.message.as_deref().unwrap_or("unknown error")
                ),
            }),
            TunnelState::Stopped => {}
        }
    }
    for record in ownership {
        if !profiles.iter().any(|p| p.id == record.profile_id) {
            issues.push(RecoveryIssue {
                kind: RecoveryIssueKind::OrphanRouteOwnership,
                profile_id: Some(record.profile_id.clone()),
                message: format!(
                    "route ownership is recorded for profile '{}' but the profile no longer exists",
                    record.profile_id
                ),
            });
            continue;
        }
        let missing: Vec<String> = record
            .routes
            .iter()
            .filter(|r| !os_routes.iter().any(|e| applied_route_present(r, e)))
            .map(|r| r.destination.to_string())
            .collect();
        if !record.routes.is_empty() && missing.is_empty() {
            issues.push(RecoveryIssue {
                kind: RecoveryIssueKind::OwnedRoutes,
                profile_id: Some(record.profile_id.clone()),
                message: format!(
                    "{} route(s) owned by profile '{}' are still present in the route table",
                    record.routes.len(),
                    record.profile_id
                ),
            });
        } else {
            let detail = if missing.is_empty() {
                format!("{} route(s)", record.routes.len())
            } else {
                missing.join(", ")
            };
            issues.push(RecoveryIssue {
                kind: RecoveryIssueKind::MissingOwnedRoutes,
                profile_id: Some(record.profile_id.clone()),
                message: format!(
                    "route(s) owned by profile '{}' are missing from the route table: {detail}",
                    record.profile_id
                ),
            });
        }
    }
    RecoveryReport {
        requires_elevation: !issues.is_empty(),
        issues,
    }
}

async fn collect_report(state: &AppState) -> Result<RecoveryReport, String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let os_routes = explorer::list_routes().await.map_err(|e| e.to_string())?;
    let mut runtime = state.runtime.lock().await;
    let statuses: Vec<(String, TunnelStatus)> = profiles
        .iter()
        .map(|p| (p.id.clone(), runtime.tunnels.status(p)))
        .collect();
    let ownership = runtime.policies.snapshot();
    drop(runtime);
    Ok(build_recovery_report(
        &profiles, &statuses, &ownership, &os_routes,
    ))
}

#[tauri::command]
pub(crate) async fn get_recovery_report(
    state: State<'_, AppState>,
) -> Result<RecoveryReport, String> {
    collect_report(&state).await
}

#[tauri::command]
pub(crate) async fn cleanup_recovery(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<RecoveryReport, String> {
    cleanup_all(&state).await?;
    let _ = app.emit("route-changed", ());
    collect_report(&state).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    fn owned(profile_id: &str, dest: &str, if_index: u32) -> AppliedProfileRoutes {
        AppliedProfileRoutes {
            profile_id: profile_id.into(),
            routes: vec![AppliedRoute {
                destination: dest.parse().unwrap(),
                interface_index: if_index,
                metric: 10,
            }],
        }
    }

    fn status(profile_id: &str, state: TunnelState) -> (String, TunnelStatus) {
        (
            profile_id.to_string(),
            TunnelStatus {
                profile_id: profile_id.into(),
                state,
                message: None,
            },
        )
    }

    #[test]
    fn running_wireguard_and_owned_routes_produce_two_issues() {
        let profiles = vec![profile("wg-work")];
        let statuses = vec![status("p1", TunnelState::Running)];
        let ownership = vec![owned("p1", "10.1.0.0/24", 5)];
        let os_routes = vec![route_entry("10.1.0.0", 24, 5, 99)];

        let report = build_recovery_report(&profiles, &statuses, &ownership, &os_routes);

        assert!(report.requires_elevation);
        assert_eq!(report.issues.len(), 2);
        assert_eq!(
            report.issues[0].kind,
            RecoveryIssueKind::SurvivingWireGuardService
        );
        assert_eq!(report.issues[1].kind, RecoveryIssueKind::OwnedRoutes);
        assert_eq!(report.issues[1].profile_id.as_deref(), Some("p1"));
    }

    #[test]
    fn missing_owned_route_produces_missing_issue() {
        let profiles = vec![profile("wg-work")];
        let statuses = vec![status("p1", TunnelState::Stopped)];
        let ownership = vec![owned("p1", "10.1.0.0/24", 5)];

        let report = build_recovery_report(&profiles, &statuses, &ownership, &[]);

        assert!(report.requires_elevation);
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].kind, RecoveryIssueKind::MissingOwnedRoutes);
        assert!(report.issues[0].message.contains("10.1.0.0/24"));
    }

    #[test]
    fn ownership_without_profile_produces_orphan_issue() {
        let profiles = vec![profile("wg-work")];
        let statuses = vec![status("p1", TunnelState::Stopped)];
        let ownership = vec![owned("gone", "10.1.0.0/24", 5)];
        let os_routes = vec![route_entry("10.1.0.0", 24, 5, 10)];

        let report = build_recovery_report(&profiles, &statuses, &ownership, &os_routes);

        assert_eq!(report.issues.len(), 1);
        assert_eq!(
            report.issues[0].kind,
            RecoveryIssueKind::OrphanRouteOwnership
        );
        assert_eq!(report.issues[0].profile_id.as_deref(), Some("gone"));
    }

    #[test]
    fn stopped_profiles_without_ownership_produce_empty_report() {
        let profiles = vec![profile("wg-work")];
        let statuses = vec![status("p1", TunnelState::Stopped)];

        let report = build_recovery_report(&profiles, &statuses, &[], &[]);

        assert!(report.issues.is_empty());
        assert!(!report.requires_elevation);
    }

    #[test]
    fn failed_wireguard_status_produces_status_check_failed() {
        let profiles = vec![profile("wg-work")];
        let mut failed = status("p1", TunnelState::Failed);
        failed.1.message = Some("service query failed".into());

        let report = build_recovery_report(&profiles, &[failed], &[], &[]);

        assert!(report.requires_elevation);
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].kind, RecoveryIssueKind::StatusCheckFailed);
        assert!(report.issues[0].message.contains("service query failed"));
    }
}
