use crate::state::AppState;
use net_manager_core::models::*;
use std::sync::atomic::Ordering;
use tauri::{Emitter, Manager};

pub(crate) async fn cleanup_all(state: &AppState) -> Result<(), String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    let mut runtime = state.runtime.lock().await;
    let mut errors: Vec<String> = Vec::new();
    if let Err(err) = runtime.proxy.restore_any() {
        errors.push(format!("system proxy: {err}"));
    }
    match runtime.routes.applied_profile_ids().await {
        Ok(ids) => {
            for id in ids {
                if let Err(err) = runtime.routes.remove_profile(&id).await {
                    errors.push(format!("routes for '{id}': {err}"));
                }
            }
        }
        Err(err) => errors.push(format!("route ownership: {err}")),
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

#[cfg(target_os = "linux")]
pub(crate) async fn disconnect_all(
    state: &AppState,
    client: &crate::daemon_client::DaemonClient,
) -> Result<(), String> {
    use net_manager_core::daemon_protocol::{method, CleanupResult};

    let mut errors = Vec::new();
    match client
        .request::<_, CleanupResult>(method::RECOVERY_CLEANUP, serde_json::Value::Null)
        .await
    {
        Ok(result) if !result.failed.is_empty() => errors.push(format!(
            "daemon could not disconnect {} owner(s)",
            result.failed.len()
        )),
        Ok(_) => {}
        Err(err) => errors.push(format!(
            "daemon cleanup: {}",
            crate::daemon_client::user_message(&err)
        )),
    }
    if let Err(err) = stop_local_tunnels(state).await {
        errors.push(err);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Stop the tunnels this UI process runs itself; daemon owners are untouched.
#[cfg(target_os = "linux")]
async fn stop_local_tunnels(state: &AppState) -> Result<(), String> {
    let document = state
        .profiles
        .load()
        .map_err(|_| "cannot read profiles for local cleanup".to_string())?;
    let mut runtime = state.runtime.lock().await;
    let mut failed = false;
    for profile in &document.profiles {
        if profile.backend == TunnelBackend::WireGuard
            || (profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun)
        {
            continue;
        }
        if runtime.tunnels.status(profile).state == TunnelState::Running
            && runtime.tunnels.disconnect(profile).is_err()
        {
            failed = true;
        }
    }
    if failed {
        Err("local process cleanup failed".to_string())
    } else {
        Ok(())
    }
}

/// Cleanup before the UI process exits. On Linux daemon owners outlive the
/// UI, so only UI-owned processes are stopped, best effort: a failure must
/// not block Quit (the children also get SIGTERM when the UI dies).
async fn exit_cleanup(state: &AppState) -> Result<(), String> {
    if should_cleanup_on_ui_exit() {
        return cleanup_all(state).await;
    }
    #[cfg(target_os = "linux")]
    let _ = stop_local_tunnels(state).await;
    Ok(())
}

fn should_cleanup_on_ui_exit() -> bool {
    !cfg!(target_os = "linux")
}

#[cfg(target_os = "linux")]
fn should_hide_on_close(tray_created: bool) -> bool {
    cfg!(target_os = "linux") && tray_created
}

pub(crate) fn handle_window_event(window: &tauri::Window, event: &tauri::WindowEvent) {
    let tauri::WindowEvent::CloseRequested { api, .. } = event else {
        return;
    };
    if window.label() != "main" {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        if should_hide_on_close(
            window
                .app_handle()
                .tray_by_id(crate::tray::TRAY_ID)
                .is_some(),
        ) && window.hide().is_ok()
        {
            api.prevent_close();
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if !should_cleanup_on_ui_exit() {
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
    }
}

pub(crate) fn handle_run_event(app: &tauri::AppHandle, event: tauri::RunEvent) {
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
        match exit_cleanup(&state).await {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_ui_exit_does_not_cleanup_daemon_owners() {
        assert!(!should_cleanup_on_ui_exit());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_close_hides_only_when_tray_was_created() {
        assert!(!should_hide_on_close(false));
        assert!(should_hide_on_close(true));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_ui_exit_keeps_cleanup() {
        assert!(should_cleanup_on_ui_exit());
    }

    #[tokio::test]
    #[cfg_attr(not(target_os = "linux"), allow(irrefutable_let_patterns))]
    async fn cleanup_all_removes_owned_routes_and_persists_empty_registry() {
        let dir = unique_dir("cleanup-all");
        let state = app_state(&dir);
        {
            let mut runtime = state.runtime.lock().await;
            if let crate::route_runtime::RouteRuntime::Local { policies, .. } = &mut runtime.routes
            {
                policies
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
                                gateway: None,
                                table: None,
                            }],
                        },
                    ])
                    .unwrap();
            }
        }
        cleanup_all(&state).await.unwrap();
        let mut runtime = state.runtime.lock().await;
        assert!(runtime
            .routes
            .applied_profile_ids()
            .await
            .unwrap()
            .is_empty());
        drop(runtime);
        let loaded =
            net_manager_core::route_state::AppliedRouteStore::new(dir.join("applied-routes.json"))
                .load()
                .unwrap();
        assert!(loaded.profiles.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cleanup_all_reports_daemon_failure_after_attempting_other_cleanup() {
        let dir = unique_dir("cleanup-daemon-unavailable");
        let state = app_state(&dir);
        {
            let mut runtime = state.runtime.lock().await;
            runtime.routes = crate::route_runtime::RouteRuntime::Daemon(
                crate::daemon_client::DaemonClient::new(dir.join("missing.sock")),
            );
        }
        let err = cleanup_all(&state).await.unwrap_err();
        assert!(err.contains("route ownership:"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn disconnect_all_requests_daemon_cleanup_and_stops_local_runtime() {
        use net_manager_core::daemon_protocol::{self, method, RequestFrame, ResponseFrame};
        use serde_json::json;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let dir = unique_dir("disconnect-all");
        let state = app_state(&dir);
        let mut profile = profile("if0");
        profile.backend = TunnelBackend::None;
        profile.routes.push(PolicyRoute {
            destination: "10.77.0.0/16".parse().unwrap(),
            metric: 5,
            via: None,
        });
        state.profiles.upsert(profile.clone()).unwrap();
        state
            .runtime
            .lock()
            .await
            .tunnels
            .connect(&profile)
            .unwrap();
        let socket = dir.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let hello: RequestFrame = serde_json::from_slice(
                &daemon_protocol::read_frame(&mut reader, 1024)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(hello.method, method::HELLO);
            writer
                .write_all(
                    &daemon_protocol::encode_line(&ResponseFrame::ok(
                        hello.id,
                        json!({"protocol":1,"daemonVersion":"test","uid":1000,"capabilities":[]}),
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
            let request: RequestFrame = serde_json::from_slice(
                &daemon_protocol::read_frame(&mut reader, 1024)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(request.method, method::RECOVERY_CLEANUP);
            writer
                .write_all(
                    &daemon_protocol::encode_line(&ResponseFrame::ok(
                        request.id,
                        json!({"removedOwners":["static"],"failed":[]}),
                    ))
                    .unwrap(),
                )
                .await
                .unwrap();
        });

        disconnect_all(&state, &crate::daemon_client::DaemonClient::new(socket))
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(
            state.runtime.lock().await.tunnels.status(&profile).state,
            TunnelState::Stopped
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_exit_stops_local_processes_without_daemon_rpc() {
        use std::time::Duration;
        use tokio::net::UnixListener;

        let dir = unique_dir("exit-local-only");
        let state = app_state(&dir);
        let socket = dir.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        state.runtime.lock().await.routes = crate::route_runtime::RouteRuntime::Daemon(
            crate::daemon_client::DaemonClient::new(socket),
        );
        let mut profile = profile("if0");
        profile.backend = TunnelBackend::None;
        profile.routes.push(PolicyRoute {
            destination: "10.79.0.0/16".parse().unwrap(),
            metric: 5,
            via: None,
        });
        state.profiles.upsert(profile.clone()).unwrap();
        state
            .runtime
            .lock()
            .await
            .tunnels
            .connect(&profile)
            .unwrap();

        exit_cleanup(&state).await.unwrap();

        assert_eq!(
            state.runtime.lock().await.tunnels.status(&profile).state,
            TunnelState::Stopped
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "UI exit must not talk to the daemon"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn disconnect_all_stops_local_runtime_even_if_daemon_is_unavailable() {
        let dir = unique_dir("disconnect-all-no-daemon");
        let state = app_state(&dir);
        let mut profile = profile("if0");
        profile.backend = TunnelBackend::None;
        profile.routes.push(PolicyRoute {
            destination: "10.78.0.0/16".parse().unwrap(),
            metric: 5,
            via: None,
        });
        state.profiles.upsert(profile.clone()).unwrap();
        state
            .runtime
            .lock()
            .await
            .tunnels
            .connect(&profile)
            .unwrap();

        let error = disconnect_all(
            &state,
            &crate::daemon_client::DaemonClient::new(dir.join("missing.sock")),
        )
        .await
        .unwrap_err();
        assert!(error.contains("daemon"));
        assert_eq!(
            state.runtime.lock().await.tunnels.status(&profile).state,
            TunnelState::Stopped
        );
    }
}
