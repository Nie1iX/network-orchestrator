use crate::state::{persist_applied_routes, AppState};
use net_manager_core::models::*;
use std::sync::atomic::Ordering;
use tauri::{Emitter, Manager};

pub(crate) async fn cleanup_all(state: &AppState) -> Result<(), String> {
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

pub(crate) fn handle_window_event(window: &tauri::Window, event: &tauri::WindowEvent) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

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
}
