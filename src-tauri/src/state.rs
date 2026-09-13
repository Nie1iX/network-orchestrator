use net_manager_core::config_vault::ConfigVault;
use net_manager_core::models::*;
use net_manager_core::policy::PolicyManager;
use net_manager_core::profiles::{ProfileDocument, ProfileStore};
use net_manager_core::route_state::{
    AppliedRouteDocument, AppliedRouteStore, APPLIED_ROUTE_DOCUMENT_VERSION,
};
use net_manager_core::vpn::TunnelManager;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

pub(crate) struct RuntimeState {
    pub(crate) tunnels: TunnelManager,
    pub(crate) policies: PolicyManager,
}

pub(crate) struct AppState {
    pub(crate) profiles: ProfileStore,
    pub(crate) config_vault: ConfigVault,
    pub(crate) applied_routes: AppliedRouteStore,
    pub(crate) shutting_down: AtomicBool,
    pub(crate) cleanup_complete: AtomicBool,
    pub(crate) runtime: tokio::sync::Mutex<RuntimeState>,
}

pub(crate) fn build_state(data_dir: PathBuf) -> std::io::Result<AppState> {
    let store = ProfileStore::new(data_dir.join("profiles.json"));
    let applied_routes = AppliedRouteStore::new(data_dir.join("applied-routes.json"));
    let mut policies = PolicyManager::new();
    policies.restore(applied_routes.load()?.profiles)?;
    let config_vault = ConfigVault::new(data_dir.join("configs"));
    config_vault.ensure_root_protected()?;
    Ok(AppState {
        profiles: store,
        config_vault,
        applied_routes,
        shutting_down: AtomicBool::new(false),
        cleanup_complete: AtomicBool::new(false),
        runtime: tokio::sync::Mutex::new(RuntimeState {
            tunnels: TunnelManager::with_log_dir(data_dir.join("logs")),
            policies,
        }),
    })
}

pub(crate) fn persist_applied_routes(
    store: &AppliedRouteStore,
    policies: &PolicyManager,
) -> Result<(), String> {
    let document = AppliedRouteDocument {
        version: APPLIED_ROUTE_DOCUMENT_VERSION,
        profiles: policies.snapshot(),
    };
    store.save(&document).map_err(|e| e.to_string())
}

pub(crate) fn find_profile(store: &ProfileStore, id: &str) -> Result<Profile, String> {
    store
        .load()
        .map_err(|e| e.to_string())?
        .profiles
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| format!("profile '{id}' not found"))
}

pub(crate) fn existing_profile_for_update<'a>(
    document: &'a ProfileDocument,
    incoming_id: &str,
) -> Option<&'a Profile> {
    document.profiles.iter().find(|p| p.id == incoming_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use std::fs;

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
}
