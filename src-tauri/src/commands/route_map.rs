use crate::state::AppState;
use net_manager_core::explorer;
use net_manager_core::models::{Profile, RouteMap, TunnelState};
use net_manager_core::route_plan::build_route_map;
use std::collections::HashMap;
use tauri::State;

pub(crate) fn select_route_profiles(
    profiles: &[Profile],
    running: &HashMap<String, bool>,
    include_inactive: bool,
) -> Vec<(Profile, bool)> {
    profiles
        .iter()
        .map(|p| (p.clone(), running.get(&p.id).copied().unwrap_or(false)))
        .filter(|(_, active)| include_inactive || *active)
        .collect()
}

#[tauri::command]
pub(crate) async fn get_route_map(
    include_inactive: bool,
    state: State<'_, AppState>,
) -> Result<RouteMap, String> {
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;

    let mut running = HashMap::new();
    {
        let mut runtime = state.runtime.lock().await;
        for profile in &profiles {
            running.insert(
                profile.id.clone(),
                runtime.tunnels.status(profile).state == TunnelState::Running,
            );
        }
    }

    let selected = select_route_profiles(&profiles, &running, include_inactive);
    let effective = explorer::list_routes().await.map_err(|e| e.to_string())?;
    Ok(build_route_map(&selected, &effective))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::profile;

    #[test]
    fn select_route_profiles_omits_stopped_unless_requested() {
        let mut a = profile("wg-a");
        a.id = "pa".into();
        let mut b = profile("wg-b");
        b.id = "pb".into();
        let profiles = vec![a.clone(), b.clone()];
        let mut running = HashMap::new();
        running.insert(a.id.clone(), true);
        running.insert(b.id.clone(), false);

        let active_only = select_route_profiles(&profiles, &running, false);
        assert_eq!(active_only.len(), 1);
        assert_eq!(active_only[0].0.id, a.id);
        assert!(active_only[0].1);

        let all = select_route_profiles(&profiles, &running, true);
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|(p, active)| p.id == b.id && !*active));
    }
}
