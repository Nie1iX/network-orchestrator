//! A static-route profile (`none` backend): its routes through a named
//! interface, kept by the privileged helper as a routing intent. Connecting
//! the profile creates the intent, disconnecting deletes it, and the helper's
//! reconcile keeps the routes in place (and waits while the interface is
//! absent). The rules live in `core::route_intents`.
use crate::privileged::Privileged;
use net_manager_core::daemon_protocol::{
    method, NetIntentDelParams, NetIntentListResult, NetIntentResult, NetIntentView,
};
use net_manager_core::models::{Profile, TunnelBackend, TunnelStatus};
use net_manager_core::route_intents::{static_intent, static_intent_id, static_state};
use serde_json::json;

pub(crate) fn is_static(profile: &Profile) -> bool {
    profile.backend == TunnelBackend::None
}

fn helper_message(error: net_manager_core::helper_client::HelperError) -> String {
    use net_manager_core::daemon_protocol::ErrorCode;
    use net_manager_core::helper_client::HelperError;
    match error {
        HelperError::Rejected(body) if body.code == ErrorCode::UnsupportedMethod => {
            "The installed helper is too old for static routes. Update it in Settings.".to_string()
        }
        other => crate::helper_error(other),
    }
}

/// Whether the machine has an interface with this name right now.
fn interface_exists(name: &str) -> bool {
    net_manager_core::explorer::list_interfaces()
        .map(|list| list.iter().any(|interface| interface.name == name))
        .unwrap_or(false)
}

fn find_intent(privileged: &dyn Privileged, id: &str) -> Result<Option<NetIntentView>, String> {
    let list: NetIntentListResult = privileged
        .call(method::NET_INTENT_LIST, json!({}))
        .map_err(helper_message)?;
    Ok(list.intents.into_iter().find(|intent| intent.id == id))
}

pub(crate) fn start(privileged: &dyn Privileged, profile: &Profile) -> Result<(), String> {
    let params = static_intent(profile)?;
    let interface = params.path.interface.clone().unwrap_or_default();
    // Strict by default, like the other clients: a missing interface is an
    // error unless the profile asked to wait for it.
    if !profile.wait_for_interface && !interface_exists(&interface) {
        return Err(format!(
            "The interface {interface} is not present. Turn on waiting for the interface to arm these routes."
        ));
    }
    privileged
        .call::<_, NetIntentResult>(method::NET_INTENT_SET, params)
        .map(|_| ())
        .map_err(helper_message)
}

pub(crate) fn stop(privileged: &dyn Privileged, profile: &Profile) -> Result<(), String> {
    let id = static_intent_id(&profile.id)?;
    privileged
        .call::<_, NetIntentResult>(method::NET_INTENT_DEL, NetIntentDelParams { id })
        .map(|_| ())
        .map_err(|error| {
            use net_manager_core::daemon_protocol::ErrorCode;
            use net_manager_core::helper_client::HelperError;
            match error {
                HelperError::Rejected(body) if body.code == ErrorCode::NotFound => {
                    "The connection is not running".to_string()
                }
                other => helper_message(other),
            }
        })
}

/// Stopped when the helper has no such intent or cannot be asked.
pub(crate) fn status(privileged: &dyn Privileged, profile: &Profile) -> TunnelStatus {
    let view = static_intent_id(&profile.id)
        .ok()
        .and_then(|id| find_intent(privileged, &id).ok().flatten());
    let (state, message) = static_state(view.as_ref());
    TunnelStatus {
        profile_id: profile.id.clone(),
        state,
        message,
        interface_name: Some(profile.interface_name.clone()).filter(|name| !name.is_empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{ErrorBody, ErrorCode, HelloResult};
    use net_manager_core::helper_client::HelperError;
    use net_manager_core::models::{PolicyRoute, TunnelState};
    use serde_json::Value;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// A helper that keeps intents like the real one and records requests.
    #[derive(Default)]
    struct Fake {
        intents: Mutex<Vec<Value>>,
        calls: Mutex<Vec<(String, Value)>>,
        old: bool,
    }

    impl Privileged for Fake {
        fn hello(&self) -> Result<HelloResult, HelperError> {
            unreachable!()
        }
        fn call_raw(&self, name: &str, params: Value) -> Result<Value, HelperError> {
            self.calls
                .lock()
                .unwrap()
                .push((name.into(), params.clone()));
            if self.old {
                return Err(HelperError::Rejected(ErrorBody {
                    code: ErrorCode::UnsupportedMethod,
                    message: "no".into(),
                }));
            }
            let mut intents = self.intents.lock().unwrap();
            match name {
                method::NET_INTENT_SET => {
                    let id = params["id"].as_str().unwrap().to_string();
                    intents.retain(|i| i["id"] != id.as_str());
                    intents.push(json!({
                        "id": id, "destinations": params["destinations"], "path": params["path"],
                        "metric": 5, "enabled": true, "status": "effective",
                        "detail": "1 route(s) in place", "installed": 1, "wanted": 1
                    }));
                    Ok(json!({ "id": id }))
                }
                method::NET_INTENT_DEL => {
                    let id = params["id"].as_str().unwrap().to_string();
                    let before = intents.len();
                    intents.retain(|i| i["id"] != id.as_str());
                    if intents.len() == before {
                        return Err(HelperError::Rejected(ErrorBody {
                            code: ErrorCode::NotFound,
                            message: "There is no intent with that name".into(),
                        }));
                    }
                    Ok(json!({ "id": id }))
                }
                method::NET_INTENT_LIST => Ok(json!({ "intents": *intents })),
                _ => Err(HelperError::Protocol("unexpected".into())),
            }
        }
        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }

    fn profile(wait: bool) -> Profile {
        Profile {
            id: "office".into(),
            name: "Office".into(),
            backend: TunnelBackend::None,
            // Not a real interface on any machine, so the strict check fails.
            interface_name: "en97".into(),
            routes: vec![PolicyRoute {
                destination: "192.0.2.0/24".parse().unwrap(),
                metric: 5,
                via: None,
            }],
            wait_for_interface: wait,
            ..Default::default()
        }
    }

    #[test]
    fn only_the_route_backend_is_static() {
        assert!(is_static(&profile(false)));
        let mut wg = profile(false);
        wg.backend = TunnelBackend::WireGuard;
        assert!(!is_static(&wg));
    }

    #[test]
    fn connecting_creates_the_intent_and_the_status_follows_it() {
        let helper = Fake::default();
        let p = profile(true);
        assert_eq!(status(&helper, &p).state, TunnelState::Stopped);
        start(&helper, &p).unwrap();
        let sent = helper
            .calls
            .lock()
            .unwrap()
            .iter()
            .find(|(n, _)| n == method::NET_INTENT_SET)
            .cloned()
            .unwrap();
        assert_eq!(sent.1["id"], "static-office");
        assert_eq!(sent.1["path"]["interface"], "en97");
        let after = status(&helper, &p);
        assert_eq!(after.state, TunnelState::Running);
        assert_eq!(after.interface_name.as_deref(), Some("en97"));
        stop(&helper, &p).unwrap();
        assert_eq!(status(&helper, &p).state, TunnelState::Stopped);
    }

    #[test]
    fn stopping_what_is_not_running_says_so() {
        let helper = Fake::default();
        assert_eq!(
            stop(&helper, &profile(true)).unwrap_err(),
            "The connection is not running"
        );
    }

    #[test]
    fn a_missing_interface_is_an_error_unless_the_profile_waits_for_it() {
        let helper = Fake::default();
        let error = start(&helper, &profile(false)).unwrap_err();
        assert!(
            error.contains("en97") && error.contains("waiting"),
            "{error}"
        );
        assert!(helper.calls.lock().unwrap().is_empty(), "nothing is sent");
        start(&helper, &profile(true)).unwrap();
    }

    #[test]
    fn a_profile_that_cannot_be_enforced_is_refused_before_the_helper_is_asked() {
        let helper = Fake::default();
        let mut with_gateway = profile(true);
        with_gateway.routes[0].via = Some("10.0.0.1".parse().unwrap());
        assert!(start(&helper, &with_gateway)
            .unwrap_err()
            .contains("gateway"));
        assert!(helper.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn an_old_helper_is_explained_and_reads_as_stopped() {
        let helper = Fake {
            old: true,
            ..Default::default()
        };
        let error = start(&helper, &profile(true)).unwrap_err();
        assert!(
            error.contains("too old") && error.contains("Settings"),
            "{error}"
        );
        assert_eq!(status(&helper, &profile(true)).state, TunnelState::Stopped);
    }

    #[test]
    fn an_intent_waiting_for_its_interface_counts_as_running_with_a_note() {
        let helper = Fake::default();
        helper.intents.lock().unwrap().push(json!({
            "id": "static-office", "destinations": ["192.0.2.0/24"],
            "path": {"kind": "interface", "interface": "en97"}, "metric": 5, "enabled": true,
            "status": "deferred", "detail": "interface en97 is absent", "installed": 0, "wanted": 0
        }));
        let s = status(&helper, &profile(true));
        assert_eq!(s.state, TunnelState::Running);
        assert_eq!(s.message.as_deref(), Some("interface en97 is absent"));
    }
}
