//! JSON face of the connection engine (`net-manager-engine`) for the native
//! client. All orchestration — Xray loopback runtime, system proxy, requests
//! to the privileged helper — lives in the engine; this module only decodes
//! arguments and encodes the engine's answers.
use net_manager_core::daemon_protocol::{OpenVpnCredentials, OpenVpnUserPass};
use net_manager_core::models::Profile;
use net_manager_core::profiles::ProfileStore;
use net_manager_engine::{find_profile, Engine};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(crate) fn managed_executable(root: &Path) -> Option<PathBuf> {
    Engine::new(root).managed_executable()
}

pub(crate) fn is_running(root: &Path, profile: &Profile) -> Result<bool, String> {
    Engine::new(root).is_running(profile)
}

/// Run a change to a profile's configuration (endpoint switch, refresh) and,
/// when the connection was running, restart it on the new configuration.
pub(crate) fn restart_around(
    root: &Path,
    store: &ProfileStore,
    id: &str,
    change: impl FnOnce() -> Result<Value, String>,
) -> Result<Value, String> {
    Engine::new(root).restart_around(store, id, change)
}

fn find(profiles: &[Profile], args: &Value) -> Result<Profile, String> {
    find_profile(profiles, args["id"].as_str().unwrap_or_default())
}

fn encode(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|_| "Could not encode the result".into())
}

/// Credentials typed into the app, passed as flat strings.
pub(crate) fn credentials_from_args(args: &Value) -> Option<OpenVpnCredentials> {
    let text = |key: &str| {
        args[key]
            .as_str()
            .map(str::to_string)
            .filter(|value| !value.is_empty())
    };
    let user_pass = match (text("username"), text("password")) {
        (Some(username), Some(password)) => Some(OpenVpnUserPass { username, password }),
        _ => None,
    };
    let passphrase = text("passphrase");
    (user_pass.is_some() || passphrase.is_some()).then_some(OpenVpnCredentials {
        auth_user_pass: user_pass,
        private_key_passphrase: passphrase,
    })
}

pub(crate) fn handle(
    root: &Path,
    store: &ProfileStore,
    method: &str,
    args: &Value,
) -> Option<Result<Value, String>> {
    let engine = Engine::new(root);
    let load = || {
        store
            .load()
            .map(|document| document.profiles)
            .map_err(|_| "Profiles could not be loaded".to_string())
    };
    let result = match method {
        "runtime" => load().and_then(|profiles| encode(engine.snapshot(&profiles)?)),
        "install_xray" => engine
            .install_xray(args["archivePath"].as_str())
            .map(|()| json!({"installed": true})),
        "credential_requirements" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            let needs = engine.credential_requirements(&profile)?;
            Ok(json!({"userPass": needs.user_pass, "keyPassphrase": needs.key_passphrase}))
        }),
        "connect" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            engine.connect(store, &profile, credentials_from_args(args))?;
            encode(engine.snapshot(&load()?)?)
        }),
        "disconnect" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            encode(engine.disconnect(&profile, &profiles)?)
        }),
        "set_system_proxy" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            let enable = args["enabled"].as_str() == Some("true");
            encode(engine.set_system_proxy(&profile, &profiles, enable)?)
        }),
        // Leftovers of a crashed session; the helper does the cleanup itself,
        // so no elevation is ever asked for.
        "recovery_report" => load().and_then(|profiles| encode(engine.recovery_report(&profiles)?)),
        "recovery_cleanup" => {
            load().and_then(|profiles| encode(engine.recovery_cleanup(&profiles)?))
        }
        "shutdown" => load().and_then(|profiles| {
            engine.shutdown(&profiles)?;
            Ok(json!({}))
        }),
        "log" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            Ok(json!(engine.log(&profile)?))
        }),
        _ => return None,
    };
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_credentials_need_a_full_pair_or_a_passphrase() {
        let both = credentials_from_args(&json!({"username": "u", "password": "p"})).unwrap();
        let pair = both.auth_user_pass.unwrap();
        assert_eq!((pair.username.as_str(), pair.password.as_str()), ("u", "p"));
        assert!(credentials_from_args(&json!({"username": "u"})).is_none());
        assert!(credentials_from_args(&json!({"passphrase": ""})).is_none());
        assert!(credentials_from_args(&json!({})).is_none());
        let key = credentials_from_args(&json!({"passphrase": "k"})).unwrap();
        assert_eq!(key.private_key_passphrase.as_deref(), Some("k"));
    }

    #[test]
    fn an_unknown_profile_id_reads_as_not_found() {
        assert_eq!(
            find(&[], &json!({"id": "x"})).unwrap_err(),
            "Profile not found"
        );
    }

    #[test]
    fn the_recovery_report_has_the_shared_shape_and_asks_for_no_elevation() {
        // Read-only: lists the helper's records when one answers, else nothing.
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let report = handle(dir.path(), &store, "recovery_report", &json!({}))
            .unwrap()
            .unwrap();
        assert!(report["issues"].is_array());
        assert_eq!(report["requiresElevation"], false);
    }

    #[test]
    fn methods_of_other_modules_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        assert!(handle(dir.path(), &store, "profiles", &json!({})).is_none());
    }
}
