//! What the privileged helper still records after a crash, and the request
//! that clears it. The helper recovers on its own start; this is for what it
//! could not undo (DNS that failed to restore) or a start that never finished.
use crate::helper_error;
use crate::privileged::Privileged;
use net_manager_core::daemon_protocol::{method, CleanupResult, OwnedListResult};
use net_manager_core::helper_client::HelperError;
use net_manager_core::models::RecoveryReport;
use net_manager_core::recovery::{helper_report, owner_profile_id};
use serde_json::{json, Value};

/// Whether the helper runs the tunnel behind `owner` (`xray:`, `wireguard:` or
/// `openvpn:` plus the profile id); `None` when it cannot be asked.
fn owner_is_live(privileged: &dyn Privileged, owner: &str) -> Option<bool> {
    let status = match owner.split_once(':')?.0 {
        "xray" => method::XRAY_STATUS,
        "wireguard" => method::WIREGUARD_STATUS,
        "openvpn" => method::OPENVPN_STATUS,
        _ => return None,
    };
    let answer = privileged
        .call_raw(status, json!({ "profileId": owner_profile_id(owner) }))
        .ok()?;
    let state = answer.get("state").and_then(Value::as_str)?;
    Some(matches!(
        state,
        "running" | "connecting" | "connected" | "reconnecting"
    ))
}

/// Leftover helper state plus, when given, a system proxy whose connection is
/// gone. An unreachable helper has nothing to report: the client already says
/// it is not running.
pub(crate) fn report(privileged: &dyn Privileged, stale_proxy: Option<&str>) -> RecoveryReport {
    let owners = match privileged.call::<_, OwnedListResult>(method::OWNED_LIST, json!({})) {
        Ok(list) => list.owners,
        Err(_) => Vec::new(),
    };
    helper_report(
        &owners,
        |owner| owner_is_live(privileged, owner),
        stale_proxy,
    )
}

/// Asks the helper to undo what it still records. A tunnel that is running is
/// left alone by the helper itself.
pub(crate) fn cleanup(privileged: &dyn Privileged) -> Result<(), String> {
    let result: CleanupResult = match privileged.call(method::RECOVERY_CLEANUP, json!({})) {
        Ok(result) => result,
        Err(HelperError::Unreachable(_)) => return Ok(()),
        Err(error) => return Err(helper_error(error)),
    };
    match result.failed.len() {
        0 => Ok(()),
        n => Err(format!(
            "The helper could not clean up {n} leftover connection(s)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{
        ErrorBody, ErrorCode, HelloResult, OwnedEntry, OwnedState,
    };
    use net_manager_core::models::RecoveryIssueKind;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Answers `owned.list`, per-owner status and cleanup like the helper.
    struct Fake {
        owners: Vec<&'static str>,
        running: Vec<&'static str>,
        failed: Vec<String>,
        calls: Mutex<Vec<String>>,
        reachable: bool,
    }

    impl Fake {
        fn new(owners: &[&'static str], running: &[&'static str]) -> Self {
            Self {
                owners: owners.to_vec(),
                running: running.to_vec(),
                failed: Vec::new(),
                calls: Mutex::new(Vec::new()),
                reachable: true,
            }
        }
    }

    impl Privileged for Fake {
        fn hello(&self) -> Result<HelloResult, HelperError> {
            unreachable!()
        }
        fn call_raw(&self, name: &str, params: Value) -> Result<Value, HelperError> {
            self.calls.lock().unwrap().push(name.to_string());
            if !self.reachable {
                return Err(HelperError::Unreachable(std::io::Error::other("no socket")));
            }
            Ok(match name {
                method::OWNED_LIST => serde_json::to_value(OwnedListResult {
                    owners: self
                        .owners
                        .iter()
                        .map(|owner| OwnedEntry {
                            owner: owner.to_string(),
                            state: OwnedState::Applied,
                            resources: Vec::new(),
                        })
                        .collect(),
                })
                .unwrap(),
                method::XRAY_STATUS | method::WIREGUARD_STATUS | method::OPENVPN_STATUS => {
                    let id = params["profileId"].as_str().unwrap();
                    let live = self.running.iter().any(|o| o.ends_with(&format!(":{id}")));
                    json!({ "state": if live { "running" } else { "stopped" } })
                }
                method::RECOVERY_CLEANUP => json!({
                    "removedOwners": [], "failed": self.failed,
                }),
                _ => {
                    return Err(HelperError::Rejected(ErrorBody {
                        code: ErrorCode::UnsupportedMethod,
                        message: "no".into(),
                    }))
                }
            })
        }
        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }

    #[test]
    fn only_owners_the_helper_no_longer_runs_are_reported() {
        let fake = Fake::new(&["xray:live", "wireguard:dead"], &["xray:live"]);
        let report = report(&fake, None);
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].kind, RecoveryIssueKind::LeftoverTunnel);
        assert_eq!(report.issues[0].profile_id.as_deref(), Some("dead"));
        assert!(!report.requires_elevation);
    }

    #[test]
    fn a_stale_proxy_is_reported_even_with_a_quiet_helper() {
        let report = report(&Fake::new(&[], &[]), Some("p"));
        assert_eq!(report.issues[0].kind, RecoveryIssueKind::ProxyOwnership);
    }

    #[test]
    fn an_unreachable_helper_reports_nothing() {
        let mut fake = Fake::new(&["xray:a"], &[]);
        fake.reachable = false;
        assert!(report(&fake, None).issues.is_empty());
        assert!(cleanup(&fake).is_ok());
    }

    #[test]
    fn an_unrecognized_owner_is_not_reported() {
        let fake = Fake::new(&["tailscale:guard"], &[]);
        assert!(report(&fake, None).issues.is_empty());
    }

    #[test]
    fn cleanup_asks_the_helper_and_names_failures() {
        let fake = Fake::new(&[], &[]);
        cleanup(&fake).unwrap();
        assert_eq!(*fake.calls.lock().unwrap(), [method::RECOVERY_CLEANUP]);
        let mut failing = Fake::new(&[], &[]);
        failing.failed = vec!["xray:a".into(), "openvpn:b".into()];
        let error = cleanup(&failing).unwrap_err();
        assert!(error.contains("2 leftover"), "{error}");
        assert!(!error.contains("xray:a"));
    }
}
