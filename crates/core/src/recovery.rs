//! Recovery report for a privileged helper that journals the tunnels it owns
//! (macOS). Pure: the caller supplies the helper's `owned.list` entries and
//! whether each owner is still alive, so the rules run without a helper.

use crate::daemon_protocol::{OwnedEntry, OwnedState};
use crate::models::{RecoveryIssue, RecoveryIssueKind, RecoveryReport};

/// `wireguard:<profile id>` → `<profile id>`.
pub fn owner_profile_id(owner: &str) -> &str {
    owner.split_once(':').map_or(owner, |(_, id)| id)
}

/// Issues for journaled owners that are not running, plus a system proxy that
/// still points at a connection which is gone.
///
/// `is_live` answers for one owner: `Some(true)` it runs, `Some(false)` it
/// does not, `None` it could not be asked. An owner that could not be asked
/// is left out rather than reported, so a flaky helper never raises a false
/// alarm. Nothing here requires elevation: the helper does the cleanup.
pub fn helper_report(
    entries: &[OwnedEntry],
    is_live: impl Fn(&str) -> Option<bool>,
    stale_proxy_profile: Option<&str>,
) -> RecoveryReport {
    let mut issues = Vec::new();
    if let Some(profile_id) = stale_proxy_profile {
        issues.push(RecoveryIssue {
            kind: RecoveryIssueKind::ProxyOwnership,
            profile_id: Some(profile_id.to_string()),
            message: format!(
                "system proxy settings owned by profile '{profile_id}' are still applied"
            ),
        });
    }
    for entry in entries {
        if is_live(&entry.owner) != Some(false) {
            continue;
        }
        let profile_id = owner_profile_id(&entry.owner);
        let detail = match entry.state {
            OwnedState::Applying => "a start that did not finish",
            OwnedState::Stale => "a teardown that failed",
            OwnedState::Applied => "a tunnel that is no longer running",
        };
        issues.push(RecoveryIssue {
            kind: RecoveryIssueKind::LeftoverTunnel,
            profile_id: Some(profile_id.to_string()),
            message: format!(
                "routes and DNS recorded for profile '{profile_id}' are still in place after {detail}"
            ),
        });
    }
    RecoveryReport {
        requires_elevation: false,
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(owner: &str, state: OwnedState) -> OwnedEntry {
        OwnedEntry {
            owner: owner.into(),
            state,
            resources: Vec::new(),
        }
    }

    #[test]
    fn a_running_tunnel_is_not_a_leftover() {
        let report = helper_report(
            &[entry("xray:a", OwnedState::Applied)],
            |_| Some(true),
            None,
        );
        assert!(report.issues.is_empty());
        assert!(!report.requires_elevation);
    }

    #[test]
    fn a_recorded_tunnel_that_is_not_running_is_reported_by_profile() {
        let report = helper_report(
            &[
                entry("wireguard:wg1", OwnedState::Applied),
                entry("openvpn:o1", OwnedState::Applying),
                entry("xray:x1", OwnedState::Stale),
            ],
            |_| Some(false),
            None,
        );
        let ids: Vec<_> = report
            .issues
            .iter()
            .map(|i| (i.kind, i.profile_id.as_deref().unwrap()))
            .collect();
        assert_eq!(
            ids,
            [
                (RecoveryIssueKind::LeftoverTunnel, "wg1"),
                (RecoveryIssueKind::LeftoverTunnel, "o1"),
                (RecoveryIssueKind::LeftoverTunnel, "x1"),
            ]
        );
        assert!(report.issues[1].message.contains("did not finish"));
        assert!(report.issues[2].message.contains("teardown that failed"));
    }

    #[test]
    fn only_the_dead_owners_are_reported() {
        let report = helper_report(
            &[
                entry("xray:live", OwnedState::Applied),
                entry("xray:dead", OwnedState::Applied),
            ],
            |owner| Some(owner == "xray:live"),
            None,
        );
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].profile_id.as_deref(), Some("dead"));
    }

    #[test]
    fn an_owner_that_cannot_be_asked_raises_no_alarm() {
        let report = helper_report(&[entry("xray:a", OwnedState::Applied)], |_| None, None);
        assert!(report.issues.is_empty());
    }

    #[test]
    fn a_proxy_left_for_a_gone_connection_is_reported_first() {
        let report = helper_report(
            &[entry("xray:a", OwnedState::Applied)],
            |_| Some(false),
            Some("p"),
        );
        assert_eq!(report.issues[0].kind, RecoveryIssueKind::ProxyOwnership);
        assert_eq!(report.issues[0].profile_id.as_deref(), Some("p"));
        assert_eq!(report.issues.len(), 2);
        assert!(!report.requires_elevation);
    }

    #[test]
    fn owner_names_without_a_prefix_are_kept_whole() {
        assert_eq!(owner_profile_id("wireguard:a:b"), "a:b");
        assert_eq!(owner_profile_id("plain"), "plain");
    }
}
