//! `DaemonCore`: owner bookkeeping on top of the journal and the executors.
//! Synchronous by design; the server calls it from `spawn_blocking`.

#[cfg(target_os = "linux")]
use crate::cond_rules::{match_interface, plan_routes, IfaceAddr, OWNER_PREFIX};
#[cfg(target_os = "linux")]
use crate::dns::{DnsApply, DnsExecutor};
use crate::openvpn::OpenVpnPlan;
use crate::openvpn_process::OpenVpnProcessRunner;
use crate::validate::{validate_apply, validate_iface_name, validate_owner};
use crate::wireguard::{WireGuardPlan, WireGuardPlanWarning};
use crate::xray::prepare_xray;
use crate::xray_process::XrayProcessRunner;
use ipnet::IpNet;
use net_manager_core::daemon_protocol::{
    CleanupResult, ConditionalRouteRule, ConditionalRuleState, ConditionalRuleStatus, IpFamily,
    OpenVpnConnectionState, OpenVpnFailure, OpenVpnPlanConflict, OpenVpnPlanResult,
    OpenVpnProbeResult, OpenVpnProcessResource, OpenVpnStatusResult, OpenVpnWarning, OwnedEntry,
    OwnedResource, OwnedRuleResource, OwnedState, RouteCondition, WireGuardAddressResource,
    WireGuardFullResource, WireGuardLinkResource, WireGuardStatusResult, WireGuardWarning,
    XrayConnectParams, XrayProcessResource, XrayStatusResult,
};
use net_manager_core::journal::{JournalDocument, JournalEntry, JournalStore};
use net_manager_core::models::TunnelState;
use net_manager_core::models::{AnalyzedRoute, AppliedRoute};
use net_manager_core::openvpn_management::{ManagementEvent, ManagementSnapshot, OpenVpnState};
use net_manager_core::policy::{
    apply_routes_transactional, remove_routes_best_effort, RouteExecutor,
};
use std::collections::{HashMap, HashSet};
use std::io;

/// What a netdev the daemon does not own is, decided via sysfs by the
/// executor. Drives `stop_external_link`: WireGuard can be unlinked, foreign
/// TUN can only be admin-downed, everything else is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalLinkKind {
    WireGuard,
    Tun,
    Missing,
    Other,
}

pub trait LinkExecutor: Send {
    fn set_link_state(&mut self, name: &str, up: bool) -> io::Result<()>;
    /// Delete a netdev by name; used for foreign tunnels, which carry no
    /// owner marker (that is why this is not `WgSystem::delete_link`).
    fn remove_link(&mut self, name: &str) -> io::Result<()>;
    /// Probe a netdev's tunnel kind without mutating it.
    fn link_kind(&mut self, name: &str) -> io::Result<ExternalLinkKind>;
}

#[cfg(test)]
mod openvpn_tests {
    use super::testing::{FakeLinks, FakeRoutes, Op, Recorder};
    use super::*;
    use crate::openvpn::prepare_openvpn;
    use net_manager_core::daemon_protocol::{
        OpenVpnConnectParams, OpenVpnConnectRequest, OpenVpnConnectionState, OpenVpnCredentials,
        OpenVpnUserPass,
    };
    use net_manager_core::openvpn_management::{parse_push_reply, ManagementEvent, OpenVpnState};
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct FakeProcess {
        calls: Arc<Mutex<Vec<String>>>,
        pending: Arc<Mutex<VecDeque<Vec<ManagementEvent>>>>,
        journal_path: Arc<Mutex<Option<std::path::PathBuf>>>,
        link_missing: Arc<Mutex<bool>>,
        staged: Arc<Mutex<Vec<String>>>,
        busy_links: Arc<Mutex<Vec<String>>>,
    }

    #[derive(Clone, Default)]
    struct FakePolicy {
        events: Arc<Mutex<Vec<String>>>,
        existing: Arc<Mutex<Vec<OwnedRuleResource>>>,
        fail_add: Arc<Mutex<bool>>,
    }

    impl PolicyRuleExecutor for FakePolicy {
        fn rules_snapshot(&mut self) -> io::Result<Vec<OwnedRuleResource>> {
            Ok(self.existing.lock().unwrap().clone())
        }
        fn table_in_use(&mut self, _table: u32) -> io::Result<bool> {
            Ok(false)
        }
        fn add_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("rule-add:{}:{}", rule.table, rule.priority));
            if *self.fail_add.lock().unwrap() {
                Err(io::Error::other("synthetic rule add failure"))
            } else {
                Ok(())
            }
        }
        fn remove_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("rule-remove:{}:{}", rule.table, rule.priority));
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeDns {
        events: Arc<Mutex<Vec<String>>>,
        unavailable: Arc<Mutex<bool>>,
    }

    impl crate::dns::DnsExecutor for FakeDns {
        fn apply(
            &mut self,
            name: &str,
            servers: &[std::net::IpAddr],
            _domains: &[String],
            full: bool,
        ) -> Result<crate::dns::DnsApply, crate::dns::DnsError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("dns-apply:{name}:{}:{full}", servers.len()));
            Ok(if *self.unavailable.lock().unwrap() {
                crate::dns::DnsApply::Unavailable
            } else {
                crate::dns::DnsApply::Applied
            })
        }
        fn revert(&mut self, name: &str) -> Result<(), crate::dns::DnsError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("dns-revert:{name}"));
            Ok(())
        }
    }

    impl OpenVpnProcessRunner for FakeProcess {
        fn verify_binary(&self) -> io::Result<()> {
            self.calls.lock().unwrap().push("verify".into());
            Ok(())
        }
        fn link_index(&self, name: &str) -> io::Result<Option<u32>> {
            let mut calls = self.calls.lock().unwrap();
            let started = calls.iter().any(|call| call == &format!("start:{name}"));
            let stopped = calls.iter().any(|call| call == &format!("stop:{name}"));
            calls.push(format!("lookup:{name}"));
            let foreign = self.busy_links.lock().unwrap().iter().any(|n| n == name);
            Ok(
                (((started && !stopped) || foreign) && !*self.link_missing.lock().unwrap())
                    .then_some(42),
            )
        }
        fn staging_exists(&self, uid: u32, name: &str) -> io::Result<bool> {
            Ok(self
                .staged
                .lock()
                .unwrap()
                .contains(&format!("{uid}/{name}")))
        }
        fn start(
            &mut self,
            _uid: u32,
            name: &str,
            _: &net_manager_core::openvpn_config::SanitizedOpenVpnConfig,
            _: Option<net_manager_core::daemon_protocol::OpenVpnCredentials>,
            mark: u32,
        ) -> io::Result<()> {
            if let Some(path) = self.journal_path.lock().unwrap().as_ref() {
                let journal = JournalStore::new(path).load().unwrap();
                assert!(journal.entries.iter().any(|entry| entry
                    .resources
                    .iter()
                    .any(|resource| matches!(resource, OwnedResource::OpenVpnProcess(_)))));
            }
            self.calls.lock().unwrap().push(format!("start:{name}"));
            self.calls.lock().unwrap().push(format!("mark:{mark}"));
            Ok(())
        }
        fn poll(&mut self, _: &str) -> io::Result<Vec<ManagementEvent>> {
            Ok(self.pending.lock().unwrap().pop_front().unwrap_or_default())
        }
        fn stop(&mut self, name: &str) -> io::Result<()> {
            self.calls.lock().unwrap().push(format!("stop:{name}"));
            Ok(())
        }
        fn cleanup(&mut self, _: u32, name: &str) -> io::Result<()> {
            self.calls.lock().unwrap().push(format!("cleanup:{name}"));
            Ok(())
        }
    }

    fn unique_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("openvpn-core-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn core(dir: &Path, process: &FakeProcess, routes: &Recorder) -> DaemonCore {
        *process.journal_path.lock().unwrap() = Some(dir.join("state.json"));
        DaemonCore::open_with_openvpn(
            JournalStore::new(dir.join("state.json")),
            Box::new(FakeRoutes::new(routes)),
            Box::new(FakeLinks(routes.clone())),
            Box::new(process.clone()),
        )
        .unwrap()
    }

    fn plan() -> OpenVpnPlan {
        prepare_openvpn(
            1000,
            OpenVpnConnectParams {
                profile_id: "home".into(),
                config: "client\nremote vpn.example 1194\n".into(),
                assets: BTreeMap::new(),
                routes: vec![],
                interface_name: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn probe_journals_process_then_returns_pushed_routes_without_network_apply() {
        let dir = unique_dir("probe-success");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        core.start_openvpn_probe(1000, plan()).unwrap();
        assert_eq!(core.journal.entries[0].owner, "ovpn-probe:home");
        assert_eq!(core.journal.entries[0].resources.len(), 1);
        assert!(matches!(
            core.journal.entries[0].resources[0],
            OwnedResource::OpenVpnProcess(_)
        ));
        assert!(core.connect_openvpn(1000, plan()).is_err());
        assert!(routes.ops().is_empty());
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,route 10.89.0.0 255.255.255.0").unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        let result = core.poll_openvpn_probe(1000, "home").unwrap().unwrap();
        assert_eq!(
            result.routes[0].destination,
            "10.89.0.0/24".parse().unwrap()
        );
        assert_eq!(result.routes[0].source, "OpenVPN pushed");
        core.finish_openvpn_probe(1000, "home").unwrap();
        assert!(core.journal.entries.is_empty());
        assert!(routes.ops().is_empty());
        assert!(process
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.starts_with("cleanup:")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn plan_predicts_paths_and_reports_conflicts_without_mutating() {
        let dir = unique_dir("plan");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut daemon = core(&dir, &process, &routes);
        let name = plan().name;
        let predicted = daemon.plan_openvpn(1000, &plan()).unwrap();
        assert_eq!(predicted.profile_id, "home");
        assert_eq!(predicted.owner, "ovpn:home");
        assert_eq!(predicted.interface_name, name);
        assert_eq!(predicted.fallback_interface_name, name);
        assert!(predicted.interface_name.starts_with("ovpn-"));
        assert_eq!(
            predicted.staging_dir,
            format!("/run/network-orchestrator/1000/{name}")
        );
        assert!(predicted.config_path.ends_with("/config.ovpn"));
        assert!(predicted.management_socket.ends_with("/management.sock"));
        assert!(predicted.conflicts.is_empty());
        assert!(daemon.journal.entries.is_empty());
        assert!(process
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| { !call.starts_with("start:") && !call.starts_with("cleanup:") }));

        daemon.connect_openvpn(1000, plan()).unwrap();
        let predicted = daemon.plan_openvpn(1000, &plan()).unwrap();
        assert!(predicted
            .conflicts
            .contains(&OpenVpnPlanConflict::ActiveConnection));
        // The fake reports the started link as present.
        assert!(predicted
            .conflicts
            .contains(&OpenVpnPlanConflict::InterfaceOccupied));
        daemon.disconnect_openvpn(1000, "home").unwrap();

        daemon.start_openvpn_probe(1000, plan()).unwrap();
        let predicted = daemon.plan_openvpn(1000, &plan()).unwrap();
        assert!(predicted
            .conflicts
            .contains(&OpenVpnPlanConflict::ActiveProbe));
        daemon.finish_openvpn_probe(1000, "home").unwrap();

        process.staged.lock().unwrap().push(format!("1000/{name}"));
        let predicted = daemon.plan_openvpn(1000, &plan()).unwrap();
        assert!(predicted
            .conflicts
            .contains(&OpenVpnPlanConflict::StagingLeftover));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hinted_names_fall_back_when_the_readable_name_is_occupied() {
        let dir = unique_dir("hinted");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut daemon = core(&dir, &process, &routes);
        let hinted = prepare_openvpn(
            1000,
            OpenVpnConnectParams {
                profile_id: "home".into(),
                config: "client\nremote vpn.example 1194\n".into(),
                assets: BTreeMap::new(),
                routes: vec![],
                interface_name: Some("Home VPN".into()),
            },
        )
        .unwrap();
        assert_eq!(hinted.name, "ovpn-home-vpn");
        assert_ne!(hinted.fallback_name, hinted.name);
        assert!(hinted.fallback_name.starts_with("ovpn-home-"));
        assert!(hinted.fallback_name.len() <= 15);

        // Free primary: prediction and connect both take the readable name.
        let predicted = daemon.plan_openvpn(1000, &hinted).unwrap();
        assert_eq!(predicted.interface_name, "ovpn-home-vpn");
        assert!(predicted.conflicts.is_empty());
        daemon.connect_openvpn(1000, hinted).unwrap();
        assert_eq!(
            daemon
                .openvpn_status(1000, "home")
                .interface_name
                .as_deref(),
            Some("ovpn-home-vpn")
        );
        daemon.disconnect_openvpn(1000, "home").unwrap();

        // Foreign link squatting on the readable name → fallback is predicted
        // and used instead of failing the connect.
        process
            .busy_links
            .lock()
            .unwrap()
            .push("ovpn-home-vpn".into());
        let hinted = prepare_openvpn(
            1000,
            OpenVpnConnectParams {
                profile_id: "home".into(),
                config: "client\nremote vpn.example 1194\n".into(),
                assets: BTreeMap::new(),
                routes: vec![],
                interface_name: Some("Home VPN".into()),
            },
        )
        .unwrap();
        let predicted = daemon.plan_openvpn(1000, &hinted).unwrap();
        assert_eq!(predicted.interface_name, hinted.fallback_name);
        assert!(predicted
            .conflicts
            .contains(&OpenVpnPlanConflict::InterfaceOccupied));
        let fallback = hinted.fallback_name.clone();
        let status = daemon.connect_openvpn(1000, hinted).unwrap();
        assert_eq!(status.interface_name.as_deref(), Some(fallback.as_str()));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_probe_is_cleaned_and_crashed_probe_is_recovered_from_journal() {
        let dir = unique_dir("probe-failure");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut daemon = core(&dir, &process, &routes);
        daemon.start_openvpn_probe(1000, plan()).unwrap();
        process
            .pending
            .lock()
            .unwrap()
            .push_back(vec![ManagementEvent::AuthenticationFailed]);
        assert!(daemon.poll_openvpn_probe(1000, "home").is_err());
        daemon.finish_openvpn_probe(1000, "home").unwrap();
        assert!(daemon.journal.entries.is_empty());

        daemon.start_openvpn_probe(1000, plan()).unwrap();
        drop(daemon);
        let recovered_process = FakeProcess::default();
        let recovered = core(&dir, &recovered_process, &routes);
        assert!(recovered.journal.entries.is_empty());
        assert!(routes.ops().is_empty());
        let calls = recovered_process.calls.lock().unwrap().clone();
        assert!(calls.iter().any(|call| call.starts_with("stop:")));
        assert!(calls.iter().any(|call| call.starts_with("cleanup:")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn uid_cleanup_stops_active_probe_process_and_staging() {
        let dir = unique_dir("probe-uid-cleanup");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut daemon = core(&dir, &process, &routes);
        daemon.start_openvpn_probe(1000, plan()).unwrap();
        let result = daemon.cleanup_uid(1000).unwrap();
        assert_eq!(result.removed_owners, ["ovpn-probe:home"]);
        assert!(daemon.journal.entries.is_empty());
        let calls = process.calls.lock().unwrap().clone();
        assert!(calls.iter().any(|call| call.starts_with("stop:")));
        assert!(calls.iter().any(|call| call.starts_with("cleanup:")));
        assert!(daemon
            .apply_routes(
                1000,
                "ovpn-probe:home",
                vec![AppliedRoute::on_link("10.1.0.0/16".parse().unwrap(), 2, 5)]
            )
            .is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn credentials_never_enter_the_ownership_journal() {
        let dir = unique_dir("credentials-journal");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        let mut request = OpenVpnConnectRequest::from(OpenVpnConnectParams {
            profile_id: "home".into(),
            config: "client\nremote vpn.example\nauth-user-pass\n".into(),
            assets: BTreeMap::new(),
            routes: vec![],
            interface_name: None,
        });
        request.credentials = Some(OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "SECRET-USER".into(),
                password: "SECRET-PASSWORD".into(),
            }),
            private_key_passphrase: None,
        });
        let plan = prepare_openvpn(1000, request).unwrap();
        core.connect_openvpn(1000, plan).unwrap();
        let journal = fs::read_to_string(dir.join("state.json")).unwrap();
        for secret in ["SECRET-USER", "SECRET-PASSWORD"] {
            assert!(!journal.contains(secret));
        }
        core.disconnect_openvpn(1000, "home").unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn only_management_auth_failure_sets_a_clearable_warning() {
        let dir = unique_dir("auth-failure-warning");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        core.connect_openvpn(1000, plan()).unwrap();
        process
            .pending
            .lock()
            .unwrap()
            .push_back(vec![ManagementEvent::AuthenticationFailed]);
        assert!(core.reconcile_openvpn().is_err());
        let status = core.openvpn_status(1000, "home");
        assert_eq!(status.state, OpenVpnConnectionState::Failed);
        assert_eq!(
            serde_json::to_value(&status.warnings).unwrap(),
            serde_json::json!(["authenticationFailed"])
        );
        core.disconnect_openvpn(1000, "home").unwrap();
        assert_eq!(
            core.openvpn_status(1000, "home").state,
            OpenVpnConnectionState::Stopped
        );
        assert!(core.openvpn_status(1000, "home").warnings.is_empty());

        core.connect_openvpn(1000, plan()).unwrap();
        process
            .pending
            .lock()
            .unwrap()
            .push_back(vec![ManagementEvent::State(OpenVpnState::Exiting)]);
        core.reconcile_openvpn().unwrap();
        assert!(core.openvpn_status(1000, "home").warnings.is_empty());
        core.disconnect_openvpn(1000, "home").unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn successful_reconnect_clears_previous_authentication_warning() {
        let dir = unique_dir("auth-warning-reconnect");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        core.connect_openvpn(1000, plan()).unwrap();
        process
            .pending
            .lock()
            .unwrap()
            .push_back(vec![ManagementEvent::AuthenticationFailed]);
        assert!(core.reconcile_openvpn().is_err());
        assert!(core
            .openvpn_status(1000, "home")
            .warnings
            .contains(&OpenVpnWarning::AuthenticationFailed));
        core.connect_openvpn(1000, plan()).unwrap();
        assert!(core.openvpn_status(1000, "home").warnings.is_empty());
        core.disconnect_openvpn(1000, "home").unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn state_detail_survives_teardown_as_failure_reason() {
        let dir = unique_dir("failure-detail");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        core.connect_openvpn(1000, plan()).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::FailureDetail(OpenVpnFailure::TlsError),
            ManagementEvent::State(OpenVpnState::Exiting),
        ]);
        core.reconcile_openvpn().unwrap();
        let status = core.openvpn_status(1000, "home");
        assert_eq!(status.state, OpenVpnConnectionState::Failed);
        assert_eq!(status.failure_reason, Some(OpenVpnFailure::TlsError));
        // Disconnect and a fresh connect clear the stored reason.
        core.disconnect_openvpn(1000, "home").unwrap();
        core.connect_openvpn(1000, plan()).unwrap();
        assert_eq!(core.openvpn_status(1000, "home").failure_reason, None);
        core.disconnect_openvpn(1000, "home").unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unanswered_password_prompt_fails_as_credentials_required() {
        let dir = unique_dir("creds-required");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        core.connect_openvpn(1000, plan()).unwrap();
        process
            .pending
            .lock()
            .unwrap()
            .push_back(vec![ManagementEvent::FailureDetail(
                OpenVpnFailure::CredentialsRequired,
            )]);
        assert!(core.reconcile_openvpn().is_err());
        let status = core.openvpn_status(1000, "home");
        assert_eq!(status.state, OpenVpnConnectionState::Failed);
        assert_eq!(
            status.failure_reason,
            Some(OpenVpnFailure::CredentialsRequired)
        );
        core.disconnect_openvpn(1000, "home").unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn one_failed_owner_does_not_stop_reconciling_the_others() {
        let dir = unique_dir("reconcile-continue");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        core.connect_openvpn(1000, plan()).unwrap();
        let office = prepare_openvpn(
            1000,
            OpenVpnConnectParams {
                profile_id: "office".into(),
                config: "client\nremote vpn.example 1194\n".into(),
                assets: BTreeMap::new(),
                routes: vec![],
                interface_name: None,
            },
        )
        .unwrap();
        core.connect_openvpn(1000, office).unwrap();
        // The queue is shared: whichever owner is polled first fails.
        process.pending.lock().unwrap().extend([
            vec![ManagementEvent::AuthenticationFailed],
            vec![
                ManagementEvent::PushReply(
                    parse_push_reply("PUSH_REPLY,route 10.89.0.0 255.255.0.0").unwrap(),
                ),
                ManagementEvent::State(OpenVpnState::Connected),
            ],
        ]);
        assert!(core.reconcile_openvpn().is_err());
        assert!(process.pending.lock().unwrap().is_empty());
        assert_eq!(routes.ops(), vec![Op::Add("10.89.0.0/16".into())]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn journals_before_spawn_and_applies_pushed_split_routes_after_connected() {
        let dir = unique_dir("split");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        let status = core.connect_openvpn(1000, plan()).unwrap();
        assert_eq!(status.state, OpenVpnConnectionState::Connecting);
        assert_eq!(
            core.openvpn_status(1001, "home").state,
            OpenVpnConnectionState::Stopped
        );
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,route 10.89.0.0 255.255.0.0").unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        core.reconcile_openvpn().unwrap();
        assert_eq!(
            core.openvpn_status(1000, "home").state,
            OpenVpnConnectionState::Connected
        );
        assert_eq!(
            core.openvpn_status(1000, "home").applied_routes,
            ["10.89.0.0/16".parse().unwrap()]
        );
        assert_eq!(routes.ops(), vec![Op::Add("10.89.0.0/16".into())]);
        assert!(core.disconnect_openvpn(1001, "home").is_err());
        core.disconnect_openvpn(1000, "home").unwrap();
        assert_eq!(
            routes.ops(),
            vec![
                Op::Add("10.89.0.0/16".into()),
                Op::Remove("10.89.0.0/16".into())
            ]
        );
        assert!(process
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.starts_with("stop:")));
        assert!(JournalStore::new(dir.join("state.json"))
            .load()
            .unwrap()
            .entries
            .is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pushed_full_or_dns_causes_teardown_without_route_mutation() {
        for (label, push) in [
            ("full", "PUSH_REPLY,redirect-gateway def1"),
            (
                "def1-routes",
                "PUSH_REPLY,route 0.0.0.0 128.0.0.0,route 128.0.0.0 128.0.0.0",
            ),
            ("dns", "PUSH_REPLY,dhcp-option DNS 10.8.0.1"),
        ] {
            let dir = unique_dir(label);
            let process = FakeProcess::default();
            let routes = Recorder::default();
            let mut core = core(&dir, &process, &routes);
            core.connect_openvpn(1000, plan()).unwrap();
            process.pending.lock().unwrap().push_back(vec![
                ManagementEvent::PushReply(parse_push_reply(push).unwrap()),
                ManagementEvent::State(OpenVpnState::Connected),
            ]);
            assert!(core.reconcile_openvpn().is_err());
            assert!(routes.ops().is_empty());
            assert!(process
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call.starts_with("stop:")));
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn connected_without_owned_tun_rolls_back_process() {
        let dir = unique_dir("missing-tun");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        core.connect_openvpn(1000, plan()).unwrap();
        *process.link_missing.lock().unwrap() = true;
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,route 10.89.0.0 255.255.0.0").unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        assert!(core.reconcile_openvpn().is_err());
        assert!(process
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.starts_with("stop:")));
        assert_eq!(
            core.openvpn_status(1000, "home").state,
            OpenVpnConnectionState::Failed
        );
        assert!(JournalStore::new(dir.join("state.json"))
            .load()
            .unwrap()
            .entries
            .is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn route_collision_rolls_back_child_without_removing_foreign_route() {
        let dir = unique_dir("route-collision");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        routes.fail_add.lock().unwrap().push("10.89.0.0/16".into());
        let mut core = core(&dir, &process, &routes);
        core.connect_openvpn(1000, plan()).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,route 10.89.0.0 255.255.0.0").unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        assert!(core.reconcile_openvpn().is_err());
        assert_eq!(routes.ops(), vec![Op::Add("10.89.0.0/16".into())]);
        assert!(process
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.starts_with("stop:")));
        assert!(JournalStore::new(dir.join("state.json"))
            .load()
            .unwrap()
            .entries
            .is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reconnect_replaces_owned_split_route_set() {
        let dir = unique_dir("reconnect-replace");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        core.connect_openvpn(1000, plan()).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,route 10.89.0.0 255.255.0.0").unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
            ManagementEvent::ByteCount {
                received: 17,
                sent: 23,
            },
        ]);
        core.reconcile_openvpn().unwrap();
        assert_eq!(core.openvpn_status(1000, "home").rx_bytes, 17);
        process
            .pending
            .lock()
            .unwrap()
            .push_back(vec![ManagementEvent::State(OpenVpnState::Reconnecting)]);
        core.reconcile_openvpn().unwrap();
        assert!(core.openvpn_status(1000, "home").applied_routes.is_empty());
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,route 10.90.0.0 255.255.0.0").unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        core.reconcile_openvpn().unwrap();
        assert_eq!(
            core.openvpn_status(1000, "home").applied_routes,
            ["10.90.0.0/16".parse().unwrap()]
        );
        assert_eq!(
            routes.ops(),
            vec![
                Op::Add("10.89.0.0/16".into()),
                Op::Remove("10.89.0.0/16".into()),
                Op::Add("10.90.0.0/16".into()),
            ]
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn simultaneous_split_profiles_use_distinct_transport_marks() {
        let dir = unique_dir("split-marks");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        core.connect_openvpn(1000, plan()).unwrap();
        let second = prepare_openvpn(
            1000,
            OpenVpnConnectParams {
                profile_id: "office".into(),
                config: "client\nremote vpn.example\n".into(),
                assets: BTreeMap::new(),
                routes: vec![],
                interface_name: None,
            },
        )
        .unwrap();
        core.connect_openvpn(1000, second).unwrap();
        let marks: Vec<_> = process
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.starts_with("mark:"))
            .cloned()
            .collect();
        assert_eq!(marks, ["mark:51820", "mark:51821"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pushed_def1_and_dns_use_owned_table_rules_and_resolved() {
        let dir = unique_dir("full-dns");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let policy = FakePolicy::default();
        let dns = FakeDns::default();
        let mut core = core(&dir, &process, &routes);
        core.policy = Some(Box::new(policy.clone()));
        core.dns = Some(Box::new(dns.clone()));
        core.connect_openvpn(1000, plan()).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.79.0.1")
                    .unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        core.reconcile_openvpn().unwrap();
        let status = core.openvpn_status(1000, "home");
        assert_eq!(status.state, OpenVpnConnectionState::Connected);
        assert_eq!(status.applied_routes.len(), 2);
        assert!(status.warnings.contains(&OpenVpnWarning::Ipv6NotCovered));
        assert!(!status.warnings.contains(&OpenVpnWarning::DnsNotApplied));
        let owned = core.owned(1000);
        let process = owned[0]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::OpenVpnProcess(process) => Some(process),
                _ => None,
            })
            .unwrap();
        assert_eq!(process.transport_mark, Some(51820));
        assert!(process.full.is_some());
        assert!(
            owned[0]
                .resources
                .iter()
                .filter(|resource| matches!(resource, OwnedResource::Rule(_)))
                .count()
                == 2
        );
        assert!(owned[0]
            .resources
            .iter()
            .filter_map(|resource| match resource {
                OwnedResource::Route(route) => Some(route),
                _ => None,
            })
            .all(|route| route.table == Some(51820)));
        assert!(dns
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.contains(":1:true")));
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let wg_config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=198.18.0.1:51820\nAllowedIPs=0.0.0.0/0\n");
        let wg_plan = crate::wireguard::parse_wireguard_config(&wg_config, &[]).unwrap();
        assert_eq!(
            core.allocate_full(&wg_plan).err().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
        core.disconnect_openvpn(1000, "home").unwrap();
        assert!(policy
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.starts_with("rule-remove:")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unavailable_dns_is_warned_and_reapplied_when_resolved_returns() {
        let dir = unique_dir("full-dns-unavailable");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let policy = FakePolicy::default();
        let dns = FakeDns::default();
        *dns.unavailable.lock().unwrap() = true;
        let mut core = core(&dir, &process, &routes);
        core.policy = Some(Box::new(policy.clone()));
        core.dns = Some(Box::new(dns.clone()));
        core.connect_openvpn(1000, plan()).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.79.0.1")
                    .unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        core.reconcile_openvpn().unwrap();
        let warnings = core.openvpn_status(1000, "home").warnings;
        assert!(
            warnings.contains(&net_manager_core::daemon_protocol::OpenVpnWarning::DnsNotApplied)
        );
        assert!(
            warnings.contains(&net_manager_core::daemon_protocol::OpenVpnWarning::Ipv6NotCovered)
        );
        *dns.unavailable.lock().unwrap() = false;
        core.reapply_dns().unwrap();
        assert!(!core
            .openvpn_status(1000, "home")
            .warnings
            .contains(&net_manager_core::daemon_protocol::OpenVpnWarning::DnsNotApplied));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pushed_dns_domain_without_server_fails_closed_before_network_mutation() {
        let dir = unique_dir("dns-domain-only");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        core.dns = Some(Box::new(FakeDns::default()));
        core.connect_openvpn(1000, plan()).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(parse_push_reply("PUSH_REPLY,route 10.89.0.0 255.255.0.0,dns server 0 resolve-domains corp.example").unwrap()),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        assert!(core.reconcile_openvpn().is_err());
        assert!(routes.ops().is_empty());
        assert_eq!(
            core.openvpn_status(1000, "home").state,
            OpenVpnConnectionState::Failed
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn second_full_owner_is_rejected_before_new_routes_or_rules() {
        let dir = unique_dir("full-collision");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let policy = FakePolicy::default();
        let mut core = core(&dir, &process, &routes);
        core.policy = Some(Box::new(policy.clone()));
        core.dns = Some(Box::new(FakeDns::default()));
        core.connect_openvpn(1000, plan()).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,redirect-gateway def1").unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        core.reconcile_openvpn().unwrap();
        let before_routes = routes.ops();
        let before_rules = policy.events.lock().unwrap().clone();
        let second = prepare_openvpn(
            1001,
            OpenVpnConnectParams {
                profile_id: "office".into(),
                config: "client\nremote vpn.example\n".into(),
                assets: BTreeMap::new(),
                routes: vec![],
                interface_name: None,
            },
        )
        .unwrap();
        core.connect_openvpn(1001, second).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,redirect-gateway def1").unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        assert!(core.reconcile_openvpn_owner(1001, "ovpn:office").is_err());
        assert_eq!(
            core.openvpn_status(1000, "home").state,
            OpenVpnConnectionState::Connected
        );
        assert_eq!(
            core.openvpn_status(1001, "office").state,
            OpenVpnConnectionState::Failed
        );
        assert_eq!(routes.ops(), before_routes);
        assert_eq!(*policy.events.lock().unwrap(), before_rules);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_full_rule_add_rolls_back_routes_and_child() {
        let dir = unique_dir("full-rule-rollback");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let policy = FakePolicy::default();
        *policy.fail_add.lock().unwrap() = true;
        let mut core = core(&dir, &process, &routes);
        core.policy = Some(Box::new(policy.clone()));
        core.dns = Some(Box::new(FakeDns::default()));
        core.connect_openvpn(1000, plan()).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,redirect-gateway def1").unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        assert!(core.reconcile_openvpn().is_err());
        assert_eq!(
            core.openvpn_status(1000, "home").state,
            OpenVpnConnectionState::Failed
        );
        assert!(process
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.starts_with("stop:")));
        assert!(JournalStore::new(dir.join("state.json"))
            .load()
            .unwrap()
            .entries
            .is_empty());
        assert!(routes.ops().iter().any(|op| matches!(op, Op::Remove(_))));
        assert!(policy
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.starts_with("rule-remove:")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn full_reconnect_replaces_routes_rules_and_dns() {
        let dir = unique_dir("full-reconnect");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let policy = FakePolicy::default();
        let dns = FakeDns::default();
        let mut core = core(&dir, &process, &routes);
        core.policy = Some(Box::new(policy.clone()));
        core.dns = Some(Box::new(dns.clone()));
        core.connect_openvpn(1000, plan()).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.79.0.1")
                    .unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        core.reconcile_openvpn().unwrap();
        process
            .pending
            .lock()
            .unwrap()
            .push_back(vec![ManagementEvent::State(OpenVpnState::Reconnecting)]);
        core.reconcile_openvpn().unwrap();
        assert!(core.openvpn_status(1000, "home").applied_routes.is_empty());
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(parse_push_reply("PUSH_REPLY,redirect-gateway def1,route 10.90.0.0 255.255.0.0,dhcp-option DNS 10.79.0.2").unwrap()),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        core.reconcile_openvpn().unwrap();
        let owned = core.owned(1000);
        let dns_resource = owned[0]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::Dns(dns) => Some(dns),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            dns_resource.servers,
            ["10.79.0.2".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(core.openvpn_status(1000, "home").applied_routes.len(), 3);
        assert!(dns
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.starts_with("dns-revert:")));
        assert!(policy
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.starts_with("rule-remove:")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn foreign_rule_appearing_after_connect_blocks_full_before_route_mutation() {
        let dir = unique_dir("full-rule-collision");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let policy = FakePolicy::default();
        let mut core = core(&dir, &process, &routes);
        core.policy = Some(Box::new(policy.clone()));
        core.dns = Some(Box::new(FakeDns::default()));
        core.connect_openvpn(1000, plan()).unwrap();
        policy.existing.lock().unwrap().push(OwnedRuleResource {
            family: IpFamily::Ipv4,
            priority: 10000,
            table: 254,
            fwmark: None,
            invert: false,
            suppress_prefix_length: Some(0),
        });
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,redirect-gateway def1").unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        assert!(core.reconcile_openvpn().is_err());
        assert!(routes.ops().is_empty());
        assert!(policy.events.lock().unwrap().is_empty());
        assert_eq!(
            core.openvpn_status(1000, "home").state,
            OpenVpnConnectionState::Failed
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ipv6_full_push_installs_only_ipv6_policy_rules() {
        let dir = unique_dir("full-ipv6");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let policy = FakePolicy::default();
        let mut core = core(&dir, &process, &routes);
        core.policy = Some(Box::new(policy));
        core.dns = Some(Box::new(FakeDns::default()));
        core.connect_openvpn(1000, plan()).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(parse_push_reply("PUSH_REPLY,route-ipv6 ::/0").unwrap()),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        core.reconcile_openvpn().unwrap();
        let owned = core.owned(1000);
        let rules: Vec<_> = owned[0]
            .resources
            .iter()
            .filter_map(|resource| match resource {
                OwnedResource::Rule(rule) => Some(rule),
                _ => None,
            })
            .collect();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|rule| rule.family == IpFamily::Ipv6));
        assert!(!core
            .openvpn_status(1000, "home")
            .warnings
            .contains(&OpenVpnWarning::Ipv6NotCovered));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn startup_recovery_cleans_full_rules_routes_and_dns_without_child_pid() {
        let dir = unique_dir("full-recovery");
        let full = WireGuardFullResource {
            table: 51820,
            fwmark: 51820,
            priority_main: 10000,
            priority_tunnel: 10001,
            ipv4: true,
            ipv6: false,
        };
        let mut first = AppliedRoute::on_link("0.0.0.0/1".parse().unwrap(), 42, 5);
        first.table = Some(51820);
        let mut second = AppliedRoute::on_link("128.0.0.0/1".parse().unwrap(), 42, 5);
        second.table = Some(51820);
        let mut resources = vec![
            OwnedResource::OpenVpnProcess(OpenVpnProcessResource {
                name: "ovpn-a123456789".into(),
                owner_marker: "network-orchestrator:1000:ovpn:home".into(),
                transport_mark: Some(51820),
                full: Some(full.clone()),
            }),
            OwnedResource::Route(first),
            OwnedResource::Route(second),
        ];
        resources.extend(
            full_policy_rules(&full)
                .into_iter()
                .map(OwnedResource::Rule),
        );
        resources.push(OwnedResource::Dns(
            net_manager_core::daemon_protocol::WireGuardDnsResource {
                interface_index: 42,
                name: "ovpn-a123456789".into(),
                servers: vec!["10.79.0.1".parse().unwrap()],
                domains: vec![],
                full: true,
                applied: true,
            },
        ));
        let journal = JournalDocument {
            version: net_manager_core::journal::JOURNAL_VERSION,
            entries: vec![JournalEntry {
                uid: 1000,
                owner: "ovpn:home".into(),
                state: OwnedState::Applied,
                resources,
            }],
        };
        let store = JournalStore::new(dir.join("state.json"));
        store.save(&journal).unwrap();
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let policy = FakePolicy::default();
        let dns = FakeDns::default();
        let mut core = DaemonCore {
            journal: store.load().unwrap(),
            store,
            routes: Box::new(FakeRoutes::new(&routes)),
            links: Box::new(FakeLinks(routes.clone())),
            wg: None,
            wg_config: None,
            openvpn: Some(Box::new(process.clone())),
            xray: None,
            openvpn_runtime: HashMap::new(),
            openvpn_failed: HashSet::new(),
            openvpn_auth_failed: HashSet::new(),
            openvpn_failures: HashMap::new(),
            clock: Box::new(unix_now),
            wireguard_handshake: HashMap::new(),
            tunnel_failed: HashSet::new(),
            xray_restarts: HashMap::new(),
            cond_eval: HashMap::new(),
            policy: Some(Box::new(policy.clone())),
            dns: Some(Box::new(dns.clone())),
        };
        let result = core.teardown(|_| true).unwrap();
        assert_eq!(result.removed_owners, ["ovpn:home"]);
        assert!(core.owned(1000).is_empty());
        assert_eq!(
            policy
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.starts_with("rule-remove:"))
                .count(),
            2
        );
        assert!(dns
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.starts_with("dns-revert:")));
        assert_eq!(
            routes
                .ops()
                .iter()
                .filter(|op| matches!(op, Op::Remove(_)))
                .count(),
            2
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn startup_recovery_removes_only_journaled_openvpn_route() {
        let dir = unique_dir("recovery");
        let journal = JournalDocument {
            version: net_manager_core::journal::JOURNAL_VERSION,
            entries: vec![JournalEntry {
                uid: 1000,
                owner: "ovpn:home".into(),
                state: OwnedState::Applied,
                resources: vec![
                    OwnedResource::OpenVpnProcess(OpenVpnProcessResource {
                        name: "ovpn-a123456789".into(),
                        owner_marker: "network-orchestrator:1000:ovpn:home".into(),
                        transport_mark: None,
                        full: None,
                    }),
                    OwnedResource::Route(AppliedRoute::on_link(
                        "10.89.0.0/16".parse().unwrap(),
                        42,
                        5,
                    )),
                ],
            }],
        };
        JournalStore::new(dir.join("state.json"))
            .save(&journal)
            .unwrap();
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let core = core(&dir, &process, &routes);
        assert!(core.owned(1000).is_empty());
        assert_eq!(routes.ops(), vec![Op::Remove("10.89.0.0/16".into())]);
        assert_eq!(
            core.openvpn_status(1001, "home").state,
            OpenVpnConnectionState::Stopped
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reconnect_route_removal_failure_stops_owned_child_and_marks_stale() {
        let dir = unique_dir("reconnect-removal");
        let process = FakeProcess::default();
        let routes = Recorder::default();
        let mut core = core(&dir, &process, &routes);
        core.connect_openvpn(1000, plan()).unwrap();
        process.pending.lock().unwrap().push_back(vec![
            ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,route 10.89.0.0 255.255.0.0").unwrap(),
            ),
            ManagementEvent::State(OpenVpnState::Connected),
        ]);
        core.reconcile_openvpn().unwrap();
        routes
            .fail_remove
            .lock()
            .unwrap()
            .push("10.89.0.0/16".into());
        process
            .pending
            .lock()
            .unwrap()
            .push_back(vec![ManagementEvent::State(OpenVpnState::Reconnecting)]);
        assert!(core.reconcile_openvpn().is_err());
        assert!(process
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.starts_with("stop:")));
        assert_eq!(core.owned(1000)[0].state, OwnedState::Stale);
        let calls = process.calls.lock().unwrap().len();
        assert!(core.reconcile_openvpn().is_ok());
        assert_eq!(process.calls.lock().unwrap().len(), calls);
        fs::remove_dir_all(dir).unwrap();
    }
}

pub trait WgSystem: Send {
    fn create_link(&mut self, name: &str, owner_marker: &str) -> io::Result<u32>;
    fn link_owned(&mut self, name: &str, index: u32, owner_marker: &str) -> io::Result<bool>;
    fn link_present(&mut self, _name: &str, _index: u32) -> io::Result<bool> {
        Ok(false)
    }
    fn delete_link(&mut self, name: &str, index: u32, owner_marker: &str) -> io::Result<()>;
    fn add_address(&mut self, index: u32, address: IpNet) -> io::Result<()>;
    fn remove_address(&mut self, index: u32, address: IpNet) -> io::Result<()>;
    fn set_mtu(&mut self, index: u32, mtu: u32) -> io::Result<()>;
    fn set_state(&mut self, index: u32, up: bool) -> io::Result<()>;
}

pub trait PolicyRuleExecutor: Send {
    fn rules_snapshot(&mut self) -> io::Result<Vec<OwnedRuleResource>>;
    fn table_in_use(&mut self, table: u32) -> io::Result<bool>;
    fn add_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()>;
    fn remove_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()>;
    /// Whether exactly this daemon-owned rule is installed.
    fn rule_present(&mut self, rule: &OwnedRuleResource) -> io::Result<bool> {
        Ok(self.rules_snapshot()?.contains(rule))
    }
}

pub trait WgConfigExecutor: Send {
    fn configure(&mut self, name: &str, config: &str) -> io::Result<()>;
    fn set_fwmark(&mut self, _name: &str, _mark: u32) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "WireGuard mark executor is unavailable",
        ))
    }
    fn marks_in_use(&self) -> io::Result<Vec<u32>> {
        Ok(Vec::new())
    }
    fn endpoint_ips(&self, _name: &str) -> io::Result<Vec<std::net::IpAddr>> {
        Ok(Vec::new())
    }
    fn verify_transport(
        &self,
        _name: &str,
        _mark: u32,
        _ipv4: bool,
        _ipv6: bool,
    ) -> io::Result<()> {
        Ok(())
    }
    fn health(&self, _name: &str) -> io::Result<(Option<u64>, u64, u64)> {
        Ok((None, 0, 0))
    }
}

/// WireGuard REJECT_AFTER_TIME: session keys older than this are unusable.
const WIREGUARD_REJECT_AFTER_SECS: u64 = 180;
/// How long sent packets may go without a handshake before the tunnel is
/// failed; WireGuard retries the initiation about every 5 s.
const WIREGUARD_UNANSWERED_SECS: u64 = 20;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Transmit counter at the moment a tunnel was first seen without a usable
/// handshake, and when it first grew after that.
#[derive(Debug, Clone, Copy)]
struct HandshakeWatch {
    baseline_tx: u64,
    sending_since: Option<u64>,
}

/// Outcome of the last [`DaemonCore::reconcile_conditional`] pass over one
/// rule. `matched_interface` is `Some` when the rule's condition currently
/// holds; `error` captures the apply/remove failure, if any.
#[derive(Debug, Clone, Default)]
pub struct CondRuleEval {
    pub matched_interface: Option<String>,
    pub error: Option<String>,
}

/// WireGuard only handshakes when it has something to send, so a missing or
/// expired handshake alone is normal for an idle tunnel. The tunnel is
/// failed only when packets keep leaving (tx grows) without any handshake
/// completing for `WIREGUARD_UNANSWERED_SECS`.
fn observe_handshake(
    watch: Option<HandshakeWatch>,
    latest_handshake: Option<u64>,
    tx: u64,
    now: u64,
) -> (TunnelState, Option<HandshakeWatch>) {
    let usable = latest_handshake
        .is_some_and(|handshake| now.saturating_sub(handshake) <= WIREGUARD_REJECT_AFTER_SECS);
    if usable {
        return (TunnelState::Running, None);
    }
    let mut watch = watch
        .filter(|watch| tx >= watch.baseline_tx)
        .unwrap_or(HandshakeWatch {
            baseline_tx: tx,
            sending_since: None,
        });
    if tx > watch.baseline_tx && watch.sending_since.is_none() {
        watch.sending_since = Some(now);
    }
    let failed = watch
        .sending_since
        .is_some_and(|since| now.saturating_sub(since) >= WIREGUARD_UNANSWERED_SECS);
    let state = if failed {
        TunnelState::Failed
    } else {
        TunnelState::Running
    };
    (state, Some(watch))
}

pub struct DaemonCore {
    store: JournalStore,
    journal: JournalDocument,
    routes: Box<dyn RouteExecutor>,
    links: Box<dyn LinkExecutor>,
    wg: Option<Box<dyn WgSystem>>,
    wg_config: Option<Box<dyn WgConfigExecutor>>,
    openvpn: Option<Box<dyn OpenVpnProcessRunner>>,
    xray: Option<Box<dyn XrayProcessRunner>>,
    openvpn_runtime: HashMap<(u32, String), OpenVpnRuntime>,
    openvpn_failed: HashSet<(u32, String)>,
    openvpn_auth_failed: HashSet<(u32, String)>,
    /// Sanitized failure reason per failed owner; survives teardown because
    /// the runtime snapshot is dropped with the journal entry.
    openvpn_failures: HashMap<(u32, String), OpenVpnFailure>,
    /// Unix seconds; injectable so handshake ageing is testable.
    clock: Box<dyn Fn() -> u64 + Send>,
    wireguard_handshake: HashMap<(u32, String), HandshakeWatch>,
    /// WireGuard/Xray owners torn down by network reconcile; reported
    /// `failed` until the user reconnects or disconnects.
    tunnel_failed: HashSet<(u32, String)>,
    /// In-place respawn budget per xray owner: a child crash gets a few
    /// restarts before reconcile gives up and fails the tunnel.
    xray_restarts: HashMap<(u32, String), u32>,
    /// Last evaluation of each conditional rule `(uid, rule id)`: which
    /// interface matched, or why the apply failed. Not journaled — the
    /// journal already records what was installed.
    cond_eval: HashMap<(u32, String), CondRuleEval>,
    #[cfg(target_os = "linux")]
    policy: Option<Box<dyn PolicyRuleExecutor>>,
    #[cfg(target_os = "linux")]
    dns: Option<Box<dyn DnsExecutor>>,
}

struct OpenVpnRuntime {
    explicit_routes: Vec<net_manager_core::models::PolicyRoute>,
    snapshot: ManagementSnapshot,
}

struct OpenVpnNetworkPlan {
    routes: Vec<net_manager_core::models::PolicyRoute>,
    full_ipv4: bool,
    full_ipv6: bool,
    dns_servers: Vec<std::net::IpAddr>,
    dns_domains: Vec<String>,
}

impl OpenVpnNetworkPlan {
    fn from_runtime(runtime: &OpenVpnRuntime) -> io::Result<Self> {
        let mut routes = runtime.explicit_routes.clone();
        let mut dns_servers = Vec::new();
        let mut dns_domains = Vec::new();
        let mut redirect_def1 = false;
        if let Some(push) = &runtime.snapshot.active_push {
            redirect_def1 = push.redirect_gateway_def1;
            for destination in &push.routes {
                if !routes.iter().any(|route| route.destination == *destination) {
                    routes.push(net_manager_core::models::PolicyRoute {
                        destination: *destination,
                        metric: 5,
                        via: None,
                    });
                }
            }
            for server in push.legacy_dns_servers.iter().chain(
                push.dns_servers
                    .iter()
                    .flat_map(|server| server.addresses.iter()),
            ) {
                if !dns_servers.contains(server) {
                    dns_servers.push(*server);
                }
            }
            for domain in push.search_domains.iter().chain(
                push.dns_servers
                    .iter()
                    .flat_map(|server| server.resolve_domains.iter()),
            ) {
                if !dns_domains.contains(domain) {
                    dns_domains.push(domain.clone());
                }
            }
        }
        if dns_servers.len() > 8 || dns_domains.len() > 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "OpenVPN pushed too many DNS settings",
            ));
        }
        if !dns_domains.is_empty() && dns_servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "OpenVPN pushed DNS domains without a server",
            ));
        }
        let has = |network: &str| {
            routes
                .iter()
                .any(|route| route.destination == network.parse::<IpNet>().unwrap())
        };
        let full_ipv4 =
            redirect_def1 || has("0.0.0.0/0") || (has("0.0.0.0/1") && has("128.0.0.0/1"));
        let full_ipv6 = has("::/0") || (has("::/1") && has("8000::/1"));
        Ok(Self {
            routes,
            full_ipv4,
            full_ipv6,
            dns_servers,
            dns_domains,
        })
    }

    fn is_full_route(&self, destination: IpNet) -> bool {
        is_full_route(self.full_ipv4, self.full_ipv6, destination)
    }
}

/// A default route or one of its def1 halves in a family that is fully tunnelled.
fn is_full_route(full_ipv4: bool, full_ipv6: bool, destination: IpNet) -> bool {
    match destination {
        IpNet::V4(_) => {
            full_ipv4
                && matches!(
                    destination.to_string().as_str(),
                    "0.0.0.0/0" | "0.0.0.0/1" | "128.0.0.0/1"
                )
        }
        IpNet::V6(_) => {
            full_ipv6
                && matches!(
                    destination.to_string().as_str(),
                    "::/0" | "::/1" | "8000::/1"
                )
        }
    }
}

impl DaemonCore {
    /// Load the journal and tear down everything it lists: whatever a
    /// previous run left behind is no longer backed by a live client.
    pub fn open(
        store: JournalStore,
        routes: Box<dyn RouteExecutor>,
        links: Box<dyn LinkExecutor>,
    ) -> io::Result<Self> {
        let journal = store.load()?;
        let mut core = Self {
            store,
            journal,
            routes,
            links,
            wg: None,
            wg_config: None,
            openvpn: None,
            xray: None,
            openvpn_runtime: HashMap::new(),
            openvpn_failed: HashSet::new(),
            openvpn_auth_failed: HashSet::new(),
            openvpn_failures: HashMap::new(),
            clock: Box::new(unix_now),
            wireguard_handshake: HashMap::new(),
            tunnel_failed: HashSet::new(),
            xray_restarts: HashMap::new(),
            cond_eval: HashMap::new(),
            #[cfg(target_os = "linux")]
            policy: None,
            #[cfg(target_os = "linux")]
            dns: None,
        };
        if !core.journal.entries.is_empty() {
            let result = core.teardown(|_| true)?;
            eprintln!(
                "network-orchestrator-daemon: startup recovery removed {} owner(s), {} stale",
                result.removed_owners.len(),
                result.failed.len()
            );
        }
        Ok(core)
    }

    pub fn open_with_wireguard(
        store: JournalStore,
        routes: Box<dyn RouteExecutor>,
        links: Box<dyn LinkExecutor>,
        wg: Box<dyn WgSystem>,
        wg_config: Box<dyn WgConfigExecutor>,
    ) -> io::Result<Self> {
        let journal = store.load()?;
        let mut core = Self {
            store,
            journal,
            routes,
            links,
            wg: Some(wg),
            wg_config: Some(wg_config),
            openvpn: None,
            xray: None,
            openvpn_runtime: HashMap::new(),
            openvpn_failed: HashSet::new(),
            openvpn_auth_failed: HashSet::new(),
            openvpn_failures: HashMap::new(),
            clock: Box::new(unix_now),
            wireguard_handshake: HashMap::new(),
            tunnel_failed: HashSet::new(),
            xray_restarts: HashMap::new(),
            cond_eval: HashMap::new(),
            #[cfg(target_os = "linux")]
            policy: None,
            #[cfg(target_os = "linux")]
            dns: None,
        };
        if !core.journal.entries.is_empty() {
            core.teardown(|_| true)?;
        }
        Ok(core)
    }

    #[cfg(target_os = "linux")]
    pub fn open_with_wireguard_full(
        store: JournalStore,
        routes: Box<dyn RouteExecutor>,
        links: Box<dyn LinkExecutor>,
        wg: Box<dyn WgSystem>,
        wg_config: Box<dyn WgConfigExecutor>,
        policy: Box<dyn PolicyRuleExecutor>,
        dns: Box<dyn DnsExecutor>,
    ) -> io::Result<Self> {
        let journal = store.load()?;
        let mut core = Self {
            store,
            journal,
            routes,
            links,
            wg: Some(wg),
            wg_config: Some(wg_config),
            openvpn: None,
            xray: None,
            openvpn_runtime: HashMap::new(),
            openvpn_failed: HashSet::new(),
            openvpn_auth_failed: HashSet::new(),
            openvpn_failures: HashMap::new(),
            clock: Box::new(unix_now),
            wireguard_handshake: HashMap::new(),
            tunnel_failed: HashSet::new(),
            xray_restarts: HashMap::new(),
            cond_eval: HashMap::new(),
            policy: Some(policy),
            dns: Some(dns),
        };
        if !core.journal.entries.is_empty() {
            core.teardown(|_| true)?;
        }
        Ok(core)
    }

    pub fn open_with_openvpn(
        store: JournalStore,
        routes: Box<dyn RouteExecutor>,
        links: Box<dyn LinkExecutor>,
        openvpn: Box<dyn OpenVpnProcessRunner>,
    ) -> io::Result<Self> {
        let journal = store.load()?;
        let mut core = Self {
            store,
            journal,
            routes,
            links,
            wg: None,
            wg_config: None,
            openvpn: Some(openvpn),
            xray: None,
            openvpn_runtime: HashMap::new(),
            openvpn_failed: HashSet::new(),
            openvpn_auth_failed: HashSet::new(),
            openvpn_failures: HashMap::new(),
            clock: Box::new(unix_now),
            wireguard_handshake: HashMap::new(),
            tunnel_failed: HashSet::new(),
            xray_restarts: HashMap::new(),
            cond_eval: HashMap::new(),
            #[cfg(target_os = "linux")]
            policy: None,
            #[cfg(target_os = "linux")]
            dns: None,
        };
        if !core.journal.entries.is_empty() {
            core.teardown(|_| true)?;
        }
        Ok(core)
    }

    #[cfg(test)]
    pub fn open_with_xray(
        store: JournalStore,
        routes: Box<dyn RouteExecutor>,
        links: Box<dyn LinkExecutor>,
        tun: Box<dyn WgSystem>,
        xray: Box<dyn XrayProcessRunner>,
    ) -> io::Result<Self> {
        let journal = store.load()?;
        let mut core = Self {
            store,
            journal,
            routes,
            links,
            wg: Some(tun),
            wg_config: None,
            openvpn: None,
            xray: Some(xray),
            openvpn_runtime: HashMap::new(),
            openvpn_failed: HashSet::new(),
            openvpn_auth_failed: HashSet::new(),
            openvpn_failures: HashMap::new(),
            clock: Box::new(unix_now),
            wireguard_handshake: HashMap::new(),
            tunnel_failed: HashSet::new(),
            xray_restarts: HashMap::new(),
            cond_eval: HashMap::new(),
            #[cfg(target_os = "linux")]
            policy: None,
            #[cfg(target_os = "linux")]
            dns: None,
        };
        if !core.journal.entries.is_empty() {
            core.teardown(|_| true)?;
        }
        Ok(core)
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn open_with_all(
        store: JournalStore,
        routes: Box<dyn RouteExecutor>,
        links: Box<dyn LinkExecutor>,
        wg: Box<dyn WgSystem>,
        wg_config: Box<dyn WgConfigExecutor>,
        policy: Box<dyn PolicyRuleExecutor>,
        dns: Box<dyn DnsExecutor>,
        openvpn: Box<dyn OpenVpnProcessRunner>,
        xray: Box<dyn XrayProcessRunner>,
    ) -> io::Result<Self> {
        let journal = store.load()?;
        let mut core = Self {
            store,
            journal,
            routes,
            links,
            wg: Some(wg),
            wg_config: Some(wg_config),
            openvpn: Some(openvpn),
            xray: Some(xray),
            openvpn_runtime: HashMap::new(),
            openvpn_failed: HashSet::new(),
            openvpn_auth_failed: HashSet::new(),
            openvpn_failures: HashMap::new(),
            clock: Box::new(unix_now),
            wireguard_handshake: HashMap::new(),
            tunnel_failed: HashSet::new(),
            xray_restarts: HashMap::new(),
            cond_eval: HashMap::new(),
            policy: Some(policy),
            dns: Some(dns),
        };
        if !core.journal.entries.is_empty() {
            core.teardown(|_| true)?;
        }
        Ok(core)
    }

    pub fn connect_xray(
        &mut self,
        uid: u32,
        params: XrayConnectParams,
    ) -> io::Result<XrayStatusResult> {
        let owner = format!("xray:{}", params.profile_id);
        validate_owner(&owner).map_err(invalid_input)?;
        if self.position(uid, &owner).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Xray profile is already connected",
            ));
        }
        let mark = self.allocate_openvpn_mark()?;
        let plan = prepare_xray(uid, params, mark)?;
        let runner = self.xray.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Xray executor is unavailable")
        })?;
        runner
            .verify_binary()
            .map_err(|err| xray_stage("binary_verify", err))?;
        if runner
            .link_index(&plan.name)
            .map_err(|err| xray_stage("link_lookup", err))?
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Xray link name is occupied",
            ));
        }
        let full = if plan.full_ipv4 || plan.full_ipv6 {
            if self.journal.entries.iter().any(|entry| {
                entry.resources.iter().any(|resource| match resource {
                    OwnedResource::WireGuardLink(link) => link.full.is_some(),
                    OwnedResource::OpenVpnProcess(process) => process.full.is_some(),
                    OwnedResource::XrayProcess(process) => process.full.is_some(),
                    _ => false,
                })
            }) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "another full tunnel owns policy routing",
                ));
            }
            #[cfg(target_os = "linux")]
            if self.policy.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "policy executor is unavailable",
                ));
            }
            let slot = mark - 51820;
            Some(WireGuardFullResource {
                table: mark,
                fwmark: mark,
                priority_main: 10000 + slot * 2,
                priority_tunnel: 10001 + slot * 2,
                ipv4: plan.full_ipv4,
                ipv6: plan.full_ipv6,
            })
        } else {
            None
        };
        if !plan.dns_servers.is_empty() {
            #[cfg(target_os = "linux")]
            if self.dns.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "DNS executor is unavailable",
                ));
            }
        }
        self.journal.entries.push(JournalEntry {
            uid,
            owner: owner.clone(),
            state: OwnedState::Applying,
            resources: vec![OwnedResource::XrayProcess(XrayProcessResource {
                name: plan.name.clone(),
                index: 0,
                owner_marker: format!("network-orchestrator:{uid}:{owner}"),
                transport_mark: mark,
                full: full.clone(),
            })],
        });
        if let Err(err) = self.store.save(&self.journal) {
            self.journal.entries.pop();
            return Err(xray_stage("journal_prepare", err));
        }
        let index = self.journal.entries.len() - 1;
        let result = self.apply_xray_plan(index, uid, &plan, full.as_ref());
        if let Err(err) = result {
            let _ = self.teardown_xray_entry(index);
            self.persist();
            return Err(err);
        }
        self.journal.entries[index].state = OwnedState::Applied;
        if let Err(err) = self.store.save(&self.journal) {
            let _ = self.teardown_xray_entry(index);
            self.persist();
            return Err(xray_stage("journal_commit", err));
        }
        self.xray_restarts.remove(&(uid, owner.clone()));
        self.tunnel_failed.remove(&(uid, owner));
        Ok(self.xray_status(uid, &plan.profile_id))
    }

    /// Hot-reload the staged Xray config of an already connected profile:
    /// kernel-level settings (routes, DNS, link name, full capture) must be
    /// identical to the running tunnel — changing those requires a reconnect.
    /// The child is restarted on the same staging directory; the journal
    /// entry, ownership and restart bookkeeping stay in place.
    pub fn reload_xray(
        &mut self,
        uid: u32,
        params: XrayConnectParams,
    ) -> io::Result<XrayStatusResult> {
        let owner = format!("xray:{}", params.profile_id);
        validate_owner(&owner).map_err(invalid_input)?;
        let index = self.position(uid, &owner).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Xray profile is not connected")
        })?;
        if self.journal.entries[index].state != OwnedState::Applied {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Xray tunnel is not fully applied",
            ));
        }
        let process = self.journal.entries[index]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::XrayProcess(process) => Some(process.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing Xray process marker")
            })?;
        let plan = prepare_xray(uid, params, process.transport_mark)?;
        self.ensure_xray_reload_compatible(index, &plan, &process)?;
        let runner = self.xray.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Xray executor is unavailable")
        })?;
        runner
            .reload(uid, &plan.name, &plan.config, plan.geo_assets.as_ref())
            .map_err(|err| xray_stage("reload", err))?;
        let new_index = self
            .xray
            .as_ref()
            .unwrap()
            .link_index(&plan.name)
            .map_err(|err| xray_stage("tun_lookup", err))?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "Xray TUN link is unavailable")
            })?;
        self.rebind_xray_link(index, process.index, new_index)
            .map_err(|err| xray_stage("rebind", err))?;
        // A successful reload hands the child a fresh restart budget.
        self.xray_restarts.remove(&(uid, owner.clone()));
        self.tunnel_failed.remove(&(uid, owner));
        Ok(self.xray_status(uid, &plan.profile_id))
    }

    /// Rejects a reload whose plan would silently change kernel state: a
    /// different link name, address, DNS set, route set (explicit or bypass)
    /// or full-capture flags all require a disconnect/connect cycle.
    fn ensure_xray_reload_compatible(
        &self,
        index: usize,
        plan: &crate::xray::XrayPlan,
        process: &XrayProcessResource,
    ) -> io::Result<()> {
        let incompatible = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Xray network parameters changed; disconnect and reconnect to apply",
            )
        };
        if plan.name != process.name
            || plan.full_ipv4 != process.full.as_ref().is_some_and(|full| full.ipv4)
            || plan.full_ipv6 != process.full.as_ref().is_some_and(|full| full.ipv6)
        {
            return Err(incompatible());
        }
        let resources = &self.journal.entries[index].resources;
        let mut addresses = resources.iter().filter_map(|resource| match resource {
            OwnedResource::Address(address) => Some(address.address),
            _ => None,
        });
        if addresses.next() != Some(plan.address) || addresses.next().is_some() {
            return Err(incompatible());
        }
        let dns = resources.iter().find_map(|resource| match resource {
            OwnedResource::Dns(dns) => Some(dns),
            _ => None,
        });
        match (dns, plan.dns_servers.is_empty()) {
            (Some(dns), false)
                if dns.servers == plan.dns_servers && dns.domains == plan.dns_domains => {}
            (None, true) => {}
            _ => return Err(incompatible()),
        }
        // Tunnel routes: the journaled gateway-less Route resources must match
        // the plan's explicit routes (a default route's table is derived from
        // the recorded full-capture slot).
        let mut journaled: Vec<_> = resources
            .iter()
            .filter_map(|resource| match resource {
                OwnedResource::Route(route) if route.gateway.is_none() => {
                    Some((route.destination, route.metric, route.table))
                }
                _ => None,
            })
            .collect();
        journaled.sort();
        let mut desired: Vec<_> = plan
            .routes
            .iter()
            .map(|route| {
                (
                    route.destination,
                    route.metric,
                    if route.destination.prefix_len() == 0 {
                        process.full.as_ref().map(|full| full.table)
                    } else {
                        None
                    },
                )
            })
            .collect();
        desired.sort();
        if journaled != desired {
            return Err(incompatible());
        }
        // Bypass host routes (journaled with a physical gateway) must cover
        // the same upstream/DNS destinations the plan would install.
        let mut bypassed: Vec<_> = resources
            .iter()
            .filter_map(|resource| match resource {
                OwnedResource::Route(route) if route.gateway.is_some() => Some(route.destination),
                _ => None,
            })
            .collect();
        bypassed.sort();
        let mut targets = resolve_host_addrs(plan.server_host.as_deref());
        for ip in crate::xray::dns_bypass_addrs(&plan.dns_servers, plan.full_ipv4, plan.full_ipv6) {
            if !targets.contains(&ip) {
                targets.push(ip);
            }
        }
        let mut wanted: Vec<_> = targets
            .iter()
            .filter_map(|ip| {
                let prefix = if ip.is_ipv4() { 32 } else { 128 };
                IpNet::new(*ip, prefix).ok()
            })
            .collect();
        wanted.sort();
        if bypassed != wanted {
            return Err(incompatible());
        }
        Ok(())
    }

    fn apply_xray_plan(
        &mut self,
        index: usize,
        uid: u32,
        plan: &crate::xray::XrayPlan,
        full: Option<&WireGuardFullResource>,
    ) -> io::Result<()> {
        self.xray
            .as_mut()
            .unwrap()
            .start(uid, &plan.name, &plan.config, plan.geo_assets.as_ref())
            .map_err(|err| {
                let stage = if matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::NotConnected
                ) {
                    "tun_wait"
                } else {
                    "spawn"
                };
                xray_stage(stage, err)
            })?;
        let link_index = self
            .xray
            .as_ref()
            .unwrap()
            .link_index(&plan.name)
            .map_err(|err| xray_stage("tun_lookup", err))?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "Xray TUN link is unavailable")
            })?;
        if let OwnedResource::XrayProcess(process) = &mut self.journal.entries[index].resources[0] {
            process.index = link_index;
        }
        self.store
            .save(&self.journal)
            .map_err(|err| xray_stage("journal_link", err))?;
        let address = WireGuardAddressResource {
            interface_index: link_index,
            address: plan.address,
        };
        self.journal.entries[index]
            .resources
            .push(OwnedResource::Address(address.clone()));
        self.store
            .save(&self.journal)
            .map_err(|err| xray_stage("journal_address", err))?;
        if let Err(err) = self
            .wg
            .as_mut()
            .unwrap()
            .add_address(link_index, plan.address)
        {
            if err.kind() == io::ErrorKind::AlreadyExists {
                self.journal.entries[index].resources.pop();
            }
            return Err(xray_stage("address_add", err));
        }
        self.wg
            .as_mut()
            .unwrap()
            .set_mtu(link_index, plan.mtu)
            .map_err(|err| xray_stage("mtu_set", err))?;
        self.wg
            .as_mut()
            .unwrap()
            .set_state(link_index, true)
            .map_err(|err| xray_stage("link_up", err))?;
        self.add_xray_bypass_routes(index, plan)?;
        for route in &plan.routes {
            let mut applied = AppliedRoute::on_link(route.destination, link_index, route.metric);
            if route.destination.prefix_len() == 0 {
                applied.table = full.map(|full| full.table);
            }
            self.journal.entries[index]
                .resources
                .push(OwnedResource::Route(applied.clone()));
            self.store
                .save(&self.journal)
                .map_err(|err| xray_stage("journal_route", err))?;
            if let Err(err) = self.routes.add_route(&applied) {
                if err.kind() == io::ErrorKind::AlreadyExists {
                    self.journal.entries[index].resources.pop();
                }
                return Err(xray_stage("route_add", err));
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(full) = full {
            for rule in full_policy_rules(full) {
                self.journal.entries[index]
                    .resources
                    .push(OwnedResource::Rule(rule.clone()));
                self.store
                    .save(&self.journal)
                    .map_err(|err| xray_stage("journal_rule", err))?;
                if let Err(err) = self.policy.as_mut().unwrap().add_rule(&rule) {
                    if err.kind() == io::ErrorKind::AlreadyExists {
                        self.journal.entries[index].resources.pop();
                    }
                    return Err(xray_stage("rule_add", err));
                }
            }
        }
        #[cfg(target_os = "linux")]
        if !plan.dns_servers.is_empty() {
            self.journal.entries[index]
                .resources
                .push(OwnedResource::Dns(
                    net_manager_core::daemon_protocol::WireGuardDnsResource {
                        interface_index: link_index,
                        name: plan.name.clone(),
                        servers: plan.dns_servers.clone(),
                        domains: plan.dns_domains.clone(),
                        full: full.is_some(),
                        applied: false,
                    },
                ));
            self.store
                .save(&self.journal)
                .map_err(|err| xray_stage("journal_dns", err))?;
            match self.dns.as_mut().unwrap().apply(
                &plan.name,
                &plan.dns_servers,
                &plan.dns_domains,
                full.is_some(),
            ) {
                Ok(DnsApply::Applied) => {
                    if let Some(OwnedResource::Dns(dns)) =
                        self.journal.entries[index].resources.last_mut()
                    {
                        dns.applied = true;
                    }
                    self.store
                        .save(&self.journal)
                        .map_err(|err| xray_stage("journal_dns_applied", err))?;
                }
                Ok(DnsApply::Unavailable | DnsApply::Skipped) => {}
                Err(_) => return Err(io::Error::other("Xray dns_apply failed")),
            }
        }
        Ok(())
    }

    /// Direct host routes through the physical gateway for the tunnel's own
    /// upstream: the proxy server (the tunnel cannot carry its own server
    /// traffic) and DNS resolvers whose family is fully captured (otherwise
    /// resolver queries re-enter the TUN and loop). These live in the main
    /// table, so host routes stay reachable under `suppress_prefix_length 0`.
    fn add_xray_bypass_routes(
        &mut self,
        index: usize,
        plan: &crate::xray::XrayPlan,
    ) -> io::Result<()> {
        let mut targets = resolve_host_addrs(plan.server_host.as_deref());
        for ip in crate::xray::dns_bypass_addrs(&plan.dns_servers, plan.full_ipv4, plan.full_ipv6) {
            if !targets.contains(&ip) {
                targets.push(ip);
            }
        }
        if targets.is_empty() {
            return Ok(());
        }
        let gateways = self.routes.default_gateways().unwrap_or_default();
        for ip in targets {
            let Some((gateway, oif)) = gateways
                .iter()
                .copied()
                .find(|(gateway, _)| gateway.is_ipv4() == ip.is_ipv4())
            else {
                eprintln!("network-orchestrator-daemon: no uplink gateway for an xray bypass route, skipping");
                continue;
            };
            let prefix = if ip.is_ipv4() { 32 } else { 128 };
            let applied = AppliedRoute {
                destination: IpNet::new(ip, prefix)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad bypass"))?,
                interface_index: oif,
                metric: 5,
                gateway: Some(gateway),
                table: None,
            };
            self.journal.entries[index]
                .resources
                .push(OwnedResource::Route(applied.clone()));
            self.store
                .save(&self.journal)
                .map_err(|err| xray_stage("journal_bypass", err))?;
            match self.routes.add_route(&applied) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    // Another owner (e.g. a foreign tunnel) already holds a
                    // matching host route; do not journal what we did not add.
                    self.journal.entries[index].resources.pop();
                }
                Err(err) => return Err(xray_stage("bypass_route_add", err)),
            }
        }
        Ok(())
    }

    pub fn disconnect_xray(&mut self, uid: u32, profile_id: &str) -> io::Result<()> {
        let owner = format!("xray:{profile_id}");
        let Some(index) = self.position(uid, &owner) else {
            if self.tunnel_failed.remove(&(uid, owner)) {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Xray profile is not connected",
            ));
        };
        let result = self.teardown_entry(index);
        self.xray_restarts.remove(&(uid, owner));
        self.store.save(&self.journal)?;
        result
    }

    pub fn xray_status(&mut self, uid: u32, profile_id: &str) -> XrayStatusResult {
        let owner = format!("xray:{profile_id}");
        let entry = self
            .journal
            .entries
            .iter()
            .find(|entry| entry.uid == uid && entry.owner == owner);
        let process = entry.and_then(|entry| {
            entry.resources.iter().find_map(|resource| match resource {
                OwnedResource::XrayProcess(process) => Some(process),
                _ => None,
            })
        });
        let state = match (entry, process) {
            (None, _) if self.tunnel_failed.contains(&(uid, owner.clone())) => TunnelState::Failed,
            (None, _) => TunnelState::Stopped,
            (Some(entry), Some(process)) if entry.state == OwnedState::Applied => {
                if self
                    .xray
                    .as_mut()
                    .is_some_and(|runner| runner.health(&process.name).unwrap_or(false))
                {
                    TunnelState::Running
                } else {
                    TunnelState::Failed
                }
            }
            _ => TunnelState::Failed,
        };
        XrayStatusResult {
            profile_id: profile_id.to_owned(),
            state,
            interface_name: process.map(|process| process.name.clone()),
            dns_applied: entry.is_some_and(|entry| {
                entry
                    .resources
                    .iter()
                    .any(|resource| matches!(resource, OwnedResource::Dns(dns) if dns.applied))
            }),
            ipv4_covered: process
                .is_some_and(|process| process.full.as_ref().is_some_and(|full| full.ipv4)),
            ipv6_covered: process
                .is_some_and(|process| process.full.as_ref().is_some_and(|full| full.ipv6)),
        }
    }

    /// Predicts the deterministic resources an OpenVPN connect would use and
    /// reports which of them already collide. Nothing is created or removed —
    /// the same checks run again inside `connect_openvpn` before mutation.
    pub fn plan_openvpn(&self, uid: u32, plan: &OpenVpnPlan) -> io::Result<OpenVpnPlanResult> {
        let runner = self.openvpn.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "OpenVPN executor is unavailable",
            )
        })?;
        let owner = format!("ovpn:{}", plan.profile_id);
        let mut conflicts = Vec::new();
        if self.position(uid, &owner).is_some() {
            conflicts.push(OpenVpnPlanConflict::ActiveConnection);
        }
        if self
            .position(uid, &format!("ovpn-probe:{}", plan.profile_id))
            .is_some()
        {
            conflicts.push(OpenVpnPlanConflict::ActiveProbe);
        }
        // Mirror `resolve_openvpn_name`: the readable primary wins unless its
        // link or staging dir is taken, then the hash-suffixed fallback does.
        // Conflicts describe the primary name being displaced or the resolved
        // name remaining occupied — both connect-blocking signals.
        let mut name = plan.name.clone();
        if runner.link_index(&plan.name)?.is_some() {
            conflicts.push(OpenVpnPlanConflict::InterfaceOccupied);
        }
        if runner.staging_exists(uid, &plan.name)? {
            conflicts.push(OpenVpnPlanConflict::StagingLeftover);
        }
        if conflicts.iter().any(|c| {
            matches!(
                c,
                OpenVpnPlanConflict::InterfaceOccupied | OpenVpnPlanConflict::StagingLeftover
            )
        }) && plan.fallback_name != plan.name
        {
            name = plan.fallback_name.clone();
            if runner.link_index(&name)?.is_some()
                && !conflicts.contains(&OpenVpnPlanConflict::InterfaceOccupied)
            {
                conflicts.push(OpenVpnPlanConflict::InterfaceOccupied);
            }
            if runner.staging_exists(uid, &name)?
                && !conflicts.contains(&OpenVpnPlanConflict::StagingLeftover)
            {
                conflicts.push(OpenVpnPlanConflict::StagingLeftover);
            }
        }
        let staging = crate::openvpn::stage_dir(uid, &name);
        Ok(OpenVpnPlanResult {
            profile_id: plan.profile_id.clone(),
            owner,
            interface_name: name,
            fallback_interface_name: plan.fallback_name.clone(),
            staging_dir: staging.display().to_string(),
            config_path: staging.join("config.ovpn").display().to_string(),
            management_socket: staging.join("management.sock").display().to_string(),
            conflicts,
        })
    }

    pub fn connect_openvpn(
        &mut self,
        uid: u32,
        plan: OpenVpnPlan,
    ) -> io::Result<OpenVpnStatusResult> {
        let owner = format!("ovpn:{}", plan.profile_id);
        validate_owner(&owner).map_err(invalid_input)?;
        if self.position(uid, &owner).is_some()
            || self
                .position(uid, &format!("ovpn-probe:{}", plan.profile_id))
                .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "OpenVPN profile is already connected",
            ));
        }
        let mark = self.allocate_openvpn_mark()?;
        let runner = self.openvpn.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "OpenVPN executor is unavailable",
            )
        })?;
        runner.verify_binary()?;
        let name = resolve_openvpn_name(&**runner, uid, &plan)?;
        self.journal.entries.push(JournalEntry {
            uid,
            owner: owner.clone(),
            state: OwnedState::Applying,
            resources: vec![OwnedResource::OpenVpnProcess(OpenVpnProcessResource {
                name: name.clone(),
                owner_marker: format!("network-orchestrator:{uid}:{owner}"),
                transport_mark: Some(mark),
                full: None,
            })],
        });
        if let Err(err) = self.store.save(&self.journal) {
            self.journal.entries.pop();
            return Err(err);
        }
        let index = self.journal.entries.len() - 1;
        let staging = crate::openvpn::stage_dir(uid, &name);
        let started = plan.sanitized_config(&staging).and_then(|config| {
            self.openvpn
                .as_mut()
                .unwrap()
                .start(uid, &name, &config, plan.credentials, mark)
        });
        if let Err(err) = started {
            let _ = self.teardown_openvpn_entry(index);
            self.persist();
            return Err(err);
        }
        self.journal.entries[index].state = OwnedState::Applied;
        self.persist();
        self.openvpn_runtime.insert(
            (uid, owner.clone()),
            OpenVpnRuntime {
                explicit_routes: plan.routes,
                snapshot: ManagementSnapshot::default(),
            },
        );
        self.openvpn_failed.remove(&(uid, owner));
        self.openvpn_auth_failed
            .remove(&(uid, format!("ovpn:{}", plan.profile_id)));
        self.openvpn_failures
            .remove(&(uid, format!("ovpn:{}", plan.profile_id)));
        Ok(self.openvpn_status(uid, &plan.profile_id))
    }

    /// A probe owns only its transient process and link. It never applies routes or DNS.
    pub fn start_openvpn_probe(&mut self, uid: u32, plan: OpenVpnPlan) -> io::Result<()> {
        let owner = format!("ovpn-probe:{}", plan.profile_id);
        validate_owner(&owner).map_err(invalid_input)?;
        if self.position(uid, &owner).is_some()
            || self
                .position(uid, &format!("ovpn:{}", plan.profile_id))
                .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "OpenVPN profile is already active",
            ));
        }
        let mark = self.allocate_openvpn_mark()?;
        let runner = self.openvpn.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "OpenVPN executor is unavailable",
            )
        })?;
        runner.verify_binary()?;
        let name = resolve_openvpn_name(&**runner, uid, &plan)?;
        self.journal.entries.push(JournalEntry {
            uid,
            owner: owner.clone(),
            state: OwnedState::Applying,
            resources: vec![OwnedResource::OpenVpnProcess(OpenVpnProcessResource {
                name: name.clone(),
                owner_marker: format!("network-orchestrator:{uid}:{owner}"),
                transport_mark: Some(mark),
                full: None,
            })],
        });
        if let Err(error) = self.store.save(&self.journal) {
            self.journal.entries.pop();
            return Err(error);
        }
        let index = self.journal.entries.len() - 1;
        let staging = crate::openvpn::stage_dir(uid, &name);
        let started = plan.sanitized_config(&staging).and_then(|config| {
            self.openvpn
                .as_mut()
                .unwrap()
                .start(uid, &name, &config, plan.credentials, mark)
        });
        if let Err(error) = started {
            let _ = self.teardown_openvpn_entry(index);
            self.persist();
            return Err(error);
        }
        self.journal.entries[index].state = OwnedState::Applied;
        self.persist();
        Ok(())
    }

    pub fn poll_openvpn_probe(
        &mut self,
        uid: u32,
        profile_id: &str,
    ) -> io::Result<Option<OpenVpnProbeResult>> {
        let owner = format!("ovpn-probe:{profile_id}");
        let index = self.position(uid, &owner).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "OpenVPN probe is not active")
        })?;
        let name = self.journal.entries[index]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::OpenVpnProcess(process) => Some(&process.name),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("OpenVPN probe has no process marker"))?
            .clone();
        let events = self
            .openvpn
            .as_mut()
            .ok_or_else(|| io::Error::other("OpenVPN executor is unavailable"))?
            .poll(&name)?;
        if events.iter().any(|event| {
            matches!(
                event,
                ManagementEvent::AuthenticationFailed
                    | ManagementEvent::PasswordPrompt(_)
                    | ManagementEvent::State(OpenVpnState::Exiting)
            )
        }) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "OpenVPN probe authentication or handshake failed",
            ));
        }
        let connected = events
            .iter()
            .any(|event| matches!(event, ManagementEvent::State(OpenVpnState::Connected)));
        if let Some(push) = events.into_iter().find_map(|event| match event {
            ManagementEvent::PushReply(push) => Some(push),
            _ => None,
        }) {
            return Ok(Some(OpenVpnProbeResult {
                routes: push
                    .routes
                    .into_iter()
                    .map(|destination| AnalyzedRoute {
                        destination,
                        source: "OpenVPN pushed".into(),
                        metric: None,
                    })
                    .collect(),
            }));
        }
        Ok(connected.then_some(OpenVpnProbeResult { routes: Vec::new() }))
    }

    pub fn finish_openvpn_probe(&mut self, uid: u32, profile_id: &str) -> io::Result<()> {
        let owner = format!("ovpn-probe:{profile_id}");
        let index = self.position(uid, &owner).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "OpenVPN probe is not active")
        })?;
        let result = self.teardown_openvpn_entry(index);
        self.persist();
        result
    }

    pub fn disconnect_openvpn(&mut self, uid: u32, profile_id: &str) -> io::Result<()> {
        let owner = format!("ovpn:{profile_id}");
        let key = (uid, owner.clone());
        let Some(index) = self.position(uid, &owner) else {
            if self.openvpn_failed.remove(&key) {
                self.openvpn_auth_failed.remove(&key);
                self.openvpn_failures.remove(&key);
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "OpenVPN profile is not connected",
            ));
        };
        let result = self.teardown_entry(index);
        self.persist();
        if result.is_ok() {
            self.openvpn_failed.remove(&key);
            self.openvpn_auth_failed.remove(&key);
            self.openvpn_failures.remove(&key);
        }
        result
    }

    fn allocate_openvpn_mark(&mut self) -> io::Result<u32> {
        #[cfg(target_os = "linux")]
        let existing_rules = match self.policy.as_mut() {
            Some(policy) => policy.rules_snapshot()?,
            None => Vec::new(),
        };
        for slot in 0..128_u32 {
            let mark = 51820 + slot;
            let priority_main = 10000 + slot * 2;
            let priority_tunnel = priority_main + 1;
            let used_by_owner = self.journal.entries.iter().any(|entry| {
                entry.resources.iter().any(|resource| match resource {
                    OwnedResource::OpenVpnProcess(process) => process.transport_mark == Some(mark),
                    OwnedResource::XrayProcess(process) => process.transport_mark == mark,
                    OwnedResource::WireGuardLink(link) => {
                        link.full.as_ref().is_some_and(|full| full.fwmark == mark)
                    }
                    _ => false,
                })
            });
            if used_by_owner {
                continue;
            }
            #[cfg(target_os = "linux")]
            if existing_rules.iter().any(|rule| {
                rule.fwmark == Some(mark)
                    || rule.priority == priority_main
                    || rule.priority == priority_tunnel
            }) {
                continue;
            }
            #[cfg(target_os = "linux")]
            if self
                .policy
                .as_mut()
                .is_some_and(|policy| policy.table_in_use(mark).unwrap_or(true))
            {
                continue;
            }
            return Ok(mark);
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "no OpenVPN transport mark is available",
        ))
    }

    #[cfg(target_os = "linux")]
    fn openvpn_full_plan(
        &mut self,
        index: usize,
        ipv4: bool,
        ipv6: bool,
    ) -> io::Result<Option<WireGuardFullResource>> {
        if !ipv4 && !ipv6 {
            return Ok(None);
        }
        if self
            .journal
            .entries
            .iter()
            .enumerate()
            .any(|(other_index, entry)| {
                other_index != index
                    && entry.resources.iter().any(|resource| match resource {
                        OwnedResource::WireGuardLink(link) => link.full.is_some(),
                        OwnedResource::OpenVpnProcess(process) => process.full.is_some(),
                        OwnedResource::XrayProcess(process) => process.full.is_some(),
                        _ => false,
                    })
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "another full tunnel owns policy routing",
            ));
        }
        let process = self.journal.entries[index]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::OpenVpnProcess(process) => Some(process),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OpenVPN process journal is malformed",
                )
            })?;
        let mark = process.transport_mark.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "OpenVPN transport mark is missing",
            )
        })?;
        let slot = mark
            .checked_sub(51820)
            .filter(|slot| *slot < 128)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OpenVPN transport mark is invalid",
                )
            })?;
        let priority_main = 10000 + slot * 2;
        let priority_tunnel = priority_main + 1;
        if process.full.is_none() {
            let policy = self.policy.as_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "policy executor is unavailable",
                )
            })?;
            let rules = policy.rules_snapshot()?;
            if rules.iter().any(|rule| {
                rule.fwmark == Some(mark)
                    || rule.priority == priority_main
                    || rule.priority == priority_tunnel
            }) || policy.table_in_use(mark)?
                || self.wg_config.as_ref().is_some_and(|wg| {
                    wg.marks_in_use()
                        .map_or(true, |marks| marks.contains(&mark))
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "OpenVPN policy slot is occupied",
                ));
            }
        }
        Ok(Some(WireGuardFullResource {
            table: mark,
            fwmark: mark,
            priority_main,
            priority_tunnel,
            ipv4,
            ipv6,
        }))
    }

    pub fn openvpn_status(&self, uid: u32, profile_id: &str) -> OpenVpnStatusResult {
        let owner = format!("ovpn:{profile_id}");
        let key = (uid, owner.clone());
        let entry = self
            .journal
            .entries
            .iter()
            .find(|entry| entry.uid == uid && entry.owner == owner);
        let interface_name = entry.and_then(|entry| {
            entry.resources.iter().find_map(|resource| match resource {
                OwnedResource::OpenVpnProcess(process) => Some(process.name.clone()),
                _ => None,
            })
        });
        let runtime = self.openvpn_runtime.get(&key);
        let state = match (entry, runtime) {
            (Some(entry), _) if entry.state == OwnedState::Stale => OpenVpnConnectionState::Failed,
            (Some(_), Some(runtime)) => match runtime.snapshot.state {
                Some(OpenVpnState::Connected) => OpenVpnConnectionState::Connected,
                Some(OpenVpnState::Reconnecting) => OpenVpnConnectionState::Reconnecting,
                Some(OpenVpnState::Exiting) => OpenVpnConnectionState::Failed,
                _ => OpenVpnConnectionState::Connecting,
            },
            (Some(_), None) => OpenVpnConnectionState::Failed,
            (None, _) if self.openvpn_failed.contains(&key) => OpenVpnConnectionState::Failed,
            (None, _) => OpenVpnConnectionState::Stopped,
        };
        let applied_routes = entry
            .map(|entry| {
                entry
                    .resources
                    .iter()
                    .filter_map(|resource| match resource {
                        OwnedResource::Route(route) => Some(route.destination),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut warnings = Vec::new();
        if let Some(entry) = entry {
            if entry
                .resources
                .iter()
                .any(|resource| matches!(resource, OwnedResource::Dns(dns) if !dns.applied))
            {
                warnings.push(OpenVpnWarning::DnsNotApplied);
            }
            if entry.resources.iter().any(|resource| matches!(resource, OwnedResource::OpenVpnProcess(process) if process.full.as_ref().is_some_and(|full| full.ipv4 && !full.ipv6))) {
                warnings.push(OpenVpnWarning::Ipv6NotCovered);
            }
        }
        if state == OpenVpnConnectionState::Failed && self.openvpn_auth_failed.contains(&key) {
            warnings.push(OpenVpnWarning::AuthenticationFailed);
        }
        let failure_reason = (state == OpenVpnConnectionState::Failed)
            .then(|| self.openvpn_failures.get(&key).copied())
            .flatten();
        OpenVpnStatusResult {
            profile_id: profile_id.to_owned(),
            state,
            interface_name,
            rx_bytes: runtime.map_or(0, |runtime| runtime.snapshot.received),
            tx_bytes: runtime.map_or(0, |runtime| runtime.snapshot.sent),
            applied_routes,
            warnings,
            failure_reason,
        }
    }

    pub fn reconcile_openvpn(&mut self) -> io::Result<()> {
        let owners: Vec<_> = self
            .openvpn_runtime
            .keys()
            .filter(|(uid, owner)| {
                self.position(*uid, owner)
                    .is_some_and(|index| self.journal.entries[index].state == OwnedState::Applied)
            })
            .cloned()
            .collect();
        // One failing owner must not starve the others; report the first error.
        let mut first_error = None;
        for (uid, owner) in owners {
            if let Err(err) = self.reconcile_openvpn_owner(uid, &owner) {
                eprintln!("network-orchestrator-daemon: OpenVPN reconcile failed: {err}");
                first_error.get_or_insert(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn reconcile_openvpn_owner(&mut self, uid: u32, owner: &str) -> io::Result<()> {
        let index = self
            .position(uid, owner)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OpenVPN owner is missing"))?;
        let name = self.journal.entries[index]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::OpenVpnProcess(process) => Some(process.name.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OpenVPN process journal is malformed",
                )
            })?;
        let events = match self.openvpn.as_mut().unwrap().poll(&name) {
            Ok(events) => events,
            Err(_) => return self.fail_openvpn(uid, owner),
        };
        for event in events {
            match &event {
                ManagementEvent::AuthenticationFailed => {
                    self.openvpn_auth_failed.insert((uid, owner.to_owned()));
                    self.openvpn_failures.insert(
                        (uid, owner.to_owned()),
                        OpenVpnFailure::AuthenticationFailure,
                    );
                    return self.fail_openvpn(uid, owner);
                }
                ManagementEvent::PasswordPrompt(_) => return self.fail_openvpn(uid, owner),
                ManagementEvent::FailureDetail(reason) => {
                    self.openvpn_failures
                        .insert((uid, owner.to_owned()), *reason);
                    if matches!(reason, OpenVpnFailure::CredentialsRequired) {
                        return self.fail_openvpn(uid, owner);
                    }
                }
                _ => {}
            }
            if let Some(runtime) = self.openvpn_runtime.get_mut(&(uid, owner.to_owned())) {
                runtime.snapshot.apply(event);
            }
        }
        let runtime = self.openvpn_runtime.get(&(uid, owner.to_owned())).unwrap();
        let network = if runtime.snapshot.state == Some(OpenVpnState::Connected) {
            match OpenVpnNetworkPlan::from_runtime(runtime) {
                Ok(plan) => plan,
                Err(_) => return self.fail_openvpn(uid, owner),
            }
        } else if runtime.snapshot.state == Some(OpenVpnState::Reconnecting) {
            OpenVpnNetworkPlan {
                routes: Vec::new(),
                full_ipv4: false,
                full_ipv6: false,
                dns_servers: Vec::new(),
                dns_domains: Vec::new(),
            }
        } else {
            return Ok(());
        };
        #[cfg(target_os = "linux")]
        let full = match self.openvpn_full_plan(index, network.full_ipv4, network.full_ipv6) {
            Ok(full) => full,
            Err(_) => return self.fail_openvpn(uid, owner),
        };
        #[cfg(not(target_os = "linux"))]
        let full: Option<WireGuardFullResource> = None;
        #[cfg(target_os = "linux")]
        if !network.dns_servers.is_empty() && self.dns.is_none() {
            return self.fail_openvpn(uid, owner);
        }
        let current: Vec<_> = self.journal.entries[index]
            .resources
            .iter()
            .filter_map(|resource| match resource {
                OwnedResource::Route(route) => Some(route.clone()),
                _ => None,
            })
            .collect();
        let desired_routes: Vec<_> = network
            .routes
            .iter()
            .map(|route| {
                (
                    route.destination,
                    route.metric,
                    network
                        .is_full_route(route.destination)
                        .then(|| full.as_ref().map(|full| full.table))
                        .flatten(),
                )
            })
            .collect();
        let current_full = self.journal.entries[index]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::OpenVpnProcess(process) => process.full.clone(),
                _ => None,
            });
        let current_dns = self.journal.entries[index]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::Dns(dns) => Some((&dns.servers, &dns.domains, dns.full)),
                _ => None,
            });
        if current
            .iter()
            .map(|route| (route.destination, route.metric, route.table))
            .collect::<Vec<_>>()
            == desired_routes
            && current_full == full
            && current_dns.is_none_or(|(servers, domains, is_full)| {
                servers == &network.dns_servers
                    && domains == &network.dns_domains
                    && is_full == full.is_some()
            })
            && (current_dns.is_some() != network.dns_servers.is_empty())
        {
            return Ok(());
        }
        if self.clear_openvpn_network(index).is_err() {
            return self.fail_openvpn(uid, owner);
        }
        if network.routes.is_empty() && network.dns_servers.is_empty() {
            return Ok(());
        }
        let link_index = match self.openvpn.as_ref().unwrap().link_index(&name) {
            Ok(Some(index)) => index,
            _ => return self.fail_openvpn(uid, owner),
        };
        if let Some(OwnedResource::OpenVpnProcess(process)) =
            self.journal.entries[index].resources.first_mut()
        {
            process.full = full.clone();
        }
        if self.store.save(&self.journal).is_err() {
            return self.fail_openvpn(uid, owner);
        }
        for route in &network.routes {
            let mut applied = AppliedRoute::on_link(route.destination, link_index, route.metric);
            if network.is_full_route(route.destination) {
                applied.table = full.as_ref().map(|full| full.table);
            }
            self.journal.entries[index]
                .resources
                .push(OwnedResource::Route(applied.clone()));
            if let Err(err) = self.store.save(&self.journal) {
                self.journal.entries[index].resources.pop();
                let _ = self.fail_openvpn(uid, owner);
                return Err(err);
            }
            if let Err(err) = self.routes.add_route(&applied) {
                if err.kind() == io::ErrorKind::AlreadyExists {
                    self.journal.entries[index].resources.pop();
                }
                return self.fail_openvpn(uid, owner);
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(full) = &full {
            for rule in full_policy_rules(full) {
                self.journal.entries[index]
                    .resources
                    .push(OwnedResource::Rule(rule.clone()));
                if self.store.save(&self.journal).is_err() {
                    self.journal.entries[index].resources.pop();
                    return self.fail_openvpn(uid, owner);
                }
                if let Err(err) = self.policy.as_mut().unwrap().add_rule(&rule) {
                    if err.kind() == io::ErrorKind::AlreadyExists {
                        self.journal.entries[index].resources.pop();
                    }
                    return self.fail_openvpn(uid, owner);
                }
            }
        }
        #[cfg(target_os = "linux")]
        if !network.dns_servers.is_empty() {
            self.journal.entries[index]
                .resources
                .push(OwnedResource::Dns(
                    net_manager_core::daemon_protocol::WireGuardDnsResource {
                        interface_index: link_index,
                        name: name.clone(),
                        servers: network.dns_servers.clone(),
                        domains: network.dns_domains.clone(),
                        full: full.is_some(),
                        applied: false,
                    },
                ));
            if self.store.save(&self.journal).is_err() {
                self.journal.entries[index].resources.pop();
                return self.fail_openvpn(uid, owner);
            }
            let result = self.dns.as_mut().unwrap().apply(
                &name,
                &network.dns_servers,
                &network.dns_domains,
                full.is_some(),
            );
            match result {
                Ok(DnsApply::Applied) => {
                    if let Some(OwnedResource::Dns(resource)) =
                        self.journal.entries[index].resources.last_mut()
                    {
                        resource.applied = true;
                    }
                    self.persist();
                }
                Ok(DnsApply::Unavailable | DnsApply::Skipped) => {}
                Err(_) => return self.fail_openvpn(uid, owner),
            }
        }
        Ok(())
    }

    fn clear_openvpn_network(&mut self, index: usize) -> io::Result<()> {
        let resources = self.journal.entries[index].resources.clone();
        let name = resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::OpenVpnProcess(process) => Some(process.name.as_str()),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OpenVPN process journal is malformed",
                )
            })?;
        let link_present = self
            .openvpn
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "OpenVPN executor is unavailable",
                )
            })?
            .link_index(name)?
            .is_some();
        for resource in resources.iter().rev() {
            let result = match resource {
                OwnedResource::Dns(dns) if dns.applied => {
                    #[cfg(target_os = "linux")]
                    {
                        match self.dns.as_mut() {
                            Some(executor) => match executor.revert(&dns.name) {
                                Ok(()) | Err(crate::dns::DnsError::Unavailable) => Ok(()),
                                Err(_) if !link_present => Ok(()),
                                Err(_) => Err(io::Error::other("OpenVPN DNS cleanup failed")),
                            },
                            None if !link_present => Ok(()),
                            None => Err(io::Error::other("OpenVPN DNS executor is unavailable")),
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        Ok(())
                    }
                }
                OwnedResource::Rule(rule) => {
                    #[cfg(target_os = "linux")]
                    {
                        self.policy
                            .as_mut()
                            .ok_or_else(|| {
                                io::Error::other("OpenVPN policy executor is unavailable")
                            })?
                            .remove_rule(rule)
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        Ok(())
                    }
                }
                OwnedResource::Route(route) => self.routes.remove_route(route),
                _ => Ok(()),
            };
            if let Err(err) = result {
                if err.kind() != io::ErrorKind::NotFound {
                    self.journal.entries[index].state = OwnedState::Stale;
                    self.persist();
                    return Err(io::Error::other("OpenVPN network cleanup failed"));
                }
            }
        }
        self.journal.entries[index]
            .resources
            .retain(|resource| matches!(resource, OwnedResource::OpenVpnProcess(_)));
        if let Some(OwnedResource::OpenVpnProcess(process)) =
            self.journal.entries[index].resources.first_mut()
        {
            process.full = None;
        }
        self.store.save(&self.journal)
    }

    fn fail_openvpn(&mut self, uid: u32, owner: &str) -> io::Result<()> {
        if let Some(reason) = self
            .openvpn_runtime
            .get(&(uid, owner.to_owned()))
            .and_then(|runtime| runtime.snapshot.last_failure)
        {
            self.openvpn_failures
                .entry((uid, owner.to_owned()))
                .or_insert(reason);
        }
        if let Some(index) = self.position(uid, owner) {
            let _ = self.teardown_openvpn_entry(index);
            self.persist();
        }
        self.openvpn_failed.insert((uid, owner.to_owned()));
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "OpenVPN connection failed or requested unsupported network options",
        ))
    }

    pub fn connect_wireguard(
        &mut self,
        uid: u32,
        profile_id: &str,
        plan: WireGuardPlan,
    ) -> io::Result<WireGuardStatusResult> {
        let owner = wireguard_owner(profile_id)?;
        #[cfg(target_os = "linux")]
        if !plan.dns_servers.is_empty() && self.dns.is_none() {
            return Err(invalid_input("DNS executor is unavailable".into()));
        }
        if self.position(uid, &owner).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "WireGuard profile is already connected",
            ));
        }
        if self.wg.is_none() || self.wg_config.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "WireGuard executor is unavailable",
            ));
        }
        #[cfg(target_os = "linux")]
        let full = self.allocate_full(&plan)?;
        #[cfg(not(target_os = "linux"))]
        let full: Option<WireGuardFullResource> = None;
        let (name, fallback_name) = wireguard_name(uid, profile_id, plan.interface_name.as_deref());
        let marker = format!("network-orchestrator:{uid}:{owner}");
        let mut warnings: Vec<_> = plan
            .warnings
            .iter()
            .map(|warning| match warning {
                WireGuardPlanWarning::IgnoredHook => WireGuardWarning::IgnoredHook,
                WireGuardPlanWarning::IgnoredSaveConfig => WireGuardWarning::IgnoredSaveConfig,
            })
            .collect();
        if plan.full_ipv4 && !plan.full_ipv6 {
            warnings.push(WireGuardWarning::Ipv6NotCovered);
        }
        let link = WireGuardLinkResource {
            name: name.clone(),
            index: 0,
            owner_marker: marker.clone(),
            full: full.clone(),
            warnings,
        };
        self.journal.entries.push(JournalEntry {
            uid,
            owner: owner.clone(),
            state: OwnedState::Applying,
            resources: vec![OwnedResource::WireGuardLink(link)],
        });
        let index = self.journal.entries.len() - 1;
        if let Err(err) = self.store.save(&self.journal) {
            self.journal.entries.pop();
            return Err(err);
        }
        let result = (|| -> io::Result<()> {
            // When the requested name is taken by a foreign interface, retry
            // once with the deterministic `wg-<slug>-<hash>` fallback instead
            // of claiming or deleting the foreign link.
            let (ifindex, name) = match self.wg.as_mut().unwrap().create_link(&name, &marker) {
                Ok(ifindex) => (ifindex, name.clone()),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists && fallback_name != name => {
                    (
                        self.wg
                            .as_mut()
                            .unwrap()
                            .create_link(&fallback_name, &marker)?,
                        fallback_name.clone(),
                    )
                }
                Err(err) => return Err(err),
            };
            if let OwnedResource::WireGuardLink(link) =
                &mut self.journal.entries[index].resources[0]
            {
                link.index = ifindex;
                link.name = name.clone();
            }
            self.store.save(&self.journal)?;
            self.wg_config
                .as_mut()
                .unwrap()
                .configure(&name, &plan.setconf)?;
            let in_full_table = |destination: IpNet| {
                full.is_some() && is_full_route(plan.full_ipv4, plan.full_ipv6, destination)
            };
            // Main-table routes and address prefixes on the tunnel link would
            // send the encrypted transport back into the tunnel.
            for endpoint in self.wg_config.as_ref().unwrap().endpoint_ips(&name)? {
                if plan
                    .addresses
                    .iter()
                    .any(|address| address.trunc().contains(&endpoint))
                    || plan.routes.iter().any(|route| {
                        !in_full_table(route.destination) && route.destination.contains(&endpoint)
                    })
                {
                    return Err(invalid_input(
                        "WireGuard endpoint is covered by tunnel routes or addresses".into(),
                    ));
                }
            }
            if let Some(full) = &full {
                self.wg_config
                    .as_mut()
                    .unwrap()
                    .set_fwmark(&name, full.fwmark)?;
            }
            for address in &plan.addresses {
                self.journal.entries[index]
                    .resources
                    .push(OwnedResource::Address(WireGuardAddressResource {
                        interface_index: ifindex,
                        address: *address,
                    }));
                self.store.save(&self.journal)?;
                self.wg.as_mut().unwrap().add_address(ifindex, *address)?;
            }
            if let Some(mtu) = plan.mtu {
                self.wg.as_mut().unwrap().set_mtu(ifindex, mtu)?;
            }
            self.wg.as_mut().unwrap().set_state(ifindex, true)?;
            for route in &plan.routes {
                if plan
                    .addresses
                    .iter()
                    .any(|address| address.trunc() == route.destination)
                {
                    continue;
                }
                let mut applied = AppliedRoute::on_link(route.destination, ifindex, route.metric);
                if in_full_table(route.destination) {
                    applied.table = full.as_ref().map(|full| full.table);
                }
                self.journal.entries[index]
                    .resources
                    .push(OwnedResource::Route(applied.clone()));
                self.store.save(&self.journal)?;
                self.routes.add_route(&applied)?;
            }
            #[cfg(target_os = "linux")]
            if let Some(full) = &full {
                for rule in full_policy_rules(full) {
                    self.journal.entries[index]
                        .resources
                        .push(OwnedResource::Rule(rule.clone()));
                    self.store.save(&self.journal)?;
                    self.policy.as_mut().unwrap().add_rule(&rule)?;
                }
                self.wg_config.as_ref().unwrap().verify_transport(
                    &name,
                    full.fwmark,
                    full.ipv4,
                    full.ipv6,
                )?;
            }
            #[cfg(target_os = "linux")]
            if !plan.dns_servers.is_empty() {
                self.journal.entries[index]
                    .resources
                    .push(OwnedResource::Dns(
                        net_manager_core::daemon_protocol::WireGuardDnsResource {
                            interface_index: ifindex,
                            name: name.clone(),
                            servers: plan.dns_servers.clone(),
                            domains: plan.dns_domains.clone(),
                            full: full.is_some(),
                            applied: false,
                        },
                    ));
                self.store.save(&self.journal)?;
                let outcome = self
                    .dns
                    .as_mut()
                    .unwrap()
                    .apply(&name, &plan.dns_servers, &plan.dns_domains, full.is_some())
                    .map_err(|err| io::Error::other(err.to_string()))?;
                match outcome {
                    DnsApply::Applied => {
                        if let Some(OwnedResource::Dns(dns)) =
                            self.journal.entries[index].resources.last_mut()
                        {
                            dns.applied = true;
                        }
                    }
                    DnsApply::Unavailable => {
                        if let OwnedResource::WireGuardLink(link) =
                            &mut self.journal.entries[index].resources[0]
                        {
                            link.warnings.push(WireGuardWarning::DnsNotApplied);
                        }
                    }
                    DnsApply::Skipped => {
                        self.journal.entries[index].resources.pop();
                        if let OwnedResource::WireGuardLink(link) =
                            &mut self.journal.entries[index].resources[0]
                        {
                            link.warnings.push(WireGuardWarning::DnsNotApplied);
                        }
                    }
                }
                self.store.save(&self.journal)?;
            }
            Ok(())
        })();
        if let Err(err) = result {
            // RTM_NEWLINK with EEXIST did not create anything; the existing
            // interface must never be claimed or removed by our WAL intent.
            if err.kind() == io::ErrorKind::AlreadyExists
                && self.journal.entries[index].resources.len() == 1
                && matches!(&self.journal.entries[index].resources[0], OwnedResource::WireGuardLink(link) if link.index == 0)
            {
                self.journal.entries.remove(index);
                self.persist();
                return Err(err);
            }
            let _ = self.teardown_entry(index);
            self.persist();
            return Err(err);
        }
        self.journal.entries[index].state = OwnedState::Applied;
        if let Err(err) = self.store.save(&self.journal) {
            let _ = self.teardown_entry(index);
            self.persist();
            return Err(err);
        }
        self.tunnel_failed.remove(&(uid, owner.clone()));
        self.wireguard_handshake.remove(&(uid, owner));
        Ok(self.wireguard_status(uid, profile_id))
    }

    #[cfg(target_os = "linux")]
    fn allocate_full(&mut self, plan: &WireGuardPlan) -> io::Result<Option<WireGuardFullResource>> {
        if !plan.full_ipv4 && !plan.full_ipv6 {
            return Ok(None);
        }
        if self.journal.entries.iter().any(|entry| {
            entry.resources.iter().any(|resource| match resource {
                OwnedResource::WireGuardLink(link) => link.full.is_some(),
                OwnedResource::OpenVpnProcess(process) => process.full.is_some(),
                OwnedResource::XrayProcess(process) => process.full.is_some(),
                _ => false,
            })
        }) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "another full tunnel owns policy routing",
            ));
        }
        let policy = self.policy.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "policy executor is unavailable",
            )
        })?;
        let existing = policy.rules_snapshot()?;
        let wg_marks = self.wg_config.as_ref().unwrap().marks_in_use()?;
        for slot in 0..128_u32 {
            let table = 51820 + slot;
            let priority_main = 10000 + slot * 2;
            let priority_tunnel = priority_main + 1;
            if wg_marks.contains(&table)
                || self.journal.entries.iter().any(|entry| entry.resources.iter().any(|resource| matches!(resource, OwnedResource::OpenVpnProcess(process) if process.transport_mark == Some(table)) || matches!(resource, OwnedResource::XrayProcess(process) if process.transport_mark == table)))
                || existing.iter().any(|rule| {
                    rule.fwmark == Some(table)
                        || rule.priority == priority_main
                        || rule.priority == priority_tunnel
                })
                || policy.table_in_use(table)?
            {
                continue;
            }
            return Ok(Some(WireGuardFullResource {
                table,
                fwmark: table,
                priority_main,
                priority_tunnel,
                ipv4: plan.full_ipv4,
                ipv6: plan.full_ipv6,
            }));
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "no safe policy routing slot is available",
        ))
    }

    pub fn disconnect_wireguard(&mut self, uid: u32, profile_id: &str) -> io::Result<()> {
        let owner = wireguard_owner(profile_id)?;
        let Some(index) = self.position(uid, &owner) else {
            if self.tunnel_failed.remove(&(uid, owner)) {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "WireGuard profile is not connected",
            ));
        };
        let result = self.teardown_entry(index);
        self.store.save(&self.journal)?;
        result
    }

    pub fn wireguard_status(&mut self, uid: u32, profile_id: &str) -> WireGuardStatusResult {
        let owner = format!("wg:{profile_id}");
        let entry = self
            .journal
            .entries
            .iter()
            .find(|entry| entry.uid == uid && entry.owner == owner);
        let interface_name = entry.and_then(|entry| {
            entry.resources.iter().find_map(|resource| match resource {
                OwnedResource::WireGuardLink(link) => Some(link.name.clone()),
                _ => None,
            })
        });
        let warnings = entry
            .and_then(|entry| {
                entry.resources.iter().find_map(|resource| match resource {
                    OwnedResource::WireGuardLink(link) => Some(link.warnings.clone()),
                    _ => None,
                })
            })
            .unwrap_or_default();
        let dns_applied = entry.is_some_and(|entry| {
            entry
                .resources
                .iter()
                .any(|resource| matches!(resource, OwnedResource::Dns(dns) if dns.applied))
        });
        let (state, latest_handshake, rx_bytes, tx_bytes) = match (entry, interface_name.as_deref())
        {
            (Some(entry), Some(name)) if entry.state == OwnedState::Applied => {
                match self.wg_config.as_ref().and_then(|wg| wg.health(name).ok()) {
                    Some((handshake, rx, tx)) => {
                        let key = (uid, owner.clone());
                        let (state, watch) = observe_handshake(
                            self.wireguard_handshake.get(&key).copied(),
                            handshake,
                            tx,
                            (self.clock)(),
                        );
                        match watch {
                            Some(watch) => self.wireguard_handshake.insert(key, watch),
                            None => self.wireguard_handshake.remove(&key),
                        };
                        (state, handshake, rx, tx)
                    }
                    None => (TunnelState::Failed, None, 0, 0),
                }
            }
            (Some(_), _) => (TunnelState::Failed, None, 0, 0),
            (None, _) if self.tunnel_failed.contains(&(uid, owner)) => {
                (TunnelState::Failed, None, 0, 0)
            }
            (None, _) => (TunnelState::Stopped, None, 0, 0),
        };
        WireGuardStatusResult {
            profile_id: profile_id.into(),
            state,
            interface_name,
            latest_handshake,
            rx_bytes,
            tx_bytes,
            dns_applied,
            warnings,
        }
    }

    #[cfg(target_os = "linux")]
    pub fn reapply_dns(&mut self) -> io::Result<()> {
        let Some(dns_executor) = self.dns.as_mut() else {
            return Ok(());
        };
        let mut changed_any = false;
        for entry in &mut self.journal.entries {
            if entry.state != OwnedState::Applied {
                continue;
            }
            if entry.owner.starts_with("ovpn:") {
                let Some(dns) = entry.resources.iter().find_map(|resource| match resource {
                    OwnedResource::Dns(dns) => Some(dns.clone()),
                    _ => None,
                }) else {
                    continue;
                };
                let active = self
                    .openvpn_runtime
                    .get(&(entry.uid, entry.owner.clone()))
                    .is_some_and(|runtime| runtime.snapshot.state == Some(OpenVpnState::Connected));
                let same_link = self
                    .openvpn
                    .as_ref()
                    .and_then(|runner| runner.link_index(&dns.name).ok().flatten())
                    == Some(dns.interface_index);
                if !active || !same_link {
                    continue;
                }
                let applied = matches!(
                    dns_executor.apply(&dns.name, &dns.servers, &dns.domains, dns.full),
                    Ok(DnsApply::Applied)
                );
                if let Some(OwnedResource::Dns(resource)) = entry
                    .resources
                    .iter_mut()
                    .find(|resource| matches!(resource, OwnedResource::Dns(_)))
                {
                    if resource.applied != applied {
                        resource.applied = applied;
                        changed_any = true;
                    }
                }
                continue;
            }
            if entry.owner.starts_with("xray:") {
                let Some(dns) = entry.resources.iter().find_map(|resource| match resource {
                    OwnedResource::Dns(dns) => Some(dns.clone()),
                    _ => None,
                }) else {
                    continue;
                };
                let same_link = self
                    .xray
                    .as_ref()
                    .and_then(|runner| runner.link_index(&dns.name).ok().flatten())
                    == Some(dns.interface_index);
                if !same_link {
                    continue;
                }
                let applied = matches!(
                    dns_executor.apply(&dns.name, &dns.servers, &dns.domains, dns.full),
                    Ok(DnsApply::Applied)
                );
                if let Some(OwnedResource::Dns(resource)) = entry
                    .resources
                    .iter_mut()
                    .find(|resource| matches!(resource, OwnedResource::Dns(_)))
                {
                    if resource.applied != applied {
                        resource.applied = applied;
                        changed_any = true;
                    }
                }
                continue;
            }
            if !entry.owner.starts_with("wg:") {
                continue;
            }
            let Some(wg) = self.wg.as_mut() else {
                continue;
            };
            let link = entry.resources.iter().find_map(|resource| match resource {
                OwnedResource::WireGuardLink(link) => Some(link.clone()),
                _ => None,
            });
            let dns = entry.resources.iter().find_map(|resource| match resource {
                OwnedResource::Dns(dns) => Some(dns.clone()),
                _ => None,
            });
            let (Some(link), Some(dns)) = (link, dns) else {
                continue;
            };
            if !wg.link_owned(&link.name, link.index, &link.owner_marker)? {
                continue;
            }
            let applied = matches!(
                dns_executor.apply(&dns.name, &dns.servers, &dns.domains, dns.full),
                Ok(DnsApply::Applied)
            );
            let mut changed = false;
            if let Some(OwnedResource::Dns(resource)) = entry
                .resources
                .iter_mut()
                .find(|resource| matches!(resource, OwnedResource::Dns(_)))
            {
                if resource.applied != applied {
                    resource.applied = applied;
                    changed = true;
                }
            }
            if let Some(OwnedResource::WireGuardLink(resource)) = entry
                .resources
                .iter_mut()
                .find(|resource| matches!(resource, OwnedResource::WireGuardLink(_)))
            {
                if applied {
                    let before = resource.warnings.len();
                    resource
                        .warnings
                        .retain(|warning| *warning != WireGuardWarning::DnsNotApplied);
                    changed |= resource.warnings.len() != before;
                } else if !resource.warnings.contains(&WireGuardWarning::DnsNotApplied) {
                    resource.warnings.push(WireGuardWarning::DnsNotApplied);
                    changed = true;
                }
            }
            changed_any |= changed;
        }
        if changed_any {
            self.store.save(&self.journal)?;
        }
        Ok(())
    }

    /// Re-verify daemon-owned tunnels after an uplink change or resume.
    /// Missing owned routes and policy rules are installed again; a tunnel
    /// whose transport is gone, or whose state cannot be restored without
    /// claiming a foreign rule, is torn down (no dead default route stays)
    /// and reported `failed`. Returns the owners that changed.
    #[cfg(target_os = "linux")]
    pub fn reconcile_network(&mut self, observed: &[AppliedRoute]) -> Vec<(u32, String)> {
        let mut changed = Vec::new();
        for index in (0..self.journal.entries.len()).rev() {
            let entry = &self.journal.entries[index];
            if entry.state != OwnedState::Applied {
                continue;
            }
            let key = (entry.uid, entry.owner.clone());
            let restored = match self.tunnel_alive(index) {
                None => continue,
                Some(false) => {
                    // A dead xray child first gets an in-place respawn; only
                    // an exhausted budget or a respawn failure tears the
                    // tunnel down.
                    if key.1.starts_with("xray:") {
                        match self.heal_xray(index) {
                            Ok(true) => self.restore_owned_network(index, observed),
                            Ok(false) | Err(_) => Err(io::Error::other("tunnel transport is gone")),
                        }
                    } else {
                        Err(io::Error::other("tunnel transport is gone"))
                    }
                }
                Some(true) => self.restore_owned_network(index, observed),
            };
            match restored {
                Ok(false) => {}
                Ok(true) => changed.push(key),
                Err(err) => {
                    eprintln!(
                        "network-orchestrator-daemon: network reconcile failed an owner: {}",
                        err.kind()
                    );
                    if key.1.starts_with("ovpn:") {
                        let _ = self.fail_openvpn(key.0, &key.1);
                    } else {
                        let _ = self.teardown_entry(index);
                        self.persist();
                        self.tunnel_failed.insert(key.clone());
                    }
                    changed.push(key);
                }
            }
        }
        changed
    }

    /// `Some(alive)` for an owned tunnel whose health is known; `None` for
    /// other owners and for transient states (lookup errors, OpenVPN
    /// reconnects, which `reconcile_openvpn` owns).
    #[cfg(target_os = "linux")]
    fn tunnel_alive(&mut self, index: usize) -> Option<bool> {
        let entry = &self.journal.entries[index];
        let runtime = self.openvpn_runtime.get(&(entry.uid, entry.owner.clone()));
        entry.resources.iter().find_map(|resource| match resource {
            OwnedResource::WireGuardLink(link) => self
                .wg
                .as_mut()?
                .link_owned(&link.name, link.index, &link.owner_marker)
                .ok(),
            OwnedResource::XrayProcess(process) if process.index != 0 => {
                let runner = self.xray.as_mut()?;
                Some(
                    runner.health(&process.name).unwrap_or(false)
                        && runner.link_index(&process.name).ok()? == Some(process.index),
                )
            }
            OwnedResource::OpenVpnProcess(process) => {
                let connected = runtime
                    .is_some_and(|runtime| runtime.snapshot.state == Some(OpenVpnState::Connected));
                let link = self
                    .openvpn
                    .as_ref()?
                    .link_index(&process.name)
                    .ok()
                    .flatten()?;
                let same_link = entry.resources.iter().all(|resource| {
                    !matches!(resource, OwnedResource::Route(route) if route.interface_index != link)
                });
                (connected && same_link).then_some(true)
            }
            _ => None,
        })
    }

    /// Resurrect a dead Xray tunnel in place: respawn the child on its
    /// staged config, re-point every link-scoped journal resource at the new
    /// ifindex, and re-apply the address, TUN routes, and DNS. Returns false
    /// once the restart budget is spent — the caller then tears the owner
    /// down. Errors are treated the same as exhaustion.
    #[cfg(target_os = "linux")]
    fn heal_xray(&mut self, index: usize) -> io::Result<bool> {
        const MAX_XRAY_RESPAWNS: u32 = 3;
        let entry = &self.journal.entries[index];
        let key = (entry.uid, entry.owner.clone());
        let process = entry
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::XrayProcess(process) => Some(process.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing Xray process marker")
            })?;
        let attempts = self.xray_restarts.get(&key).copied().unwrap_or(0);
        if attempts >= MAX_XRAY_RESPAWNS {
            return Ok(false);
        }
        // The attempt counts even when the respawn itself fails: a flapping
        // child must not loop forever.
        let uid = key.0;
        self.xray_restarts.insert(key, attempts + 1);
        self.xray
            .as_mut()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "Xray executor is unavailable")
            })?
            .respawn(uid, &process.name)?;
        let new_index = self
            .xray
            .as_ref()
            .unwrap()
            .link_index(&process.name)?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "Xray TUN link is unavailable")
            })?;
        self.rebind_xray_link(index, process.index, new_index)?;
        eprintln!(
            "network-orchestrator-daemon: respawned xray child for {}",
            self.journal.entries[index].owner
        );
        Ok(true)
    }

    /// The Xray child restarted and its TUN reappeared under `new_index`:
    /// re-point every link-scoped journal resource at it and re-apply
    /// addresses, tunnel routes and DNS to the fresh link.
    fn rebind_xray_link(&mut self, index: usize, old_index: u32, new_index: u32) -> io::Result<()> {
        for resource in &mut self.journal.entries[index].resources {
            match resource {
                OwnedResource::XrayProcess(process) => process.index = new_index,
                OwnedResource::Route(route) if route.interface_index == old_index => {
                    route.interface_index = new_index;
                }
                OwnedResource::Address(address) if address.interface_index == old_index => {
                    address.interface_index = new_index;
                }
                OwnedResource::Dns(dns) if dns.interface_index == old_index => {
                    dns.interface_index = new_index;
                }
                _ => {}
            }
        }
        self.store.save(&self.journal)?;
        let resources = self.journal.entries[index].resources.clone();
        for resource in &resources {
            if let OwnedResource::Address(address) = resource {
                self.wg
                    .as_mut()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotConnected, "TUN executor is unavailable")
                    })?
                    .add_address(new_index, address.address)?;
            }
        }
        self.wg.as_mut().unwrap().set_state(new_index, true)?;
        for resource in &resources {
            if let OwnedResource::Route(route) = resource {
                // Bypass routes keep their physical oif/gateway; the generic
                // restore pass right after this refresh handles those.
                if route.interface_index == new_index && route.gateway.is_none() {
                    match self.routes.add_route(route) {
                        Ok(()) => {}
                        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(err) => return Err(err),
                    }
                }
            }
        }
        if let Some(dns) = resources.iter().find_map(|resource| match resource {
            OwnedResource::Dns(dns) => Some(dns.clone()),
            _ => None,
        }) {
            if let Some(executor) = self.dns.as_mut() {
                let applied = matches!(
                    executor.apply(&dns.name, &dns.servers, &dns.domains, dns.full),
                    Ok(DnsApply::Applied)
                );
                if let Some(OwnedResource::Dns(resource)) = self.journal.entries[index]
                    .resources
                    .iter_mut()
                    .find(|resource| matches!(resource, OwnedResource::Dns(_)))
                {
                    resource.applied = applied;
                }
                self.store.save(&self.journal)?;
            }
        }
        Ok(())
    }

    /// A bypass host route pointing at the *current* physical default
    /// gateway for its address family, or `None` when no such gateway
    /// exists right now.
    #[cfg(target_os = "linux")]
    fn fresh_bypass_route(&self, route: &AppliedRoute) -> Option<AppliedRoute> {
        let (gateway, oif) = self
            .routes
            .default_gateways()
            .ok()?
            .iter()
            .copied()
            .find(|(gateway, _)| gateway.is_ipv4() == route.destination.addr().is_ipv4())?;
        Some(AppliedRoute {
            interface_index: oif,
            gateway: Some(gateway),
            ..route.clone()
        })
    }

    /// Install owned routes, then owned rules, that are missing. A foreign
    /// route with the same key counts as present; a rule priority taken by a
    /// foreign rule is an error, so it is never claimed.
    #[cfg(target_os = "linux")]
    fn restore_owned_network(
        &mut self,
        index: usize,
        observed: &[AppliedRoute],
    ) -> io::Result<bool> {
        let resources = self.journal.entries[index].resources.clone();
        let mut restored = false;
        for resource in &resources {
            let OwnedResource::Route(route) = resource else {
                continue;
            };
            if observed
                .iter()
                .any(|seen| kernel_route(seen) == kernel_route(route))
            {
                continue;
            }
            // Bypass host routes point at a physical gateway that can vanish
            // on roam/DHCP renew/suspend — re-point at the live default
            // gateway and update the journal instead of re-adding a stale
            // route. No gateway at all is transient: skip and retry next pass.
            let mut desired = route.clone();
            if route.gateway.is_some() {
                match self.fresh_bypass_route(route) {
                    Some(fresh) => {
                        if fresh != *route {
                            if let Some(slot) = self.journal.entries[index]
                                .resources
                                .iter_mut()
                                .find(|res| {
                                    matches!(res, OwnedResource::Route(existing) if existing == route)
                                })
                            {
                                *slot = OwnedResource::Route(fresh.clone());
                            }
                            let _ = self.store.save(&self.journal);
                        }
                        desired = fresh;
                    }
                    None => continue,
                }
            }
            match self.routes.add_route(&desired) {
                Ok(()) => restored = true,
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                // A bypass add failing while the uplink is flaky must not
                // kill the tunnel; the next reconcile pass retries.
                Err(err) if route.gateway.is_some() => {
                    eprintln!(
                        "network-orchestrator-daemon: bypass route re-add deferred: {}",
                        err.kind()
                    );
                }
                Err(err) => return Err(err),
            }
        }
        for resource in &resources {
            let OwnedResource::Rule(rule) = resource else {
                continue;
            };
            let policy = self.policy.as_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "policy executor is unavailable",
                )
            })?;
            if !policy.rule_present(rule)? {
                policy.add_rule(rule)?;
                restored = true;
            }
        }
        Ok(restored)
    }

    /// Apply `routes` for `(uid, owner)` all-or-nothing. The journal entry is
    /// persisted as `applying` before the first kernel change.
    pub fn apply_routes(
        &mut self,
        uid: u32,
        owner: &str,
        routes: Vec<AppliedRoute>,
    ) -> io::Result<usize> {
        validate_owner(owner).map_err(invalid_input)?;
        if owner.starts_with("wg:")
            || owner.starts_with("ovpn:")
            || owner.starts_with("ovpn-probe:")
            || owner.starts_with("xray:")
            || owner.starts_with("cond:")
        {
            return Err(invalid_input("reserved owner prefix".into()));
        }
        self.apply_routes_inner(uid, owner, routes)
    }

    /// `apply_routes` for daemon-internal owners (`cond:*`): skips the
    /// client-facing reserved-prefix check but still validates the routes.
    fn apply_routes_inner(
        &mut self,
        uid: u32,
        owner: &str,
        routes: Vec<AppliedRoute>,
    ) -> io::Result<usize> {
        validate_apply(&routes).map_err(invalid_input)?;
        if self.position(uid, owner).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "owner already has routes applied; remove them first",
            ));
        }
        self.journal.entries.push(JournalEntry {
            uid,
            owner: owner.to_string(),
            state: OwnedState::Applying,
            resources: routes.iter().cloned().map(OwnedResource::Route).collect(),
        });
        if let Err(err) = self.store.save(&self.journal) {
            self.journal.entries.pop();
            return Err(err);
        }
        let index = self.journal.entries.len() - 1;
        match apply_routes_transactional(self.routes.as_mut(), &routes) {
            Ok(()) => {
                self.journal.entries[index].state = OwnedState::Applied;
                self.persist();
                Ok(routes.len())
            }
            Err((err, still_applied)) => {
                if still_applied.is_empty() {
                    self.journal.entries.remove(index);
                } else {
                    // Rollback left routes behind: keep them owned so a later
                    // remove or startup recovery can clean them up.
                    let entry = &mut self.journal.entries[index];
                    entry.state = OwnedState::Stale;
                    entry.resources = still_applied
                        .into_iter()
                        .map(OwnedResource::Route)
                        .collect();
                }
                self.persist();
                Err(err)
            }
        }
    }

    /// Remove everything `(uid, owner)` owns. Routes already gone count as
    /// removed; routes that fail stay in the journal as `stale`.
    pub fn remove_owner(&mut self, uid: u32, owner: &str) -> io::Result<usize> {
        validate_owner(owner).map_err(invalid_input)?;
        let index = self
            .position(uid, owner)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "owner has nothing applied"))?;
        if owner.starts_with("wg:") || owner.starts_with("ovpn:") {
            return Err(invalid_input(
                "use the tunnel disconnect method for tunnel owners".into(),
            ));
        }
        if owner.starts_with("cond:") {
            return Err(invalid_input(
                "conditional owners are managed by rule evaluation".into(),
            ));
        }
        let count = self.journal.entries[index].resources.len();
        let result = self.teardown_entry(index);
        self.persist();
        result.map(|()| count)
    }

    /// `remove_owner` for daemon-internal owners: no reserved-prefix checks.
    fn remove_owner_inner(&mut self, uid: u32, owner: &str) -> io::Result<usize> {
        let index = self
            .position(uid, owner)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "owner has nothing applied"))?;
        let count = self.journal.entries[index].resources.len();
        let result = self.teardown_entry(index);
        self.persist();
        result.map(|()| count)
    }

    pub fn owned(&self, uid: u32) -> Vec<OwnedEntry> {
        self.journal
            .entries
            .iter()
            .filter(|entry| entry.uid == uid)
            .map(|entry| OwnedEntry {
                owner: entry.owner.clone(),
                state: entry.state,
                resources: entry.resources.clone(),
            })
            .collect()
    }

    /// Forget only always-on static owners (`replayable`) whose routes
    /// disappeared from the kernel (for example after a physical link flap).
    /// A later always-on replay resolves the current ifindex before installing
    /// them again; other owners are never torn down here.
    pub fn reconcile_static_routes(
        &mut self,
        observed: &[AppliedRoute],
        replayable: &HashSet<(u32, String)>,
    ) -> io::Result<usize> {
        let mut removed = 0;
        let mut failed = false;
        for index in (0..self.journal.entries.len()).rev() {
            let entry = &self.journal.entries[index];
            if entry.state != OwnedState::Applied
                || !replayable.contains(&(entry.uid, entry.owner.clone()))
                || entry.owner.starts_with("wg:")
                || entry.owner.starts_with("ovpn:")
                || entry.owner.starts_with("xray:")
                || entry.resources.is_empty()
                || !entry
                    .resources
                    .iter()
                    .all(|resource| matches!(resource, OwnedResource::Route(_)))
            {
                continue;
            }
            let missing = entry.resources.iter().any(|resource| match resource {
                OwnedResource::Route(route) => !observed
                    .iter()
                    .any(|seen| kernel_route(seen) == kernel_route(route)),
                _ => false,
            });
            if missing {
                if self.teardown_entry(index).is_ok() {
                    removed += 1;
                } else {
                    failed = true;
                }
            }
        }
        self.store.save(&self.journal)?;
        if failed {
            Err(io::Error::other(
                "static route reconciliation left stale resources",
            ))
        } else {
            Ok(removed)
        }
    }

    /// Ifindices of links the daemon itself created (tunnels, addresses on
    /// them). A self-made interface must never satisfy an "on this LAN"
    /// condition, so these are excluded from address matching.
    fn owned_ifindices(&self) -> HashSet<u32> {
        self.journal
            .entries
            .iter()
            .flat_map(|entry| entry.resources.iter())
            .filter_map(|resource| match resource {
                OwnedResource::WireGuardLink(link) => Some(link.index),
                OwnedResource::XrayProcess(process) => Some(process.index),
                OwnedResource::Address(address) => Some(address.interface_index),
                _ => None,
            })
            .filter(|index| *index != 0)
            .collect()
    }

    /// Evaluate every stored conditional rule against the address snapshot:
    /// install a rule's routes while its condition holds, withdraw them when
    /// it stops, re-install routes the kernel lost, and drop `cond:*`
    /// journal entries whose rule was deleted. Returns changed owners for
    /// `owned.changed` events.
    ///
    /// `observed` is the kernel snapshot of daemon-owned routes — the same
    /// one [`Self::reconcile_network`] consumes.
    #[cfg(target_os = "linux")]
    pub fn reconcile_conditional(
        &mut self,
        addrs: &[IfaceAddr],
        observed: &[AppliedRoute],
        rules: &[(u32, ConditionalRouteRule)],
    ) -> Vec<(u32, String)> {
        let mut changed = Vec::new();
        let live: HashSet<(u32, String)> = rules
            .iter()
            .map(|(uid, rule)| (*uid, format!("{OWNER_PREFIX}{}", rule.id)))
            .collect();
        // Orphans first: a rule deleted while the daemon was off still has
        // its routes installed.
        for index in (0..self.journal.entries.len()).rev() {
            let entry = &self.journal.entries[index];
            if !entry.owner.starts_with(OWNER_PREFIX)
                || live.contains(&(entry.uid, entry.owner.clone()))
            {
                continue;
            }
            let key = (entry.uid, entry.owner.clone());
            if self.remove_owner_inner(key.0, &key.1).is_err() {
                eprintln!(
                    "network-orchestrator-daemon: conditional route cleanup failed for {}",
                    key.1
                );
            }
            changed.push(key);
        }
        let owned = self.owned_ifindices();
        for (uid, rule) in rules {
            let owner = format!("{OWNER_PREFIX}{}", rule.id);
            let matched = if rule.enabled {
                match &rule.condition {
                    RouteCondition::InterfaceAddressIn { prefix } => {
                        match_interface(addrs, *prefix, &owned)
                    }
                }
            } else {
                None
            };
            let mut eval = CondRuleEval {
                matched_interface: matched.as_ref().map(|(_, name)| name.clone()),
                error: None,
            };
            let desired = matched.map(|(ifindex, _)| plan_routes(rule, ifindex));
            match (self.position(*uid, &owner), desired) {
                (None, None) => {}
                (Some(_), None) => {
                    if let Err(err) = self.remove_owner_inner(*uid, &owner) {
                        eval.error = Some(err.to_string());
                    } else {
                        changed.push((*uid, owner.clone()));
                    }
                }
                (None, Some(routes)) => match self.apply_routes_inner(*uid, &owner, routes) {
                    Ok(_) => changed.push((*uid, owner.clone())),
                    Err(err) => eval.error = Some(err.to_string()),
                },
                (Some(index), Some(routes)) => {
                    let entry = &self.journal.entries[index];
                    let journaled: Vec<&AppliedRoute> = entry
                        .resources
                        .iter()
                        .filter_map(|resource| match resource {
                            OwnedResource::Route(route) => Some(route),
                            _ => None,
                        })
                        .collect();
                    let in_sync = entry.state == OwnedState::Applied
                        && journaled.len() == routes.len()
                        && routes.iter().all(|route| journaled.contains(&route))
                        && routes.iter().all(|route| {
                            observed
                                .iter()
                                .any(|seen| kernel_route(seen) == kernel_route(route))
                        });
                    if !in_sync {
                        match self
                            .remove_owner_inner(*uid, &owner)
                            .and_then(|_| self.apply_routes_inner(*uid, &owner, routes))
                        {
                            Ok(_) => changed.push((*uid, owner.clone())),
                            Err(err) => eval.error = Some(err.to_string()),
                        }
                    }
                }
            }
            self.cond_eval.insert((*uid, rule.id.clone()), eval);
        }
        // Drop eval entries for rules that no longer exist nor own anything.
        let owned_cond: HashSet<(u32, String)> = self
            .journal
            .entries
            .iter()
            .filter(|entry| entry.owner.starts_with(OWNER_PREFIX))
            .map(|entry| (entry.uid, entry.owner.clone()))
            .collect();
        self.cond_eval.retain(|(uid, id), _| {
            rules
                .iter()
                .any(|(rule_uid, rule)| rule_uid == uid && rule.id == *id)
                || owned_cond.contains(&(*uid, format!("{OWNER_PREFIX}{id}")))
        });
        changed
    }

    /// Status of one stored rule, for `condRules.list`. Journal state wins
    /// over the last evaluation: an applied entry means the routes are out
    /// there even before the first reconcile pass after a daemon restart.
    pub fn cond_rule_status(&self, uid: u32, rule: &ConditionalRouteRule) -> ConditionalRuleStatus {
        let eval = self.cond_eval.get(&(uid, rule.id.clone()));
        let matched_interface = eval.and_then(|eval| eval.matched_interface.clone());
        let applied = self
            .position(uid, &format!("cond:{}", rule.id))
            .map(|index| self.journal.entries[index].resources.len())
            .unwrap_or(0);
        let (state, detail) = if !rule.enabled {
            (ConditionalRuleState::Disabled, None)
        } else if let Some(error) = eval.and_then(|eval| eval.error.as_ref()) {
            (ConditionalRuleState::Error, Some(error.clone()))
        } else {
            match self.position(uid, &format!("cond:{}", rule.id)) {
                Some(index) if self.journal.entries[index].state == OwnedState::Applied => {
                    (ConditionalRuleState::Active, None)
                }
                Some(_) => (
                    ConditionalRuleState::Error,
                    Some("route apply did not complete".into()),
                ),
                None => (ConditionalRuleState::Inactive, None),
            }
        };
        ConditionalRuleStatus {
            state,
            matched_interface,
            applied_routes: applied,
            detail,
        }
    }

    pub fn cleanup_uid(&mut self, uid: u32) -> io::Result<CleanupResult> {
        self.tunnel_failed
            .retain(|(owner_uid, _)| *owner_uid != uid);
        self.teardown(|entry| entry.uid == uid)
    }

    /// Tear down every owner of every uid, newest first (SIGTERM path).
    pub fn shutdown(&mut self) -> io::Result<CleanupResult> {
        self.teardown(|_| true)
    }

    pub fn set_link_state(&mut self, name: &str, up: bool) -> io::Result<()> {
        validate_iface_name(name).map_err(invalid_input)?;
        self.links.set_link_state(name, up)
    }

    /// Stop a tunnel netdev this daemon does not own (wg-quick, another VPN
    /// app). A live `wg-quick@<name>` unit is stopped first so its routes and
    /// DNS tear down cleanly; otherwise a WireGuard device is deleted via
    /// netlink. Foreign TUN devices cannot be unlinked from outside, so they
    /// are admin-downed — traffic stops even though the device stays.
    pub fn stop_external_link(&mut self, name: &str) -> io::Result<()> {
        validate_iface_name(name).map_err(invalid_input)?;
        if self.journal_owns_iface(name) {
            return Err(invalid_input(
                "interface is managed by a profile — disconnect it instead".into(),
            ));
        }
        match self.links.link_kind(name)? {
            ExternalLinkKind::Missing => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "interface not found",
            )),
            ExternalLinkKind::Other => Err(invalid_input(
                "only tunnel interfaces can be stopped".into(),
            )),
            ExternalLinkKind::Tun => self.links.set_link_state(name, false),
            ExternalLinkKind::WireGuard => {
                if stop_wg_quick_unit(name) {
                    Ok(())
                } else {
                    self.links.remove_link(name)
                }
            }
        }
    }

    /// The journal references interface names for every link/process it owns;
    /// if a name appears there it is managed and must not be stopped here.
    fn journal_owns_iface(&self, name: &str) -> bool {
        self.journal.entries.iter().any(|entry| {
            entry.resources.iter().any(|res| match res {
                OwnedResource::WireGuardLink(link) => link.name == name,
                OwnedResource::OpenVpnProcess(proc) => proc.name == name,
                OwnedResource::XrayProcess(proc) => proc.name == name,
                _ => false,
            })
        })
    }

    fn position(&self, uid: u32, owner: &str) -> Option<usize> {
        self.journal
            .entries
            .iter()
            .position(|entry| entry.uid == uid && entry.owner == owner)
    }

    fn teardown(&mut self, matches: impl Fn(&JournalEntry) -> bool) -> io::Result<CleanupResult> {
        let mut result = CleanupResult::default();
        for index in (0..self.journal.entries.len()).rev() {
            if !matches(&self.journal.entries[index]) {
                continue;
            }
            let owner = self.journal.entries[index].owner.clone();
            match self.teardown_entry(index) {
                Ok(()) => result.removed_owners.push(owner),
                Err(_) => result.failed.push(owner),
            }
        }
        self.store.save(&self.journal)?;
        Ok(result)
    }

    /// Remove the entry's resources. On success the entry is dropped; on
    /// failure it keeps only what could not be removed and becomes `stale`.
    /// The caller persists the journal.
    fn teardown_entry(&mut self, index: usize) -> io::Result<()> {
        if self.journal.entries[index].owner.starts_with("xray:") {
            return self.teardown_xray_entry(index);
        }
        let owner = &self.journal.entries[index].owner;
        if owner.starts_with("ovpn:") || owner.starts_with("ovpn-probe:") {
            return self.teardown_openvpn_entry(index);
        }
        if self.journal.entries[index].owner.starts_with("wg:") {
            return self.teardown_wireguard_entry(index);
        }
        let routes: Vec<AppliedRoute> = self.journal.entries[index]
            .resources
            .iter()
            .filter_map(|resource| match resource {
                OwnedResource::Route(route) => Some(route.clone()),
                _ => None,
            })
            .collect();
        match remove_routes_best_effort(&mut IgnoreMissing(self.routes.as_mut()), &routes) {
            Ok(()) => {
                self.journal.entries.remove(index);
                Ok(())
            }
            Err((failed, message)) => {
                let entry = &mut self.journal.entries[index];
                entry.state = OwnedState::Stale;
                // `remove_routes_best_effort` reports failures newest first.
                entry.resources = failed.into_iter().rev().map(OwnedResource::Route).collect();
                Err(io::Error::other(message))
            }
        }
    }

    fn teardown_xray_entry(&mut self, index: usize) -> io::Result<()> {
        let entry = self.journal.entries[index].clone();
        let process = entry
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::XrayProcess(process) => Some(process),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Xray owner has no process marker",
                )
            })?;
        let Some(runner) = self.xray.as_mut() else {
            self.journal.entries[index].state = OwnedState::Stale;
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Xray executor is unavailable",
            ));
        };
        let current_index = runner.link_index(&process.name)?;
        if current_index.is_some_and(|current| process.index == 0 || current != process.index) {
            self.journal.entries[index].state = OwnedState::Stale;
            return Err(io::Error::other("Xray TUN link identity is unverified"));
        }
        let mut failed = Vec::new();
        for resource in entry.resources.iter().rev() {
            let result = match resource {
                OwnedResource::Dns(_) if current_index.is_none() => Ok(()),
                OwnedResource::Dns(dns) => {
                    #[cfg(target_os = "linux")]
                    {
                        match self.dns.as_mut() {
                            Some(executor) => match executor.revert(&dns.name) {
                                Ok(()) | Err(crate::dns::DnsError::Unavailable) => Ok(()),
                                Err(_) => Err(io::Error::other("Xray DNS cleanup failed")),
                            },
                            None => Err(io::Error::new(
                                io::ErrorKind::NotConnected,
                                "DNS executor is unavailable",
                            )),
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "DNS executor is unavailable",
                        ))
                    }
                }
                OwnedResource::Rule(rule) => {
                    #[cfg(target_os = "linux")]
                    {
                        self.policy
                            .as_mut()
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::NotConnected,
                                    "policy executor is unavailable",
                                )
                            })?
                            .remove_rule(rule)
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "policy executor is unavailable",
                        ))
                    }
                }
                OwnedResource::Route(route) => self.routes.remove_route(route),
                OwnedResource::Address(address) if current_index.is_some() => self
                    .wg
                    .as_mut()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotConnected, "TUN executor is unavailable")
                    })?
                    .remove_address(address.interface_index, address.address),
                OwnedResource::Address(_) => Ok(()),
                OwnedResource::XrayProcess(_) => {
                    match self.xray.as_mut().unwrap().stop(&process.name) {
                        Ok(()) => self
                            .xray
                            .as_mut()
                            .unwrap()
                            .cleanup(entry.uid, &process.name),
                        Err(ref e) if e.kind() == io::ErrorKind::NotFound => self
                            .xray
                            .as_mut()
                            .unwrap()
                            .cleanup(entry.uid, &process.name),
                        Err(err) => Err(err),
                    }
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected Xray journal resource",
                )),
            };
            let removed = match result {
                Ok(()) => true,
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => true,
                Err(_) => false,
            };
            if !removed || matches!(resource, OwnedResource::XrayProcess(_)) && !failed.is_empty() {
                failed.push(resource.clone());
            }
        }
        if failed.is_empty() {
            self.journal.entries.remove(index);
            Ok(())
        } else {
            self.journal.entries[index].state = OwnedState::Stale;
            self.journal.entries[index].resources = failed.into_iter().rev().collect();
            Err(io::Error::other("Xray cleanup left owned resources"))
        }
    }

    fn teardown_openvpn_entry(&mut self, index: usize) -> io::Result<()> {
        let entry = self.journal.entries[index].clone();
        let process = entry
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::OpenVpnProcess(process) => Some(process),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OpenVPN owner has no process marker",
                )
            })?;
        let Some(runner) = self.openvpn.as_mut() else {
            self.journal.entries[index].state = OwnedState::Stale;
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "OpenVPN executor is unavailable",
            ));
        };
        if let Err(err) = runner.stop(&process.name) {
            if err.kind() != io::ErrorKind::NotFound {
                self.journal.entries[index].state = OwnedState::Stale;
                return Err(io::Error::other("OpenVPN child termination failed"));
            }
        }
        if runner.link_index(&process.name)?.is_some() {
            self.journal.entries[index].state = OwnedState::Stale;
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "OpenVPN link identity is unverified",
            ));
        }
        if self.clear_openvpn_network(index).is_err() {
            self.journal.entries[index].state = OwnedState::Stale;
            return Err(io::Error::other("OpenVPN network cleanup failed"));
        }
        if let Err(err) = self
            .openvpn
            .as_mut()
            .unwrap()
            .cleanup(entry.uid, &process.name)
        {
            if err.kind() != io::ErrorKind::NotFound {
                self.journal.entries[index].state = OwnedState::Stale;
                return Err(io::Error::other("OpenVPN staging cleanup failed"));
            }
        }
        self.journal.entries.remove(index);
        self.openvpn_runtime.remove(&(entry.uid, entry.owner));
        Ok(())
    }

    fn teardown_wireguard_entry(&mut self, index: usize) -> io::Result<()> {
        let entry = &self.journal.entries[index];
        self.wireguard_handshake
            .remove(&(entry.uid, entry.owner.clone()));
        let resources = self.journal.entries[index].resources.clone();
        let link = resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::WireGuardLink(link) => Some(link),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "WireGuard owner has no link")
            })?;
        let Some(wg) = self.wg.as_mut() else {
            self.journal.entries[index].state = OwnedState::Stale;
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "WireGuard executor is unavailable",
            ));
        };
        let owned = match wg.link_owned(&link.name, link.index, &link.owner_marker) {
            Ok(owned) => owned,
            Err(err) => {
                self.journal.entries[index].state = OwnedState::Stale;
                return Err(err);
            }
        };
        if !owned {
            let present = match wg.link_present(&link.name, link.index) {
                Ok(present) => present,
                Err(err) => {
                    self.journal.entries[index].state = OwnedState::Stale;
                    return Err(err);
                }
            };
            if present {
                self.journal.entries[index].state = OwnedState::Stale;
                return Err(io::Error::other("WireGuard link identity is unverified"));
            }
        }
        let mut failed = Vec::new();
        for resource in resources.iter().rev() {
            let result = match resource {
                OwnedResource::Route(route) if owned => self.routes.remove_route(route),
                OwnedResource::Route(_) => Ok(()),
                OwnedResource::Address(address) if owned => {
                    wg.remove_address(address.interface_index, address.address)
                }
                OwnedResource::Address(_) => Ok(()),
                OwnedResource::WireGuardLink(link) if failed.is_empty() => {
                    if owned {
                        wg.delete_link(&link.name, link.index, &link.owner_marker)
                    } else {
                        Ok(())
                    }
                }
                OwnedResource::WireGuardLink(_) => {
                    failed.push(resource.clone());
                    continue;
                }
                OwnedResource::Rule(rule) => {
                    #[cfg(target_os = "linux")]
                    {
                        self.policy
                            .as_mut()
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::NotConnected,
                                    "policy executor is unavailable",
                                )
                            })?
                            .remove_rule(rule)
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "policy executor is unavailable",
                        ))
                    }
                }
                OwnedResource::Dns(dns) if owned => {
                    #[cfg(target_os = "linux")]
                    {
                        match self.dns.as_mut() {
                            Some(executor) => match executor.revert(&dns.name) {
                                Ok(()) | Err(crate::dns::DnsError::Unavailable) => Ok(()),
                                Err(err) => Err(io::Error::other(err.to_string())),
                            },
                            None => Err(io::Error::new(
                                io::ErrorKind::NotConnected,
                                "DNS executor is unavailable",
                            )),
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "DNS executor is unavailable",
                        ))
                    }
                }
                OwnedResource::Dns(_) => Ok(()),
                OwnedResource::OpenVpnProcess(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "OpenVPN resource in WireGuard journal entry",
                )),
                OwnedResource::XrayProcess(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Xray resource in WireGuard journal entry",
                )),
            };
            let removed = match result {
                Ok(()) => true,
                Err(err) if err.kind() == io::ErrorKind::NotFound => true,
                Err(_) => false,
            };
            if !removed {
                failed.push(resource.clone());
            }
        }
        if failed.is_empty() {
            self.journal.entries.remove(index);
            Ok(())
        } else {
            let entry = &mut self.journal.entries[index];
            entry.state = OwnedState::Stale;
            entry.resources = failed.into_iter().rev().collect();
            Err(io::Error::other("WireGuard cleanup left owned resources"))
        }
    }

    /// Save after a kernel change already happened. The in-memory journal
    /// stays authoritative; a stale file only causes harmless `NotFound`
    /// removals on the next start, so the failure is logged, not returned.
    fn persist(&mut self) {
        if let Err(err) = self.store.save(&self.journal) {
            eprintln!("network-orchestrator-daemon: failed to save journal: {err}");
        }
    }
}

/// The kernel stores an IPv6 route requested with metric 0 as metric 1024.
fn kernel_route(route: &AppliedRoute) -> AppliedRoute {
    let mut route = route.clone();
    if route.destination.addr().is_ipv6() && route.metric == 0 {
        route.metric = 1024;
    }
    route
}

/// Removing a route that is already gone is success: the goal state holds.
struct IgnoreMissing<'a>(&'a mut dyn RouteExecutor);

fn full_policy_rules(full: &WireGuardFullResource) -> Vec<OwnedRuleResource> {
    let mut rules = Vec::new();
    for family in [IpFamily::Ipv4, IpFamily::Ipv6] {
        if (family == IpFamily::Ipv4 && !full.ipv4) || (family == IpFamily::Ipv6 && !full.ipv6) {
            continue;
        }
        rules.push(OwnedRuleResource {
            family,
            priority: full.priority_main,
            table: 254,
            fwmark: None,
            invert: false,
            suppress_prefix_length: Some(0),
        });
        rules.push(OwnedRuleResource {
            family,
            priority: full.priority_tunnel,
            table: full.table,
            fwmark: Some(full.fwmark),
            invert: true,
            suppress_prefix_length: None,
        });
    }
    rules
}

impl RouteExecutor for IgnoreMissing<'_> {
    fn add_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
        self.0.add_route(route)
    }

    fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
        match self.0.remove_route(route) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

#[cfg(test)]
mod xray_core_tests {
    use super::*;
    use crate::xray_process::XrayProcessRunner;
    use net_manager_core::daemon_protocol::XrayConnectParams;
    use net_manager_core::models::PolicyRoute;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Events(Arc<Mutex<Vec<String>>>);
    impl Events {
        fn push(&self, event: impl Into<String>) {
            self.0.lock().unwrap().push(event.into());
        }
        fn list(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }
    struct Routes(Events);
    impl RouteExecutor for Routes {
        fn add_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
            self.0.push(format!("route-add:{}", route.destination));
            Ok(())
        }
        fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
            self.0.push(format!("route-del:{}", route.destination));
            Ok(())
        }
    }
    struct RejectRoutes(Events);
    impl RouteExecutor for RejectRoutes {
        fn add_route(&mut self, _: &AppliedRoute) -> io::Result<()> {
            self.0.push("route-reject");
            Err(io::Error::other("fake route failure"))
        }
        fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
            self.0.push(format!("route-del:{}", route.destination));
            Ok(())
        }
    }
    struct GatewayRoutes {
        events: Events,
        gateways: Arc<Mutex<Vec<(std::net::IpAddr, u32)>>>,
    }
    impl GatewayRoutes {
        fn new(events: Events) -> Self {
            Self {
                events,
                gateways: Arc::new(Mutex::new(vec![
                    ("192.0.2.1".parse().unwrap(), 3),
                    ("fe80::abcd".parse().unwrap(), 3),
                ])),
            }
        }
        fn shared_gateways(&self) -> Arc<Mutex<Vec<(std::net::IpAddr, u32)>>> {
            self.gateways.clone()
        }
    }
    impl RouteExecutor for GatewayRoutes {
        fn add_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
            self.events.push(format!("route-add:{}", route.destination));
            Ok(())
        }
        fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
            self.events.push(format!("route-del:{}", route.destination));
            Ok(())
        }
        fn default_gateways(&self) -> io::Result<Vec<(std::net::IpAddr, u32)>> {
            Ok(self.gateways.lock().unwrap().clone())
        }
    }
    struct Links;
    impl LinkExecutor for Links {
        fn set_link_state(&mut self, _: &str, _: bool) -> io::Result<()> {
            Ok(())
        }
        fn remove_link(&mut self, _: &str) -> io::Result<()> {
            Ok(())
        }
        fn link_kind(&mut self, _: &str) -> io::Result<ExternalLinkKind> {
            Ok(ExternalLinkKind::Missing)
        }
    }
    struct Tun(Events);
    impl WgSystem for Tun {
        fn create_link(&mut self, _: &str, _: &str) -> io::Result<u32> {
            unreachable!()
        }
        fn link_owned(&mut self, _: &str, _: u32, _: &str) -> io::Result<bool> {
            unreachable!()
        }
        fn delete_link(&mut self, _: &str, _: u32, _: &str) -> io::Result<()> {
            unreachable!()
        }
        fn add_address(&mut self, _: u32, address: IpNet) -> io::Result<()> {
            self.0.push(format!("address-add:{address}"));
            Ok(())
        }
        fn remove_address(&mut self, _: u32, address: IpNet) -> io::Result<()> {
            self.0.push(format!("address-del:{address}"));
            Ok(())
        }
        fn set_mtu(&mut self, _: u32, _: u32) -> io::Result<()> {
            Ok(())
        }
        fn set_state(&mut self, _: u32, _: bool) -> io::Result<()> {
            Ok(())
        }
    }
    struct Process(Events);
    impl XrayProcessRunner for Process {
        fn verify_binary(&self) -> io::Result<()> {
            Ok(())
        }
        fn link_index(&self, _: &str) -> io::Result<Option<u32>> {
            Ok(self.0.list().contains(&"spawn".to_owned()).then_some(42))
        }
        fn start(
            &mut self,
            _: u32,
            _: &str,
            _: &str,
            _: Option<&net_manager_core::daemon_protocol::XrayGeoAssets>,
        ) -> io::Result<()> {
            self.0.push("spawn");
            Ok(())
        }
        fn health(&mut self, _: &str) -> io::Result<bool> {
            Ok(true)
        }
        fn stop(&mut self, _: &str) -> io::Result<()> {
            self.0.push("stop");
            Ok(())
        }
        fn cleanup(&mut self, _: u32, _: &str) -> io::Result<()> {
            Ok(())
        }
    }
    fn params() -> XrayConnectParams {
        XrayConnectParams {
            profile_id: "home".into(),
            config: json!({
                "inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"udp":true}}],
                "outbounds":[
                    {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"proxy.test","port":443,"users":[{"id":"SECRET-ID","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}},
                    {"tag":"direct","protocol":"freedom"}
                ],
                "routing":{"domainStrategy":"AsIs","rules":[]}
            }).to_string(),
            routes: vec![PolicyRoute { destination: "10.20.0.0/16".parse().unwrap(), metric: 5, via: None }],
            dns_servers: vec![], dns_domains: vec![],
            interface_name: None,
            geo_assets: None,
        }
    }

    struct Policy(Events);
    impl PolicyRuleExecutor for Policy {
        fn rules_snapshot(&mut self) -> io::Result<Vec<OwnedRuleResource>> {
            Ok(vec![])
        }
        fn table_in_use(&mut self, _: u32) -> io::Result<bool> {
            Ok(false)
        }
        fn add_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
            self.0.push(format!("rule-add:{}", rule.priority));
            Ok(())
        }
        fn remove_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
            self.0.push(format!("rule-del:{}", rule.priority));
            Ok(())
        }
    }
    struct Dns(Events);
    impl DnsExecutor for Dns {
        fn apply(
            &mut self,
            name: &str,
            _: &[std::net::IpAddr],
            _: &[String],
            _: bool,
        ) -> Result<DnsApply, crate::dns::DnsError> {
            self.0.push(format!("dns-apply:{name}"));
            Ok(DnsApply::Applied)
        }
        fn revert(&mut self, name: &str) -> Result<(), crate::dns::DnsError> {
            self.0.push(format!("dns-revert:{name}"));
            Ok(())
        }
    }
    /// An Xray child that exits (taking its TUN link) once "killed" is logged.
    struct Dying(Events);
    impl XrayProcessRunner for Dying {
        fn verify_binary(&self) -> io::Result<()> {
            Ok(())
        }
        fn link_index(&self, _: &str) -> io::Result<Option<u32>> {
            let events = self.0.list();
            Ok(
                (events.contains(&"spawn".to_owned()) && !events.contains(&"killed".to_owned()))
                    .then_some(42),
            )
        }
        fn start(
            &mut self,
            _: u32,
            _: &str,
            _: &str,
            _: Option<&net_manager_core::daemon_protocol::XrayGeoAssets>,
        ) -> io::Result<()> {
            self.0.push("spawn");
            Ok(())
        }
        fn health(&mut self, name: &str) -> io::Result<bool> {
            Ok(self.link_index(name)?.is_some())
        }
        fn stop(&mut self, _: &str) -> io::Result<()> {
            self.0.push("stop");
            Ok(())
        }
        fn cleanup(&mut self, _: u32, _: &str) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn network_reconcile_fails_xray_whose_process_died() {
        let events = Events::default();
        let dir = std::env::temp_dir().join(format!("netmgr-xray-dead-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(Routes(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(Dying(events.clone())),
        )
        .unwrap();
        core.connect_xray(1000, params()).unwrap();
        let observed: Vec<_> = core.owned(1000)[0]
            .resources
            .iter()
            .filter_map(|resource| match resource {
                OwnedResource::Route(route) => Some(route.clone()),
                _ => None,
            })
            .collect();
        assert!(core.reconcile_network(&observed).is_empty());
        events.push("killed");
        assert_eq!(
            core.reconcile_network(&observed),
            vec![(1000, "xray:home".to_string())]
        );
        assert!(core.owned(1000).is_empty());
        assert_eq!(core.xray_status(1000, "home").state, TunnelState::Failed);
        core.disconnect_xray(1000, "home").unwrap();
        assert_eq!(core.xray_status(1000, "home").state, TunnelState::Stopped);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A process runner whose child dies on demand and revives on `respawn`
    /// with a fresh TUN ifindex — the suspend/roam scenario in miniature.
    struct Flaky {
        events: Events,
        state: Arc<Mutex<(bool, u32)>>,
    }
    impl Flaky {
        fn new(events: Events) -> Self {
            Self {
                events,
                state: Arc::new(Mutex::new((true, 0))),
            }
        }
        fn handle(&self) -> Arc<Mutex<(bool, u32)>> {
            self.state.clone()
        }
    }
    impl XrayProcessRunner for Flaky {
        fn verify_binary(&self) -> io::Result<()> {
            Ok(())
        }
        fn link_index(&self, _: &str) -> io::Result<Option<u32>> {
            let (dead, index) = *self.state.lock().unwrap();
            Ok((!dead).then_some(index))
        }
        fn start(
            &mut self,
            _: u32,
            _: &str,
            _: &str,
            _: Option<&net_manager_core::daemon_protocol::XrayGeoAssets>,
        ) -> io::Result<()> {
            self.events.push("spawn");
            *self.state.lock().unwrap() = (false, 42);
            Ok(())
        }
        fn respawn(&mut self, _: u32, _: &str) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            self.events.push("respawn");
            state.0 = false;
            state.1 += 1;
            Ok(())
        }
        fn reload(
            &mut self,
            _: u32,
            _: &str,
            config: &str,
            _: Option<&net_manager_core::daemon_protocol::XrayGeoAssets>,
        ) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            self.events.push(format!("reload:{}", config.len()));
            state.0 = false;
            state.1 += 1;
            Ok(())
        }
        fn health(&mut self, _: &str) -> io::Result<bool> {
            Ok(!self.state.lock().unwrap().0)
        }
        fn stop(&mut self, _: &str) -> io::Result<()> {
            self.events.push("stop");
            Ok(())
        }
        fn cleanup(&mut self, _: u32, _: &str) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn network_reconcile_respawns_dead_xray_and_reapplies_link_state() {
        let events = Events::default();
        let dir = std::env::temp_dir().join(format!("netmgr-xray-heal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let runner = Flaky::new(events.clone());
        let state = runner.handle();
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(Routes(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(runner),
        )
        .unwrap();
        core.connect_xray(1000, params()).unwrap();
        // Suspend/resume miniature: the child died and the TUN vanished.
        state.lock().unwrap().0 = true;
        assert_eq!(
            core.reconcile_network(&[]),
            vec![(1000, "xray:home".to_string())]
        );
        // The child was respawned in place and every link-scoped resource
        // moved to the fresh ifindex (43) and was re-applied.
        assert_eq!(events.list().iter().filter(|e| *e == "respawn").count(), 1);
        let owned = core.owned(1000);
        assert_eq!(owned.len(), 1);
        let process_index = owned[0]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::XrayProcess(process) => Some(process.index),
                _ => None,
            })
            .unwrap();
        assert_eq!(process_index, 43);
        assert!(owned[0].resources.iter().all(|resource| match resource {
            OwnedResource::Route(route) => route.interface_index == 43,
            OwnedResource::Address(address) => address.interface_index == 43,
            OwnedResource::Dns(dns) => dns.interface_index == 43,
            _ => true,
        }));
        assert!(events.list().iter().any(|e| e == "route-add:10.20.0.0/16"));
        assert_eq!(core.xray_status(1000, "home").state, TunnelState::Running);
        core.disconnect_xray(1000, "home").unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn network_reconcile_teardown_after_xray_respawn_budget_is_spent() {
        let events = Events::default();
        let dir = std::env::temp_dir().join(format!("netmgr-xray-healcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let runner = Flaky::new(events.clone());
        let state = runner.handle();
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(Routes(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(runner),
        )
        .unwrap();
        core.connect_xray(1000, params()).unwrap();
        for _ in 0..3 {
            state.lock().unwrap().0 = true;
            core.reconcile_network(&[]);
        }
        assert_eq!(events.list().iter().filter(|e| *e == "respawn").count(), 3);
        assert_eq!(core.xray_status(1000, "home").state, TunnelState::Running);
        // Fourth death exhausts the budget: the owner is torn down and
        // marked failed instead of restarting forever.
        state.lock().unwrap().0 = true;
        core.reconcile_network(&[]);
        assert_eq!(events.list().iter().filter(|e| *e == "respawn").count(), 3);
        assert!(core.owned(1000).is_empty());
        assert_eq!(core.xray_status(1000, "home").state, TunnelState::Failed);
        // A fresh connect gets a fresh budget.
        core.connect_xray(1000, params()).unwrap();
        assert_eq!(core.xray_status(1000, "home").state, TunnelState::Running);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn network_reconcile_retargets_bypass_route_to_new_gateway() {
        let events = Events::default();
        let dir = std::env::temp_dir().join(format!("netmgr-xray-roam-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let routes = GatewayRoutes::new(events.clone());
        let gateways = routes.shared_gateways();
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(routes),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(Process(events.clone())),
        )
        .unwrap();
        core.policy = Some(Box::new(Policy(events.clone())));
        let mut input = params();
        input.config = json!({
            "inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"udp":true}}],
            "outbounds":[
                {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"id":"SECRET-ID","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}},
                {"tag":"direct","protocol":"freedom"}
            ],
            "routing":{"domainStrategy":"AsIs","rules":[]}
        })
        .to_string();
        core.connect_xray(1000, input).unwrap();
        // Wi-Fi roam/DHCP renew: the physical default gateway moved.
        gateways.lock().unwrap().clear();
        gateways
            .lock()
            .unwrap()
            .push(("198.51.100.1".parse().unwrap(), 7));
        // The bypass route is missing from the kernel snapshot, so reconcile
        // must re-add it against the *new* gateway, not the journaled one.
        core.reconcile_network(&[]);
        let owned = core.owned(1000);
        let bypass = owned[0]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::Route(route) if route.gateway.is_some() => Some(route),
                _ => None,
            })
            .expect("bypass route");
        assert_eq!(bypass.gateway, Some("198.51.100.1".parse().unwrap()));
        assert_eq!(bypass.interface_index, 7);
        // Uplink entirely gone (e.g. mid-suspend): the bypass is deferred,
        // the tunnel stays up.
        gateways.lock().unwrap().clear();
        core.reconcile_network(&[]);
        assert_eq!(core.xray_status(1000, "home").state, TunnelState::Running);
        core.disconnect_xray(1000, "home").unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn reload_params() -> XrayConnectParams {
        let mut updated = params();
        updated.config = json!({
            "inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"udp":true}}],
            "outbounds":[
                {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"proxy.test","port":443,"users":[{"id":"SECRET-ID","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}},
                {"tag":"direct","protocol":"freedom"}
            ],
            "routing":{"domainStrategy":"AsIs","rules":[{"type":"field","domain":["example.test"],"outboundTag":"direct"}]}
        })
        .to_string();
        updated
    }

    #[test]
    fn reload_swaps_the_staged_config_and_rebinds_link_resources() {
        let events = Events::default();
        let dir = std::env::temp_dir().join(format!("netmgr-xray-reload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let runner = Flaky::new(events.clone());
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(Routes(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(runner),
        )
        .unwrap();
        core.connect_xray(1000, params()).unwrap();
        let status = core.reload_xray(1000, reload_params()).unwrap();
        assert_eq!(status.state, TunnelState::Running);
        let events = events.list();
        assert_eq!(
            events.iter().filter(|e| e.starts_with("reload:")).count(),
            1
        );
        // The child restarted onto a fresh TUN ifindex and every link-scoped
        // journal resource followed it.
        let owned = core.owned(1000);
        assert_eq!(owned.len(), 1);
        let process_index = owned[0]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::XrayProcess(process) => Some(process.index),
                _ => None,
            })
            .unwrap();
        assert_eq!(process_index, 43);
        assert!(owned[0].resources.iter().all(|resource| match resource {
            OwnedResource::Route(route) => route.interface_index == 43,
            OwnedResource::Address(address) => address.interface_index == 43,
            OwnedResource::Dns(dns) => dns.interface_index == 43,
            _ => true,
        }));
        core.disconnect_xray(1000, "home").unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reload_rejects_network_changes_and_keeps_the_running_tunnel() {
        let events = Events::default();
        let dir =
            std::env::temp_dir().join(format!("netmgr-xray-reloadnet-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let runner = Flaky::new(events.clone());
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(Routes(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(runner),
        )
        .unwrap();
        core.connect_xray(1000, params()).unwrap();
        for mutate in [
            |params: &mut XrayConnectParams| params.routes.clear(),
            |params: &mut XrayConnectParams| params.dns_servers = vec!["1.1.1.1".parse().unwrap()],
            |params: &mut XrayConnectParams| params.interface_name = Some("xray-other".into()),
        ] {
            let mut changed = params();
            mutate(&mut changed);
            let err = core.reload_xray(1000, changed).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
        // No reload happened and the tunnel still runs.
        assert!(!events.list().iter().any(|e| e.starts_with("reload:")));
        assert_eq!(core.xray_status(1000, "home").state, TunnelState::Running);
        core.disconnect_xray(1000, "home").unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reload_without_a_connected_profile_is_not_found() {
        let events = Events::default();
        let dir =
            std::env::temp_dir().join(format!("netmgr-xray-reload404-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(Routes(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(Flaky::new(events.clone())),
        )
        .unwrap();
        let err = core.reload_xray(1000, params()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn split_xray_is_journaled_before_spawn_and_cleans_up_in_reverse_order() {
        let events = Events::default();
        let dir = std::env::temp_dir().join(format!("netmgr-xray-core-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(Routes(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(Process(events.clone())),
        )
        .unwrap();
        let status = core.connect_xray(1000, params()).unwrap();
        assert_eq!(status.state, TunnelState::Running);
        assert!(!status.ipv4_covered);
        assert!(core.disconnect_xray(1001, "home").is_err());
        core.disconnect_xray(1000, "home").unwrap();
        let events = events.list();
        assert_eq!(events[0], "spawn");
        assert!(events[1].starts_with("address-add:"));
        assert_eq!(events[2], "route-add:10.20.0.0/16");
        assert_eq!(events[3], "route-del:10.20.0.0/16");
        assert!(events[4].starts_with("address-del:"));
        assert_eq!(events[5], "stop");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn full_xray_marks_transport_before_rules_and_reverts_dns_rules_routes() {
        let events = Events::default();
        let dir = std::env::temp_dir().join(format!("netmgr-xray-full-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(Routes(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(Process(events.clone())),
        )
        .unwrap();
        core.policy = Some(Box::new(Policy(events.clone())));
        core.dns = Some(Box::new(Dns(events.clone())));
        let mut input = params();
        input.routes = vec![PolicyRoute {
            destination: "0.0.0.0/0".parse().unwrap(),
            metric: 5,
            via: None,
        }];
        input.dns_servers = vec!["1.1.1.1".parse().unwrap()];
        let status = core.connect_xray(1000, input).unwrap();
        assert!(status.ipv4_covered && !status.ipv6_covered && status.dns_applied);
        let owned = core.owned(1000);
        assert!(owned[0]
            .resources
            .iter()
            .any(|r| matches!(r, OwnedResource::Route(route) if route.table == Some(51820))));
        assert_eq!(
            owned[0]
                .resources
                .iter()
                .filter(|r| matches!(r, OwnedResource::Rule(_)))
                .count(),
            2
        );
        let events_before = events.list();
        assert_eq!(
            events_before
                .iter()
                .filter(|e| e.starts_with("rule-add:"))
                .count(),
            2
        );
        assert!(
            events_before
                .iter()
                .position(|e| e.starts_with("route-add:"))
                .unwrap()
                < events_before
                    .iter()
                    .position(|e| e.starts_with("rule-add:"))
                    .unwrap()
        );
        core.disconnect_xray(1000, "home").unwrap();
        let all = events.list();
        assert!(
            all.iter()
                .position(|e| e.starts_with("dns-revert:"))
                .unwrap()
                < all.iter().position(|e| e.starts_with("rule-del:")).unwrap()
        );
        assert!(
            all.iter().position(|e| e.starts_with("rule-del:")).unwrap()
                < all
                    .iter()
                    .position(|e| e.starts_with("route-del:"))
                    .unwrap()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn full_xray_bypasses_server_and_captured_dns_via_physical_gateway() {
        let events = Events::default();
        let dir = std::env::temp_dir().join(format!("netmgr-xray-bypass-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(GatewayRoutes::new(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(Process(events.clone())),
        )
        .unwrap();
        core.policy = Some(Box::new(Policy(events.clone())));
        core.dns = Some(Box::new(Dns(events.clone())));
        let mut input = params();
        input.config = json!({
            "inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"udp":true}}],
            "outbounds":[
                {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"id":"SECRET-ID","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}},
                {"tag":"direct","protocol":"freedom"}
            ],
            "routing":{"domainStrategy":"AsIs","rules":[]}
        })
        .to_string();
        input.routes = vec![PolicyRoute {
            destination: "0.0.0.0/0".parse().unwrap(),
            metric: 5,
            via: None,
        }];
        input.dns_servers = vec!["1.1.1.1".parse().unwrap()];
        core.connect_xray(1000, input).unwrap();
        let applied = events.list();
        // Bypass host routes land before the policy rules that would send
        // those destinations into the tunnel table.
        let first_rule = applied
            .iter()
            .position(|e| e.starts_with("rule-add:"))
            .unwrap();
        for bypass in ["route-add:203.0.113.10/32", "route-add:1.1.1.1/32"] {
            let position = applied
                .iter()
                .position(|e| e == bypass)
                .unwrap_or_else(|| panic!("missing {bypass}"));
            assert!(position < first_rule, "{bypass} after policy rules");
        }
        // Bypasses are journaled as owned routes on the physical gateway and
        // in the main table, so teardown and recovery both remove them.
        let owned = core.owned(1000);
        let bypass: Vec<_> = owned[0]
            .resources
            .iter()
            .filter_map(|resource| match resource {
                OwnedResource::Route(route) if route.gateway.is_some() => Some(route),
                _ => None,
            })
            .collect();
        assert_eq!(bypass.len(), 2);
        for route in bypass {
            assert_eq!(route.gateway, Some("192.0.2.1".parse().unwrap()));
            assert_eq!(route.interface_index, 3);
            assert_eq!(route.table, None);
        }
        core.disconnect_xray(1000, "home").unwrap();
        let teardown = events.list();
        assert!(teardown.iter().any(|e| e == "route-del:203.0.113.10/32"));
        assert!(teardown.iter().any(|e| e == "route-del:1.1.1.1/32"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn split_xray_bypasses_server_but_keeps_dns_inside_tunnel() {
        let events = Events::default();
        let dir =
            std::env::temp_dir().join(format!("netmgr-xray-splitbypass-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(GatewayRoutes::new(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(Process(events.clone())),
        )
        .unwrap();
        let mut input = params();
        input.config = json!({
            "inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"udp":true}}],
            "outbounds":[
                {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"id":"SECRET-ID","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}},
                {"tag":"direct","protocol":"freedom"}
            ],
            "routing":{"domainStrategy":"AsIs","rules":[]}
        })
        .to_string();
        // Split profile: DNS server is intentionally resolved through the
        // tunnel, so only the upstream server gets a bypass route.
        input.routes = vec![PolicyRoute {
            destination: "1.0.0.0/8".parse().unwrap(),
            metric: 5,
            via: None,
        }];
        input.dns_servers = vec!["1.1.1.1".parse().unwrap()];
        core.dns = Some(Box::new(Dns(events.clone())));
        core.connect_xray(1000, input).unwrap();
        let events = events.list();
        assert!(events.iter().any(|e| e == "route-add:203.0.113.10/32"));
        assert!(!events.iter().any(|e| e == "route-add:1.1.1.1/32"));
        core.disconnect_xray(1000, "home").unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_xray_route_rolls_back_owned_address_and_process() {
        let events = Events::default();
        let dir = std::env::temp_dir().join(format!("netmgr-xray-rollback-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut core = DaemonCore::open_with_xray(
            JournalStore::new(dir.join("state.json")),
            Box::new(RejectRoutes(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(Process(events.clone())),
        )
        .unwrap();
        let error = core.connect_xray(1000, params()).unwrap_err();
        assert_eq!(error.to_string(), "Xray route_add failed");
        assert!(!error.to_string().contains("SECRET-ID"));
        assert!(core.owned(1000).is_empty());
        let events = events.list();
        assert!(events.iter().any(|e| e == "route-reject"));
        assert!(events.iter().any(|e| e.starts_with("address-del:")));
        assert!(events.iter().any(|e| e == "stop"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn startup_recovery_removes_xray_routes_after_process_exit() {
        let events = Events::default();
        let dir = std::env::temp_dir().join(format!("netmgr-xray-recover-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = JournalStore::new(dir.join("state.json"));
        store
            .save(&JournalDocument {
                version: net_manager_core::journal::JOURNAL_VERSION,
                entries: vec![JournalEntry {
                    uid: 1000,
                    owner: "xray:home".into(),
                    state: OwnedState::Applying,
                    resources: vec![
                        OwnedResource::XrayProcess(XrayProcessResource {
                            name: "xray-123abc".into(),
                            index: 42,
                            owner_marker: "network-orchestrator:1000:xray:home".into(),
                            transport_mark: 51820,
                            full: None,
                        }),
                        OwnedResource::Address(WireGuardAddressResource {
                            interface_index: 42,
                            address: "198.18.0.1/32".parse().unwrap(),
                        }),
                        OwnedResource::Route(AppliedRoute::on_link(
                            "10.20.0.0/16".parse().unwrap(),
                            42,
                            5,
                        )),
                        OwnedResource::Dns(
                            net_manager_core::daemon_protocol::WireGuardDnsResource {
                                interface_index: 42,
                                name: "xray-123abc".into(),
                                servers: vec!["10.20.0.53".parse().unwrap()],
                                domains: vec![],
                                full: false,
                                applied: true,
                            },
                        ),
                    ],
                }],
            })
            .unwrap();
        let core = DaemonCore::open_with_xray(
            store,
            Box::new(Routes(events.clone())),
            Box::new(Links),
            Box::new(Tun(events.clone())),
            Box::new(Process(events.clone())),
        )
        .unwrap();
        assert!(core.owned(1000).is_empty());
        assert_eq!(events.list(), vec!["route-del:10.20.0.0/16", "stop"]);
        assert!(JournalStore::new(dir.join("state.json"))
            .load()
            .unwrap()
            .entries
            .is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn xray_stage(stage: &'static str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("Xray {stage} failed"))
}

/// Literal IPs pass through; hostnames resolve best-effort through the
/// system resolver while the physical uplink is still intact. Resolution
/// failure skips the bypass rather than failing the connect — the tunnel's
/// own dial would break identically either way.
fn resolve_host_addrs(host: Option<&str>) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    let Some(host) = host else {
        return Vec::new();
    };
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![ip];
    }
    (host, 443)
        .to_socket_addrs()
        .map(|iter| iter.map(|addr| addr.ip()).collect())
        .unwrap_or_default()
}

fn wireguard_owner(profile_id: &str) -> io::Result<String> {
    validate_owner(profile_id).map_err(invalid_input)?;
    Ok(format!("wg:{profile_id}"))
}

fn wireguard_name(uid: u32, profile_id: &str, hint: Option<&str>) -> (String, String) {
    crate::link_names::tunnel_link_names("wg-", uid, profile_id, hint)
}

/// Resolves the link/staging name for an OpenVPN plan: the readable primary
/// unless its link or staging dir is occupied, else the deterministic
/// fallback. Errors when both are taken.
fn resolve_openvpn_name(
    runner: &dyn OpenVpnProcessRunner,
    uid: u32,
    plan: &OpenVpnPlan,
) -> io::Result<String> {
    for name in [&plan.name, &plan.fallback_name] {
        if runner.link_index(name)?.is_none() && !runner.staging_exists(uid, name)? {
            return Ok(name.clone());
        }
        if name == &plan.fallback_name {
            break;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "OpenVPN link name is occupied",
    ))
}

#[cfg(target_os = "linux")]
pub struct TrustedWgCommand;

fn parse_wg_dump(dump: &str) -> io::Result<(Option<u64>, u64, u64)> {
    let mut lines = dump.lines();
    if lines.next().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WireGuard status is malformed",
        ));
    }
    let mut latest = None;
    let mut rx = 0_u64;
    let mut tx = 0_u64;
    for line in lines {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WireGuard status is malformed",
            ));
        }
        let numbers = (
            fields[4].parse::<u64>(),
            fields[5].parse::<u64>(),
            fields[6].parse::<u64>(),
        );
        let (handshake, peer_rx, peer_tx) = match numbers {
            (Ok(handshake), Ok(peer_rx), Ok(peer_tx)) => (handshake, peer_rx, peer_tx),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WireGuard status is malformed",
                ))
            }
        };
        if handshake != 0 {
            latest = Some(latest.map_or(handshake, |prior: u64| prior.max(handshake)));
        }
        rx = rx.saturating_add(peer_rx);
        tx = tx.saturating_add(peer_tx);
    }
    Ok((latest, rx, tx))
}

fn parse_wg_endpoint_ips(dump: &str) -> io::Result<Vec<std::net::IpAddr>> {
    let mut lines = dump.lines();
    if lines.next().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WireGuard status is malformed",
        ));
    }
    let mut endpoints = Vec::new();
    for line in lines {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WireGuard status is malformed",
            ));
        }
        if fields[2] == "(none)" {
            continue;
        }
        let socket = fields[2].parse::<std::net::SocketAddr>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "WireGuard endpoint is malformed",
            )
        })?;
        endpoints.push(socket.ip());
    }
    Ok(endpoints)
}

fn parse_ip_route_device(output: &[u8]) -> io::Result<String> {
    let rows: serde_json::Value = serde_json::from_slice(output)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "route lookup is malformed"))?;
    rows.as_array()
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("dev"))
        .and_then(|dev| dev.as_str())
        .map(str::to_string)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "route lookup has no interface"))
}

#[cfg(target_os = "linux")]
pub(crate) fn trusted_wg_binary() -> io::Result<&'static str> {
    use std::os::unix::fs::MetadataExt;
    const PATH: &str = "/usr/bin/wg";
    let metadata = std::fs::symlink_metadata(PATH).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotConnected,
            "trusted WireGuard binary is unavailable",
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "trusted WireGuard binary is unsafe",
        ));
    }
    Ok(PATH)
}

#[cfg(target_os = "linux")]
fn trusted_ip_binary() -> io::Result<&'static str> {
    use std::os::unix::fs::MetadataExt;
    const PATH: &str = "/usr/bin/ip";
    let metadata = std::fs::symlink_metadata(PATH).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotConnected,
            "trusted ip binary is unavailable",
        )
    })?;
    if !metadata.file_type().is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "trusted ip binary is unsafe",
        ));
    }
    Ok(PATH)
}

/// Stop `wg-quick@<name>` when an active unit owns the device — it removes
/// the link along with its routes and DNS. `name` comes from
/// `validate_iface_name`, so the unit name cannot escape the template.
/// Returns true once the link is gone.
fn stop_wg_quick_unit(name: &str) -> bool {
    use std::process::{Command, Stdio};
    let unit = format!("wg-quick@{name}");
    let quiet = |args: &[&str]| {
        Command::new("/usr/bin/systemctl")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    if !quiet(&["is-active", "--quiet", &unit]) {
        return false;
    }
    let _ = quiet(&["stop", "--no-block", &unit]);
    // wg-quick's down pass is fast; give it a short window before the caller
    // falls back to a plain link delete.
    for _ in 0..20 {
        if !std::path::Path::new(&format!("/sys/class/net/{name}")).exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

#[cfg(target_os = "linux")]
fn wg_dump(name: &str) -> io::Result<String> {
    use std::process::{Command, Stdio};
    let output = Command::new(trusted_wg_binary()?)
        .args(["show", name, "dump"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| io::Error::other("WireGuard status is unavailable"))?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        return Err(io::Error::other("WireGuard status is unavailable"));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "WireGuard status is malformed"))
}

#[cfg(target_os = "linux")]
fn ip_route_device(destination: std::net::IpAddr, mark: Option<u32>) -> io::Result<String> {
    use std::process::{Command, Stdio};
    let mut args = vec![
        "-j".to_string(),
        "route".into(),
        "get".into(),
        destination.to_string(),
    ];
    if let Some(mark) = mark {
        args.push("mark".into());
        args.push(mark.to_string());
    }
    let output = Command::new(trusted_ip_binary()?)
        .args(&args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| io::Error::other("route lookup failed"))?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        return Err(io::Error::other("route lookup failed"));
    }
    parse_ip_route_device(&output.stdout)
}

#[cfg(target_os = "linux")]
impl WgConfigExecutor for TrustedWgCommand {
    fn configure(&mut self, name: &str, config: &str) -> io::Result<()> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new(trusted_wg_binary()?)
            .arg("setconf")
            .arg(name)
            .arg("/dev/stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "trusted WireGuard binary is unavailable",
                )
            })?;
        let write_result = child.stdin.take().unwrap().write_all(config.as_bytes());
        let status = child
            .wait()
            .map_err(|_| io::Error::other("WireGuard configuration failed"))?;
        if write_result.is_err() {
            return Err(io::Error::other("WireGuard config transfer failed"));
        }
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("WireGuard configuration failed"))
        }
    }

    fn health(&self, name: &str) -> io::Result<(Option<u64>, u64, u64)> {
        parse_wg_dump(&wg_dump(name)?)
    }

    fn set_fwmark(&mut self, name: &str, mark: u32) -> io::Result<()> {
        use std::process::{Command, Stdio};
        let status = Command::new(trusted_wg_binary()?)
            .args(["set", name, "fwmark", &mark.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| io::Error::other("WireGuard fwmark configuration failed"))?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("WireGuard fwmark configuration failed"))
        }
    }

    fn marks_in_use(&self) -> io::Result<Vec<u32>> {
        use std::process::{Command, Stdio};
        let output = Command::new(trusted_wg_binary()?)
            .args(["show", "all", "fwmark"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| io::Error::other("WireGuard mark inspection failed"))?;
        if !output.status.success() || output.stdout.len() > 64 * 1024 {
            return Err(io::Error::other("WireGuard mark inspection failed"));
        }
        let output = std::str::from_utf8(&output.stdout).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "WireGuard mark inspection failed",
            )
        })?;
        let mut marks = Vec::new();
        for line in output.lines() {
            let mut fields = line.split_whitespace();
            let _name = fields.next();
            let Some(mark) = fields.next() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WireGuard mark inspection failed",
                ));
            };
            if mark == "off" {
                continue;
            }
            let parsed = match mark.strip_prefix("0x") {
                Some(hex) => u32::from_str_radix(hex, 16),
                None => mark.parse(),
            }
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WireGuard mark inspection failed",
                )
            })?;
            marks.push(parsed);
        }
        Ok(marks)
    }

    fn endpoint_ips(&self, name: &str) -> io::Result<Vec<std::net::IpAddr>> {
        parse_wg_endpoint_ips(&wg_dump(name)?)
    }

    fn verify_transport(&self, name: &str, mark: u32, ipv4: bool, ipv6: bool) -> io::Result<()> {
        let endpoints = self.endpoint_ips(name)?;
        if endpoints.is_empty() {
            return Err(io::Error::other("WireGuard endpoint is unavailable"));
        }
        for endpoint in endpoints {
            if ip_route_device(endpoint, Some(mark))? == name {
                return Err(io::Error::other(
                    "WireGuard transport route loops into the tunnel",
                ));
            }
        }
        for probe in [
            ipv4.then(|| "198.19.255.253".parse::<std::net::IpAddr>().unwrap()),
            ipv6.then(|| "2001:db8:ffff::7".parse::<std::net::IpAddr>().unwrap()),
        ]
        .into_iter()
        .flatten()
        {
            if ip_route_device(probe, None)? != name {
                return Err(io::Error::other(
                    "WireGuard policy route does not select the tunnel",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::{ExternalLinkKind, LinkExecutor};
    use net_manager_core::models::AppliedRoute;
    use net_manager_core::policy::RouteExecutor;
    use std::collections::HashMap;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Op {
        Add(String),
        Remove(String),
        Link(String, bool),
        LinkDel(String),
    }

    /// Shared recorder for fake executors; failure knobs by destination.
    #[derive(Clone, Default)]
    pub struct Recorder {
        pub ops: Arc<Mutex<Vec<Op>>>,
        pub fail_add: Arc<Mutex<Vec<String>>>,
        pub fail_remove: Arc<Mutex<Vec<String>>>,
        pub missing_on_remove: Arc<Mutex<Vec<String>>>,
        /// Foreign-link kinds probed by `FakeLinks::link_kind`; absent = Missing.
        pub link_kinds: Arc<Mutex<HashMap<String, ExternalLinkKind>>>,
    }

    impl Recorder {
        pub fn ops(&self) -> Vec<Op> {
            self.ops.lock().unwrap().clone()
        }
    }

    pub struct FakeRoutes {
        pub recorder: Recorder,
        /// Called before each add, e.g. to inspect the journal on disk.
        pub before_add: Option<Box<dyn FnMut() + Send>>,
    }

    impl FakeRoutes {
        pub fn new(recorder: &Recorder) -> Self {
            Self {
                recorder: recorder.clone(),
                before_add: None,
            }
        }
    }

    impl RouteExecutor for FakeRoutes {
        fn add_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
            if let Some(hook) = self.before_add.as_mut() {
                hook();
            }
            let dest = route.destination.to_string();
            self.recorder
                .ops
                .lock()
                .unwrap()
                .push(Op::Add(dest.clone()));
            if self.recorder.fail_add.lock().unwrap().contains(&dest) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "file exists"));
            }
            Ok(())
        }

        fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
            let dest = route.destination.to_string();
            self.recorder
                .ops
                .lock()
                .unwrap()
                .push(Op::Remove(dest.clone()));
            if self.recorder.fail_remove.lock().unwrap().contains(&dest) {
                return Err(io::Error::other("device busy"));
            }
            if self
                .recorder
                .missing_on_remove
                .lock()
                .unwrap()
                .contains(&dest)
            {
                return Err(io::Error::new(io::ErrorKind::NotFound, "no such route"));
            }
            Ok(())
        }
    }

    pub struct FakeLinks(pub Recorder);

    impl LinkExecutor for FakeLinks {
        fn set_link_state(&mut self, name: &str, up: bool) -> io::Result<()> {
            self.0.ops.lock().unwrap().push(Op::Link(name.into(), up));
            Ok(())
        }
        fn remove_link(&mut self, name: &str) -> io::Result<()> {
            self.0.ops.lock().unwrap().push(Op::LinkDel(name.into()));
            Ok(())
        }
        fn link_kind(&mut self, name: &str) -> io::Result<ExternalLinkKind> {
            Ok(self
                .0
                .link_kinds
                .lock()
                .unwrap()
                .get(name)
                .copied()
                .unwrap_or(ExternalLinkKind::Missing))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{FakeLinks, FakeRoutes, Op, Recorder};
    use super::*;
    use net_manager_core::daemon_protocol::{OwnedResource, OwnedState};
    use net_manager_core::journal::{JournalDocument, JournalEntry, JournalStore, JOURNAL_FILE};
    use net_manager_core::models::AppliedRoute;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-daemon-core-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn route(dest: &str) -> AppliedRoute {
        AppliedRoute::on_link(dest.parse().unwrap(), 2, 5)
    }

    fn open_core(dir: &Path, recorder: &Recorder) -> DaemonCore {
        DaemonCore::open(
            JournalStore::new(dir.join(JOURNAL_FILE)),
            Box::new(FakeRoutes::new(recorder)),
            Box::new(FakeLinks(recorder.clone())),
        )
        .unwrap()
    }

    fn journal_on_disk(dir: &Path) -> JournalDocument {
        JournalStore::new(dir.join(JOURNAL_FILE)).load().unwrap()
    }

    fn add(dest: &str) -> Op {
        Op::Add(dest.into())
    }

    fn remove(dest: &str) -> Op {
        Op::Remove(dest.into())
    }

    struct FakeWg {
        events: Arc<Mutex<Vec<String>>>,
        fail_remove_address: bool,
        before_create: Option<PathBuf>,
        occupied: Vec<String>,
    }

    impl WgSystem for FakeWg {
        fn create_link(&mut self, name: &str, _marker: &str) -> io::Result<u32> {
            if let Some(path) = &self.before_create {
                let journal = JournalStore::new(path).load().unwrap();
                assert_eq!(journal.entries[0].state, OwnedState::Applying);
                assert!(
                    matches!(&journal.entries[0].resources[0], OwnedResource::WireGuardLink(link) if link.name == name && link.index == 0)
                );
            }
            if self.occupied.iter().any(|taken| taken == name) {
                self.events.lock().unwrap().push(format!("exists:{name}"));
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "name taken"));
            }
            self.events.lock().unwrap().push(format!("create:{name}"));
            Ok(42)
        }
        fn link_owned(&mut self, _name: &str, _index: u32, _marker: &str) -> io::Result<bool> {
            Ok(true)
        }
        fn delete_link(&mut self, name: &str, _index: u32, _marker: &str) -> io::Result<()> {
            self.events.lock().unwrap().push(format!("delete:{name}"));
            Ok(())
        }
        fn add_address(&mut self, _index: u32, address: ipnet::IpNet) -> io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("address+:{address}"));
            Ok(())
        }
        fn remove_address(&mut self, _index: u32, address: ipnet::IpNet) -> io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("address-:{address}"));
            if self.fail_remove_address {
                return Err(io::Error::other("remove failed"));
            }
            Ok(())
        }
        fn set_mtu(&mut self, _index: u32, _mtu: u32) -> io::Result<()> {
            Ok(())
        }
        fn set_state(&mut self, _index: u32, up: bool) -> io::Result<()> {
            self.events.lock().unwrap().push(format!("state:{up}"));
            Ok(())
        }
    }

    struct FakeWgConfig {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl WgConfigExecutor for FakeWgConfig {
        fn configure(&mut self, _name: &str, _config: &str) -> io::Result<()> {
            self.events.lock().unwrap().push("configure".into());
            Ok(())
        }
        fn health(&self, _name: &str) -> io::Result<(Option<u64>, u64, u64)> {
            Ok((Some(42), 7, 8))
        }
        fn set_fwmark(&mut self, _name: &str, mark: u32) -> io::Result<()> {
            self.events.lock().unwrap().push(format!("fwmark:{mark}"));
            Ok(())
        }
        fn verify_transport(
            &self,
            _name: &str,
            mark: u32,
            _ipv4: bool,
            _ipv6: bool,
        ) -> io::Result<()> {
            self.events.lock().unwrap().push(format!("verify:{mark}"));
            Ok(())
        }
    }

    struct FakePolicyRules {
        events: Arc<Mutex<Vec<String>>>,
        rules: Arc<Mutex<Vec<OwnedRuleResource>>>,
        journal_path: PathBuf,
    }

    impl PolicyRuleExecutor for FakePolicyRules {
        fn rules_snapshot(&mut self) -> io::Result<Vec<OwnedRuleResource>> {
            Ok(self.rules.lock().unwrap().clone())
        }
        fn table_in_use(&mut self, _table: u32) -> io::Result<bool> {
            Ok(false)
        }
        fn add_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
            let journal = JournalStore::new(&self.journal_path).load().unwrap();
            assert!(
                matches!(journal.entries[0].resources.last(), Some(OwnedResource::Rule(intent)) if intent == rule)
            );
            self.events
                .lock()
                .unwrap()
                .push(format!("rule+:{:?}:{}", rule.family, rule.priority));
            self.rules.lock().unwrap().push(rule.clone());
            Ok(())
        }
        fn remove_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("rule-:{:?}:{}", rule.family, rule.priority));
            self.rules
                .lock()
                .unwrap()
                .retain(|existing| existing != rule);
            Ok(())
        }
    }

    struct FakeDns {
        result: crate::dns::DnsApply,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl crate::dns::DnsExecutor for FakeDns {
        fn apply(
            &mut self,
            _link: &str,
            _servers: &[std::net::IpAddr],
            _domains: &[String],
            _full: bool,
        ) -> Result<crate::dns::DnsApply, crate::dns::DnsError> {
            self.events.lock().unwrap().push("dns-apply".into());
            Ok(self.result)
        }
        fn revert(&mut self, _link: &str) -> Result<(), crate::dns::DnsError> {
            self.events.lock().unwrap().push("dns-revert".into());
            Ok(())
        }
    }

    #[test]
    fn full_ipv4_uses_marked_transport_and_ordered_policy_rules() {
        let dir = unique_dir("wireguard-full-v4");
        let journal_path = dir.join(JOURNAL_FILE);
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let rules = Arc::new(Mutex::new(Vec::new()));
        let mut core = DaemonCore::open_with_wireguard_full(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: Some(journal_path.clone()),
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
            Box::new(FakePolicyRules {
                events: events.clone(),
                rules: rules.clone(),
                journal_path: journal_path.clone(),
            }),
            Box::new(FakeDns {
                result: crate::dns::DnsApply::Skipped,
                events: events.clone(),
            }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=198.18.0.1:51820\nAllowedIPs=0.0.0.0/0\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        let status = core.connect_wireguard(1000, "home", plan).unwrap();
        assert_eq!(status.state, TunnelState::Running);
        assert_eq!(status.warnings, vec![WireGuardWarning::Ipv6NotCovered]);
        let owned = core.owned(1000);
        let full = owned[0]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::WireGuardLink(link) => link.full.as_ref(),
                _ => None,
            })
            .unwrap();
        assert_eq!(full.table, 51820);
        assert_eq!(full.fwmark, 51820);
        assert_eq!((full.priority_main, full.priority_tunnel), (10000, 10001));
        assert!(owned[0].resources.iter().any(|resource| matches!(resource, OwnedResource::Route(route) if route.destination.to_string() == "0.0.0.0/0" && route.table == Some(51820))));
        assert_eq!(rules.lock().unwrap().len(), 2);
        assert!(events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event == "fwmark:51820"));
        assert!(events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event == "verify:51820"));
        let before_second_connect = events.lock().unwrap().len();
        let second_plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        assert_eq!(
            core.connect_wireguard(1001, "other", second_plan)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(events.lock().unwrap().len(), before_second_connect);
        core.disconnect_wireguard(1000, "home").unwrap();
        assert!(rules.lock().unwrap().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dual_stack_full_installs_rules_for_both_families() {
        let dir = unique_dir("wireguard-full-dual");
        let journal_path = dir.join(JOURNAL_FILE);
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let rules = Arc::new(Mutex::new(Vec::new()));
        let mut core = DaemonCore::open_with_wireguard_full(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder)),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
            Box::new(FakePolicyRules {
                events: events.clone(),
                rules: rules.clone(),
                journal_path,
            }),
            Box::new(FakeDns {
                result: crate::dns::DnsApply::Skipped,
                events,
            }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32, fd77::2/128\n[Peer]\nPublicKey={key}\nEndpoint=198.18.0.1:51820\nAllowedIPs=0.0.0.0/0, ::/0\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        let status = core.connect_wireguard(1000, "home", plan).unwrap();
        assert!(!status.warnings.contains(&WireGuardWarning::Ipv6NotCovered));
        let rules = rules.lock().unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(
            rules
                .iter()
                .filter(|rule| rule.family == IpFamily::Ipv4)
                .count(),
            2
        );
        assert_eq!(
            rules
                .iter()
                .filter(|rule| rule.family == IpFamily::Ipv6)
                .count(),
            2
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn full_allocator_skips_foreign_rule_priority_without_deleting_it() {
        let dir = unique_dir("wireguard-full-priority-conflict");
        let journal_path = dir.join(JOURNAL_FILE);
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let foreign = OwnedRuleResource {
            family: IpFamily::Ipv4,
            priority: 10000,
            table: 254,
            fwmark: None,
            invert: false,
            suppress_prefix_length: None,
        };
        let rules = Arc::new(Mutex::new(vec![foreign.clone()]));
        let mut core = DaemonCore::open_with_wireguard_full(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder)),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
            Box::new(FakePolicyRules {
                events: events.clone(),
                rules: rules.clone(),
                journal_path,
            }),
            Box::new(FakeDns {
                result: crate::dns::DnsApply::Skipped,
                events,
            }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=198.18.0.1:51820\nAllowedIPs=0.0.0.0/0\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        core.connect_wireguard(1000, "home", plan).unwrap();
        let full = core.owned(1000)[0]
            .resources
            .iter()
            .find_map(|resource| match resource {
                OwnedResource::WireGuardLink(link) => link.full.clone(),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            (
                full.table,
                full.fwmark,
                full.priority_main,
                full.priority_tunnel
            ),
            (51821, 51821, 10002, 10003)
        );
        core.disconnect_wireguard(1000, "home").unwrap();
        assert_eq!(*rules.lock().unwrap(), vec![foreign]);
        fs::remove_dir_all(&dir).unwrap();
    }

    struct MissingWgLink;

    impl WgSystem for MissingWgLink {
        fn create_link(&mut self, _name: &str, _marker: &str) -> io::Result<u32> {
            unreachable!()
        }
        fn link_owned(&mut self, _name: &str, _index: u32, _marker: &str) -> io::Result<bool> {
            Ok(false)
        }
        fn link_present(&mut self, _name: &str, _index: u32) -> io::Result<bool> {
            Ok(false)
        }
        fn delete_link(&mut self, _name: &str, _index: u32, _marker: &str) -> io::Result<()> {
            unreachable!()
        }
        fn add_address(&mut self, _index: u32, _address: ipnet::IpNet) -> io::Result<()> {
            unreachable!()
        }
        fn remove_address(&mut self, _index: u32, _address: ipnet::IpNet) -> io::Result<()> {
            unreachable!()
        }
        fn set_mtu(&mut self, _index: u32, _mtu: u32) -> io::Result<()> {
            unreachable!()
        }
        fn set_state(&mut self, _index: u32, _up: bool) -> io::Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn missing_wireguard_link_still_cleans_independent_full_policy_rules() {
        let dir = unique_dir("wireguard-missing-full-link");
        let journal_path = dir.join(JOURNAL_FILE);
        let rule = OwnedRuleResource {
            family: IpFamily::Ipv4,
            priority: 10000,
            table: 254,
            fwmark: None,
            invert: false,
            suppress_prefix_length: Some(0),
        };
        let store = JournalStore::new(&journal_path);
        store
            .save(&JournalDocument {
                version: net_manager_core::journal::JOURNAL_VERSION,
                entries: vec![JournalEntry {
                    uid: 1000,
                    owner: "wg:home".into(),
                    state: OwnedState::Applied,
                    resources: vec![
                        OwnedResource::WireGuardLink(WireGuardLinkResource {
                            name: "wg-ab12".into(),
                            index: 42,
                            owner_marker: "network-orchestrator:1000:wg:home".into(),
                            full: None,
                            warnings: vec![],
                        }),
                        OwnedResource::Rule(rule.clone()),
                    ],
                }],
            })
            .unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let rules = Arc::new(Mutex::new(vec![rule]));
        let recorder = Recorder::default();
        let core = DaemonCore::open_with_wireguard_full(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder)),
            Box::new(MissingWgLink),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
            Box::new(FakePolicyRules {
                events: events.clone(),
                rules: rules.clone(),
                journal_path: journal_path.clone(),
            }),
            Box::new(FakeDns {
                result: crate::dns::DnsApply::Skipped,
                events,
            }),
        )
        .unwrap();
        assert!(core.owned(1000).is_empty());
        assert!(rules.lock().unwrap().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn full_dns_is_journaled_and_reverted_before_link_teardown() {
        let dir = unique_dir("wireguard-full-dns");
        let journal_path = dir.join(JOURNAL_FILE);
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let rules = Arc::new(Mutex::new(Vec::new()));
        let mut core = DaemonCore::open_with_wireguard_full(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder)),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
            Box::new(FakePolicyRules {
                events: events.clone(),
                rules,
                journal_path: journal_path.clone(),
            }),
            Box::new(FakeDns {
                result: crate::dns::DnsApply::Applied,
                events: events.clone(),
            }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\nDNS=10.77.0.1\n[Peer]\nPublicKey={key}\nEndpoint=198.18.0.1:51820\nAllowedIPs=0.0.0.0/0\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        let status = core.connect_wireguard(1000, "home", plan).unwrap();
        assert!(status.dns_applied);
        assert!(
            matches!(core.owned(1000)[0].resources.last(), Some(OwnedResource::Dns(dns)) if dns.applied)
        );
        core.disconnect_wireguard(1000, "home").unwrap();
        let events = events.lock().unwrap();
        let dns_revert = events
            .iter()
            .position(|event| event == "dns-revert")
            .unwrap();
        let link_delete = events
            .iter()
            .position(|event| event.starts_with("delete:wg-"))
            .unwrap();
        assert!(dns_revert < link_delete);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn split_dns_without_route_only_domain_is_reported_not_applied() {
        let dir = unique_dir("wireguard-split-dns-skipped");
        let journal_path = dir.join(JOURNAL_FILE);
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let mut core = DaemonCore::open_with_wireguard_full(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder)),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
            Box::new(FakePolicyRules {
                events: events.clone(),
                rules: Arc::new(Mutex::new(Vec::new())),
                journal_path,
            }),
            Box::new(FakeDns {
                result: crate::dns::DnsApply::Skipped,
                events,
            }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\nDNS=10.77.0.1\n[Peer]\nPublicKey={key}\nEndpoint=192.0.2.1:51820\nAllowedIPs=10.77.0.0/24\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        let status = core.connect_wireguard(1000, "home", plan).unwrap();
        assert!(!status.dns_applied);
        assert_eq!(status.warnings, vec![WireGuardWarning::DnsNotApplied]);
        assert!(!core.owned(1000)[0]
            .resources
            .iter()
            .any(|resource| matches!(resource, OwnedResource::Dns(_))));
        fs::remove_dir_all(&dir).unwrap();
    }

    struct SequenceDns {
        outcomes: Arc<Mutex<std::collections::VecDeque<crate::dns::DnsApply>>>,
    }

    impl crate::dns::DnsExecutor for SequenceDns {
        fn apply(
            &mut self,
            _link: &str,
            _servers: &[std::net::IpAddr],
            _domains: &[String],
            _full: bool,
        ) -> Result<crate::dns::DnsApply, crate::dns::DnsError> {
            Ok(self
                .outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(crate::dns::DnsApply::Applied))
        }
        fn revert(&mut self, _link: &str) -> Result<(), crate::dns::DnsError> {
            Ok(())
        }
    }

    #[test]
    fn dns_reconcile_reports_unavailable_then_restores_applied_state() {
        let dir = unique_dir("wireguard-dns-reconcile");
        let journal_path = dir.join(JOURNAL_FILE);
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let outcomes = Arc::new(Mutex::new(std::collections::VecDeque::from([
            crate::dns::DnsApply::Applied,
            crate::dns::DnsApply::Unavailable,
            crate::dns::DnsApply::Applied,
        ])));
        let mut core = DaemonCore::open_with_wireguard_full(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder)),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
            Box::new(FakePolicyRules {
                events,
                rules: Arc::new(Mutex::new(Vec::new())),
                journal_path,
            }),
            Box::new(SequenceDns { outcomes }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\nDNS=10.77.0.1\n[Peer]\nPublicKey={key}\nEndpoint=198.18.0.1:51820\nAllowedIPs=0.0.0.0/0\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        assert!(
            core.connect_wireguard(1000, "home", plan)
                .unwrap()
                .dns_applied
        );
        core.reapply_dns().unwrap();
        let unavailable = core.wireguard_status(1000, "home");
        assert!(!unavailable.dns_applied);
        assert!(unavailable
            .warnings
            .contains(&WireGuardWarning::DnsNotApplied));
        core.reapply_dns().unwrap();
        let restored = core.wireguard_status(1000, "home");
        assert!(restored.dns_applied);
        assert!(!restored.warnings.contains(&WireGuardWarning::DnsNotApplied));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dns_unavailable_at_connect_remains_retryable_until_resolved_starts() {
        let dir = unique_dir("wireguard-dns-initially-unavailable");
        let journal_path = dir.join(JOURNAL_FILE);
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let outcomes = Arc::new(Mutex::new(std::collections::VecDeque::from([
            crate::dns::DnsApply::Unavailable,
            crate::dns::DnsApply::Applied,
        ])));
        let mut core = DaemonCore::open_with_wireguard_full(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder)),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
            Box::new(FakePolicyRules {
                events,
                rules: Arc::new(Mutex::new(Vec::new())),
                journal_path,
            }),
            Box::new(SequenceDns { outcomes }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\nDNS=10.77.0.1\n[Peer]\nPublicKey={key}\nEndpoint=198.18.0.1:51820\nAllowedIPs=0.0.0.0/0\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        let unavailable = core.connect_wireguard(1000, "home", plan).unwrap();
        assert_eq!(unavailable.state, TunnelState::Running);
        assert!(!unavailable.dns_applied);
        assert!(unavailable
            .warnings
            .contains(&WireGuardWarning::DnsNotApplied));
        assert!(core.owned(1000)[0]
            .resources
            .iter()
            .any(|resource| matches!(resource, OwnedResource::Dns(dns) if !dns.applied)));
        core.reapply_dns().unwrap();
        let restored = core.wireguard_status(1000, "home");
        assert!(restored.dns_applied);
        assert!(!restored.warnings.contains(&WireGuardWarning::DnsNotApplied));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_split_journals_before_create_and_tears_down_in_reverse_order() {
        let dir = unique_dir("wireguard-split");
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let journal_path = dir.join(JOURNAL_FILE);
        let journal_path_in_hook = journal_path.clone();
        let events_in_hook = events.clone();
        let mut routes = FakeRoutes::new(&recorder);
        routes.before_add = Some(Box::new(move || {
            let loaded = JournalStore::new(&journal_path_in_hook).load().unwrap();
            assert!(matches!(
                loaded.entries[0].resources.last(),
                Some(OwnedResource::Route(_))
            ));
            events_in_hook.lock().unwrap().push("route-wal".into());
        }));
        let mut core = DaemonCore::open_with_wireguard(
            JournalStore::new(&journal_path),
            Box::new(routes),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: Some(journal_path.clone()),
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\nPostUp=echo SECRET-HOOK\n[Peer]\nPublicKey={key}\nEndpoint=192.0.2.1:51820\nAllowedIPs=10.77.0.0/24\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        let status = core.connect_wireguard(1000, "home", plan).unwrap();
        assert_eq!(status.state, net_manager_core::models::TunnelState::Running);
        assert_eq!(
            (status.latest_handshake, status.rx_bytes, status.tx_bytes),
            (Some(42), 7, 8)
        );
        assert_eq!(status.warnings, vec![WireGuardWarning::IgnoredHook]);
        assert_eq!(core.owned(1000)[0].resources.len(), 3);
        assert!(!fs::read_to_string(&journal_path).unwrap().contains(key));
        assert!(!fs::read_to_string(&journal_path)
            .unwrap()
            .contains("SECRET-HOOK"));
        core.disconnect_wireguard(1000, "home").unwrap();
        assert!(core.owned(1000).is_empty());
        assert_eq!(
            recorder.ops(),
            vec![add("10.77.0.0/24"), remove("10.77.0.0/24")]
        );
        assert!(events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event == "route-wal"));
        fs::remove_dir_all(&dir).unwrap();
    }

    struct EndpointWgConfig(std::net::IpAddr);

    impl WgConfigExecutor for EndpointWgConfig {
        fn configure(&mut self, _name: &str, _config: &str) -> io::Result<()> {
            Ok(())
        }
        fn endpoint_ips(&self, _name: &str) -> io::Result<Vec<std::net::IpAddr>> {
            Ok(vec![self.0])
        }
    }

    #[test]
    fn split_route_or_address_covering_endpoint_is_rejected_before_mutation() {
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        for (address, allowed, rejected) in [
            ("10.77.0.2/32", "192.0.2.0/24", true),
            ("192.0.2.2/24", "10.0.0.0/8", true),
            ("10.77.0.2/32", "10.0.0.0/8", false),
        ] {
            let dir = unique_dir("wireguard-endpoint-loop");
            let events = Arc::new(Mutex::new(Vec::new()));
            let recorder = Recorder::default();
            let mut core = DaemonCore::open_with_wireguard(
                JournalStore::new(dir.join(JOURNAL_FILE)),
                Box::new(FakeRoutes::new(&recorder)),
                Box::new(FakeLinks(recorder.clone())),
                Box::new(FakeWg {
                    events: events.clone(),
                    fail_remove_address: false,
                    before_create: None,
                    occupied: Vec::new(),
                }),
                Box::new(EndpointWgConfig("192.0.2.1".parse().unwrap())),
            )
            .unwrap();
            let config = format!("[Interface]\nPrivateKey={key}\nAddress={address}\n[Peer]\nPublicKey={key}\nEndpoint=vpn.example.test:51820\nAllowedIPs={allowed}\n");
            let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
            let result = core.connect_wireguard(1000, "home", plan);
            if rejected {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert!(error.to_string().contains("endpoint"));
                assert!(recorder.ops().is_empty());
                let events = events.lock().unwrap();
                assert!(!events.iter().any(|event| event.starts_with("address+")));
                assert!(events.iter().any(|event| event.starts_with("delete:wg-")));
                assert!(core.owned(1000).is_empty());
            } else {
                result.unwrap();
            }
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn wireguard_def1_halves_use_full_table_and_policy_rules() {
        let dir = unique_dir("wireguard-full-halves");
        let journal_path = dir.join(JOURNAL_FILE);
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let rules = Arc::new(Mutex::new(Vec::new()));
        let mut core = DaemonCore::open_with_wireguard_full(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
            Box::new(FakePolicyRules {
                events: events.clone(),
                rules: rules.clone(),
                journal_path: journal_path.clone(),
            }),
            Box::new(FakeDns {
                result: crate::dns::DnsApply::Skipped,
                events,
            }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=198.18.0.1:51820\nAllowedIPs=0.0.0.0/1, 128.0.0.0/1\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        core.connect_wireguard(1000, "home", plan).unwrap();
        let routes: Vec<_> = core.owned(1000)[0]
            .resources
            .iter()
            .filter_map(|resource| match resource {
                OwnedResource::Route(route) => Some((route.destination.to_string(), route.table)),
                _ => None,
            })
            .collect();
        assert_eq!(
            routes,
            vec![
                ("0.0.0.0/1".to_string(), Some(51820)),
                ("128.0.0.0/1".to_string(), Some(51820))
            ]
        );
        assert_eq!(rules.lock().unwrap().len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_failed_disconnect_persists_stale_for_restart_recovery() {
        let dir = unique_dir("wireguard-stale");
        let journal_path = dir.join(JOURNAL_FILE);
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=192.0.2.1:51820\nAllowedIPs=10.77.0.0/24\n");
        let mut core = DaemonCore::open_with_wireguard(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: true,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
        )
        .unwrap();
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        core.connect_wireguard(1000, "home", plan).unwrap();
        assert!(core.disconnect_wireguard(1000, "home").is_err());
        assert_eq!(
            JournalStore::new(&journal_path).load().unwrap().entries[0].state,
            OwnedState::Stale
        );
        drop(core);
        let recovered = DaemonCore::open_with_wireguard(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig { events }),
        )
        .unwrap();
        assert!(recovered.owned(1000).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Kernel-like rule table: one rule per (family, priority), exact removal.
    #[derive(Clone, Default)]
    struct KernelRules(Arc<Mutex<Vec<OwnedRuleResource>>>);

    impl PolicyRuleExecutor for KernelRules {
        fn rules_snapshot(&mut self) -> io::Result<Vec<OwnedRuleResource>> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn table_in_use(&mut self, _table: u32) -> io::Result<bool> {
            Ok(false)
        }
        fn add_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
            let mut rules = self.0.lock().unwrap();
            if rules
                .iter()
                .any(|seen| seen.family == rule.family && seen.priority == rule.priority)
            {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "occupied"));
            }
            rules.push(rule.clone());
            Ok(())
        }
        fn remove_rule(&mut self, rule: &OwnedRuleResource) -> io::Result<()> {
            let mut rules = self.0.lock().unwrap();
            let before = rules.len();
            rules.retain(|seen| seen != rule);
            if rules.len() == before {
                return Err(io::Error::new(io::ErrorKind::NotFound, "no such rule"));
            }
            Ok(())
        }
    }

    /// A WireGuard link that can vanish (e.g. deleted while suspended).
    struct VanishingWg(Arc<std::sync::atomic::AtomicBool>);

    impl WgSystem for VanishingWg {
        fn create_link(&mut self, _name: &str, _marker: &str) -> io::Result<u32> {
            Ok(42)
        }
        fn link_owned(&mut self, _name: &str, _index: u32, _marker: &str) -> io::Result<bool> {
            Ok(self.0.load(Ordering::SeqCst))
        }
        fn delete_link(&mut self, _name: &str, _index: u32, _marker: &str) -> io::Result<()> {
            Ok(())
        }
        fn add_address(&mut self, _index: u32, _address: ipnet::IpNet) -> io::Result<()> {
            Ok(())
        }
        fn remove_address(&mut self, _index: u32, _address: ipnet::IpNet) -> io::Result<()> {
            Ok(())
        }
        fn set_mtu(&mut self, _index: u32, _mtu: u32) -> io::Result<()> {
            Ok(())
        }
        fn set_state(&mut self, _index: u32, _up: bool) -> io::Result<()> {
            Ok(())
        }
    }

    struct FullWgFixture {
        dir: PathBuf,
        core: DaemonCore,
        recorder: Recorder,
        rules: KernelRules,
        link: Arc<std::sync::atomic::AtomicBool>,
    }

    fn full_wireguard_fixture(name: &str) -> FullWgFixture {
        let dir = unique_dir(name);
        let recorder = Recorder::default();
        let rules = KernelRules::default();
        let link = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut core = DaemonCore::open_with_wireguard_full(
            JournalStore::new(dir.join(JOURNAL_FILE)),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(VanishingWg(link.clone())),
            Box::new(FakeWgConfig {
                events: Arc::new(Mutex::new(Vec::new())),
            }),
            Box::new(rules.clone()),
            Box::new(FakeDns {
                result: crate::dns::DnsApply::Skipped,
                events: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=198.18.0.1:51820\nAllowedIPs=0.0.0.0/0\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        core.connect_wireguard(1000, "home", plan).unwrap();
        FullWgFixture {
            dir,
            core,
            recorder,
            rules,
            link,
        }
    }

    fn owned_routes(core: &DaemonCore) -> Vec<AppliedRoute> {
        core.owned(1000)
            .into_iter()
            .flat_map(|entry| entry.resources)
            .filter_map(|resource| match resource {
                OwnedResource::Route(route) => Some(route),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn network_reconcile_restores_flushed_owned_rules_and_routes_idempotently() {
        let FullWgFixture {
            dir,
            mut core,
            recorder,
            rules,
            link: _link,
        } = full_wireguard_fixture("reconcile-restore");
        let applied_rules = rules.0.lock().unwrap().clone();
        let applied_routes = owned_routes(&core);
        assert_eq!(applied_rules.len(), 2);
        // Everything is in place: nothing to do.
        let before = recorder.ops().len();
        assert!(core.reconcile_network(&applied_routes).is_empty());
        assert_eq!(recorder.ops().len(), before);
        // A network manager flushed foreign (to it) rules and routes; an
        // unrelated rule elsewhere must be left alone.
        let foreign = OwnedRuleResource {
            family: IpFamily::Ipv4,
            priority: 32000,
            table: 200,
            fwmark: None,
            invert: false,
            suppress_prefix_length: None,
        };
        *rules.0.lock().unwrap() = vec![foreign.clone()];
        let changed = core.reconcile_network(&[]);
        assert_eq!(changed, vec![(1000, "wg:home".to_string())]);
        let restored = rules.0.lock().unwrap().clone();
        assert!(restored.contains(&foreign));
        assert!(applied_rules.iter().all(|rule| restored.contains(rule)));
        assert_eq!(
            recorder.ops()[before..],
            [add("0.0.0.0/0")],
            "only the owned default route is re-added"
        );
        assert_eq!(
            core.wireguard_status(1000, "home").state,
            TunnelState::Running
        );
        assert!(core.reconcile_network(&applied_routes).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn network_reconcile_fails_tunnel_whose_link_vanished_without_dead_default_route() {
        let FullWgFixture {
            dir,
            mut core,
            recorder,
            rules,
            link,
        } = full_wireguard_fixture("reconcile-vanished");
        let applied_routes = owned_routes(&core);
        link.store(false, Ordering::SeqCst);
        let before = recorder.ops().len();
        let changed = core.reconcile_network(&applied_routes);
        assert_eq!(changed, vec![(1000, "wg:home".to_string())]);
        assert!(core.owned(1000).is_empty());
        assert!(rules.0.lock().unwrap().is_empty(), "policy rules removed");
        // The kernel dropped the link's routes with it; nothing is re-added.
        assert!(!recorder.ops()[before..]
            .iter()
            .any(|op| matches!(op, Op::Add(_))));
        assert_eq!(
            core.wireguard_status(1000, "home").state,
            TunnelState::Failed
        );
        // Nothing left to reconcile; an explicit disconnect acknowledges it.
        assert!(core.reconcile_network(&[]).is_empty());
        core.disconnect_wireguard(1000, "home").unwrap();
        assert_eq!(
            core.wireguard_status(1000, "home").state,
            TunnelState::Stopped
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn network_reconcile_never_claims_a_foreign_rule_at_the_owned_priority() {
        let FullWgFixture {
            dir,
            mut core,
            recorder: _recorder,
            rules,
            link: _link,
        } = full_wireguard_fixture("reconcile-foreign");
        let applied_routes = owned_routes(&core);
        let mut foreign = rules.0.lock().unwrap()[1].clone();
        foreign.table = 200;
        foreign.fwmark = None;
        foreign.invert = false;
        *rules.0.lock().unwrap() = vec![foreign.clone()];
        let changed = core.reconcile_network(&applied_routes);
        assert_eq!(changed, vec![(1000, "wg:home".to_string())]);
        assert_eq!(*rules.0.lock().unwrap(), vec![foreign]);
        assert_eq!(
            core.wireguard_status(1000, "home").state,
            TunnelState::Failed
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    struct DumpWgConfig(Arc<Mutex<String>>);

    impl WgConfigExecutor for DumpWgConfig {
        fn configure(&mut self, _name: &str, _config: &str) -> io::Result<()> {
            Ok(())
        }
        fn health(&self, _name: &str) -> io::Result<(Option<u64>, u64, u64)> {
            parse_wg_dump(&self.0.lock().unwrap())
        }
    }

    #[test]
    fn wireguard_status_fails_only_when_sent_traffic_gets_no_handshake() {
        let dir = unique_dir("wireguard-handshake");
        let recorder = Recorder::default();
        let dump = Arc::new(Mutex::new(String::new()));
        let set_peer = |handshake: u64, tx: u64| {
            *dump.lock().unwrap() = format!("PRIVATE\tPUBLIC\t51820\toff\nPEER\t(none)\t192.0.2.1:51820\t10.77.0.0/24\t{handshake}\t5\t{tx}\toff\n");
        };
        set_peer(0, 0);
        let mut core = DaemonCore::open_with_wireguard(
            JournalStore::new(dir.join(JOURNAL_FILE)),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(FakeWg {
                events: Arc::new(Mutex::new(Vec::new())),
                fail_remove_address: false,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(DumpWgConfig(dump.clone())),
        )
        .unwrap();
        let now = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
        let clock = now.clone();
        core.clock = Box::new(move || clock.load(Ordering::SeqCst));
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=192.0.2.1:51820\nAllowedIPs=10.77.0.0/24\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        let state_at = |core: &mut DaemonCore, at: u64| {
            now.store(at, Ordering::SeqCst);
            core.wireguard_status(1000, "home").state
        };
        assert_eq!(
            core.connect_wireguard(1000, "home", plan).unwrap().state,
            TunnelState::Running
        );
        // Idle split tunnel: WireGuard does not handshake without traffic.
        for at in [1_010, 1_030, 1_060] {
            assert_eq!(state_at(&mut core, at), TunnelState::Running, "{at}");
        }
        // Packets leave (handshake initiations are retried every ~5 s) but no
        // handshake completes: failed once that lasts 20 s.
        set_peer(0, 148);
        assert_eq!(state_at(&mut core, 1_062), TunnelState::Running);
        set_peer(0, 444);
        assert_eq!(state_at(&mut core, 1_077), TunnelState::Running);
        set_peer(0, 740);
        assert_eq!(state_at(&mut core, 1_087), TunnelState::Failed);
        // A completed handshake recovers and resets the tracking.
        set_peer(1_090, 900);
        assert_eq!(state_at(&mut core, 1_090), TunnelState::Running);
        // Idle long after the handshake (keys expired, nothing sent): running.
        assert_eq!(state_at(&mut core, 1_271), TunnelState::Running);
        assert_eq!(state_at(&mut core, 1_400), TunnelState::Running);
        // Traffic resumes but the peer is gone: failed after 20 s of retries.
        set_peer(1_090, 1_048);
        assert_eq!(state_at(&mut core, 1_401), TunnelState::Running);
        assert_eq!(state_at(&mut core, 1_420), TunnelState::Running);
        let status = {
            now.store(1_421, Ordering::SeqCst);
            core.wireguard_status(1000, "home")
        };
        assert_eq!(status.state, TunnelState::Failed);
        assert_eq!(status.latest_handshake, Some(1_090));
        core.disconnect_wireguard(1000, "home").unwrap();
        assert_eq!(state_at(&mut core, 1_422), TunnelState::Stopped);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_dump_extracts_numeric_health_without_keys() {
        let dump = "PRIVATE\tPUBLIC\t51820\toff\nPEER\tPSK\t192.0.2.1:51820\t10.77.0.0/24\t42\t7\t8\t25\nPEER2\t(none)\t(none)\t192.0.2.0/24\t0\t3\t4\toff\n";
        assert_eq!(parse_wg_dump(dump).unwrap(), (Some(42), 10, 12));
        assert!(parse_wg_dump(
            "PRIVATE\tPUBLIC\t51820\toff\nPEER\tPSK\tendpoint\tallowed\tSECRET\t7\t8\t25\n"
        )
        .is_err());
    }

    #[test]
    fn endpoint_and_route_lookup_parsers_keep_only_network_metadata() {
        let dump = "PRIVATE\tPUBLIC\t51820\t0xca6c\nPEER\tPSK\t198.18.0.1:51820\t0.0.0.0/0\t42\t7\t8\t25\nPEER2\tPSK\t[2001:db8::1]:51820\t::/0\t0\t0\t0\toff\n";
        assert_eq!(
            parse_wg_endpoint_ips(dump).unwrap(),
            vec![
                "198.18.0.1".parse::<std::net::IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
        assert_eq!(
            parse_ip_route_device(br#"[{"dst":"198.18.0.1","dev":"eth0"}]"#).unwrap(),
            "eth0"
        );
        assert!(parse_ip_route_device(br#"[{"dst":"198.18.0.1"}]"#).is_err());
    }

    #[test]
    fn wireguard_route_failure_rolls_back_link_and_addresses_without_secrets() {
        let dir = unique_dir("wireguard-route-rollback");
        let journal_path = dir.join(JOURNAL_FILE);
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        recorder
            .fail_add
            .lock()
            .unwrap()
            .push("10.77.0.0/24".into());
        let mut core = DaemonCore::open_with_wireguard(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=192.0.2.1:51820\nAllowedIPs=10.77.0.0/24\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        let error = core.connect_wireguard(1000, "home", plan).unwrap_err();
        assert!(!error.to_string().contains(key));
        assert!(core.owned(1000).is_empty());
        assert!(JournalStore::new(&journal_path)
            .load()
            .unwrap()
            .entries
            .is_empty());
        let events = events.lock().unwrap();
        assert!(events.iter().any(|event| event == "address-:10.77.0.2/32"));
        assert!(events.iter().any(|event| event.starts_with("delete:wg-")));
        fs::remove_dir_all(&dir).unwrap();
    }

    struct AliaslessWg {
        probe_error: bool,
    }

    impl WgSystem for AliaslessWg {
        fn create_link(&mut self, _name: &str, _marker: &str) -> io::Result<u32> {
            Err(io::Error::other("alias assignment failed"))
        }
        fn link_owned(&mut self, _name: &str, _index: u32, _marker: &str) -> io::Result<bool> {
            Ok(false)
        }
        fn link_present(&mut self, _name: &str, _index: u32) -> io::Result<bool> {
            if self.probe_error {
                Err(io::Error::other("link lookup failed"))
            } else {
                Ok(true)
            }
        }
        fn delete_link(&mut self, _name: &str, _index: u32, _marker: &str) -> io::Result<()> {
            panic!("must not delete unmarked link")
        }
        fn add_address(&mut self, _index: u32, _address: ipnet::IpNet) -> io::Result<()> {
            unreachable!()
        }
        fn remove_address(&mut self, _index: u32, _address: ipnet::IpNet) -> io::Result<()> {
            unreachable!()
        }
        fn set_mtu(&mut self, _index: u32, _mtu: u32) -> io::Result<()> {
            unreachable!()
        }
        fn set_state(&mut self, _index: u32, _up: bool) -> io::Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn aliasless_created_link_keeps_stale_ownership_instead_of_being_forgotten() {
        let dir = unique_dir("wireguard-aliasless");
        let journal_path = dir.join(JOURNAL_FILE);
        let recorder = Recorder::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut core = DaemonCore::open_with_wireguard(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder)),
            Box::new(AliaslessWg { probe_error: false }),
            Box::new(FakeWgConfig { events }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=192.0.2.1:51820\nAllowedIPs=10.77.0.0/24\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        assert!(core.connect_wireguard(1000, "home", plan).is_err());
        assert_eq!(
            JournalStore::new(&journal_path).load().unwrap().entries[0].state,
            OwnedState::Stale
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn failed_link_lookup_marks_wireguard_entry_stale() {
        let dir = unique_dir("wireguard-lookup-failure");
        let journal_path = dir.join(JOURNAL_FILE);
        let recorder = Recorder::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut core = DaemonCore::open_with_wireguard(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder)),
            Box::new(AliaslessWg { probe_error: true }),
            Box::new(FakeWgConfig { events }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=192.0.2.1:51820\nAllowedIPs=10.77.0.0/24\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        assert!(core.connect_wireguard(1000, "home", plan).is_err());
        assert_eq!(
            JournalStore::new(&journal_path).load().unwrap().entries[0].state,
            OwnedState::Stale
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    struct ExistingForeignWg;

    impl WgSystem for ExistingForeignWg {
        fn create_link(&mut self, _name: &str, _marker: &str) -> io::Result<u32> {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "foreign link exists",
            ))
        }
        fn link_owned(&mut self, _name: &str, _index: u32, _marker: &str) -> io::Result<bool> {
            panic!("must not inspect foreign ownership after EEXIST")
        }
        fn delete_link(&mut self, _name: &str, _index: u32, _marker: &str) -> io::Result<()> {
            panic!("must not delete foreign link")
        }
        fn add_address(&mut self, _index: u32, _address: ipnet::IpNet) -> io::Result<()> {
            unreachable!()
        }
        fn remove_address(&mut self, _index: u32, _address: ipnet::IpNet) -> io::Result<()> {
            unreachable!()
        }
        fn set_mtu(&mut self, _index: u32, _mtu: u32) -> io::Result<()> {
            unreachable!()
        }
        fn set_state(&mut self, _index: u32, _up: bool) -> io::Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn wireguard_create_eexist_does_not_claim_or_delete_foreign_link() {
        let dir = unique_dir("wireguard-eexist");
        let journal_path = dir.join(JOURNAL_FILE);
        let recorder = Recorder::default();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut core = DaemonCore::open_with_wireguard(
            JournalStore::new(&journal_path),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder)),
            Box::new(ExistingForeignWg),
            Box::new(FakeWgConfig { events }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=192.0.2.1:51820\nAllowedIPs=10.77.0.0/24\n");
        let plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        assert_eq!(
            core.connect_wireguard(1000, "home", plan)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(core.owned(1000).is_empty());
        assert!(JournalStore::new(&journal_path)
            .load()
            .unwrap()
            .entries
            .is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_writes_journal_before_first_add() {
        let dir = unique_dir("wal");
        let recorder = Recorder::default();
        let seen: Arc<Mutex<Vec<Option<OwnedState>>>> = Arc::default();
        let mut routes = FakeRoutes::new(&recorder);
        let (seen_in_hook, journal_path) = (seen.clone(), dir.join(JOURNAL_FILE));
        routes.before_add = Some(Box::new(move || {
            let doc = JournalStore::new(&journal_path).load().unwrap();
            seen_in_hook
                .lock()
                .unwrap()
                .push(doc.entries.first().map(|entry| entry.state));
        }));
        let mut core = DaemonCore::open(
            JournalStore::new(dir.join(JOURNAL_FILE)),
            Box::new(routes),
            Box::new(FakeLinks(recorder.clone())),
        )
        .unwrap();

        core.apply_routes(1000, "office", vec![route("10.1.0.0/16")])
            .unwrap();

        assert_eq!(*seen.lock().unwrap(), vec![Some(OwnedState::Applying)]);
        assert_eq!(journal_on_disk(&dir).entries[0].state, OwnedState::Applied);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_rollback_failure_keeps_stale_entry() {
        let dir = unique_dir("rollback-stale");
        let recorder = Recorder::default();
        recorder.fail_add.lock().unwrap().push("10.2.0.0/16".into());
        recorder
            .fail_remove
            .lock()
            .unwrap()
            .push("10.1.0.0/16".into());
        let mut core = open_core(&dir, &recorder);

        core.apply_routes(
            1000,
            "office",
            vec![route("10.1.0.0/16"), route("10.2.0.0/16")],
        )
        .unwrap_err();

        // 10.1.0.0/16 may still be in the kernel, so the journal must keep it.
        let owned = core.owned(1000);
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].state, OwnedState::Stale);
        assert_eq!(
            owned[0].resources,
            vec![OwnedResource::Route(route("10.1.0.0/16"))]
        );
        assert_eq!(journal_on_disk(&dir).entries.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_failure_rolls_back_and_drops_entry() {
        let dir = unique_dir("rollback");
        let recorder = Recorder::default();
        recorder.fail_add.lock().unwrap().push("10.2.0.0/16".into());
        let mut core = open_core(&dir, &recorder);

        let err = core
            .apply_routes(
                1000,
                "office",
                vec![route("10.1.0.0/16"), route("10.2.0.0/16")],
            )
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            recorder.ops(),
            vec![
                add("10.1.0.0/16"),
                add("10.2.0.0/16"),
                remove("10.1.0.0/16")
            ]
        );
        assert!(core.owned(1000).is_empty());
        assert!(journal_on_disk(&dir).entries.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_rejects_invalid_input_before_executor() {
        let dir = unique_dir("invalid");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        let err = core
            .apply_routes(1000, "", vec![route("10.1.0.0/16")])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = core
            .apply_routes(1000, "office", vec![route("10.1.0.1/16")])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(recorder.ops().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn same_owner_same_uid_conflicts() {
        let dir = unique_dir("conflict");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "office", vec![route("10.1.0.0/16")])
            .unwrap();
        let err = core
            .apply_routes(1000, "office", vec![route("10.2.0.0/16")])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(recorder.ops(), vec![add("10.1.0.0/16")]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn same_owner_different_uid_is_independent() {
        let dir = unique_dir("uids");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "office", vec![route("10.1.0.0/16")])
            .unwrap();
        core.apply_routes(1001, "office", vec![route("10.2.0.0/16")])
            .unwrap();
        assert_eq!(core.owned(1000).len(), 1);
        assert_eq!(core.owned(1001).len(), 1);
        assert_eq!(core.remove_owner(1001, "office").unwrap(), 1);
        assert_eq!(core.owned(1000).len(), 1);
        assert!(core.owned(1001).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_foreign_uid_owner_is_not_found() {
        let dir = unique_dir("foreign");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "office", vec![route("10.1.0.0/16")])
            .unwrap();
        let err = core.remove_owner(1001, "office").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(recorder.ops(), vec![add("10.1.0.0/16")]);
        assert_eq!(core.owned(1000).len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_treats_missing_route_as_removed() {
        let dir = unique_dir("missing");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "office", vec![route("10.1.0.0/16")])
            .unwrap();
        recorder
            .missing_on_remove
            .lock()
            .unwrap()
            .push("10.1.0.0/16".into());
        assert_eq!(core.remove_owner(1000, "office").unwrap(), 1);
        assert!(core.owned(1000).is_empty());
        assert!(journal_on_disk(&dir).entries.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn partial_remove_retains_failed_routes() {
        let dir = unique_dir("partial");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(
            1000,
            "office",
            vec![route("10.1.0.0/16"), route("10.2.0.0/16")],
        )
        .unwrap();
        recorder
            .fail_remove
            .lock()
            .unwrap()
            .push("10.1.0.0/16".into());

        assert!(core.remove_owner(1000, "office").is_err());

        let owned = core.owned(1000);
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].state, OwnedState::Stale);
        assert_eq!(
            owned[0].resources,
            vec![OwnedResource::Route(route("10.1.0.0/16"))]
        );
        assert_eq!(journal_on_disk(&dir).entries[0].resources.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    fn leftover(uid: u32, owner: &str, dests: &[&str]) -> JournalEntry {
        JournalEntry {
            uid,
            owner: owner.into(),
            state: OwnedState::Applying,
            resources: dests
                .iter()
                .map(|dest| OwnedResource::Route(route(dest)))
                .collect(),
        }
    }

    #[test]
    fn open_tears_down_leftovers_and_empties_journal() {
        let dir = unique_dir("leftovers");
        JournalStore::new(dir.join(JOURNAL_FILE))
            .save(&JournalDocument {
                entries: vec![
                    leftover(1000, "a", &["10.1.0.0/16", "10.2.0.0/16"]),
                    leftover(1001, "b", &["10.3.0.0/16"]),
                ],
                ..JournalDocument::default()
            })
            .unwrap();
        let recorder = Recorder::default();
        let core = open_core(&dir, &recorder);

        assert_eq!(
            recorder.ops(),
            vec![
                remove("10.3.0.0/16"),
                remove("10.2.0.0/16"),
                remove("10.1.0.0/16")
            ]
        );
        assert!(core.owned(1000).is_empty() && core.owned(1001).is_empty());
        assert!(journal_on_disk(&dir).entries.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_marks_failed_teardown_as_stale() {
        let dir = unique_dir("stale");
        JournalStore::new(dir.join(JOURNAL_FILE))
            .save(&JournalDocument {
                entries: vec![leftover(1000, "a", &["10.1.0.0/16", "10.2.0.0/16"])],
                ..JournalDocument::default()
            })
            .unwrap();
        let recorder = Recorder::default();
        recorder
            .fail_remove
            .lock()
            .unwrap()
            .push("10.2.0.0/16".into());
        let core = open_core(&dir, &recorder);

        let owned = core.owned(1000);
        assert_eq!(owned[0].state, OwnedState::Stale);
        assert_eq!(
            owned[0].resources,
            vec![OwnedResource::Route(route("10.2.0.0/16"))]
        );
        assert_eq!(journal_on_disk(&dir).entries[0].state, OwnedState::Stale);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cleanup_uid_only_touches_that_uid() {
        let dir = unique_dir("cleanup");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "a", vec![route("10.1.0.0/16")])
            .unwrap();
        core.apply_routes(1001, "b", vec![route("10.2.0.0/16")])
            .unwrap();
        let result = core.cleanup_uid(1000).unwrap();
        assert_eq!(result.removed_owners, vec!["a".to_string()]);
        assert!(result.failed.is_empty());
        assert!(core.owned(1000).is_empty());
        assert_eq!(core.owned(1001).len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shutdown_removes_all_uids_in_reverse_order() {
        let dir = unique_dir("shutdown");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "a", vec![route("10.1.0.0/16")])
            .unwrap();
        core.apply_routes(1001, "b", vec![route("10.2.0.0/16")])
            .unwrap();
        core.apply_routes(1000, "c", vec![route("10.3.0.0/16")])
            .unwrap();
        recorder.ops.lock().unwrap().clear();

        core.shutdown().unwrap();

        assert_eq!(
            recorder.ops(),
            vec![
                remove("10.3.0.0/16"),
                remove("10.2.0.0/16"),
                remove("10.1.0.0/16")
            ]
        );
        assert!(journal_on_disk(&dir).entries.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn link_state_validates_name_before_executor() {
        let dir = unique_dir("link");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        let err = core.set_link_state("wg0; reboot", false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(recorder.ops().is_empty());
        core.set_link_state("enp0s3", false).unwrap();
        assert_eq!(recorder.ops(), vec![Op::Link("enp0s3".into(), false)]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_connect_uses_hinted_name_and_retries_on_collision() {
        let dir = unique_dir("wireguard-name");
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let mut core = DaemonCore::open_with_wireguard(
            JournalStore::new(dir.join(JOURNAL_FILE)),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: None,
                occupied: vec!["wg-kzn2".into()],
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=192.0.2.1:51820\nAllowedIPs=10.77.0.0/24\n");
        let mut plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        plan.interface_name = Some("wg-kzn2".into());
        let status = core.connect_wireguard(1000, "home", plan).unwrap();
        let name = status.interface_name.expect("interface name");
        assert!(
            name.starts_with("wg-kzn2-") && name.len() <= 15,
            "expected shortened fallback, got {name}"
        );
        let events = events.lock().unwrap();
        let exists = events.iter().position(|e| e == "exists:wg-kzn2");
        let created = events.iter().position(|e| e == &format!("create:{name}"));
        assert!(exists.is_some() && created.is_some() && exists < created);
    }

    #[test]
    fn wireguard_connect_uses_hinted_name_verbatim_when_free() {
        let dir = unique_dir("wireguard-name-free");
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder::default();
        let mut core = DaemonCore::open_with_wireguard(
            JournalStore::new(dir.join(JOURNAL_FILE)),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(FakeWg {
                events: events.clone(),
                fail_remove_address: false,
                before_create: None,
                occupied: Vec::new(),
            }),
            Box::new(FakeWgConfig {
                events: events.clone(),
            }),
        )
        .unwrap();
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let config = format!("[Interface]\nPrivateKey={key}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={key}\nEndpoint=192.0.2.1:51820\nAllowedIPs=10.77.0.0/24\n");
        let mut plan = crate::wireguard::parse_wireguard_config(&config, &[]).unwrap();
        plan.interface_name = Some("wg-kzn2".into());
        let status = core.connect_wireguard(1000, "home", plan).unwrap();
        assert_eq!(status.interface_name.as_deref(), Some("wg-kzn2"));
        // The journal stores the effective name so teardown/recovery target it.
        let owned = core.owned(1000);
        assert!(
            matches!(&owned[0].resources[0], OwnedResource::WireGuardLink(link) if link.name == "wg-kzn2")
        );
        core.disconnect_wireguard(1000, "home").unwrap();
        assert!(events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event == "delete:wg-kzn2"));
    }

    // ── Conditional rules ────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    fn iface_addr(
        ifindex: u32,
        name: &str,
        ip: &str,
        prefix_len: u8,
    ) -> crate::cond_rules::IfaceAddr {
        crate::cond_rules::IfaceAddr {
            ifindex,
            name: name.into(),
            address: IpNet::new(ip.parse().unwrap(), prefix_len).unwrap(),
            scope: 0,
        }
    }

    #[cfg(target_os = "linux")]
    fn cond_rule(id: &str, dest: &str) -> ConditionalRouteRule {
        use net_manager_core::models::PolicyRoute;
        ConditionalRouteRule {
            id: id.into(),
            name: "Office LAN".into(),
            enabled: true,
            condition: RouteCondition::InterfaceAddressIn {
                prefix: "10.228.32.0/21".parse().unwrap(),
            },
            routes: vec![PolicyRoute {
                destination: dest.parse().unwrap(),
                metric: 5,
                via: None,
            }],
        }
    }

    #[cfg(target_os = "linux")]
    fn cond_status(
        core: &DaemonCore,
        uid: u32,
        rule: &ConditionalRouteRule,
    ) -> ConditionalRuleStatus {
        core.cond_rule_status(uid, rule)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conditional_rule_applies_routes_while_the_condition_holds() {
        let dir = unique_dir("cond-apply");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        let rules = vec![(1000u32, cond_rule("office", "10.99.0.0/24"))];
        let addrs = vec![iface_addr(2, "enp1s0", "10.228.33.5", 21)];

        let changed = core.reconcile_conditional(&addrs, &[], &rules);

        assert_eq!(changed, vec![(1000, "cond:office".to_string())]);
        assert_eq!(recorder.ops(), vec![add("10.99.0.0/24")]);
        let owned = core.owned(1000);
        assert_eq!(owned[0].owner, "cond:office");
        assert!(
            matches!(&owned[0].resources[0], OwnedResource::Route(route) if route.interface_index == 2)
        );
        let status = cond_status(&core, 1000, &rules[0].1);
        assert_eq!(status.state, ConditionalRuleState::Active);
        assert_eq!(status.matched_interface.as_deref(), Some("enp1s0"));
        assert_eq!(status.applied_routes, 1);
        // A second pass over the same state is a no-op.
        let observed = vec![route("10.99.0.0/24")];
        assert!(core
            .reconcile_conditional(&addrs, &observed, &rules)
            .is_empty());
        assert_eq!(recorder.ops(), vec![add("10.99.0.0/24")]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conditional_rule_withdraws_routes_when_the_condition_drops() {
        let dir = unique_dir("cond-withdraw");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        let rules = vec![(1000u32, cond_rule("office", "10.99.0.0/24"))];
        let addrs = vec![iface_addr(2, "enp1s0", "10.228.33.5", 21)];
        core.reconcile_conditional(&addrs, &[], &rules);

        // Leaving the LAN: address replaced by a home-network one.
        let away = vec![iface_addr(2, "enp1s0", "192.168.1.40", 24)];
        let changed = core.reconcile_conditional(&away, &[], &rules);

        assert_eq!(changed, vec![(1000, "cond:office".to_string())]);
        assert_eq!(
            recorder.ops(),
            vec![add("10.99.0.0/24"), remove("10.99.0.0/24")]
        );
        assert!(core.owned(1000).is_empty());
        let status = cond_status(&core, 1000, &rules[0].1);
        assert_eq!(status.state, ConditionalRuleState::Inactive);
        assert_eq!(status.applied_routes, 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conditional_rule_reinstalls_routes_the_kernel_lost() {
        let dir = unique_dir("cond-flap");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        let rules = vec![(1000u32, cond_rule("office", "10.99.0.0/24"))];
        let addrs = vec![iface_addr(2, "enp1s0", "10.228.33.5", 21)];
        core.reconcile_conditional(&addrs, &[], &rules);
        recorder.ops.lock().unwrap().clear();

        // Link flap wiped the route but kept the address: journal still
        // says applied, `observed` no longer lists it.
        let changed = core.reconcile_conditional(&addrs, &[], &rules);

        assert_eq!(changed, vec![(1000, "cond:office".to_string())]);
        assert_eq!(
            recorder.ops(),
            vec![remove("10.99.0.0/24"), add("10.99.0.0/24")]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conditional_rule_rebinds_routes_when_the_matched_interface_changes() {
        let dir = unique_dir("cond-rebind");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        let rules = vec![(1000u32, cond_rule("office", "10.99.0.0/24"))];
        core.reconcile_conditional(&[iface_addr(2, "enp1s0", "10.228.33.5", 21)], &[], &rules);

        // The office address moved to another interface (e.g. USB dock).
        let moved = vec![iface_addr(7, "enp3s0", "10.228.33.5", 21)];
        let changed = core.reconcile_conditional(&moved, &[], &rules);

        assert_eq!(changed, vec![(1000, "cond:office".to_string())]);
        let owned = core.owned(1000);
        assert!(
            matches!(&owned[0].resources[0], OwnedResource::Route(route) if route.interface_index == 7)
        );
        let status = cond_status(&core, 1000, &rules[0].1);
        assert_eq!(status.matched_interface.as_deref(), Some("enp3s0"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conditional_rule_removes_orphaned_journal_owner() {
        let dir = unique_dir("cond-orphan");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        let rules = vec![(1000u32, cond_rule("office", "10.99.0.0/24"))];
        core.reconcile_conditional(&[iface_addr(2, "enp1s0", "10.228.33.5", 21)], &[], &rules);
        recorder.ops.lock().unwrap().clear();

        // The rule was deleted while the daemon was off: no rules remain,
        // the journal owner is orphaned and must be cleaned up.
        let changed = core.reconcile_conditional(&[], &[], &[]);

        assert_eq!(changed, vec![(1000, "cond:office".to_string())]);
        assert_eq!(recorder.ops(), vec![remove("10.99.0.0/24")]);
        assert!(core.owned(1000).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conditional_rule_disabled_or_unmatched_applies_nothing() {
        let dir = unique_dir("cond-off");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        let mut rule = cond_rule("office", "10.99.0.0/24");
        rule.enabled = false;
        let rules = vec![(1000u32, rule)];
        let addrs = vec![iface_addr(2, "enp1s0", "10.228.33.5", 21)];

        assert!(core.reconcile_conditional(&addrs, &[], &rules).is_empty());
        assert!(recorder.ops().is_empty());
        let status = cond_status(&core, 1000, &rules[0].1);
        assert_eq!(status.state, ConditionalRuleState::Disabled);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conditional_rule_surfaces_apply_errors_in_status() {
        let dir = unique_dir("cond-error");
        let recorder = Recorder::default();
        recorder
            .fail_add
            .lock()
            .unwrap()
            .push("10.99.0.0/24".into());
        let mut core = open_core(&dir, &recorder);
        let rules = vec![(1000u32, cond_rule("office", "10.99.0.0/24"))];
        let addrs = vec![iface_addr(2, "enp1s0", "10.228.33.5", 21)];

        let changed = core.reconcile_conditional(&addrs, &[], &rules);

        assert!(changed.is_empty());
        let status = cond_status(&core, 1000, &rules[0].1);
        assert_eq!(status.state, ConditionalRuleState::Error);
        assert!(status.detail.is_some());
        // Rollback left nothing owned.
        assert!(core.owned(1000).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conditional_rule_ignores_addresses_on_daemon_owned_interfaces() {
        let dir = unique_dir("cond-owned");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        // Pretend a WireGuard link the daemon owns carries a matching
        // address — the rule must not fire on it.
        core.journal.entries.push(JournalEntry {
            uid: 1000,
            owner: "wg:home".into(),
            state: OwnedState::Applied,
            resources: vec![OwnedResource::WireGuardLink(WireGuardLinkResource {
                name: "wg-deadbeef".into(),
                index: 9,
                owner_marker: "network-orchestrator:1000:wg:home".into(),
                full: None,
                warnings: Vec::new(),
            })],
        });
        let rules = vec![(1000u32, cond_rule("office", "10.99.0.0/24"))];
        // The address is on ifindex 9 — the daemon-owned link.
        let addrs = vec![iface_addr(9, "wg-deadbeef", "10.228.33.5", 21)];

        assert!(core.reconcile_conditional(&addrs, &[], &rules).is_empty());
        assert!(recorder.ops().is_empty());
        assert_eq!(
            cond_status(&core, 1000, &rules[0].1).state,
            ConditionalRuleState::Inactive
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn conditional_owner_prefix_is_reserved_for_clients() {
        let dir = unique_dir("cond-reserved");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        assert_eq!(
            core.apply_routes(1000, "cond:office", vec![route("10.1.0.0/16")])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        // Removing an existing conditional owner is also refused.
        #[cfg(target_os = "linux")]
        {
            let rules = vec![(1000u32, cond_rule("office", "10.99.0.0/24"))];
            core.reconcile_conditional(&[iface_addr(2, "enp1s0", "10.228.33.5", 21)], &[], &rules);
            let err = core.remove_owner(1000, "cond:office").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            // The journal entry survived — only rule evaluation may move it.
            assert_eq!(core.owned(1000)[0].owner, "cond:office");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    fn managed_link_entry(name: &str) -> JournalEntry {
        JournalEntry {
            uid: 1000,
            owner: "wg:test".into(),
            state: OwnedState::Applied,
            resources: vec![OwnedResource::WireGuardLink(WireGuardLinkResource {
                name: name.into(),
                index: 7,
                owner_marker: "marker".into(),
                full: None,
                warnings: vec![],
            })],
        }
    }

    #[test]
    fn stop_external_link_rejects_managed_interface() {
        let dir = unique_dir("stop-ext-managed");
        let recorder = Recorder::default();
        recorder
            .link_kinds
            .lock()
            .unwrap()
            .insert("wg-ours".into(), ExternalLinkKind::WireGuard);
        let mut core = open_core(&dir, &recorder);
        core.journal.entries.push(managed_link_entry("wg-ours"));
        let err = core.stop_external_link("wg-ours").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(recorder.ops().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stop_external_link_deletes_foreign_wireguard() {
        // No `wg-quick@wg-f4ke-q7x` unit can exist, so the probe falls through
        // to a plain netdev delete.
        let dir = unique_dir("stop-ext-wg");
        let recorder = Recorder::default();
        recorder
            .link_kinds
            .lock()
            .unwrap()
            .insert("wg-f4ke-q7x".into(), ExternalLinkKind::WireGuard);
        let mut core = open_core(&dir, &recorder);
        core.stop_external_link("wg-f4ke-q7x").unwrap();
        assert_eq!(recorder.ops(), vec![Op::LinkDel("wg-f4ke-q7x".into())]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stop_external_link_downs_foreign_tun() {
        let dir = unique_dir("stop-ext-tun");
        let recorder = Recorder::default();
        recorder
            .link_kinds
            .lock()
            .unwrap()
            .insert("tun-happ".into(), ExternalLinkKind::Tun);
        let mut core = open_core(&dir, &recorder);
        core.stop_external_link("tun-happ").unwrap();
        assert_eq!(recorder.ops(), vec![Op::Link("tun-happ".into(), false)]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stop_external_link_rejects_plain_interfaces() {
        let dir = unique_dir("stop-ext-eth");
        let recorder = Recorder::default();
        recorder
            .link_kinds
            .lock()
            .unwrap()
            .insert("eth9".into(), ExternalLinkKind::Other);
        let mut core = open_core(&dir, &recorder);
        let err = core.stop_external_link("eth9").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(recorder.ops().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stop_external_link_reports_missing() {
        let dir = unique_dir("stop-ext-missing");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        let err = core.stop_external_link("wg-gone").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stop_external_link_validates_name() {
        let dir = unique_dir("stop-ext-name");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        assert_eq!(
            core.stop_external_link("bad name!").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            core.stop_external_link("-wg").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(recorder.ops().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
