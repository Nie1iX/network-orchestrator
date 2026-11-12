use super::*;
use sha2::{Digest, Sha256};

impl ProfileService {
    fn editor_revision(&self, profile: &Profile) -> Result<String, String> {
        let endpoints = if profile.backend == TunnelBackend::Xray {
            self.endpoints(profile)?
        } else {
            Vec::new()
        };
        let mut hash = Sha256::new();
        hash.update(profiles::profile_edit_revision(profile).map_err(failed)?);
        hash.update(serde_json::to_vec(&endpoints).map_err(failed)?);
        Ok(format!("{:x}", hash.finalize()))
    }

    fn editor_result(&self, profile: &Profile) -> Result<EditorDocumentResult, String> {
        let endpoints = if profile.backend == TunnelBackend::Xray && profile.subscription.is_some()
        {
            self.subscription_endpoints(&profile.id)?
        } else {
            Vec::new()
        };
        Ok(EditorDocumentResult {
            document: editor_view(profile)?,
            revision: self.editor_revision(profile)?,
            endpoints,
            running: self.engine.status(profile)?.state == TunnelState::Running,
            running_revision: None,
        })
    }

    pub fn get_document(&self, id: &str) -> Result<EditorDocumentResult, String> {
        let _lock = self.mutation()?;
        self.editor_result(&self.profile(id)?)
    }

    fn editor_candidate(
        &self,
        stored: &Profile,
        document: &Value,
    ) -> Result<(Profile, Option<Value>), String> {
        let mut candidate = editor_restore(stored, document)?;
        match (&stored.subscription, &mut candidate.subscription) {
            (Some(old), Some(new)) => {
                if new.active_index != old.active_index {
                    return Err("Select a primary endpoint by key".into());
                }
                let mut protected = new.clone();
                protected.active_key = old.active_key.clone();
                protected.active_index = old.active_index;
                protected.backup_keys = old.backup_keys.clone();
                protected.pool_keys = old.pool_keys.clone();
                protected.node_pool = old.node_pool.clone();
                protected.auto_return_primary = old.auto_return_primary;
                protected.refresh_interval_minutes = old.refresh_interval_minutes;
                validate_interval(new.refresh_interval_minutes)?;
                if &protected != old {
                    return Err("Subscription source fields cannot be changed".into());
                }
            }
            (None, None) => {}
            _ => return Err("Subscription source cannot be changed".into()),
        }
        if candidate.backend == TunnelBackend::Mihomo {
            validate(&candidate).map_err(|_| "Invalid profile settings".to_string())?;
            return Ok((candidate, None));
        }
        let endpoints = self.endpoints(stored)?;
        let lookup = |key: &str| -> Result<usize, String> {
            let mut matches = endpoints
                .iter()
                .enumerate()
                .filter(|(_, endpoint)| endpoint.id == key);
            let index = matches
                .next()
                .map(|(i, _)| i)
                .ok_or("A referenced endpoint is missing")?;
            if matches.next().is_some() {
                return Err("A referenced endpoint is ambiguous".into());
            }
            Ok(index)
        };
        let mut base = None;
        if let Some(meta) = &mut candidate.subscription {
            if let Some(key) = &meta.active_key {
                let index = lookup(key)?;
                meta.active_index = index;
                if stored
                    .subscription
                    .as_ref()
                    .and_then(|s| s.active_key.as_ref())
                    != Some(key)
                {
                    base = Some(
                        net_manager_core::xray::generate_share_link_config_with_http(
                            &endpoints[index].url,
                            candidate
                                .xray_socks_port
                                .ok_or("Xray listener port is missing")?,
                            candidate
                                .xray_http_port
                                .ok_or("Xray listener port is missing")?,
                        )
                        .map_err(|_| "The selected endpoint is invalid")?,
                    );
                }
            } else if stored
                .subscription
                .as_ref()
                .and_then(|s| s.active_key.as_ref())
                .is_some()
            {
                return Err("The primary endpoint cannot be cleared".into());
            } else {
                let endpoint = endpoints
                    .get(meta.active_index)
                    .ok_or("The primary endpoint is missing")?;
                lookup(&endpoint.id)?;
            }
            for item in meta.backup_keys.iter().chain(&meta.pool_keys) {
                lookup(&item.key)?;
            }
        }
        for pin in &candidate.pinned_policies {
            lookup(&pin.endpoint_key)?;
        }
        for check in &candidate.xray_service_checks {
            lookup(&check.endpoint_key)?;
        }
        for exit in &candidate.xray_proxy_exits {
            for key in exit.target.endpoint_keys() {
                lookup(key)?;
            }
        }
        if let Some(key) = &candidate.xray_dns.outbound_key {
            lookup(key)?;
        }
        validate(&candidate).map_err(|_| "Invalid profile settings".to_string())?;
        Ok((candidate, base))
    }

    fn editor_preview(&self, stored: &Profile, document: &Value) -> EditorPreviewResult {
        let changed_paths = editor_view(stored)
            .map(|v| editor_diff(&v, document))
            .unwrap_or_default();
        let mut preview = EditorPreviewResult {
            valid: false,
            issues: Vec::new(),
            daemon_validated: false,
            requires_reconnect: !changed_paths.is_empty(),
            changed_paths,
        };
        let (candidate, base) = match self.editor_candidate(stored, document) {
            Ok(candidate) => candidate,
            Err(message) => {
                let path = message
                    .strip_prefix("Unknown setting at ")
                    .unwrap_or("/profile")
                    .to_string();
                preview.issues.push(EditorIssue {
                    path,
                    message,
                    severity: "error",
                });
                return preview;
            }
        };
        let result: Result<(), String> = (|| {
            if candidate.backend == TunnelBackend::Xray && candidate.xray_mode == XrayMode::Tun {
                let params = crate::linux::prepare_linux_xray_tun_params_with_base(
                    &self.vault(),
                    &candidate,
                    base.as_ref(),
                )?;
                let response: Value = self.engine.ask(
                    net_manager_core::daemon_protocol::method::XRAY_VALIDATE,
                    &params,
                )?;
                match response.get("valid").and_then(Value::as_bool) {
                    Some(true) => preview.daemon_validated = true,
                    Some(false) => {
                        let issues = response
                            .get("issues")
                            .and_then(Value::as_array)
                            .ok_or("Invalid daemon validation response")?;
                        for issue in issues {
                            let path = issue
                                .get("path")
                                .and_then(Value::as_str)
                                .filter(|path| matches!(*path, "/profile" | "/profile/configPath"))
                                .ok_or("Invalid daemon validation response")?;
                            let message = issue
                                .get("message")
                                .and_then(Value::as_str)
                                .filter(|message| message.len() <= 512)
                                .ok_or("Invalid daemon validation response")?;
                            preview.issues.push(EditorIssue {
                                path: path.into(),
                                message: message.into(),
                                severity: "error",
                            });
                        }
                        return Err("The daemon rejected the configuration".into());
                    }
                    None => return Err("Invalid daemon validation response".into()),
                }
            } else {
                match candidate.backend {
                    TunnelBackend::WireGuard => {
                        let params =
                            crate::linux::wireguard_connect_params(&self.vault(), &candidate)?;
                        net_manager_core::wireguard_config::parse_wireguard_config(
                            &params.config,
                            &params.routes,
                        )
                        .map_err(|_| "Invalid WireGuard configuration".to_string())?;
                    }
                    TunnelBackend::Mihomo => {
                        let source = crate::linux::read_mihomo_source(&self.vault(), &candidate)?;
                        net_manager_core::mihomo::compile_config(&source, &candidate)
                            .map_err(|error| error.to_string())?;
                    }
                    TunnelBackend::OpenVpn | TunnelBackend::Xray => {
                        net_manager_core::analysis::analyze_profile(&candidate).map_err(|_| {
                            "The managed configuration could not be inspected".to_string()
                        })?;
                    }
                    TunnelBackend::None => {}
                }
                preview.issues.push(EditorIssue {
                    path: "/profile".into(),
                    message:
                        "Validated locally; daemon validation is not available for this backend"
                            .into(),
                    severity: "warning",
                });
            }
            Ok(())
        })();
        match result {
            Ok(()) => preview.valid = true,
            Err(message) if preview.issues.is_empty() => preview.issues.push(EditorIssue {
                path: "/profile".into(),
                message: if candidate.backend == TunnelBackend::Mihomo {
                    message
                } else {
                    "Profile validation failed or the daemon validator is unavailable".into()
                },
                severity: "error",
            }),
            Err(_) => {}
        }
        preview
    }

    pub fn preview_document(
        &self,
        id: &str,
        document: Value,
        expected_revision: &str,
    ) -> Result<EditorPreviewResult, String> {
        let _lock = self.mutation()?;
        let stored = self.profile(id)?;
        if self.editor_revision(&stored)? != expected_revision {
            return Err(profiles::PROFILE_EDIT_CONFLICT.into());
        }
        Ok(self.editor_preview(&stored, &document))
    }

    pub fn save_document(
        &self,
        id: &str,
        document: Value,
        expected_revision: &str,
    ) -> Result<EditorDocumentResult, String> {
        let _lock = self.mutation()?;
        let stored = self.profile(id)?;
        if self.editor_revision(&stored)? != expected_revision {
            return Err(profiles::PROFILE_EDIT_CONFLICT.into());
        }
        if !self.editor_preview(&stored, &document).valid {
            return Err("Profile validation failed; nothing was saved".into());
        }
        let (mut candidate, base) = self.editor_candidate(&stored, &document)?;
        let mut new_path = None;
        if let Some(base) = base {
            let imported = self
                .vault()
                .store_generated_xray(id, &serde_json::to_vec_pretty(&base).map_err(failed)?)
                .map_err(failed)?;
            candidate.config_path = imported.config_path.clone();
            new_path = Some(imported.config_path);
        }
        let old_revision = profiles::profile_edit_revision(&stored).map_err(failed)?;
        if let Err(error) = self
            .store()
            .compare_upsert(candidate.clone(), Some(&old_revision))
        {
            if let Some(path) = &new_path {
                let _ = self.vault().remove_revision_for_config(path);
            }
            return Err(if error.to_string() == profiles::PROFILE_EDIT_CONFLICT {
                profiles::PROFILE_EDIT_CONFLICT.into()
            } else {
                failed(error)
            });
        }
        // A concurrent runtime may still use the previous revision; profile
        // deletion removes the retained revisions together with the vault.
        self.editor_result(&candidate)
            .map_err(|_| "Profile was saved, but its updated status could not be read".into())
    }

    pub fn apply_document(
        &self,
        id: &str,
        expected_revision: &str,
        credentials: &dyn crate::linux::CredentialSource,
    ) -> Result<TunnelStatus, String> {
        let _lock = self.mutation()?;
        let profile = self.profile(id)?;
        if self.editor_revision(&profile)? != expected_revision {
            return Err(profiles::PROFILE_EDIT_CONFLICT.into());
        }
        let vault = self.vault();
        let prepared =
            self.engine
                .prepare_connection(&vault, &profile, None, credentials, false)?;
        if self.engine.status(&profile)?.state != TunnelState::Stopped {
            let status = crate::linux_runtime::disconnect_profile_with_root(
                &self.engine,
                &self.root,
                &profile,
            )?;
            if status.state != TunnelState::Stopped {
                return Err("The previous connection did not stop".into());
            }
        }
        self.engine.execute_prepared(&prepared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::config_vault::SubscriptionEndpoint;

    struct RecordingDaemon(std::sync::Mutex<Vec<String>>);
    impl crate::privileged::Privileged for RecordingDaemon {
        fn hello(
            &self,
        ) -> Result<
            net_manager_core::daemon_protocol::HelloResult,
            net_manager_core::helper_client::HelperError,
        > {
            Ok(net_manager_core::daemon_protocol::HelloResult {
                protocol: net_manager_core::daemon_protocol::PROTOCOL_VERSION,
                daemon_version: "test".into(),
                uid: 1000,
                capabilities: vec![],
                tools: Default::default(),
            })
        }
        fn call_raw(
            &self,
            method: &str,
            _: Value,
        ) -> Result<Value, net_manager_core::helper_client::HelperError> {
            self.0.lock().unwrap().push(method.to_string());
            match method {
                net_manager_core::daemon_protocol::method::OWNED_LIST => {
                    Ok(json!({"owners":[{"owner":"example","state":"applied","resources":[]}]}))
                }
                _ => panic!("unexpected daemon mutation: {method}"),
            }
        }
        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }

    #[test]
    fn native_preview_rejects_missing_selected_group_without_daemon_request() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = std::sync::Arc::new(RecordingDaemon(std::sync::Mutex::new(Vec::new())));
        let service = ProfileService::new(
            dir.path().to_path_buf(),
            LinuxEngine::with_privileged(daemon.clone()),
        );
        let imported = service.vault().store_mihomo_source(
            "native",
            br#"{"proxies":[],"proxy-groups":[{"name":"Available","type":"select","proxies":["DIRECT"]}],"rules":["MATCH,Available"]}"#,
        ).unwrap();
        let profile = Profile {
            id: "native".into(),
            name: "Native".into(),
            backend: TunnelBackend::Mihomo,
            config_path: imported.config_path,
            mihomo: Some(MihomoProfileOptions {
                entry_group: Some("Disappeared".into()),
                ..Default::default()
            }),
            ..Profile::default()
        };
        let preview = service.editor_preview(&profile, &editor_view(&profile).unwrap());
        assert!(!preview.valid);
        assert!(daemon.0.lock().unwrap().is_empty());
    }

    #[test]
    fn editor_saves_running_profile_without_mutation_and_rejects_stale_revision() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let daemon = std::sync::Arc::new(RecordingDaemon(std::sync::Mutex::new(Vec::new())));
        let service = ProfileService::new(
            dir.path().to_path_buf(),
            LinuxEngine::with_privileged(daemon.clone()),
        );
        let profile = Profile {
            id: "example".into(),
            name: "Before".into(),
            backend: TunnelBackend::None,
            ..Profile::default()
        };
        service.store().upsert(profile).unwrap();
        let initial = service.get_document("example").unwrap();
        assert!(initial.running);
        let mut draft = initial.document.clone();
        draft["profile"]["name"] = json!("After");
        let saved = service
            .save_document("example", draft.clone(), &initial.revision)
            .unwrap();
        assert!(saved.running);
        assert_eq!(service.profile("example").unwrap().name, "After");
        assert_eq!(
            service
                .save_document("example", draft, &initial.revision)
                .unwrap_err(),
            profiles::PROFILE_EDIT_CONFLICT
        );
        assert!(daemon
            .0
            .lock()
            .unwrap()
            .iter()
            .all(|call| call == net_manager_core::daemon_protocol::method::OWNED_LIST));
    }

    #[test]
    fn editor_preview_surfaces_safe_daemon_issue() {
        struct RejectingDaemon;
        impl crate::privileged::Privileged for RejectingDaemon {
            fn hello(
                &self,
            ) -> Result<
                net_manager_core::daemon_protocol::HelloResult,
                net_manager_core::helper_client::HelperError,
            > {
                Ok(net_manager_core::daemon_protocol::HelloResult {
                    protocol: net_manager_core::daemon_protocol::PROTOCOL_VERSION,
                    daemon_version: "test".into(),
                    uid: 1000,
                    capabilities: vec![],
                    tools: Default::default(),
                })
            }
            fn call_raw(
                &self,
                method: &str,
                _: Value,
            ) -> Result<Value, net_manager_core::helper_client::HelperError> {
                assert_eq!(
                    method,
                    net_manager_core::daemon_protocol::method::XRAY_VALIDATE
                );
                Ok(
                    json!({"valid": false, "issues": [{"path": "/profile/configPath", "severity": "error", "message": "Unsupported vless transport at outbounds[0].streamSettings"}]}),
                )
            }
            fn log_dir(&self) -> PathBuf {
                PathBuf::new()
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let service = ProfileService::new(
            dir.path().to_path_buf(),
            LinuxEngine::with_privileged(std::sync::Arc::new(RejectingDaemon)),
        );
        net_manager_core::profile_import::import_share_link(
            &service.vault(),
            &service.store(),
            "example",
            "Example",
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?security=none",
            XrayMode::Tun,
            |_| true,
        )
        .unwrap();
        let profile = service.profile("example").unwrap();
        let preview = service.editor_preview(&profile, &editor_view(&profile).unwrap());
        assert!(!preview.valid);
        assert_eq!(preview.issues[0].path, "/profile/configPath");
        assert!(preview.issues[0]
            .message
            .contains("outbounds[0].streamSettings"));
    }

    #[test]
    fn editor_selects_distinct_catalog_records_sharing_a_transport() {
        let dir = tempfile::tempdir().unwrap();
        let service =
            ProfileService::new(dir.path().to_path_buf(), LinuxEngine::new("editor-test"));
        subscription::import_body(
            &service.vault(),
            &service.store(),
            &subscription::SubscriptionImport {
                id: "example",
                url: "https://example.test/list",
                hwid: "device",
                name: "Example",
                refresh_interval_minutes: None,
            },
            "vless://one@node.test:443?security=none#Auto\nvless://two@node.test:443?security=none#UK",
            subscription::ResponseMeta::default(),
            XrayMode::Tun,
            |_| true,
        ).unwrap();
        let profile = service.store().load().unwrap().profiles.remove(0);
        let endpoints = service
            .vault()
            .read_subscription_endpoints("example")
            .unwrap();
        assert_ne!(endpoints[0].id, endpoints[1].id);
        let mut draft = editor_view(&profile).unwrap();
        draft["profile"]["subscription"]["activeKey"] = json!(endpoints[1].id);
        let (candidate, _) = service.editor_candidate(&profile, &draft).unwrap();
        assert_eq!(candidate.subscription.unwrap().active_index, 1);
    }

    #[test]
    fn editor_primary_switch_retains_running_source_and_regenerates_config() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        struct RunningXray(std::sync::Mutex<Vec<String>>);
        impl crate::privileged::Privileged for RunningXray {
            fn hello(
                &self,
            ) -> Result<
                net_manager_core::daemon_protocol::HelloResult,
                net_manager_core::helper_client::HelperError,
            > {
                Ok(net_manager_core::daemon_protocol::HelloResult {
                    protocol: net_manager_core::daemon_protocol::PROTOCOL_VERSION,
                    daemon_version: "test".into(),
                    uid: 1000,
                    capabilities: vec![],
                    tools: Default::default(),
                })
            }
            fn call_raw(
                &self,
                method: &str,
                _: Value,
            ) -> Result<Value, net_manager_core::helper_client::HelperError> {
                self.0.lock().unwrap().push(method.into());
                match method {
                    net_manager_core::daemon_protocol::method::XRAY_STATUS => Ok(
                        json!({"profileId":"example","state":"running","interfaceName":"nxray1","dnsApplied":true,"ipv4Covered":true,"ipv6Covered":false,"rxBytes":null,"txBytes":null,"failover":null,"watchdog":null,"proxyExits":[]}),
                    ),
                    net_manager_core::daemon_protocol::method::XRAY_VALIDATE => {
                        Ok(json!({"valid":true,"issues":[]}))
                    }
                    _ => panic!("unexpected mutation {method}"),
                }
            }
            fn log_dir(&self) -> PathBuf {
                PathBuf::new()
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let daemon = std::sync::Arc::new(RunningXray(std::sync::Mutex::new(Vec::new())));
        let service = ProfileService::new(
            dir.path().to_path_buf(),
            LinuxEngine::with_privileged(daemon.clone()),
        );
        let first = "vless://11111111-2222-3333-4444-555555555555@first.test:443?security=none";
        let second = "vless://11111111-2222-3333-4444-555555555555@second.test:443?security=none";
        subscription::import_body(
            &service.vault(),
            &service.store(),
            &subscription::SubscriptionImport {
                id: "example",
                url: "https://example.test/list",
                hwid: "device",
                name: "Example",
                refresh_interval_minutes: None,
            },
            &format!("{first}\n{second}"),
            subscription::ResponseMeta::default(),
            XrayMode::Tun,
            |_| true,
        )
        .unwrap();
        let before = service.profile("example").unwrap();
        let initial = service.get_document("example").unwrap();
        let mut draft = initial.document;
        draft["profile"]["subscription"]["activeKey"] = json!(
            service
                .vault()
                .read_subscription_endpoints("example")
                .unwrap()[1]
                .id
        );
        draft["profile"]["subscription"]["refreshIntervalMinutes"] = json!(60);
        service
            .save_document("example", draft, &initial.revision)
            .unwrap();
        let after = service.profile("example").unwrap();
        assert_ne!(before.config_path, after.config_path);
        assert!(before.config_path.exists());
        assert!(fs::read_to_string(&after.config_path)
            .unwrap()
            .contains("second.test"));
        assert_eq!(
            after.subscription.unwrap().refresh_interval_minutes,
            Some(60)
        );
        assert!(daemon.0.lock().unwrap().iter().all(|method| matches!(
            method.as_str(),
            net_manager_core::daemon_protocol::method::XRAY_STATUS
                | net_manager_core::daemon_protocol::method::XRAY_VALIDATE
        )));
    }

    #[test]
    fn editor_apply_reconnects_the_selected_running_snapshot() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        struct RunningDaemon(std::sync::Mutex<Vec<String>>);
        impl crate::privileged::Privileged for RunningDaemon {
            fn hello(
                &self,
            ) -> Result<
                net_manager_core::daemon_protocol::HelloResult,
                net_manager_core::helper_client::HelperError,
            > {
                Ok(net_manager_core::daemon_protocol::HelloResult {
                    protocol: net_manager_core::daemon_protocol::PROTOCOL_VERSION,
                    daemon_version: "test".into(),
                    uid: 1000,
                    capabilities: vec![],
                    tools: Default::default(),
                })
            }
            fn call_raw(
                &self,
                method: &str,
                _: Value,
            ) -> Result<Value, net_manager_core::helper_client::HelperError> {
                self.0.lock().unwrap().push(method.into());
                let status = json!({"profileId":"example", "state":"running", "interfaceName":"wg1", "latestHandshake":null, "rxBytes":0, "txBytes":0, "dnsApplied":false, "warnings":[]});
                match method {
                    net_manager_core::daemon_protocol::method::WIREGUARD_STATUS => Ok(status),
                    net_manager_core::daemon_protocol::method::WIREGUARD_DISCONNECT => {
                        Ok(json!({"stopped":true}))
                    }
                    net_manager_core::daemon_protocol::method::WIREGUARD_CONNECT => {
                        Ok(json!({"status":status}))
                    }
                    _ => panic!("unexpected method {method}"),
                }
            }
            fn log_dir(&self) -> PathBuf {
                PathBuf::new()
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let daemon = std::sync::Arc::new(RunningDaemon(std::sync::Mutex::new(Vec::new())));
        let service = ProfileService::new(
            dir.path().to_path_buf(),
            LinuxEngine::with_privileged(daemon.clone()),
        );
        let imported = service.vault().store_wireguard_config("example", b"[Interface]\nPrivateKey = x\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = y\nAllowedIPs = 10.0.0.0/8\nEndpoint = 203.0.113.5:51820\n").unwrap();
        let profile = Profile {
            id: "example".into(),
            name: "VPN".into(),
            backend: TunnelBackend::WireGuard,
            config_path: imported.config_path,
            ..Profile::default()
        };
        service.store().upsert(profile.clone()).unwrap();
        let revision = service.editor_revision(&profile).unwrap();
        assert_eq!(
            service
                .apply_document("example", &revision, &())
                .unwrap()
                .state,
            TunnelState::Running
        );
        let calls = daemon.0.lock().unwrap();
        assert_eq!(
            calls.as_slice(),
            [
                net_manager_core::daemon_protocol::method::WIREGUARD_STATUS,
                net_manager_core::daemon_protocol::method::WIREGUARD_DISCONNECT,
                net_manager_core::daemon_protocol::method::WIREGUARD_CONNECT
            ]
        );
    }

    #[test]
    fn editor_rejects_duplicate_catalog_ids() {
        let dir = tempfile::tempdir().unwrap();
        let service =
            ProfileService::new(dir.path().to_path_buf(), LinuxEngine::new("editor-test"));
        let url = "vless://11111111-2222-3333-4444-555555555555@node.test:443?security=none";
        let endpoint = SubscriptionEndpoint {
            id: "1111111111111111".into(),
            url: url.into(),
            name: "one".into(),
        };
        service
            .vault()
            .store_subscription_endpoints("example", std::slice::from_ref(&endpoint))
            .unwrap();
        let endpoint = service
            .vault()
            .read_subscription_endpoints("example")
            .unwrap()
            .remove(0);
        let profile = Profile {
            id: "example".into(),
            backend: TunnelBackend::Xray,
            subscription: Some(
                serde_json::from_value(json!({
                    "url": "https://example.test/secret", "hwid": "secret", "endpointCount": 1,
                    "activeIndex": 0, "activeKey": endpoint.id
                }))
                .unwrap(),
            ),
            ..Default::default()
        };
        let path = service.vault().root().join("example/subscription.json");
        let mut catalog: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let duplicate = catalog["endpoints"][0].clone();
        catalog["endpoints"].as_array_mut().unwrap().push(duplicate);
        fs::write(path, serde_json::to_vec(&catalog).unwrap()).unwrap();
        assert!(service.editor_revision(&profile).is_err());
    }
}
