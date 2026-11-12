//! Saved profile and subscription orchestration shared by the Linux GUI and CLI.
//! Input/configuration errors deliberately omit source text, paths and provider credentials.
use crate::linux_engine::LinuxEngine;
use net_manager_core::config_vault::{ConfigImport, ConfigVault};
use net_manager_core::models::*;
use net_manager_core::profiles::{self, ProfileDocument, ProfileStore};
use net_manager_core::{config_security, profile_import, subscription};
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub enum ProfileSource {
    Config(PathBuf),
    ShareLink(String),
    WireGuard(WireGuardFields),
    MihomoDocument(String),
}

#[derive(Clone)]
pub struct ProfileService {
    root: PathBuf,
    engine: LinuxEngine,
}

fn failed(_: impl std::fmt::Display) -> String {
    "The profile operation could not be completed; check the input and file permissions".into()
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn available(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl ProfileService {
    pub fn new(root: PathBuf, engine: LinuxEngine) -> Self {
        Self {
            engine: engine.with_data_root(root.clone()),
            root,
        }
    }

    pub fn store(&self) -> ProfileStore {
        ProfileStore::new(self.root.join("profiles.json"))
    }
    pub fn vault(&self) -> ConfigVault {
        ConfigVault::new(self.root.join("configs"))
    }
    pub fn profiles(&self) -> Result<Vec<Profile>, String> {
        let store = self.store();
        let vault = self.vault();
        let mut profiles = store.load().map_err(failed)?.profiles;
        for profile in &mut profiles {
            if profile.backend == TunnelBackend::Xray && profile.subscription.is_some() {
                *profile = subscription::migrate_endpoint_ids(&vault, &store, &profile.id)
                    .map_err(failed)?;
            }
        }
        Ok(profiles)
    }
    pub fn profile(&self, id: &str) -> Result<Profile, String> {
        self.profiles()?
            .into_iter()
            .find(|profile| profile.id == id)
            .ok_or_else(|| "The requested profile could not be selected".into())
    }

    // The store has its own atomic transaction lock. This second, cross-process
    // lock also covers vault revisions and endpoint files, shared by both frontends.
    fn mutation(&self) -> Result<File, String> {
        if unsafe { libc::geteuid() } == 0 {
            return Err("Run profile changes as your own user, without sudo".into());
        }
        fs::create_dir_all(&self.root).map_err(failed)?;
        config_security::protect_path(&self.root).map_err(failed)?;
        let path = self.root.join("profile-operations.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(failed)?;
        config_security::protect_path(&path).map_err(failed)?;
        file.lock().map_err(failed)?;
        Ok(file)
    }

    pub fn ensure_editable(&self, profile: &Profile) -> Result<(), String> {
        if self
            .engine
            .status(profile)
            .map_err(|_| "Could not check the connection state".to_string())?
            .state
            != TunnelState::Stopped
        {
            return Err(
                "The profile is active; disconnect it before editing or deleting it".into(),
            );
        }
        crate::linux_services::ensure_not_enrolled(&self.engine, profile)?;
        Ok(())
    }

    pub fn patch(&self, id: &str, patch: &Value) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let expected = self.profile(id)?;
        self.ensure_editable(&expected)?;
        let merged = merge_profile(&expected, patch).map_err(failed)?;
        validate(&merged).map_err(failed)?;
        if merged.backend == TunnelBackend::Mihomo {
            let source = crate::linux::read_mihomo_source(&self.vault(), &expected)?;
            validate_mihomo_source(&source, &merged).map_err(|error| error.to_string())?;
        }
        self.store()
            .update_profile(id, |stored| {
                if stored != &expected {
                    return Err(invalid("Profile changed; retry the edit"));
                }
                *stored = merged;
                Ok(())
            })
            .map_err(failed)
    }

    /// GUI forms own only their existing editable fields. Canonical subscription
    /// state and dedicated endpoint/check/exit settings remain store-owned.
    pub fn save_form(
        &self,
        mut profile: Profile,
        source: Option<ProfileSource>,
        expected_revision: Option<&str>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let stored = self.profiles()?.into_iter().find(|p| p.id == profile.id);
        let actual_revision = stored
            .as_ref()
            .map(profiles::profile_edit_revision)
            .transpose()
            .map_err(failed)?;
        if actual_revision.as_deref() != expected_revision {
            return Err(profiles::PROFILE_EDIT_CONFLICT.into());
        }
        if let Some(existing) = &stored {
            self.ensure_editable(existing)?;
            preserve_form_settings(&mut profile, existing, source.is_none());
        } else {
            profile.subscription = None;
            profile.pinned_policies.clear();
            profile.xray_service_checks.clear();
            profile.xray_proxy_exits.clear();
        }
        self.save_locked(profile, source, stored.as_ref(), expected_revision, None)
    }

    pub fn create(
        &self,
        mut profile: Profile,
        source: Option<ProfileSource>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        if profile.id.is_empty() {
            profile.id = new_id()?;
        }
        if self.profiles()?.iter().any(|p| p.id == profile.id) {
            return Err("A profile with that identifier already exists".into());
        }
        if profile.subscription.is_some()
            || !profile.pinned_policies.is_empty()
            || !profile.xray_service_checks.is_empty()
            || !profile.xray_proxy_exits.is_empty()
        {
            return Err("Use subscription, routing, checks and proxy commands for canonical endpoint settings".into());
        }
        self.save_locked(profile, source, None, None, None)
    }

    fn save_locked(
        &self,
        mut profile: Profile,
        source: Option<ProfileSource>,
        stored: Option<&Profile>,
        expected_revision: Option<&str>,
        prepared_native: Option<Value>,
    ) -> Result<ProfileDocument, String> {
        net_manager_core::config_vault::sanitize_profile_id(&profile.id).map_err(failed)?;
        let vault = self.vault();
        let source = source.or_else(|| {
            (profile.backend != TunnelBackend::None && !vault.is_managed_path(&profile.config_path))
                .then(|| ProfileSource::Config(profile.config_path.clone()))
        });
        // Validate everything before writing a new revision. A temporary extension
        // permits structured builders whose config path has not been assigned yet.
        let mut validation = profile.clone();
        if source.is_some() {
            validation.config_path = match profile.backend {
                TunnelBackend::WireGuard => "source.conf".into(),
                TunnelBackend::OpenVpn => "source.ovpn".into(),
                TunnelBackend::Xray => "source.json".into(),
                TunnelBackend::Mihomo => "source.yaml".into(),
                TunnelBackend::None => PathBuf::new(),
            };
        }
        if matches!(&source, Some(ProfileSource::ShareLink(_))) {
            validation.xray_socks_port = Some(10808);
            validation.xray_http_port = Some(10809);
        }
        validate(&validation).map_err(failed)?;
        if source.is_none()
            && profile.backend != TunnelBackend::None
            && (!vault.is_managed_profile_path(&profile.id, &profile.config_path)
                || stored.is_none_or(|p| {
                    p.config_path != profile.config_path || p.backend != profile.backend
                }))
        {
            return Err(
                "Select an existing profile's current managed revision or import a source".into(),
            );
        }
        if source.is_none() && profile.backend == TunnelBackend::Mihomo {
            let native = crate::linux::read_mihomo_source(&vault, &profile)?;
            validate_mihomo_source(&native, &profile).map_err(|error| error.to_string())?;
        }
        let imported: Option<ConfigImport> = match source {
            Some(ProfileSource::Config(path)) => {
                if vault.is_managed_path(&path) {
                    return Err(
                        "A managed revision cannot be imported as another profile's source".into(),
                    );
                }
                if profile.backend == TunnelBackend::Mihomo {
                    use std::io::Read;
                    let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                    if !["yaml", "yml", "json"]
                        .iter()
                        .any(|s| extension.eq_ignore_ascii_case(s))
                    {
                        return Err("Native configuration must be YAML or JSON".into());
                    }
                    let mut bytes = Vec::new();
                    File::open(&path)
                        .map_err(failed)?
                        .take(net_manager_core::mihomo::MAX_CONFIG_BYTES as u64 + 1)
                        .read_to_end(&mut bytes)
                        .map_err(failed)?;
                    let source = mihomo::resolve_source(&bytes)?;
                    validate_mihomo_source(&source, &profile).map_err(|error| error.to_string())?;
                    let body = serde_json::to_vec(&source).map_err(failed)?;
                    Some(
                        vault
                            .store_mihomo_source(&profile.id, &body)
                            .map_err(failed)?,
                    )
                } else {
                    Some(
                        vault
                            .import(&profile.id, profile.backend, &path)
                            .map_err(failed)?,
                    )
                }
            }
            Some(ProfileSource::ShareLink(link)) => {
                if profile.backend != TunnelBackend::Xray {
                    return Err("Share-link fields require an Xray profile".into());
                }
                let all = self.profiles()?;
                let used = profile_import::profile_listener_ports(&all, &profile.id);
                let (socks, http) = profile_import::select_generated_ports(
                    profile.xray_socks_port,
                    profile.xray_http_port,
                    &used,
                    available,
                )
                .map_err(failed)?;
                let config = net_manager_core::xray::generate_share_link_config_with_http(
                    link.trim(),
                    socks,
                    http,
                )
                .map_err(failed)?;
                let body = serde_json::to_vec_pretty(&config).map_err(failed)?;
                profile.xray_socks_port = Some(socks);
                profile.xray_http_port = Some(http);
                Some(
                    vault
                        .store_generated_xray(&profile.id, &body)
                        .map_err(failed)?,
                )
            }
            Some(ProfileSource::WireGuard(fields)) => {
                if profile.backend != TunnelBackend::WireGuard {
                    return Err("WireGuard fields require a WireGuard profile".into());
                }
                let body = render_wireguard_config(&fields)?;
                Some(
                    vault
                        .store_wireguard_config(&profile.id, body.as_bytes())
                        .map_err(failed)?,
                )
            }
            Some(ProfileSource::MihomoDocument(body)) => {
                if profile.backend != TunnelBackend::Mihomo {
                    return Err("Native configuration requires a Mihomo profile".into());
                }
                let parsed = match prepared_native {
                    Some(source) => source,
                    None => mihomo::resolve_source(body.as_bytes())?,
                };
                validate_mihomo_source(&parsed, &profile).map_err(|error| error.to_string())?;
                let body = serde_json::to_vec(&parsed).map_err(failed)?;
                Some(
                    vault
                        .store_mihomo_source(&profile.id, &body)
                        .map_err(failed)?,
                )
            }
            None => None,
        };
        if let Some(imported) = &imported {
            profile.config_path = imported.config_path.clone();
        }
        let new_path = profile.config_path.clone();
        let result = validate(&profile)
            .and_then(|()| self.store().compare_upsert(profile, expected_revision));
        let document = match result {
            Ok(document) => document,
            Err(error) => {
                if imported.is_some() {
                    let _ = vault.remove_revision_for_config(&new_path);
                }
                return Err(if error.to_string() == profiles::PROFILE_EDIT_CONFLICT {
                    profiles::PROFILE_EDIT_CONFLICT.into()
                } else {
                    failed(error)
                });
            }
        };
        if let Some(old) = stored {
            if old.config_path != new_path
                && vault.is_managed_profile_path(&old.id, &old.config_path)
            {
                vault
                    .remove_revision_for_config(&old.config_path)
                    .map_err(|_| {
                        "Profile saved, but the old managed revision could not be removed"
                            .to_string()
                    })?;
            }
        }
        if imported.is_some() {
            if let Some(native) = document.profiles.iter().find(|profile| {
                profile.backend == TunnelBackend::Mihomo && profile.config_path == new_path
            }) {
                let source = crate::linux::read_mihomo_source(&vault, native).map_err(|_| {
                    "Profile saved, but its provider schedule could not be inspected".to_string()
                })?;
                if crate::linux_subscriptions::provider_interval(&source).is_some() {
                    self.engine.sync_subscription_schedule().map_err(|_| {
                        "Profile saved, but the provider refresh runtime could not be started"
                            .to_string()
                    })?;
                }
            }
        }
        Ok(document)
    }

    pub fn delete(&self, id: &str) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let profile = self.profile(id)?;
        self.ensure_editable(&profile)?;
        let document = self.store().delete(id).map_err(failed)?;
        self.vault().remove_profile(id).map_err(|_| {
            "Profile deleted, but its managed configuration could not be removed".to_string()
        })?;
        if profile.backend == TunnelBackend::OpenVpn {
            crate::linux_credentials::OpenVpnCredentialStore::new(Box::new(
                crate::linux_credentials::SecretServiceStore,
            ))
            .forget(id, None)?;
        }
        Ok(document)
    }

    pub fn reorder(
        &self,
        backend: TunnelBackend,
        ids: &[String],
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.store().reorder(backend, ids).map_err(failed)
    }

    pub async fn import_subscription(
        &self,
        request: &subscription::SubscriptionImport<'_>,
        cached: Option<&str>,
    ) -> Result<BatchImportResult, String> {
        if unsafe { libc::geteuid() } == 0 {
            return Err("Run subscription changes as your own user, without sudo".into());
        }
        validate_interval(request.refresh_interval_minutes)?;
        let fetched;
        let (body, meta) = if let Some(body) = cached {
            (body, subscription::response_meta(&[], body))
        } else {
            let client = subscription::http_client().map_err(failed)?;
            fetched = subscription::fetch(&client, request.url, request.hwid)
                .await
                .map_err(failed)?;
            (fetched.body.as_str(), fetched.meta.clone())
        };
        let _lock = self.mutation()?;
        subscription::import_body(
            &self.vault(),
            &self.store(),
            request,
            body,
            meta,
            net_manager_core::models::XrayMode::platform_default(),
            available,
        )
        .map_err(failed)
    }

    pub fn import_subscription_body(
        &self,
        request: &subscription::SubscriptionImport<'_>,
        body: &str,
        meta: subscription::ResponseMeta,
    ) -> Result<BatchImportResult, String> {
        let _lock = self.mutation()?;
        validate_interval(request.refresh_interval_minutes)?;
        subscription::import_body(
            &self.vault(),
            &self.store(),
            request,
            body,
            meta,
            net_manager_core::models::XrayMode::platform_default(),
            available,
        )
        .map_err(failed)
    }

    pub async fn refresh_subscription(
        &self,
        id: &str,
        cached: Option<&str>,
    ) -> Result<SubscriptionRefreshResult, String> {
        if unsafe { libc::geteuid() } == 0 {
            return Err("Run subscription changes as your own user, without sudo".into());
        }
        let current = self.profile(id)?;
        if current.backend == TunnelBackend::Mihomo {
            return if current.subscription.is_some() {
                self.refresh_mihomo_subscription(id, cached).await
            } else if cached.is_none() {
                self.refresh_mihomo_providers(id, false).await
            } else {
                Err("Cached subscription data requires a subscription profile".into())
            };
        }
        let expected = self.subscription_profile(id)?;
        let refresh_lock =
            crate::linux_session::lock_file(&self.root.join("subscription-refresh.lock"))
                .map_err(failed)?;
        refresh_lock
            .try_lock()
            .map_err(|_| "A subscription refresh is already in progress".to_string())?;
        let meta = expected
            .subscription
            .as_ref()
            .expect("subscription checked");
        let refreshed = async {
            let fetched;
            let (body, response_meta) = if let Some(body) = cached {
                (body, subscription::response_meta(&[], body))
            } else {
                let client = subscription::http_client().map_err(failed)?;
                fetched = subscription::fetch(&client, &meta.url, &meta.hwid)
                    .await
                    .map_err(failed)?;
                (fetched.body.as_str(), fetched.meta.clone())
            };
            let _lock = self.mutation()?;
            if self.profile(id)? != expected {
                return Err("The subscription changed during refresh; retry".into());
            }
            subscription::refresh_body(
                &self.vault(),
                &self.store(),
                id,
                body,
                response_meta,
                true,
                available,
            )
            .map_err(failed)
        }
        .await;
        let outcome = match refreshed {
            Ok(outcome) => outcome,
            Err(error) => {
                self.store()
                    .update_profile(id, |current| {
                        if current.subscription != expected.subscription {
                            return Err(invalid("Subscription changed during refresh"));
                        }
                        let meta = current
                            .subscription
                            .as_mut()
                            .ok_or_else(|| invalid("Profile is no longer a subscription"))?;
                        meta.last_refresh_at_unix = Some(now());
                        meta.last_refresh_error = Some("Subscription refresh failed".into());
                        Ok(())
                    })
                    .map_err(|_| {
                        "Subscription refresh failed, and its failure notice could not be saved"
                            .to_string()
                    })?;
                return Err(error);
            }
        };
        let refreshed = self.subscription_profile(id)?;
        let pool_report = match self.rebuild_node_pool(id).await {
            Ok(report) => report,
            Err(_) => {
                let recorded = self.store().update_profile(id, |current| {
                    if current.subscription != refreshed.subscription {
                        return Err(invalid("Subscription changed after refresh"));
                    }
                    let meta = current
                        .subscription
                        .as_mut()
                        .ok_or_else(|| invalid("Profile is no longer a subscription"))?;
                    meta.last_refresh_error = Some(
                        "Subscription refreshed, but the backup pool could not be rebuilt".into(),
                    );
                    Ok(())
                });
                return Err(if recorded.is_ok() {
                    "Subscription refreshed, but backup-pool rebuild failed; the previously stored pool was not replaced"
                } else {
                    "Subscription refreshed, but backup-pool rebuild failed; its failure notice could not be saved"
                }.into());
            }
        };
        Ok(SubscriptionRefreshResult {
            endpoint_count: outcome.endpoint_count,
            active_index: outcome.active_index,
            skipped_count: outcome.skipped_count,
            fallback_used: outcome.fallback_used,
            cleanup_failed: outcome.cleanup_failed,
            pool_report,
        })
    }

    pub fn set_refresh_interval(
        &self,
        id: &str,
        minutes: Option<u32>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        validate_interval(minutes)?;
        self.store()
            .update_profile(id, |profile| {
                if !matches!(profile.backend, TunnelBackend::Xray | TunnelBackend::Mihomo) {
                    return Err(invalid("Profile is not a subscription"));
                }
                let meta = profile
                    .subscription
                    .as_mut()
                    .ok_or_else(|| invalid("Profile is not a subscription"))?;
                meta.refresh_interval_minutes = minutes;
                Ok(())
            })
            .map_err(failed)
    }

    pub fn rename(&self, id: &str, name: &str) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 128 || name.contains(['\r', '\n']) {
            return Err("The name must be 1-128 characters on one line".into());
        }
        self.store()
            .update_profile(id, |profile| {
                profile.name = name.into();
                Ok(())
            })
            .map_err(failed)
    }

    fn update_xray(
        &self,
        id: &str,
        update: impl FnOnce(&mut Profile),
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.store()
            .update_profile(id, |profile| {
                if profile.backend != TunnelBackend::Xray {
                    return Err(invalid("This setting requires an Xray profile"));
                }
                update(profile);
                validate(profile)
            })
            .map_err(failed)
    }

    pub fn set_routing(
        &self,
        id: &str,
        policies: Vec<DomainPolicy>,
        private_lan_direct: bool,
    ) -> Result<ProfileDocument, String> {
        self.update_xray(id, |profile| {
            profile.domain_policies = policies;
            profile.private_lan_direct = private_lan_direct;
        })
    }

    pub fn set_quic(&self, id: &str, enabled: bool) -> Result<ProfileDocument, String> {
        self.update_xray(id, |profile| profile.xray_quic_reject = enabled)
    }

    pub fn set_proxy_exits(
        &self,
        id: &str,
        exits: Vec<NamedProxyExit>,
    ) -> Result<ProfileDocument, String> {
        self.update_xray(id, |profile| profile.xray_proxy_exits = exits)
    }

    pub fn upsert_proxy_exit(
        &self,
        id: &str,
        exit: NamedProxyExit,
    ) -> Result<ProfileDocument, String> {
        self.update_xray(id, |profile| {
            match profile
                .xray_proxy_exits
                .iter_mut()
                .find(|saved| saved.name == exit.name)
            {
                Some(saved) => *saved = exit,
                None => profile.xray_proxy_exits.push(exit),
            }
        })
    }

    pub fn remove_proxy_exit(&self, id: &str, name: &str) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.store()
            .update_profile(id, |profile| {
                if profile.backend != TunnelBackend::Xray {
                    return Err(invalid("Named exits require an Xray profile"));
                }
                let before = profile.xray_proxy_exits.len();
                profile.xray_proxy_exits.retain(|exit| exit.name != name);
                if profile.xray_proxy_exits.len() == before {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "The named exit was not found",
                    ));
                }
                validate(profile)
            })
            .map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    "The named exit was not found".into()
                } else {
                    failed(error)
                }
            })
    }

    pub fn set_role(&self, id: &str, role: TunnelRole) -> Result<ProfileDocument, String> {
        if self.profile(id)?.backend == TunnelBackend::None {
            return Err("Static routes do not create a tunnel".into());
        }
        self.patch(id, &json!({"tunnelRole": role}))
    }

    pub fn set_networks(
        &self,
        id: &str,
        networks: &str,
        dns_domains: &str,
    ) -> Result<ProfileDocument, String> {
        if self.profile(id)?.backend == TunnelBackend::None {
            return Err("Static routes do not create a tunnel".into());
        }
        let networks =
            parse_networks(networks).map_err(|_| "Invalid connection networks".to_string())?;
        let domains =
            parse_dns_domains(dns_domains).map_err(|_| "Invalid split-DNS domains".to_string())?;
        self.patch(
            id,
            &json!({"tunnelNetworks": networks, "tunnelDnsDomains": domains}),
        )
    }

    pub fn import_configs(
        &self,
        paths: &[String],
        backend: Option<TunnelBackend>,
    ) -> Result<BatchImportResult, String> {
        if backend == Some(TunnelBackend::Mihomo) {
            return self.import_mihomo_configs(paths);
        }
        if backend.is_none()
            && paths.iter().any(|path| {
                std::path::Path::new(path)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml")
                    })
            })
        {
            let mut errors = Vec::new();
            for (index, path) in paths.iter().enumerate() {
                let native = std::path::Path::new(path)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml")
                    });
                let result = if native {
                    self.import_mihomo_configs(std::slice::from_ref(path))
                } else {
                    self.import_configs(std::slice::from_ref(path), None)
                };
                if result
                    .as_ref()
                    .map_or(true, |result| !result.errors.is_empty())
                {
                    errors.push(BatchImportError {
                        path: format!("Input {}", index + 1),
                        error: "The configuration could not be imported".into(),
                    });
                }
            }
            return Ok(BatchImportResult {
                profiles: self.profiles()?,
                errors,
            });
        }
        let _lock = self.mutation()?;
        // Arbitrary imported JSON is not a daemon-validated generated TUN config.
        profile_import::import_configs_into(
            &self.vault(),
            &self.store(),
            paths,
            backend,
            XrayMode::Socks,
        )
        .map(|mut result| {
            for (index, error) in result.errors.iter_mut().enumerate() {
                error.path = format!("Input {}", index + 1);
                error.error = "The configuration could not be imported".into();
            }
            result
        })
        .map_err(failed)
    }

    pub fn import_link(&self, id: &str, name: &str, link: &str) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        profile_import::import_share_link(
            &self.vault(),
            &self.store(),
            id,
            name,
            link,
            net_manager_core::models::XrayMode::platform_default(),
            available,
        )
        .map_err(failed)
    }

    pub fn subscription_profile(&self, id: &str) -> Result<Profile, String> {
        let profile = self.profile(id)?;
        if profile.backend != TunnelBackend::Xray || profile.subscription.is_none() {
            return Err("The profile is not an Xray subscription".into());
        }
        Ok(profile)
    }

    pub fn subscription_endpoints(
        &self,
        id: &str,
    ) -> Result<Vec<SubscriptionEndpointInfo>, String> {
        self.subscription_profile(id)?;
        subscription::list_endpoints(&self.vault(), &self.store(), id).map_err(failed)
    }

    fn endpoints(
        &self,
        profile: &Profile,
    ) -> Result<Vec<net_manager_core::config_vault::SubscriptionEndpoint>, String> {
        if profile.subscription.is_none() {
            return Ok(Vec::new());
        }
        self.vault()
            .read_subscription_endpoints(&profile.id)
            .map_err(failed)
    }

    pub fn xray_executable(&self) -> Result<PathBuf, String> {
        crate::linux_system::backend_executable(&self.root, TunnelBackend::Xray)
    }

    pub async fn measure_endpoint_delay(
        &self,
        id: &str,
        index: usize,
    ) -> Result<SubscriptionDelayResult, String> {
        let expected = self.subscription_profile(id)?;
        let endpoints = self.endpoints(&expected)?;
        let endpoint = endpoints
            .get(index)
            .ok_or("The endpoint index is out of range")?;
        let result = subscription::measure_endpoint_delay(
            &self.xray_executable()?,
            &endpoint.url,
            subscription::DELAY_PROBE_TIMEOUT,
        )
        .await;
        if self.profile(id)? != expected || self.endpoints(&expected)? != endpoints {
            return Err("The profile or endpoint selection changed; repeat the probe".into());
        }
        Ok(match result {
            Ok(delay_ms) => SubscriptionDelayResult {
                delay_ms: Some(delay_ms),
                error: None,
            },
            Err(_) => SubscriptionDelayResult {
                delay_ms: None,
                error: Some("Endpoint delay probe failed".into()),
            },
        })
    }

    pub async fn measure_endpoint_delays(
        &self,
        id: &str,
        indices: &[usize],
    ) -> Result<Vec<(usize, SubscriptionDelayResult)>, String> {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
        let mut tasks = tokio::task::JoinSet::new();
        for (order, &index) in indices.iter().enumerate() {
            let gate = gate.clone();
            let service = self.clone();
            let id = id.to_string();
            tasks.spawn(async move {
                let _permit = gate
                    .acquire_owned()
                    .await
                    .map_err(|_| "Endpoint probes were cancelled".to_string())?;
                let result = service.measure_endpoint_delay(&id, index).await?;
                Ok::<_, String>((order, index, result))
            });
        }
        let mut results = Vec::with_capacity(indices.len());
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(result)) => results.push(result),
                _ => {
                    tasks.abort_all();
                    return Err("Endpoint probes could not be completed".into());
                }
            }
        }
        results.sort_by_key(|(order, _, _)| *order);
        Ok(results
            .into_iter()
            .map(|(_, index, result)| (index, result))
            .collect())
    }

    pub fn switch_endpoint(&self, id: &str, key: &str) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.ensure_editable(&self.subscription_profile(id)?)?;
        subscription::switch_endpoint_key(&self.vault(), &self.store(), id, key, available)
            .map_err(failed)
    }

    pub fn switch_endpoint_live(
        &self,
        id: &str,
        key: &str,
        remembered: &dyn crate::linux::CredentialSource,
    ) -> Result<SwitchOutcome, String> {
        let _lock = self.mutation()?;
        let profiles = self.profiles()?;
        let profile = profiles
            .iter()
            .find(|profile| {
                profile.id == id
                    && profile.backend == TunnelBackend::Xray
                    && profile.subscription.is_some()
            })
            .cloned()
            .ok_or("The profile is not an Xray subscription")?;
        crate::linux_services::ensure_not_enrolled(&self.engine, &profile)?;
        let vault = self.vault();
        let endpoints = self.endpoints(&profile)?;
        let was_running = self.engine.status(&profile)?.state != TunnelState::Stopped;
        let original_prepared = if was_running {
            Some(
                self.engine
                    .prepare_connection(&vault, &profile, None, remembered, false)?,
            )
        } else {
            None
        };
        let candidate = subscription::prepare_endpoint_switch(&vault, &profiles, id, key, |port| {
            was_running || profile.xray_mode == XrayMode::Tun || available(port)
        })
        .map_err(failed)?;
        let candidate_path = candidate.config_path.clone();
        let discard_candidate = || vault.remove_revision_for_config(&candidate_path).is_ok();
        let before_start_failure = |error: String| {
            if discard_candidate() {
                error
            } else {
                format!("{error}; temporary managed configuration could not be removed")
            }
        };
        let preparation = validate(&candidate).map_err(failed).and_then(|()| {
            if was_running {
                self.engine
                    .prepare_connection(&vault, &candidate, None, remembered, false)
                    .map(Some)
            } else {
                Ok(None)
            }
        });
        let candidate_prepared = match preparation {
            Ok(prepared) => prepared,
            Err(error) => return Err(before_start_failure(error)),
        };
        if was_running {
            let teardown = self.engine.disconnect(&profile).and_then(|status| {
                if status.state == TunnelState::Stopped {
                    Ok(())
                } else {
                    Err("The previous connection did not stop; selection was not changed".into())
                }
            });
            if let Err(error) = teardown {
                // The candidate never started. Its profile ID is also the old
                // connection's ID, so candidate teardown could kill a healthy old session.
                let detail = match self.engine.status(&profile).map(|status| status.state) {
                    Ok(TunnelState::Running) => {
                        "the previous connection is still running; selection was not changed"
                    }
                    Ok(TunnelState::Stopped | TunnelState::Failed) => {
                        let previous = original_prepared.as_ref().expect("rollback was prepared");
                        if self.engine.execute_prepared(previous)
                            .is_ok_and(|status| status.state == TunnelState::Running)
                        {
                            "the previous server and connection state were restored"
                        } else {
                            "restoring the previous connection was not confirmed; its original managed revision was retained"
                        }
                    }
                    Err(_) => {
                        "restoring the previous connection was not confirmed; its original managed revision was retained"
                    }
                };
                return Err(before_start_failure(format!("{error}; {detail}")));
            }
        }
        let rollback_failure = || {
            let next = candidate_prepared
                .as_ref()
                .expect("a running switch was prepared");
            let previous = original_prepared.as_ref().expect("rollback was prepared");
            let stopped = self
                .engine
                .disconnect(next.profile())
                .is_ok_and(|status| status.state == TunnelState::Stopped);
            if stopped
                && self
                    .engine
                    .execute_prepared(previous)
                    .is_ok_and(|status| status.state == TunnelState::Running)
            {
                if discard_candidate() {
                    "The server switch failed; the previous server and connection state were restored".into()
                } else {
                    "The server switch failed; the previous server and connection state were restored, but temporary managed configuration could not be removed".into()
                }
            } else {
                // Either process may still need its prepared revision.
                "The server switch failed; restoring the previous server or connection was not confirmed; managed revisions were retained".into()
            }
        };
        if let Some(prepared) = &candidate_prepared {
            if !self
                .engine
                .execute_prepared(prepared)
                .is_ok_and(|status| status.state == TunnelState::Running)
            {
                return Err(rollback_failure());
            }
        }
        // Until this CAS succeeds, the original profile and its exact managed
        // revision remain canonical and available for rollback.
        let saved = self.store().update_profile(id, |current| {
            if current != &profile || self.endpoints(current).map_err(invalid_owned)? != endpoints {
                return Err(invalid(
                    "The profile or endpoint selection changed during switching",
                ));
            }
            *current = candidate;
            Ok(())
        });
        let document = match saved {
            Ok(document) => document,
            Err(_) if was_running => return Err(rollback_failure()),
            Err(_) => {
                return Err(before_start_failure(
                    "The profile changed; selection was not saved".into(),
                ))
            }
        };
        if vault.is_managed_profile_path(id, &profile.config_path) {
            vault
                .remove_revision_for_config(&profile.config_path)
                .map_err(|_| {
                    "The endpoint switched, but its previous managed revision could not be removed"
                        .to_string()
                })?;
        }
        let profile = document
            .profiles
            .into_iter()
            .find(|profile| profile.id == id)
            .expect("the transaction retained the switched profile");
        Ok(SwitchOutcome {
            profile,
            was_running,
        })
    }

    pub fn set_backups(&self, id: &str, keys: &[String]) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.subscription_profile(id)?;
        subscription::set_backup_endpoints(&self.vault(), &self.store(), id, keys).map_err(failed)
    }

    pub fn set_auto_return(&self, id: &str, enabled: bool) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.subscription_profile(id)?;
        subscription::set_auto_return_primary(&self.store(), id, enabled).map_err(failed)
    }

    pub fn sync_background(
        &self,
        profile: &Profile,
        checks: &[ServiceCheck],
    ) -> Result<(), String> {
        if profile.xray_mode != XrayMode::Tun
            || (!profile
                .xray_service_checks
                .iter()
                .any(|check| check.background)
                && !checks.iter().any(|check| check.background))
        {
            return Ok(());
        }
        let checks = checks
            .iter()
            .filter(|check| {
                check.background
                    && net_manager_core::service_checks::service_check_is_bound(
                        profile,
                        &check.endpoint_key,
                    )
            })
            .cloned()
            .collect();
        if self
            .engine
            .set_xray_service_checks(&profile.id, checks)
            .is_ok()
            || self
                .engine
                .status(profile)
                .is_ok_and(|status| status.state == TunnelState::Stopped)
        {
            Ok(())
        } else {
            Err(
                "The daemon did not confirm the diagnostic change; configuration was not saved"
                    .into(),
            )
        }
    }

    pub fn set_pinned_routes(
        &self,
        id: &str,
        routes: Vec<PinnedRoute>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let expected = self.subscription_profile(id)?;
        let mut candidate = expected.clone();
        candidate.pinned_policies = routes.clone();
        profiles::validate_profile(&candidate).map_err(failed)?;
        self.sync_background(&candidate, &candidate.xray_service_checks)?;
        let saved = subscription::set_pinned_routes(&self.vault(), &self.store(), id, routes);
        if saved.is_err() {
            self.sync_background(&candidate, &[])?;
        }
        saved.map_err(failed)
    }

    pub fn set_service_checks(
        &self,
        id: &str,
        checks: Vec<ServiceCheck>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let expected = self.subscription_profile(id)?;
        let endpoints = self.endpoints(&expected)?;
        net_manager_core::service_checks::validate_service_checks(&checks).map_err(failed)?;
        for check in &checks {
            let retained = expected.xray_service_checks.iter().any(|previous| {
                previous.id == check.id && previous.endpoint_key == check.endpoint_key
            });
            if !retained
                && !net_manager_core::service_checks::service_check_is_bound(
                    &expected,
                    &check.endpoint_key,
                )
            {
                return Err("The selected endpoint is not explicitly pinned".into());
            }
        }
        let mut candidate = expected.clone();
        candidate.xray_service_checks = checks.clone();
        profiles::validate_profile(&candidate).map_err(failed)?;
        self.sync_background(&expected, &checks)?;
        let result = self.store().update_profile(id, |current| {
            if current != &expected || self.endpoints(current).map_err(invalid_owned)? != endpoints
            {
                return Err(invalid("The profile or endpoint selection changed"));
            }
            current.xray_service_checks = checks;
            Ok(())
        });
        if result.is_err() {
            let prior = if expected
                .xray_service_checks
                .iter()
                .any(|check| check.background)
            {
                &expected
            } else {
                &candidate
            };
            return Err(if self.sync_background(prior, &[]).is_ok() {
                "Checks were not saved; background diagnostics are stopped."
            } else {
                "Checks were not saved; the daemon did not confirm background cancellation."
            }
            .into());
        }
        result.map_err(failed)
    }

    pub async fn run_service_checks(
        &self,
        id: &str,
        ids: Option<&[String]>,
    ) -> Result<Vec<ServiceCheckResult>, String> {
        let (expected, endpoints) = {
            let _lock = self.mutation()?;
            let profile = self.subscription_profile(id)?;
            let endpoints = self.endpoints(&profile)?;
            (profile, endpoints)
        };
        let executable = std::sync::OnceLock::<Result<PathBuf, String>>::new();
        let results = net_manager_core::service_checks::check_profile_services(
            &self.vault(),
            &expected,
            ids,
            || {
                let path = executable
                    .get_or_init(|| self.xray_executable())
                    .as_ref()
                    .map_err(Clone::clone)?;
                Ok(tokio::process::Command::new(path))
            },
        )
        .await
        .map_err(failed)?;
        if self.profile(id)? != expected || self.endpoints(&expected)? != endpoints {
            return Err("The profile or endpoint selection changed; run the checks again".into());
        }
        Ok(results)
    }

    pub fn set_node_pool(
        &self,
        id: &str,
        pool: Option<NodePoolSettings>,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        self.subscription_profile(id)?;
        net_manager_core::node_pool::set_node_pool(&self.store(), id, pool).map_err(failed)
    }

    pub async fn rebuild_node_pool(
        &self,
        id: &str,
    ) -> Result<Option<net_manager_core::node_pool::NodePoolReport>, String> {
        drop(self.mutation()?);
        let profile = self.subscription_profile(id)?;
        let Some(pool) = profile
            .subscription
            .as_ref()
            .and_then(|meta| meta.node_pool.as_ref())
        else {
            return Ok(None);
        };
        let executable = pool
            .verify_exit_country
            .then(|| self.xray_executable())
            .transpose()?;
        // Core rechecks the snapshot before its transactional pool update.
        net_manager_core::node_pool::rebuild_node_pool(
            &self.vault(),
            &self.store(),
            id,
            &net_manager_core::node_pool::EXIT_COUNTRY_PROBES,
            net_manager_core::node_pool::EXIT_COUNTRY_PROBE_TIMEOUT,
            move |_| {
                executable
                    .as_ref()
                    .ok_or_else(|| invalid("Xray executable unavailable"))
                    .map(tokio::process::Command::new)
            },
        )
        .await
        .map(Some)
        .map_err(failed)
    }

    pub fn plan_migration(
        &self,
        id: &str,
        path: &std::path::Path,
    ) -> Result<
        (
            net_manager_core::xray_migrate::XrayPolicyMigration,
            Vec<net_manager_core::config_vault::SubscriptionEndpoint>,
        ),
        String,
    > {
        use std::io::Read;
        let profile = self.profile(id)?;
        if profile.backend != TunnelBackend::Xray {
            return Err("Policy migration requires an Xray profile".into());
        }
        let mut body = Vec::new();
        File::open(path)
            .and_then(|file| file.take(512 * 1024 + 1).read_to_end(&mut body))
            .map_err(failed)?;
        if body.len() > 512 * 1024 {
            return Err("The selected Xray policy exceeds 512 KiB".into());
        }
        let source: Value = serde_json::from_slice(&body).map_err(failed)?;
        let endpoints = self.endpoints(&profile)?;
        let primary = profile.subscription.as_ref().and_then(|meta| {
            meta.active_key.clone().or_else(|| {
                endpoints
                    .get(meta.active_index)
                    .map(|endpoint| endpoint.id.clone())
            })
        });
        let migration = net_manager_core::xray_migrate::plan_xray_policy_migration(
            &source,
            primary.as_deref(),
            net_manager_core::xray_migrate::subscription_outbound_resolver(
                &endpoints,
                primary.as_deref(),
            ),
        )
        .map_err(failed)?;
        Ok((migration, endpoints))
    }

    pub fn preview_migration(
        &self,
        id: &str,
        path: &std::path::Path,
    ) -> Result<XrayPolicyPreview, String> {
        self.plan_migration(id, path)
            .map(|(migration, _)| preview_of(&migration))
    }

    pub fn apply_migration(
        &self,
        id: &str,
        path: &std::path::Path,
    ) -> Result<ProfileDocument, String> {
        let _lock = self.mutation()?;
        let expected = self.profile(id)?;
        self.ensure_editable(&expected)?;
        let (migration, endpoints) = self.plan_migration(id, path)?;
        if !migration.refused.is_empty() {
            return Err(format!(
                "Policy migration refused {} source construct(s); nothing was changed",
                migration.refused.len()
            ));
        }
        self.store()
            .update_profile(id, |current| {
                if current != &expected
                    || self.endpoints(current).map_err(invalid_owned)? != endpoints
                {
                    return Err(invalid("The profile or endpoint selection changed"));
                }
                net_manager_core::xray_migrate::apply_xray_policy_migration(current, migration)
                    .map_err(|_| invalid("Policy could not be applied"))?;
                let live: std::collections::HashSet<_> = endpoints
                    .iter()
                    .map(|endpoint| endpoint.id.clone())
                    .collect();
                for pin in &mut current.pinned_policies {
                    pin.missing = !live.contains(&pin.endpoint_key);
                }
                validate(current)
            })
            .map_err(failed)
    }

    pub async fn verify_subscription_exits(
        &self,
        id: &str,
    ) -> Result<Vec<SubscriptionExitCheck>, String> {
        let profile = self.subscription_profile(id)?;
        let (nodes, _) = subscription::failover_plan(&self.vault(), &profile).map_err(failed)?;
        if nodes.is_empty() {
            return Err("The profile has no failover candidates".into());
        }
        let expected_nodes = nodes.clone();
        let executable = self.xray_executable()?;
        let infos = self.subscription_endpoints(id)?;
        let roles: std::collections::HashMap<_, _> = infos
            .iter()
            .map(|info| {
                let role = if info.active {
                    "primary"
                } else if info.is_backup {
                    "backup"
                } else if info.in_pool {
                    "pool"
                } else {
                    "node"
                };
                (info.key.clone(), role)
            })
            .collect();
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(
            net_manager_core::node_pool::POOL_PROBE_PARALLELISM,
        ));
        let mut tasks = tokio::task::JoinSet::new();
        for (index, endpoint) in nodes.into_iter().enumerate() {
            let gate = gate.clone();
            let executable = executable.clone();
            tasks.spawn(async move {
                let _permit = gate
                    .acquire_owned()
                    .await
                    .map_err(|_| "Exit verification was cancelled")?;
                let key = endpoint.id.clone();
                let mut command = tokio::process::Command::new(executable);
                command.args(["run", "-config", "stdin:"]);
                let outcome = net_manager_core::node_pool::measure_exit_country(
                    &endpoint.url,
                    command,
                    &net_manager_core::node_pool::EXIT_COUNTRY_PROBES,
                    net_manager_core::node_pool::EXIT_COUNTRY_PROBE_TIMEOUT,
                )
                .await;
                Ok::<_, &str>((index, key, endpoint.name, outcome))
            });
        }
        let mut results = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(result)) => results.push(result),
                _ => {
                    tasks.abort_all();
                    return Err("An exit-verification worker failed".into());
                }
            }
        }
        if self.profile(id)? != profile
            || subscription::failover_plan(&self.vault(), &profile)
                .map_err(failed)?
                .0
                != expected_nodes
        {
            return Err("The profile or endpoint selection changed; verify again".into());
        }
        results.sort_by_key(|(index, _, _, _)| *index);
        Ok(results
            .into_iter()
            .map(|(_, key, name, outcome)| {
                let role = roles.get(&key).copied().unwrap_or("node").to_string();
                let named_country = flag_country(&name);
                let (exit_country, exit_ip, error) = match outcome {
                    Ok(exit) => (Some(exit.country), Some(exit.ip), None),
                    Err(_) => (None, None, Some("Exit-country verification failed".into())),
                };
                let mismatch = named_country.is_some()
                    && exit_country.is_some()
                    && named_country != exit_country;
                SubscriptionExitCheck {
                    key,
                    name: name.trim().into(),
                    role,
                    named_country,
                    exit_country,
                    exit_ip,
                    mismatch,
                    error,
                }
            })
            .collect())
    }
}

pub fn new_id() -> Result<String, String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(failed)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id = String::with_capacity(40);
    id.push_str("profile-");
    for byte in bytes {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(id)
}

pub fn validate_interval(minutes: Option<u32>) -> Result<(), String> {
    if minutes.is_some_and(|minutes| !matches!(minutes, 15 | 60 | 360)) {
        Err("Refresh interval must be off, 15, 60 or 360 minutes".into())
    } else {
        Ok(())
    }
}

fn validate(profile: &Profile) -> io::Result<()> {
    if profile.backend != TunnelBackend::Mihomo && profile.mihomo.is_some() {
        return Err(invalid("Mihomo options require a Mihomo profile"));
    }
    if profile.backend == TunnelBackend::None
        && (profile.tunnel_role != TunnelRole::Primary
            || !profile.tunnel_networks.is_empty()
            || !profile.tunnel_dns_domains.is_empty())
    {
        return Err(invalid("Static routes do not create a tunnel"));
    }
    if profile.tunnel_role == TunnelRole::Secondary {
        validate_secondary(
            profile.tunnel_role,
            &profile.secondary_routes(),
            &profile.tunnel_dns_domains,
        )
        .map_err(|_| invalid("Invalid connection networks or DNS scope"))?;
    }
    if !profile
        .tunnel_dns_domains
        .iter()
        .all(|domain| valid_dns_suffix(domain))
    {
        return Err(invalid("Invalid split-DNS domain"));
    }
    if profile.backend == TunnelBackend::Xray {
        if profile.xray_mode == XrayMode::Tun
            && (profile.xray_socks_port.is_none() || profile.xray_http_port.is_none())
        {
            return Err(invalid("Xray TUN requires a generated share-link profile"));
        }
        for url in [
            profile.xray_geoip_url.as_deref(),
            profile.xray_geosite_url.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            crate::linux_geo_assets::validate_geo_asset_url(url)
                .map_err(|_| invalid("Invalid geo asset URL"))?;
        }
    }
    profiles::validate_profile(profile)
}

fn merge_profile(profile: &Profile, patch: &Value) -> io::Result<Profile> {
    let object = patch
        .as_object()
        .ok_or_else(|| invalid("A profile patch must be a JSON object"))?;
    let mut value = serde_json::to_value(profile).map_err(|_| invalid("Invalid profile"))?;
    let target = value.as_object_mut().expect("profile is an object");
    // Optional fields omitted by serde are still editable.
    const OPTIONAL: &[&str] = &[
        "mihomo",
        "xrayServiceChecks",
        "xrayProxyExits",
        "xrayGeoipUrl",
        "xrayGeositeUrl",
        "xrayDomainStrategy",
        "xrayDomainMatcher",
        "xrayDns",
        "xraySockopts",
        "xrayTrafficRules",
        "xrayInterfaceRoutes",
        "xrayConnectionIdleSecs",
        "xrayTunMtu",
        "xrayTunDnsServers",
        "xrayDirectDomainStrategy",
        "tunnelRole",
        "tunnelDnsDomains",
        "tunnelNetworks",
    ];
    if let Some(value) = object.get("mihomo") {
        editor_nested_fields(value, "/profile/mihomo").map_err(invalid_owned)?;
    }
    for (key, value) in object {
        if matches!(
            key.as_str(),
            "id" | "backend"
                | "configPath"
                | "subscription"
                | "pinnedPolicies"
                | "xrayServiceChecks"
                | "xrayProxyExits"
                | "xraySocksPort"
                | "xrayHttpPort"
        ) {
            return Err(invalid(
                "This field is owned by a source or dedicated endpoint command",
            ));
        }
        if !target.contains_key(key) && !OPTIONAL.contains(&key.as_str()) {
            return Err(invalid("Unknown profile setting"));
        }
        let destination = target.entry(key.clone()).or_insert(Value::Null);
        merge_value(destination, value);
        if key == "mihomo" {
            if let (Some(options), Some(selections)) =
                (destination.as_object_mut(), value.get("groupSelections"))
            {
                options.insert("groupSelections".into(), selections.clone());
            }
        }
    }
    serde_json::from_value(value).map_err(|_| invalid("Invalid profile settings"))
}

fn merge_value(target: &mut Value, patch: &Value) {
    if let (Some(target), Some(patch)) = (target.as_object_mut(), patch.as_object()) {
        for (key, value) in patch {
            merge_value(target.entry(key.clone()).or_insert(Value::Null), value);
        }
    } else {
        *target = patch.clone();
    }
}

fn preserve_form_settings(profile: &mut Profile, stored: &Profile, same_source: bool) {
    if profile.backend == TunnelBackend::Mihomo && stored.backend == TunnelBackend::Mihomo {
        profile.subscription = stored.subscription.clone();
        if profile.mihomo.is_none() {
            profile.mihomo = stored.mihomo.clone();
        }
    }
    if profile.backend != TunnelBackend::Xray || stored.backend != TunnelBackend::Xray {
        if profile.backend != TunnelBackend::Mihomo || stored.backend != TunnelBackend::Mihomo {
            profile.subscription = None;
        }
        profile.pinned_policies.clear();
        profile.xray_service_checks.clear();
        profile.xray_proxy_exits.clear();
        if profile.backend != TunnelBackend::Xray {
            profile.xray_sockopts = None;
            profile.xray_traffic_rules.clear();
            profile.xray_interface_routes.clear();
            profile.xray_connection_idle_secs = None;
            profile.xray_tun_mtu = None;
            profile.xray_tun_dns_servers.clear();
            profile.xray_direct_domain_strategy = None;
            profile.xray_quic_reject = false;
        }
        return;
    }
    profile.subscription = stored.subscription.clone();
    profile.pinned_policies = stored.pinned_policies.clone();
    profile.xray_service_checks = stored.xray_service_checks.clone();
    profile.xray_proxy_exits = stored.xray_proxy_exits.clone();
    profile.xray_sockopts = stored.xray_sockopts.clone();
    profile.xray_traffic_rules = stored.xray_traffic_rules.clone();
    profile.xray_interface_routes = stored.xray_interface_routes.clone();
    profile.xray_connection_idle_secs = stored.xray_connection_idle_secs;
    profile.xray_tun_mtu = stored.xray_tun_mtu;
    profile.xray_tun_dns_servers = stored.xray_tun_dns_servers.clone();
    profile.xray_direct_domain_strategy = stored.xray_direct_domain_strategy.clone();
    profile.endpoint_bypasses = stored.endpoint_bypasses.clone();
    if same_source && profile.config_path == stored.config_path {
        profile.xray_socks_port = stored.xray_socks_port;
        profile.xray_http_port = stored.xray_http_port;
    }
}

pub fn render_wireguard_config(fields: &WireGuardFields) -> Result<String, String> {
    for value in [
        &fields.private_key,
        &fields.address,
        &fields.peer_public_key,
        &fields.peer_endpoint,
        &fields.allowed_ips,
    ] {
        if value.trim().is_empty() || value.contains(['\r', '\n']) {
            return Err("Required WireGuard fields must be nonempty single-line values".into());
        }
    }
    if fields.dns.contains(['\r', '\n']) || fields.preshared_key.contains(['\r', '\n']) {
        return Err("WireGuard fields must be single-line values".into());
    }
    let mut result = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}\n",
        fields.private_key.trim(),
        fields.address.trim()
    );
    if !fields.dns.trim().is_empty() {
        result.push_str(&format!("DNS = {}\n", fields.dns.trim()));
    }
    result.push_str(&format!(
        "\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\n",
        fields.peer_public_key.trim(),
        fields.peer_endpoint.trim(),
        fields.allowed_ips.trim()
    ));
    if !fields.preshared_key.trim().is_empty() {
        result.push_str(&format!("PresharedKey = {}\n", fields.preshared_key.trim()));
    }
    if let Some(keepalive) = fields.persistent_keepalive {
        result.push_str(&format!("PersistentKeepalive = {keepalive}\n"));
    }
    Ok(result)
}

/// Full saved settings, with credentials, provider-supplied prose, sensitive URLs
/// and managed source paths removed. This is presentation only, never persisted.
pub fn metadata(profile: &Profile) -> Value {
    let mut value = serde_json::to_value(profile).expect("profile metadata is JSON-compatible");
    if let Some(object) = value.as_object_mut() {
        object.remove("configPath");
        for key in ["xrayGeoipUrl", "xrayGeositeUrl"] {
            if object.contains_key(key) {
                object.insert(key.into(), json!("<redacted>"));
            }
        }
        if let Some(meta) = object
            .get_mut("subscription")
            .and_then(Value::as_object_mut)
        {
            for key in [
                "url",
                "hwid",
                "probeUrl",
                "supportUrl",
                "webPageUrl",
                "announce",
                "providerTitle",
                "skippedProtocols",
            ] {
                meta.remove(key);
            }
            if let Some(error) = meta
                .get_mut("lastRefreshError")
                .filter(|value| value.is_string())
            {
                if !matches!(
                    error.as_str(),
                    Some(
                        "Selected Mihomo group no longer exists"
                            | "Selected Mihomo group member no longer exists"
                            | "Selected Mihomo entry group does not exist"
                    )
                ) {
                    *error = json!("Subscription refresh needs attention");
                }
            }
        }
        if let Some(checks) = object
            .get_mut("xrayServiceChecks")
            .and_then(Value::as_array_mut)
        {
            for check in checks {
                if let Some(check) = check.as_object_mut() {
                    check.remove("url");
                }
            }
        }
    }
    value
}

#[derive(Debug)]
pub struct SwitchOutcome {
    pub profile: Profile,
    pub was_running: bool,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRefreshResult {
    pub endpoint_count: usize,
    pub active_index: usize,
    pub skipped_count: usize,
    pub fallback_used: bool,
    pub cleanup_failed: bool,
    pub pool_report: Option<net_manager_core::node_pool::NodePoolReport>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionDelayResult {
    pub delay_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionExitCheck {
    pub key: String,
    pub name: String,
    pub role: String,
    pub named_country: Option<String>,
    pub exit_country: Option<String>,
    pub exit_ip: Option<String>,
    pub mismatch: bool,
    pub error: Option<String>,
}

fn flag_country(name: &str) -> Option<String> {
    let mut code = String::new();
    for ch in name.chars() {
        let value = ch as u32;
        if (0x1F1E6..=0x1F1FF).contains(&value) {
            code.push((b'A' + (value - 0x1F1E6) as u8) as char);
        }
    }
    (code.len() == 2).then_some(code)
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XrayPolicyPreview {
    pub direct: usize,
    pub proxy: usize,
    pub block: usize,
    pub pinned_count: usize,
    pub private_lan_direct: bool,
    pub quic_reject: bool,
    pub domain_strategy: Option<XrayDomainStrategy>,
    pub domain_matcher: Option<XrayDomainMatcher>,
    pub endpoint_bypass_count: usize,
    pub has_geoip_override: bool,
    pub has_geosite_override: bool,
    pub has_dns: bool,
    pub has_sockopts: bool,
    pub traffic_rule_count: usize,
    pub interface_route_count: usize,
    pub dns_server_count: usize,
    pub dns_host_count: usize,
    pub dns_rewrite_rule_count: usize,
    pub tun_dns_server_count: usize,
    pub tun_mtu: Option<u32>,
    pub connection_idle_secs: Option<u32>,
    pub direct_domain_strategy: Option<String>,
    pub dns_enable_parallel_query: Option<bool>,
    pub has_dns_outbound: bool,
    pub backup_count: Option<usize>,
    pub skipped: Vec<String>,
    pub refused: Vec<String>,
}

pub fn preview_of(
    migration: &net_manager_core::xray_migrate::XrayPolicyMigration,
) -> XrayPolicyPreview {
    let count = |target| {
        migration
            .domain_policies
            .iter()
            .filter(|policy| policy.target == target)
            .map(|policy| policy.domains.len())
            .sum()
    };
    XrayPolicyPreview {
        direct: count(DomainRouteTarget::Direct),
        proxy: count(DomainRouteTarget::Proxy),
        block: count(DomainRouteTarget::Block),
        pinned_count: migration.pinned_routes.len(),
        private_lan_direct: migration.private_lan_direct,
        quic_reject: migration.quic_reject,
        domain_strategy: migration.domain_strategy,
        domain_matcher: migration.domain_matcher,
        endpoint_bypass_count: migration.endpoint_bypasses.len(),
        has_geoip_override: migration.geoip_url.is_some(),
        has_geosite_override: migration.geosite_url.is_some(),
        has_dns: !migration.dns.is_empty(),
        has_sockopts: migration.sockopts.is_some(),
        traffic_rule_count: migration.traffic_rules.len(),
        interface_route_count: migration.interface_routes.len(),
        dns_server_count: migration.dns.servers.len(),
        dns_host_count: migration.dns.hosts.len(),
        dns_rewrite_rule_count: migration
            .dns
            .outbound
            .as_ref()
            .map_or(0, |outbound| outbound.rules.len()),
        tun_dns_server_count: migration.tun_dns_servers.len(),
        tun_mtu: migration.tun_mtu,
        connection_idle_secs: migration.connection_idle_secs,
        direct_domain_strategy: migration.direct_domain_strategy.clone(),
        dns_enable_parallel_query: migration.dns.enable_parallel_query,
        has_dns_outbound: migration.dns.outbound.is_some(),
        backup_count: migration.backup_keys.as_ref().map(Vec::len),
        skipped: migration
            .skipped
            .iter()
            .map(|item| item.reason.clone())
            .collect(),
        refused: migration
            .refused
            .iter()
            .map(|item| item.reason.clone())
            .collect(),
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorDocumentResult {
    pub document: Value,
    pub revision: String,
    pub endpoints: Vec<SubscriptionEndpointInfo>,
    pub running: bool,
    pub running_revision: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorIssue {
    pub path: String,
    pub message: String,
    pub severity: &'static str,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorPreviewResult {
    pub valid: bool,
    pub issues: Vec<EditorIssue>,
    pub daemon_validated: bool,
    pub changed_paths: Vec<String>,
    pub requires_reconnect: bool,
}

fn editor_sensitive(path: &str, value: &Value) -> bool {
    if value.is_null() {
        return false;
    }
    let key = path.rsplit('/').next().unwrap_or("");
    path == "/profile/configPath"
        || matches!(path, "/profile/xrayGeoipUrl" | "/profile/xrayGeositeUrl")
        || (path.starts_with("/profile/subscription/")
            && matches!(
                key,
                "url"
                    | "hwid"
                    | "probeUrl"
                    | "supportUrl"
                    | "webPageUrl"
                    | "announce"
                    | "providerTitle"
                    | "lastRefreshError"
                    | "skippedProtocols"
            ))
        || (path.starts_with("/profile/xrayServiceChecks/") && key == "url")
        || (path.starts_with("/profile/xrayDns/servers/")
            && key == "address"
            && value
                .as_str()
                .is_some_and(|s| s.contains("://") || s.starts_with("vault:")))
}

fn editor_token(path: &str, _value: &Value) -> String {
    use sha2::{Digest, Sha256};
    format!("vault:{:x}", Sha256::digest(path.as_bytes()))
}

fn editor_protect(
    value: &mut Value,
    path: &str,
    refs: &mut std::collections::HashMap<String, (String, Value)>,
) {
    if editor_sensitive(path, value) {
        let token = editor_token(path, value);
        refs.insert(token.clone(), (path.to_string(), value.clone()));
        *value = Value::String(token);
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                editor_protect(
                    child,
                    &format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                    refs,
                );
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                editor_protect(child, &format!("{path}/{index}"), refs);
            }
        }
        _ => {}
    }
}

fn editor_view(profile: &Profile) -> Result<Value, String> {
    let mut document =
        json!({"version": 1, "profile": serde_json::to_value(profile).map_err(failed)?});
    editor_protect(&mut document, "", &mut std::collections::HashMap::new());
    Ok(document)
}

fn safe_editor_https_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn editor_nested_fields(value: &Value, path: &str) -> Result<(), String> {
    let shape = path
        .split('/')
        .map(|part| {
            if part.parse::<usize>().is_ok() {
                "*"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    if shape == "/profile/xrayDns/hosts" || shape == "/profile/mihomo/groupSelections" {
        return Ok(());
    }
    let allowed: Option<&[&str]> = match shape.as_str() {
        "/profile/mihomo" => Some(&["mode", "entryGroup", "mixedPort", "groupSelections"]),
        "/profile/routes/*" => Some(&["destination", "metric", "via"]),
        "/profile/domainPolicies/*" => Some(&["domains", "target"]),
        "/profile/pinnedPolicies/*" => Some(&["selectors", "endpointKey", "missing"]),
        "/profile/subscription" => Some(&[
            "url",
            "hwid",
            "endpointCount",
            "activeIndex",
            "refreshIntervalMinutes",
            "lastRefreshAtUnix",
            "lastRefreshError",
            "userInfo",
            "providerTitle",
            "announce",
            "supportUrl",
            "webPageUrl",
            "updateIntervalHours",
            "skippedProtocols",
            "activeKey",
            "backupKeys",
            "autoReturnPrimary",
            "probeUrl",
            "nodePool",
            "poolKeys",
        ]),
        "/profile/subscription/userInfo" => Some(&[
            "uploadBytes",
            "downloadBytes",
            "totalBytes",
            "expiresAtUnix",
        ]),
        "/profile/subscription/backupKeys/*" | "/profile/subscription/poolKeys/*" => {
            Some(&["key", "name"])
        }
        "/profile/subscription/nodePool" => Some(&["filters", "verifyExitCountry"]),
        "/profile/subscription/nodePool/filters/*" => Some(&["nameContains", "exitCountry"]),
        "/profile/xrayServiceChecks/*" => Some(&["id", "name", "url", "endpointKey", "background"]),
        "/profile/xrayProxyExits/*" => Some(&["name", "target", "noProxy"]),
        "/profile/xrayProxyExits/*/target" => Some(&["kind", "endpointKey", "endpointKeys"]),
        "/profile/xrayDns" => Some(&[
            "servers",
            "hosts",
            "fakeDns",
            "queryStrategy",
            "enableParallelQuery",
            "outboundKey",
            "outbound",
        ]),
        "/profile/xrayDns/servers/*" => {
            Some(&["address", "port", "domains", "skipFallback", "route"])
        }
        "/profile/xrayDns/outbound" => {
            Some(&["rewriteAddress", "rewriteNetwork", "rewritePort", "rules"])
        }
        "/profile/xrayDns/outbound/rules/*" => Some(&["action", "qType", "rCode", "domain"]),
        "/profile/xraySockopts" => Some(&[
            "tcpKeepAliveIdle",
            "tcpKeepAliveInterval",
            "tcpUserTimeout",
            "tcpNoDelay",
        ]),
        "/profile/xrayTrafficRules/*" => Some(&["ips", "port", "network", "target"]),
        "/profile/xrayInterfaceRoutes/*" => Some(&["selectors", "interfaceName", "domainStrategy"]),
        _ => None,
    };
    match value {
        Value::Object(object) => {
            let fields = allowed.ok_or_else(|| format!("Unknown setting at {path}"))?;
            for (key, child) in object {
                if !fields.contains(&key.as_str()) {
                    return Err(format!("Unknown setting at {path}"));
                }
                editor_nested_fields(child, &format!("{path}/{key}"))?;
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                editor_nested_fields(child, &format!("{path}/{index}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn editor_restore(profile: &Profile, document: &Value) -> Result<Profile, String> {
    let mut original =
        json!({"version": 1, "profile": serde_json::to_value(profile).map_err(failed)?});
    let mut refs = std::collections::HashMap::new();
    editor_protect(&mut original, "", &mut refs);
    if document.get("version") != Some(&json!(1))
        || document.as_object().is_none_or(|o| o.len() != 2)
        || document.pointer("/profile/id") != original.pointer("/profile/id")
        || document.pointer("/profile/backend") != original.pointer("/profile/backend")
        || document.pointer("/profile/configPath") != original.pointer("/profile/configPath")
        || document.pointer("/profile/subscription/url")
            != original.pointer("/profile/subscription/url")
        || document.pointer("/profile/xrayGeoipUrl") != original.pointer("/profile/xrayGeoipUrl")
        || document.pointer("/profile/xrayGeositeUrl")
            != original.pointer("/profile/xrayGeositeUrl")
        || document.pointer("/profile/subscription/hwid")
            != original.pointer("/profile/subscription/hwid")
    {
        return Err("Protected profile fields cannot be changed".into());
    }
    let original_profile = original["profile"].as_object().ok_or("Invalid profile")?;
    let input_profile = document["profile"].as_object().ok_or("Invalid profile")?;
    const OPTIONAL: &[&str] = &[
        "mihomo",
        "xrayServiceChecks",
        "xrayProxyExits",
        "xrayGeoipUrl",
        "xrayGeositeUrl",
        "xrayDomainStrategy",
        "xrayDomainMatcher",
        "xrayDns",
        "xraySockopts",
        "xrayTrafficRules",
        "xrayInterfaceRoutes",
        "xrayConnectionIdleSecs",
        "xrayTunMtu",
        "xrayTunDnsServers",
        "xrayDirectDomainStrategy",
        "tunnelRole",
        "tunnelDnsDomains",
        "tunnelNetworks",
    ];
    if input_profile
        .keys()
        .any(|key| !original_profile.contains_key(key) && !OPTIONAL.contains(&key.as_str()))
    {
        return Err("Unknown profile setting".into());
    }
    for (key, value) in input_profile {
        editor_nested_fields(value, &format!("/profile/{key}"))?;
    }
    if let Some(checks) = document
        .pointer("/profile/xrayServiceChecks")
        .and_then(Value::as_array)
    {
        for check in checks {
            let Some(object) = check.as_object() else {
                return Err("Invalid setting at /profile/xrayServiceChecks".into());
            };
            if object.keys().any(|key| {
                !["id", "name", "url", "endpointKey", "background"].contains(&key.as_str())
            }) {
                return Err("Unknown setting at /profile/xrayServiceChecks".into());
            }
            if let Some(url) = object.get("url").and_then(Value::as_str) {
                if !url.starts_with("vault:") && !safe_editor_https_url(url) {
                    return Err("Unsafe service-check URL".into());
                }
            }
        }
    }
    if let Some(servers) = document
        .pointer("/profile/xrayDns/servers")
        .and_then(Value::as_array)
    {
        if let Some(old) = original
            .pointer("/profile/xrayDns/servers")
            .and_then(Value::as_array)
        {
            if servers.len() >= old.len() {
                for token in old
                    .iter()
                    .filter_map(|server| server.get("address").and_then(Value::as_str))
                    .filter(|address| address.starts_with("vault:"))
                {
                    if !servers
                        .iter()
                        .any(|server| server.get("address").and_then(Value::as_str) == Some(token))
                    {
                        return Err("Protected DNS reference cannot be changed".into());
                    }
                }
            }
        }
        for server in servers {
            let Some(object) = server.as_object() else {
                return Err("Invalid setting at /profile/xrayDns/servers".into());
            };
            if object.keys().any(|key| {
                !["address", "port", "domains", "skipFallback", "route"].contains(&key.as_str())
            }) {
                return Err("Unknown setting at /profile/xrayDns/servers".into());
            }
            if let Some(address) = object.get("address").and_then(Value::as_str) {
                if address.starts_with("https://") && !safe_editor_https_url(address) {
                    return Err("Unsafe DNS HTTPS address".into());
                }
            }
        }
    }
    if let Some(checks) = document
        .pointer("/profile/xrayServiceChecks")
        .and_then(Value::as_array)
    {
        let old = original
            .pointer("/profile/xrayServiceChecks")
            .and_then(Value::as_array);
        for check in checks {
            let id = check.get("id");
            let prior = old.and_then(|items| items.iter().find(|item| item.get("id") == id));
            let url = check
                .get("url")
                .and_then(Value::as_str)
                .ok_or("Invalid service-check URL")?;
            if url.starts_with("vault:") {
                if prior.and_then(|item| item.get("url")) != Some(&json!(url)) {
                    return Err("Protected service-check reference cannot be changed".into());
                }
            } else if prior.is_some() || !safe_editor_https_url(url) {
                return Err("Unsafe service-check URL".into());
            }
        }
    }
    fn restore(
        value: &mut Value,
        path: &str,
        refs: &std::collections::HashMap<String, (String, Value)>,
    ) -> Result<(), String> {
        if (path.starts_with("/profile/xrayServiceChecks/") && path.ends_with("/url")
            || path.starts_with("/profile/xrayDns/servers/") && path.ends_with("/address"))
            && value.as_str().is_some_and(safe_editor_https_url)
        {
            return Ok(());
        }
        if editor_sensitive(path, value) {
            let token = value
                .as_str()
                .ok_or("Protected references cannot be changed")?;
            let (source, original) = refs
                .get(token)
                .ok_or("Protected references cannot be changed")?;
            let shape = |p: &str| {
                p.split('/')
                    .map(|part| {
                        if part.parse::<usize>().is_ok() {
                            "*"
                        } else {
                            part
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("/")
            };
            if shape(source) != shape(path) {
                return Err("Protected reference is in an invalid field".into());
            }
            *value = original.clone();
            return Ok(());
        }
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    restore(
                        child,
                        &format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                        refs,
                    )?;
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter_mut().enumerate() {
                    restore(child, &format!("{path}/{index}"), refs)?;
                }
            }
            Value::String(s) if s.starts_with("vault:") => {
                return Err("Protected reference is in an invalid field".into())
            }
            _ => {}
        }
        Ok(())
    }
    let mut restored = document.clone();
    restore(&mut restored, "", &refs)?;
    let candidate: Profile = serde_json::from_value(restored["profile"].clone())
        .map_err(|_| "Invalid profile settings".to_string())?;
    Ok(candidate)
}

fn editor_diff(before: &Value, after: &Value) -> Vec<String> {
    fn walk(a: &Value, b: &Value, path: &str, out: &mut Vec<String>) {
        if a == b {
            return;
        }
        match (a, b) {
            (Value::Object(a), Value::Object(b)) => {
                let keys: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
                for key in keys {
                    let next = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                    match (a.get(key), b.get(key)) {
                        (Some(a), Some(b)) => walk(a, b, &next, out),
                        _ => out.push(next),
                    }
                }
            }
            (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
                for (i, (a, b)) in a.iter().zip(b).enumerate() {
                    walk(a, b, &format!("{path}/{i}"), out);
                }
            }
            _ => out.push(path.to_string()),
        }
    }
    let mut out = Vec::new();
    walk(before, after, "", &mut out);
    out
}

#[path = "linux_profile_editor.rs"]
mod editor;
#[path = "linux_profiles_mihomo.rs"]
mod mihomo;
use mihomo::validate_mihomo_source;
pub use net_manager_core::mihomo::MihomoGroupInfo;

#[cfg(test)]
mod editor_document_tests {
    use super::*;

    #[test]
    fn mihomo_selection_patch_and_editor_reject_unknown_fields() {
        let profile = Profile {
            backend: TunnelBackend::Mihomo,
            mihomo: Some(MihomoProfileOptions::default()),
            ..Default::default()
        };
        let changed = merge_profile(&profile, &json!({"mihomo":{"entryGroup":"Auto"}})).unwrap();
        assert_eq!(changed.mihomo.unwrap().entry_group.as_deref(), Some("Auto"));
        let selected = merge_profile(
            &profile,
            &json!({"mihomo":{"groupSelections":{"Auto":"Node"}}}),
        )
        .unwrap();
        let cleared = merge_profile(&selected, &json!({"mihomo":{"groupSelections":{}}})).unwrap();
        assert!(cleared.mihomo.unwrap().group_selections.is_empty());
        assert!(merge_profile(&profile, &json!({"mihomo":{"secret":"leak"}})).is_err());
        let mut document = editor_view(&profile).unwrap();
        document["profile"]["mihomo"]["unknown"] = json!(true);
        assert!(editor_restore(&profile, &document).is_err());
    }

    #[test]
    fn mihomo_refresh_rejects_vanished_selection_before_vault_write() {
        let profile = Profile {
            backend: TunnelBackend::Mihomo,
            mihomo: Some(MihomoProfileOptions {
                entry_group: Some("Missing".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let source = json!({"proxies": [], "proxy-groups": [{"name":"Auto","type":"select","proxies":["DIRECT"]}], "rules":["MATCH,Auto"]});
        assert!(validate_mihomo_source(&source, &profile).is_err());
    }

    #[test]
    fn mihomo_failed_revision_conflict_keeps_existing_source() {
        let dir = tempfile::tempdir().unwrap();
        let service = ProfileService::new(dir.path().into(), LinuxEngine::new("native-test"));
        let profile = Profile {
            id: "native".into(),
            name: "Native".into(),
            backend: TunnelBackend::Mihomo,
            ..Default::default()
        };
        let source = r#"{"proxies":[],"proxy-groups":[{"name":"Auto","type":"select","proxies":["DIRECT"]}],"rules":["MATCH,Auto"]}"#;
        let saved = service
            .save_locked(
                profile,
                Some(ProfileSource::MihomoDocument(source.into())),
                None,
                None,
                None,
            )
            .unwrap();
        let original = saved
            .profiles
            .into_iter()
            .find(|p| p.id == "native")
            .unwrap();
        let old_bytes = fs::read(&original.config_path).unwrap();
        let result = service.save_locked(
            original.clone(),
            Some(ProfileSource::MihomoDocument(source.into())),
            Some(&original),
            Some("stale"),
            None,
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&original.config_path).unwrap(), old_bytes);
        assert_eq!(
            service.store().load().unwrap().profiles[0].config_path,
            original.config_path
        );
    }

    #[test]
    fn native_refresh_keeps_selection_and_rejects_missing_member_transactionally() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let service =
            ProfileService::new(dir.path().into(), LinuxEngine::new("native-refresh-test"));
        let options = MihomoProfileOptions {
            entry_group: Some("Auto".into()),
            group_selections: [("Auto".into(), "DIRECT".into())].into_iter().collect(),
            ..Default::default()
        };
        let mut profile = Profile {
            id: "native".into(),
            name: "Native".into(),
            backend: TunnelBackend::Mihomo,
            mihomo: Some(options.clone()),
            ..Default::default()
        };
        profile.subscription = Some(
            serde_json::from_value(json!({
                "url":"https://example.test/private", "hwid":"", "endpointCount":0,
                "activeIndex":0, "refreshIntervalMinutes":60
            }))
            .unwrap(),
        );
        let original = r#"{"proxies":[],"proxy-groups":[{"name":"Auto","type":"select","proxies":["DIRECT","REJECT"]}],"rules":["MATCH,Auto"]}"#;
        service
            .save_locked(
                profile,
                Some(ProfileSource::MihomoDocument(original.into())),
                None,
                None,
                None,
            )
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let rotated = r#"{"proxies":[],"proxy-groups":[{"name":"Auto","type":"select","proxies":["REJECT","DIRECT"]}],"rules":["MATCH,Auto"]}"#;
        runtime
            .block_on(service.refresh_subscription("native", Some(rotated)))
            .unwrap();
        let after = service.profile("native").unwrap();
        assert_eq!(after.mihomo.as_ref(), Some(&options));
        let missing = r#"{"proxies":[],"proxy-groups":[{"name":"Auto","type":"select","proxies":["REJECT"]}],"rules":["MATCH,Auto"]}"#;
        assert!(runtime
            .block_on(service.refresh_subscription("native", Some(missing)))
            .is_err());
        let failed = service.profile("native").unwrap();
        assert_eq!(failed.config_path, after.config_path);
        assert_eq!(failed.mihomo.as_ref(), Some(&options));
        assert!(failed.subscription.unwrap().last_refresh_error.is_some());
    }

    #[test]
    fn editor_protects_sources_and_rejects_changed_references() {
        let profile = Profile {
            id: "example".into(),
            config_path: "/private/secret.conf".into(),
            xray_geoip_url: Some("https://example.test/secret-token".into()),
            ..Default::default()
        };
        let document = editor_view(&profile).unwrap();
        let text = document.to_string();
        assert!(!text.contains("secret.conf"));
        assert!(!text.contains("secret-token"));
        assert_eq!(editor_restore(&profile, &document).unwrap(), profile);
        let mut changed = document;
        changed["profile"]["configPath"] = json!("forged");
        assert!(editor_restore(&profile, &changed).is_err());
    }

    #[test]
    fn editor_rejects_unknown_nested_fields_and_accepts_safe_check_urls() {
        let profile = Profile {
            xray_service_checks: vec![ServiceCheck {
                id: "one".into(),
                name: "one".into(),
                url: "https://one.test/secret".into(),
                endpoint_key: "one".into(),
                background: false,
            }],
            ..Default::default()
        };
        let document = editor_view(&profile).unwrap();
        let mut changed = document.clone();
        changed["profile"]["xrayServiceChecks"][0]["extra"] = json!(true);
        assert!(editor_restore(&profile, &changed).is_err());
        let mut changed = document;
        changed["profile"]["xrayServiceChecks"].as_array_mut().unwrap().push(json!({"id":"two","name":"two","url":"https://new.test/check","endpointKey":"two","background":false}));
        assert!(editor_restore(&profile, &changed).is_ok());
        changed["profile"]["xrayServiceChecks"][1]["url"] =
            json!("https://user:pass@new.test/check");
        assert!(editor_restore(&profile, &changed).is_err());
        changed["profile"]["xrayServiceChecks"][1]["url"] = json!("https://new.test/check?token=x");
        assert!(editor_restore(&profile, &changed).is_err());
    }

    #[test]
    fn editor_allows_safe_dns_https_address_and_rejects_nested_unknowns() {
        let profile = Profile {
            xray_dns: XrayDnsConfig {
                servers: vec![XrayDnsServer {
                    address: "https://dns.example/dns-query".into(),
                    port: None,
                    domains: vec![],
                    skip_fallback: false,
                    route: XrayDnsRoute::None,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut document = editor_view(&profile).unwrap();
        document["profile"]["xrayDns"]["servers"][0]["unknown"] = json!(1);
        assert!(editor_restore(&profile, &document).is_err());
        let mut changed = editor_view(&profile).unwrap();
        changed["profile"]["xrayDns"]["servers"].as_array_mut().unwrap().push(json!({"address":"https://new.example/dns-query","skipFallback":false,"route":"none"}));
        assert!(editor_restore(&profile, &changed).is_ok());
    }

    #[test]
    fn editor_rejects_unknown_fields_in_all_nested_profile_sections() {
        let profile = Profile::default();
        for (path, object) in [
            (
                "routes",
                json!([{"destination":"10.0.0.0/8","metric":5,"hidden":"secret"}]),
            ),
            (
                "domainPolicies",
                json!([{"domains":["example.test"],"target":"direct","hidden":true}]),
            ),
            ("xrayDns", json!({"fakeDns":false,"hidden":true})),
            ("xraySockopts", json!({"tcpNoDelay":false,"hidden":true})),
            (
                "xrayTrafficRules",
                json!([{"ips":["1.1.1.1"],"port":443,"network":"tcp","target":"block","hidden":true}]),
            ),
        ] {
            let mut document = editor_view(&profile).unwrap();
            document["profile"][path] = object;
            assert!(editor_restore(&profile, &document).is_err(), "{path}");
        }
    }

    #[test]
    fn editor_diff_reports_paths_without_values() {
        let before = json!({"version": 1, "profile": {"name": "secret", "routes": []}});
        let after = json!({"version": 1, "profile": {"name": "other", "routes": []}});
        assert_eq!(editor_diff(&before, &after), vec!["/profile/name"]);
    }
}
