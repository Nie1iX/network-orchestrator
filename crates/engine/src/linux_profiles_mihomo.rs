use super::*;

pub(super) fn validate_mihomo_source(source: &Value, profile: &Profile) -> io::Result<()> {
    net_manager_core::mihomo::compile_config(source, profile).map(|_| ())
}

pub(super) fn resolve_source(bytes: &[u8]) -> Result<Value, String> {
    let source = net_manager_core::mihomo::parse_config(bytes).map_err(failed)?;
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(failed)?;
                runtime
                    .block_on(net_manager_core::mihomo::resolve_provider_snapshots(
                        &source,
                    ))
                    .map_err(failed)
            })
            .join()
            .map_err(|_| "Could not resolve native providers".to_string())?
    })
}

fn proxy_count(source: &Value) -> usize {
    source
        .get("proxies")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
        + source
            .get("proxy-providers")
            .and_then(Value::as_object)
            .map_or(0, |providers| {
                providers
                    .values()
                    .map(|provider| {
                        provider
                            .get("payload")
                            .and_then(Value::as_array)
                            .map_or(0, Vec::len)
                    })
                    .sum()
            })
}

impl ProfileService {
    pub(crate) async fn refresh_mihomo_providers(
        &self,
        id: &str,
        due_only: bool,
    ) -> Result<SubscriptionRefreshResult, String> {
        if unsafe { libc::geteuid() } == 0 {
            return Err("Run subscription changes as your own user, without sudo".into());
        }
        let expected = self.profile(id)?;
        let vault = self.vault();
        let original = crate::linux::read_mihomo_source(&vault, &expected)?;
        if original
            .pointer("/x-netorch-source/proxy-providers")
            .and_then(Value::as_object)
            .is_none_or(|providers| {
                !providers
                    .values()
                    .any(|provider| provider.get("type").and_then(Value::as_str) == Some("http"))
            })
        {
            return Err("The profile has no refreshable Mihomo proxy providers".into());
        }
        let refresh_lock =
            crate::linux_session::lock_file(&self.root.join("subscription-refresh.lock"))
                .map_err(failed)?;
        refresh_lock
            .try_lock()
            .map_err(|_| "A subscription refresh is already in progress".to_string())?;
        let attempt = now();
        let refreshed = if due_only {
            net_manager_core::mihomo::resolve_due_provider_snapshots(&original, attempt).await
        } else {
            net_manager_core::mihomo::resolve_provider_snapshots(&original).await
        };
        let candidate = refreshed.map_err(failed).and_then(|source| {
            validate_mihomo_source(&source, &expected).map_err(|error| error.to_string())?;
            Ok(source)
        });
        let mut source = candidate
            .as_ref()
            .cloned()
            .unwrap_or_else(|_| original.clone());
        if let Some(providers) = source
            .pointer_mut("/x-netorch-source/proxy-providers")
            .and_then(Value::as_object_mut)
        {
            for provider in providers.values_mut().filter_map(Value::as_object_mut) {
                if provider.get("type").and_then(Value::as_str) != Some("http") {
                    continue;
                }
                let interval = provider
                    .get("interval")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let last = provider
                    .get("lastAttemptUnix")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if !due_only || (interval > 0 && attempt.saturating_sub(last) >= interval) {
                    provider.insert("lastAttemptUnix".into(), json!(attempt));
                    if candidate.is_err() {
                        provider.insert("lastError".into(), json!("Provider refresh failed"));
                    } else {
                        provider.remove("lastError");
                    }
                }
            }
        }
        let _lock = self.mutation()?;
        if self.profile(id)? != expected {
            return Err("The profile changed during provider refresh; retry".into());
        }
        let body = serde_json::to_vec(&source).map_err(failed)?;
        let imported = vault.store_mihomo_source(id, &body).map_err(failed)?;
        let new_path = imported.config_path;
        if self
            .store()
            .update_profile(id, |current| {
                if current != &expected {
                    return Err(invalid("Profile changed during provider refresh"));
                }
                current.config_path = new_path.clone();
                Ok(())
            })
            .is_err()
        {
            let _ = vault.remove_revision_for_config(&new_path);
            return Err("The profile changed during provider refresh; retry".into());
        }
        let cleanup_failed = vault.is_managed_profile_path(id, &expected.config_path)
            && vault
                .remove_revision_for_config(&expected.config_path)
                .is_err();
        candidate?;
        Ok(SubscriptionRefreshResult {
            endpoint_count: proxy_count(&source),
            active_index: 0,
            skipped_count: 0,
            fallback_used: false,
            cleanup_failed,
            pool_report: None,
        })
    }

    pub fn mihomo_groups(&self, id: &str) -> Result<Vec<MihomoGroupInfo>, String> {
        let profile = self.profile(id)?;
        if profile.backend != TunnelBackend::Mihomo {
            return Err("The profile is not a Mihomo profile".into());
        }
        let source = crate::linux::read_mihomo_source(&self.vault(), &profile)?;
        net_manager_core::mihomo::group_info(&source, &profile.mihomo.clone().unwrap_or_default())
            .map_err(failed)
    }

    pub async fn import_mihomo_subscription(
        &self,
        mut profile: Profile,
        url: &str,
        hwid: &str,
        refresh_interval_minutes: Option<u32>,
    ) -> Result<BatchImportResult, String> {
        if unsafe { libc::geteuid() } == 0 {
            return Err("Run subscription changes as your own user, without sudo".into());
        }
        if profile.backend != TunnelBackend::Mihomo
            || profile.subscription.is_some()
            || !profile.pinned_policies.is_empty()
            || !profile.xray_service_checks.is_empty()
            || !profile.xray_proxy_exits.is_empty()
        {
            return Err("Invalid native subscription profile".into());
        }
        validate_interval(refresh_interval_minutes)?;
        subscription::validate_url(url).map_err(failed)?;
        let (source, fetched) = subscription::fetch_mihomo(url, hwid)
            .await
            .map_err(failed)?;
        let source = net_manager_core::mihomo::resolve_provider_snapshots(&source)
            .await
            .map_err(failed)?;
        validate_mihomo_source(&source, &profile).map_err(|error| error.to_string())?;
        let count = proxy_count(&source);
        let _lock = self.mutation()?;
        if profile.id.is_empty() {
            profile.id = new_id()?;
        }
        if self.profiles()?.iter().any(|item| item.id == profile.id) {
            return Err("A profile with that identifier already exists".into());
        }
        profile.subscription = Some(SubscriptionMeta {
            url: url.trim().into(),
            hwid: hwid.into(),
            endpoint_count: count,
            active_index: 0,
            refresh_interval_minutes,
            last_refresh_at_unix: Some(now()),
            last_refresh_error: None,
            user_info: fetched.meta.user_info,
            provider_title: None,
            announce: None,
            support_url: None,
            web_page_url: None,
            update_interval_hours: fetched.meta.update_interval_hours,
            skipped_protocols: Vec::new(),
            active_key: None,
            backup_keys: Vec::new(),
            auto_return_primary: None,
            probe_url: None,
            node_pool: None,
            pool_keys: Vec::new(),
        });
        let document = self.save_locked(
            profile,
            Some(ProfileSource::MihomoDocument(fetched.body)),
            None,
            None,
            Some(source),
        )?;
        Ok(BatchImportResult {
            profiles: document.profiles,
            errors: Vec::new(),
        })
    }

    pub(super) fn import_mihomo_configs(
        &self,
        paths: &[String],
    ) -> Result<BatchImportResult, String> {
        let mut errors = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            let profile = Profile {
                id: new_id()?,
                name: "Mihomo".into(),
                backend: TunnelBackend::Mihomo,
                ..Default::default()
            };
            if self
                .create(profile, Some(ProfileSource::Config(path.into())))
                .is_err()
            {
                errors.push(BatchImportError {
                    path: format!("Input {}", index + 1),
                    error: "The configuration could not be imported".into(),
                });
            }
        }
        Ok(BatchImportResult {
            profiles: self.profiles()?,
            errors,
        })
    }

    pub(super) async fn refresh_mihomo_subscription(
        &self,
        id: &str,
        cached: Option<&str>,
    ) -> Result<SubscriptionRefreshResult, String> {
        let expected = self.profile(id)?;
        let meta = expected
            .subscription
            .as_ref()
            .ok_or("The profile is not a subscription")?;
        let refresh_lock =
            crate::linux_session::lock_file(&self.root.join("subscription-refresh.lock"))
                .map_err(failed)?;
        refresh_lock
            .try_lock()
            .map_err(|_| "A subscription refresh is already in progress".to_string())?;
        let result: Result<SubscriptionRefreshResult, String> = async {
            let (source, response) = if let Some(body) = cached {
                (
                    net_manager_core::mihomo::parse_config(body.as_bytes()).map_err(failed)?,
                    subscription::response_meta(&[], body),
                )
            } else {
                let (source, fetched) = subscription::fetch_mihomo(&meta.url, &meta.hwid)
                    .await
                    .map_err(failed)?;
                (source, fetched.meta)
            };
            let source = net_manager_core::mihomo::resolve_provider_snapshots(&source)
                .await
                .map_err(failed)?;
            validate_mihomo_source(&source, &expected).map_err(|error| error.to_string())?;
            let count = proxy_count(&source);
            let _lock = self.mutation()?;
            if self.profile(id)? != expected {
                return Err("The subscription changed during refresh; retry".into());
            }
            let vault = self.vault();
            let body = serde_json::to_vec(&source).map_err(failed)?;
            let imported = vault.store_mihomo_source(id, &body).map_err(failed)?;
            let new_path = imported.config_path;
            let saved = self.store().update_profile(id, |current| {
                if current != &expected {
                    return Err(invalid("Subscription changed during refresh"));
                }
                current.config_path = new_path.clone();
                let meta = current
                    .subscription
                    .as_mut()
                    .ok_or_else(|| invalid("Profile is no longer a subscription"))?;
                meta.endpoint_count = count;
                meta.last_refresh_at_unix = Some(now());
                meta.last_refresh_error = None;
                meta.user_info = response.user_info;
                meta.update_interval_hours = response.update_interval_hours;
                Ok(())
            });
            if saved.is_err() {
                let _ = vault.remove_revision_for_config(&new_path);
                return Err("The subscription changed during refresh; retry".into());
            }
            let cleanup_failed = vault.is_managed_profile_path(id, &expected.config_path)
                && vault
                    .remove_revision_for_config(&expected.config_path)
                    .is_err();
            Ok(SubscriptionRefreshResult {
                endpoint_count: count,
                active_index: 0,
                skipped_count: 0,
                fallback_used: false,
                cleanup_failed,
                pool_report: None,
            })
        }
        .await;
        if let Err(error) = &result {
            let notice = match error.as_str() {
                "Selected Mihomo group no longer exists" => {
                    "Selected Mihomo group no longer exists"
                }
                "Selected Mihomo group member no longer exists" => {
                    "Selected Mihomo group member no longer exists"
                }
                "Selected Mihomo entry group does not exist" => {
                    "Selected Mihomo entry group does not exist"
                }
                _ => "Subscription refresh failed",
            };
            self.store()
                .update_profile(id, |current| {
                    if current != &expected {
                        return Err(invalid("Subscription changed during refresh"));
                    }
                    let meta = current
                        .subscription
                        .as_mut()
                        .ok_or_else(|| invalid("Profile is no longer a subscription"))?;
                    meta.last_refresh_at_unix = Some(now());
                    meta.last_refresh_error = Some(notice.into());
                    Ok(())
                })
                .map_err(|_| {
                    "Subscription refresh failed, and its failure notice could not be saved"
                        .to_string()
                })?;
        }
        result
    }
}
