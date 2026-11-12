//! User-owned subscription scheduling; it never reconnects or mutates system networking.
use crate::linux_engine::LinuxEngine;
use crate::linux_profiles::ProfileService;
use net_manager_core::models::{Profile, TunnelBackend};
use net_manager_core::profiles::ProfileStore;
use net_manager_core::subscription;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

fn enabled(profile: &Profile) -> bool {
    matches!(profile.backend, TunnelBackend::Xray | TunnelBackend::Mihomo)
        && profile.subscription.as_ref().is_some_and(|meta| {
            meta.refresh_interval_minutes
                .is_some_and(|minutes| subscription::REFRESH_INTERVALS.contains(&minutes))
        })
}

pub(crate) fn provider_interval(source: &serde_json::Value) -> Option<u64> {
    source
        .pointer("/x-netorch-source/proxy-providers")?
        .as_object()?
        .values()
        .filter(|provider| provider.get("type").and_then(|v| v.as_str()) == Some("http"))
        .filter_map(|provider| {
            provider
                .get("interval")
                .and_then(|v| v.as_u64())
                .filter(|n| *n > 0)
        })
        .min()
}

fn provider_due(source: &serde_json::Value, now: u64) -> bool {
    source
        .pointer("/x-netorch-source/proxy-providers")
        .and_then(|v| v.as_object())
        .is_some_and(|providers| {
            providers.values().any(|provider| {
                provider.get("type").and_then(|v| v.as_str()) == Some("http")
                    && provider
                        .get("interval")
                        .and_then(|v| v.as_u64())
                        .filter(|n| *n > 0)
                        .is_some_and(|interval| {
                            now.saturating_sub(
                                provider
                                    .get("lastAttemptUnix")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0),
                            ) >= interval
                        })
            })
        })
}

fn provider_source(root: &Path, profile: &Profile) -> Option<serde_json::Value> {
    if profile.backend != TunnelBackend::Mihomo {
        return None;
    }
    crate::linux::read_mihomo_source(
        &net_manager_core::config_vault::ConfigVault::new(root.join("configs")),
        profile,
    )
    .ok()
}

fn scheduled(root: &Path, profile: &Profile) -> bool {
    enabled(profile)
        || provider_source(root, profile)
            .as_ref()
            .and_then(provider_interval)
            .is_some()
}

pub(crate) fn configured(root: &Path) -> io::Result<bool> {
    ProfileStore::new(root.join("profiles.json"))
        .load()
        .map(|document| {
            document
                .profiles
                .iter()
                .any(|profile| scheduled(root, profile))
        })
}

pub(crate) struct Scheduler {
    wake: Arc<Notify>,
    shutdown: Arc<Notify>,
    stopping: Arc<AtomicBool>,
    has_work: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Scheduler {
    pub(crate) fn start(root: PathBuf, daemon: PathBuf) -> io::Result<Self> {
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let wake = Arc::new(Notify::new());
        let shutdown = Arc::new(Notify::new());
        let stopping = Arc::new(AtomicBool::new(false));
        let has_work = Arc::new(AtomicBool::new(configured(&root)?));
        let service = ProfileService::new(
            root.clone(),
            LinuxEngine::for_socket(daemon, "netorch-subscriptions"),
        );
        let thread = {
            let wake = Arc::clone(&wake);
            let shutdown = Arc::clone(&shutdown);
            let stopping = Arc::clone(&stopping);
            let has_work = Arc::clone(&has_work);
            std::thread::Builder::new().name("subscription-refresh".into()).spawn(move || {
                executor.block_on(async {
                    loop {
                        if stopping.load(Ordering::Acquire) {
                            return;
                        }
                        match service.profiles() {
                            Ok(profiles) => {
                                has_work.store(profiles.iter().any(|profile| scheduled(&root, profile)), Ordering::Release);
                                let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                    .unwrap_or_default().as_secs();
                                for profile in &profiles {
                                    let subscription_due = enabled(profile) && profile.subscription.as_ref().is_some_and(|meta| subscription::refresh_due(meta, now));
                                    let providers_due = provider_source(&root, profile).is_some_and(|source| provider_due(&source, now));
                                    if !subscription_due && !providers_due { continue; }
                                    let result = tokio::select! {
                                        result = async {
                                            if subscription_due {
                                                service.refresh_subscription(&profile.id, None).await
                                            } else {
                                                service.refresh_mihomo_providers(&profile.id, true).await
                                            }
                                        } => result,
                                        _ = shutdown.notified() => return,
                                    };
                                    let (level, message) = if result.is_ok() {
                                        (crate::linux_diagnostics::LogLevel::Info, "Background subscription refresh completed")
                                    } else {
                                        (crate::linux_diagnostics::LogLevel::Warn, "Background subscription refresh failed; inspect the saved subscription status")
                                    };
                                    let _ = crate::linux_diagnostics::try_record_log(&root, level, message);
                                    if stopping.load(Ordering::Acquire) {
                                        return;
                                    }
                                }
                            }
                            Err(_) => {
                                let _ = crate::linux_diagnostics::try_record_log(
                                    &root,
                                    crate::linux_diagnostics::LogLevel::Error,
                                    "Subscription scheduler could not load saved profiles",
                                );
                            }
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(60)) => {},
                            _ = wake.notified() => {},
                            _ = shutdown.notified() => return,
                        }
                    }
                });
            })?
        };
        Ok(Self {
            wake,
            shutdown,
            stopping,
            has_work,
            thread: Some(thread),
        })
    }

    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }

    pub(crate) fn has_work(&self) -> bool {
        self.has_work.load(Ordering::Acquire)
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.thread.as_ref().is_some_and(JoinHandle::is_finished)
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.shutdown.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_subscriptions_use_the_shared_scheduler() {
        let mut profile = Profile {
            backend: TunnelBackend::Mihomo,
            subscription: Some(
                serde_json::from_value(serde_json::json!({
                    "url": "https://example.test/private",
                    "hwid": "",
                    "endpointCount": 1,
                    "activeIndex": 0,
                    "refreshIntervalMinutes": 60
                }))
                .unwrap(),
            ),
            ..Default::default()
        };
        assert!(enabled(&profile));
        profile
            .subscription
            .as_mut()
            .unwrap()
            .refresh_interval_minutes = None;
        assert!(!enabled(&profile));
    }

    #[test]
    fn file_provider_schedule_requires_positive_interval() {
        let mut source = serde_json::json!({"x-netorch-source": {"proxy-providers": {
            "one": {"type":"http", "interval":0, "lastAttemptUnix":100}
        }}});
        assert_eq!(super::provider_interval(&source), None);
        source["x-netorch-source"]["proxy-providers"]["one"]["interval"] = 300.into();
        assert_eq!(super::provider_interval(&source), Some(300));
        assert!(!super::provider_due(&source, 399));
        assert!(super::provider_due(&source, 400));
        source["x-netorch-source"]["proxy-providers"]["two"] =
            serde_json::json!({"type":"http", "interval":900, "lastAttemptUnix":350});
        source["x-netorch-source"]["proxy-providers"]["one"]["lastAttemptUnix"] = 400.into();
        assert!(!super::provider_due(&source, 699));
        assert!(super::provider_due(&source, 700));
    }
}
