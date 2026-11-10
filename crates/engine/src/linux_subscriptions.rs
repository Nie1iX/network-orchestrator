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
    profile.backend == TunnelBackend::Xray
        && profile.subscription.as_ref().is_some_and(|meta| {
            meta.refresh_interval_minutes
                .is_some_and(|minutes| subscription::REFRESH_INTERVALS.contains(&minutes))
        })
}

pub(crate) fn configured(root: &Path) -> io::Result<bool> {
    ProfileStore::new(root.join("profiles.json"))
        .load()
        .map(|document| document.profiles.iter().any(enabled))
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
                                has_work.store(profiles.iter().any(enabled), Ordering::Release);
                                let now = SystemTime::now().duration_since(UNIX_EPOCH)
                                    .unwrap_or_default().as_secs();
                                for profile in profiles.iter().filter(|profile| enabled(profile)) {
                                    if !profile.subscription.as_ref().is_some_and(|meta| subscription::refresh_due(meta, now)) {
                                        continue;
                                    }
                                    let result = tokio::select! {
                                        result = service.refresh_subscription(&profile.id, None) => result,
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
