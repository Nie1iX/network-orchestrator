use super::*;
#[cfg(target_arch = "x86_64")]
use net_manager_core::managed_mihomo;

pub type ManagedMihomoOffer = ManagedXrayOffer;

pub fn managed_mihomo_offer() -> ManagedMihomoOffer {
    #[cfg(target_arch = "x86_64")]
    let (version, url, hash, maximum) = (
        managed_mihomo::LINUX_MIHOMO_VERSION,
        managed_mihomo::LINUX_MIHOMO_URL,
        managed_mihomo::LINUX_MIHOMO_SHA256,
        managed_mihomo::MAX_MIHOMO_ARCHIVE_BYTES as u64,
    );
    #[cfg(not(target_arch = "x86_64"))]
    let (version, url, hash, maximum) = ("unavailable", "", "", 0);
    ManagedMihomoOffer {
        version: version.into(),
        source_url: url.into(),
        sha256: hash.into(),
        max_download_bytes: maximum,
    }
}

fn managed_path() -> Result<PathBuf, String> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(managed_mihomo::linux_managed_version_dir(Path::new(
            managed_mihomo::LINUX_MIHOMO_PACKAGE_ROOT,
        ))
        .join("mihomo"))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err("Managed Mihomo installation requires Linux x86_64".into())
    }
}

pub(super) fn verified_managed(setting: &BackendExecutableSetting) -> Result<(), String> {
    #[cfg(target_arch = "x86_64")]
    {
        if setting.version.as_deref() != Some(managed_mihomo::LINUX_MIHOMO_VERSION)
            || setting.path != managed_path()?
        {
            return Err("Managed Mihomo setting does not match the pinned installation".into());
        }
        managed_mihomo::verify_managed_linux_executable(
            Path::new(managed_mihomo::LINUX_MIHOMO_PACKAGE_ROOT),
            &setting.path,
        )
        .map_err(|_| "Managed Mihomo verification failed".into())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = setting;
        Err("Managed Mihomo installation requires Linux x86_64".into())
    }
}

pub(super) fn resolve(configured: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(path) = configured {
        let path = path
            .canonicalize()
            .map_err(|_| "Mihomo executable is unavailable")?;
        let metadata = fs::metadata(&path).map_err(|_| "Mihomo executable is unavailable")?;
        if metadata.is_file() && metadata.mode() & 0o111 != 0 {
            return Ok(path);
        }
        return Err("Mihomo executable is not an executable regular file".into());
    }
    let path = managed_path()?;
    verified_managed(&BackendExecutableSetting {
        path: path.clone(),
        source: BackendExecutableSource::Managed,
        version: Some(managed_mihomo_offer().version),
    })
    .map_err(|_| "Mihomo is unavailable; install the optional managed component".to_string())?;
    Ok(path)
}

pub(super) fn availability(
    store: &BackendSettingsStore,
    hello: Option<&protocol::HelloResult>,
) -> Result<BackendAvailability, String> {
    let persisted = store
        .get(TunnelBackend::Mihomo)
        .map_err(|_| "Cannot read backend settings")?;
    let managed = resolve(None);
    let managed_available = managed.is_ok();
    let resolved = match persisted.as_ref() {
        Some(setting) if setting.source == BackendExecutableSource::Managed => {
            if managed_path().is_ok_and(|path| setting.path == path)
                && setting.version.as_deref() == Some(managed_mihomo_offer().version.as_str())
            {
                managed
            } else {
                Err("Managed Mihomo setting does not match the pinned installation".into())
            }
        }
        Some(setting) => resolve(Some(&setting.path)),
        None => managed,
    };
    let local = resolved.is_ok();
    let tun = managed_available
        && hello.is_some_and(|hello| {
            [
                method::MIHOMO_CONNECT,
                method::MIHOMO_DISCONNECT,
                method::MIHOMO_STATUS,
            ]
            .iter()
            .all(|method| {
                hello
                    .capabilities
                    .iter()
                    .any(|capability| capability == method)
            })
        });
    Ok(BackendAvailability {
        backend: TunnelBackend::Mihomo,
        available: local || tun,
        path: resolved.ok().or_else(|| persisted.as_ref().map(|setting| setting.path.clone())),
        source: persisted.as_ref().map(|setting| setting.source)
            .or(local.then_some(BackendExecutableSource::AutoDetected)),
        version: persisted.and_then(|setting| setting.version),
        message: match (local, tun) {
            (true, true) => "Mihomo SOCKS5/HTTP and TUN available.",
            (true, false) => "Mihomo SOCKS5/HTTP available; TUN requires the verified managed component and a compatible daemon.",
            (false, true) => "Mihomo TUN available; the local executable setting is unavailable.",
            (false, false) => "Mihomo is optional and unavailable; install the managed component and use a compatible daemon.",
        }.into(),
    })
}

fn control_directory(directory: &Path) -> Result<PathBuf, String> {
    let path = directory.join("mihomo-installer");
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("Cannot prepare Mihomo installer coordination".into()),
    }
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| "Cannot inspect Mihomo installer coordination")?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("Mihomo installer coordination is not private and user-owned".into());
    }
    Ok(path)
}

pub(super) fn begin_install(directory: &Path) -> Result<InstallGuard, String> {
    let mutation = mutation_lock(directory)?;
    InstallGuard::begin_with_mutation(&control_directory(directory)?, mutation)
}

pub(super) fn cancel_in(directory: &Path) -> Result<(), String> {
    super::cancel_in(&control_directory(directory)?)
}

pub fn cancel_managed_mihomo_install(root: &Path) -> Result<(), String> {
    user_only()?;
    managed_path()?;
    cancel_in(&coordination_directory(root).map_err(|_| "Cannot access user runtime")?)
}

fn remove_via_daemon(engine: &LinuxEngine) -> Result<(), String> {
    let _: protocol::MihomoRemoveResult =
        engine.ask(method::MIHOMO_REMOVE, serde_json::Value::Null)?;
    Ok(())
}

pub async fn install_managed_mihomo(
    engine: &LinuxEngine,
    root: &Path,
    store: &ProfileStore,
    progress: &(dyn Fn(BackendInstallProgress) + Send + Sync),
) -> Result<(), String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    user_only()?;
    let executable = managed_path()?;
    let directory = coordination_directory(root).map_err(|_| "Cannot access user runtime")?;
    let guard = begin_install(&directory)?;
    ensure_stopped(engine, store, TunnelBackend::Mihomo)?;
    let hello = engine
        .privileged()
        .hello()
        .map_err(|_| "The network daemon is unavailable")?;
    if !hello
        .capabilities
        .iter()
        .any(|method| method == method::MIHOMO_INSTALL)
    {
        return Err("Update the network daemon before installing Mihomo".into());
    }
    let offer = managed_mihomo_offer();
    let emit = |stage: &str, downloaded, total| {
        progress(BackendInstallProgress {
            backend: TunnelBackend::Mihomo,
            stage: stage.into(),
            downloaded,
            total,
        })
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("Network-Orchestrator")
        .build()
        .map_err(|_| "Cannot build download client")?;
    emit("downloading", 0, None);
    let mut response = cancellable_download(&guard, client.get(&offer.source_url).send())
        .await?
        .error_for_status()
        .map_err(|_| "Managed Mihomo download failed")?;
    let total = response.content_length();
    if total.is_some_and(|length| length > offer.max_download_bytes) {
        return Err("Managed Mihomo archive exceeds the maximum size".into());
    }
    let mut archive = Vec::new();
    loop {
        guard
            .check_cancelled()
            .inspect_err(|_| emit("cancelled", archive.len() as u64, total))?;
        let Some(chunk) = cancellable_download(&guard, response.chunk()).await? else {
            break;
        };
        let length = archive
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length as u64 <= offer.max_download_bytes)
            .ok_or("Managed Mihomo archive exceeds the maximum size")?;
        archive.extend_from_slice(&chunk);
        emit("downloading", length as u64, total);
    }
    let downloaded = archive.len() as u64;
    if total.is_some_and(|length| length != downloaded) {
        return Err("Managed Mihomo download length did not match Content-Length".into());
    }
    emit("verifying", downloaded, total);
    if format!("{:x}", Sha256::digest(&archive)) != offer.sha256 {
        return Err("Managed Mihomo archive hash did not match the pinned release".into());
    }
    guard.check_cancelled()?;
    ensure_stopped(engine, store, TunnelBackend::Mihomo)?;
    emit("installing", downloaded, total);
    let archive_b64 = base64::engine::general_purpose::STANDARD.encode(&archive);
    drop(archive);
    let installed: protocol::MihomoInstallResult = engine.ask(
        method::MIHOMO_INSTALL,
        protocol::MihomoInstallParams { archive_b64 },
    )?;
    let selected = guard.commit(|| {
        ensure_stopped(engine, store, TunnelBackend::Mihomo)?;
        let setting = BackendExecutableSetting {
            path: executable,
            source: BackendExecutableSource::Managed,
            version: Some(installed.version.clone()),
        };
        verified_managed(&setting)?;
        write_settings(root, TunnelBackend::Mihomo, Some(setting))
    });
    if let Err(error) = selected {
        emit(
            if error == "Managed backend install cancelled" {
                "cancelled"
            } else {
                "failed"
            },
            downloaded,
            total,
        );
        if installed.created {
            match settings(root).get(TunnelBackend::Mihomo) {
                Ok(Some(setting))
                    if setting.source == BackendExecutableSource::Managed
                        && setting.path == managed_path()? =>
                {
                    return Err(format!("{error}; managed package remains selected"))
                }
                Err(_) => {
                    return Err(format!(
                        "{error}; cannot confirm selection; managed package retained"
                    ))
                }
                _ => remove_via_daemon(engine).map_err(|_| {
                    format!("{error}; rollback failed; managed package remains installed")
                })?,
            }
        }
        return Err(error);
    }
    emit("ready", downloaded, total);
    Ok(())
}

pub fn remove_managed_mihomo(
    engine: &LinuxEngine,
    root: &Path,
    store: &ProfileStore,
) -> Result<(), String> {
    user_only()?;
    let expected = managed_path()?;
    let directory = coordination_directory(root).map_err(|_| "Cannot access user runtime")?;
    let _mutation = mutation_lock(&directory)?;
    ensure_stopped(engine, store, TunnelBackend::Mihomo)?;
    let selected = settings(root)
        .get(TunnelBackend::Mihomo)
        .map_err(|_| "Cannot read backend settings")?;
    if selected.as_ref().is_some_and(|selected| {
        selected.source != BackendExecutableSource::Managed
            || selected.path != expected
            || selected.version.as_deref() != Some(managed_mihomo_offer().version.as_str())
    }) {
        return Err("The selected Mihomo backend is not the pinned managed installation".into());
    }
    if selected.is_some() {
        write_settings(root, TunnelBackend::Mihomo, None)?;
    }
    if let Err(error) = remove_via_daemon(engine) {
        if let Some(selected) = selected {
            write_settings(root, TunnelBackend::Mihomo, Some(selected))
                .map_err(|_| format!("{error}; restoring the managed selection failed"))?;
        }
        return Err(error);
    }
    Ok(())
}
