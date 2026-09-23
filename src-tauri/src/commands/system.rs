use crate::elevation;
use crate::state::{resolve_backend_path, AppState, ResolvedBackendExecutable, RuntimeState};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use net_manager_core::managed_xray::ManagedXrayInstallation;
use net_manager_core::managed_xray::{
    self, MANAGED_XRAY_URL, MANAGED_XRAY_VERSION, MAX_XRAY_ARCHIVE_BYTES,
};
use net_manager_core::models::{
    BackendAvailability, BackendExecutableSetting, BackendExecutableSource, Profile, TunnelBackend,
    TunnelState,
};
use net_manager_core::vpn::TunnelManager;
use serde::Serialize;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use tauri::Emitter;
use tauri::State;

#[tauri::command]
pub(crate) async fn is_elevated() -> Result<bool, String> {
    #[cfg(target_os = "linux")]
    {
        Ok(false)
    }
    #[cfg(not(target_os = "linux"))]
    elevation::is_elevated().map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn daemon_status() -> Result<serde_json::Value, String> {
    #[cfg(target_os = "linux")]
    {
        serde_json::to_value(crate::daemon_client::daemon_status().await).map_err(|e| e.to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(serde_json::json!({"state":"notRequired","message":""}))
    }
}

/// Administrator-chosen VPN password mode; `None` where no daemon exists.
#[tauri::command]
pub(crate) async fn get_vpn_auth_mode(
) -> Result<Option<net_manager_core::daemon_protocol::VpnAuthMode>, String> {
    #[cfg(target_os = "linux")]
    {
        use net_manager_core::daemon_protocol::{method, SettingsResult};
        let result: SettingsResult = crate::daemon_client::DaemonClient::system()
            .request(method::SETTINGS_GET, serde_json::Value::Null)
            .await
            .map_err(|e| crate::daemon_client::user_message(&e))?;
        Ok(Some(result.vpn_auth_mode))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(None)
    }
}

/// Changing the mode asks the daemon, which requires an administrator.
#[tauri::command]
pub(crate) async fn set_vpn_auth_mode(
    mode: net_manager_core::daemon_protocol::VpnAuthMode,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use net_manager_core::daemon_protocol::{method, SettingsResult, SettingsSetParams};
        let _: SettingsResult = crate::daemon_client::DaemonClient::system()
            .request(
                method::SETTINGS_SET,
                SettingsSetParams {
                    vpn_auth_mode: mode,
                },
            )
            .await
            .map_err(|e| crate::daemon_client::user_message(&e))?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mode;
        Err("VPN password mode is managed by the Linux daemon".into())
    }
}

/// Discover WireGuard configs in the standard Windows service location
/// `C:\Program Files\WireGuard\Data\Configurations\`. Requires elevation to
/// read the ACL-protected directory. Returns sorted absolute paths to
/// `.conf.dpapi` (and `.conf`) files.
#[tauri::command]
pub(crate) async fn discover_wireguard_configs() -> Result<Vec<String>, String> {
    #[cfg(windows)]
    {
        let dir = PathBuf::from(r"C:\Program Files\WireGuard\Data\Configurations");
        let mut paths = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(err) => {
                return Err(format!(
                    "cannot read WireGuard configs directory '{}': {err}. Run as administrator.",
                    dir.display()
                ));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.ends_with(".conf") || name.ends_with(".conf.dpapi") {
                paths.push(entry.path().to_string_lossy().to_string());
            }
        }
        paths.sort();
        Ok(paths)
    }
    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}

fn backend_entry(
    backend: TunnelBackend,
    resolved: Result<ResolvedBackendExecutable, io::Error>,
    persisted: io::Result<Option<BackendExecutableSetting>>,
) -> BackendAvailability {
    let persisted = persisted.ok().flatten();
    match resolved {
        Ok(resolved) => BackendAvailability {
            backend,
            available: true,
            path: Some(resolved.path),
            source: Some(resolved.source),
            version: resolved.version,
            message: "executable found".to_string(),
        },
        Err(err) => BackendAvailability {
            backend,
            available: false,
            path: persisted.as_ref().map(|s| s.path.clone()),
            source: persisted.as_ref().map(|s| s.source),
            version: persisted.and_then(|s| s.version),
            message: format!("executable unavailable: {err}"),
        },
    }
}

pub(crate) fn collect_backend_availability(state: &AppState) -> Vec<BackendAvailability> {
    [
        TunnelBackend::WireGuard,
        TunnelBackend::OpenVpn,
        TunnelBackend::Xray,
    ]
    .into_iter()
    .map(|backend| {
        #[cfg(target_os = "linux")]
        if matches!(backend, TunnelBackend::WireGuard | TunnelBackend::OpenVpn) {
            return BackendAvailability {
                backend,
                available: false,
                path: None,
                source: None,
                version: None,
                message: "Network daemon status pending.".into(),
            };
        }
        backend_entry(
            backend,
            state.resolve_backend_executable(backend),
            state.backend_settings.get(backend),
        )
    })
    .collect()
}

#[cfg(target_os = "linux")]
fn linux_wireguard_backend_availability(
    status: crate::daemon_client::DaemonStatus,
    supported: bool,
) -> BackendAvailability {
    let available = status.state == crate::daemon_client::DaemonState::Ready && supported;
    BackendAvailability {
        backend: TunnelBackend::WireGuard,
        available,
        path: None,
        source: None,
        version: None,
        message: if status.state == crate::daemon_client::DaemonState::Ready && !supported {
            "Network daemon does not support WireGuard. Update the daemon.".into()
        } else {
            status.message
        },
    }
}

#[cfg(target_os = "linux")]
fn linux_openvpn_backend_availability(
    status: crate::daemon_client::DaemonStatus,
    supported: bool,
) -> BackendAvailability {
    let available = status.state == crate::daemon_client::DaemonState::Ready && supported;
    BackendAvailability {
        backend: TunnelBackend::OpenVpn,
        available,
        path: None,
        source: None,
        version: None,
        message: if status.state == crate::daemon_client::DaemonState::Ready && !supported {
            "Network daemon does not support OpenVPN. Update the daemon.".into()
        } else {
            status.message
        },
    }
}

#[cfg(target_os = "linux")]
fn linux_xray_backend_availability(
    mut entry: BackendAvailability,
    status: &crate::daemon_client::DaemonStatus,
    supported: bool,
    package_verified: bool,
) -> BackendAvailability {
    let tun_available =
        status.state == crate::daemon_client::DaemonState::Ready && supported && package_verified;
    let socks_available = entry.available;
    entry.available |= tun_available;
    entry.message = match (socks_available, tun_available) {
        (true, true) => "Xray SOCKS5/HTTP and TUN available.".into(),
        (false, true) => {
            "Xray TUN available; SOCKS5/HTTP executable setting is unavailable.".into()
        }
        (true, false) => {
            "Xray SOCKS5/HTTP available; TUN requires verified package Xray and network daemon."
                .into()
        }
        (false, false) => {
            "Xray unavailable; TUN requires verified package Xray and network daemon.".into()
        }
    };
    entry
}

#[tauri::command]
pub(crate) async fn get_backend_availability(
    state: State<'_, AppState>,
) -> Result<Vec<BackendAvailability>, String> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut availability = collect_backend_availability(&state);
    #[cfg(target_os = "linux")]
    {
        let client = crate::daemon_client::DaemonClient::system();
        let hello = client.hello().await;
        let status = if hello.is_ok() {
            crate::daemon_client::DaemonStatus {
                state: crate::daemon_client::DaemonState::Ready,
                message: "Network daemon is ready.".into(),
            }
        } else {
            crate::daemon_client::daemon_status().await
        };
        for entry in availability.iter_mut().filter(|entry| {
            matches!(
                entry.backend,
                TunnelBackend::WireGuard | TunnelBackend::OpenVpn
            )
        }) {
            let methods = match entry.backend {
                TunnelBackend::WireGuard => [
                    net_manager_core::daemon_protocol::method::WIREGUARD_CONNECT,
                    net_manager_core::daemon_protocol::method::WIREGUARD_DISCONNECT,
                    net_manager_core::daemon_protocol::method::WIREGUARD_STATUS,
                ],
                TunnelBackend::OpenVpn => [
                    net_manager_core::daemon_protocol::method::OPENVPN_CONNECT,
                    net_manager_core::daemon_protocol::method::OPENVPN_DISCONNECT,
                    net_manager_core::daemon_protocol::method::OPENVPN_STATUS,
                ],
                _ => unreachable!(),
            };
            let supported = hello.as_ref().is_ok_and(|result| {
                methods
                    .iter()
                    .all(|method| result.capabilities.iter().any(|cap| cap == method))
            });
            *entry = match entry.backend {
                TunnelBackend::WireGuard => {
                    linux_wireguard_backend_availability(status.clone(), supported)
                }
                TunnelBackend::OpenVpn => {
                    linux_openvpn_backend_availability(status.clone(), supported)
                }
                _ => unreachable!(),
            };
        }
        if let Some(entry) = availability
            .iter_mut()
            .find(|entry| entry.backend == TunnelBackend::Xray)
        {
            let supported = hello.as_ref().is_ok_and(|result| {
                [
                    net_manager_core::daemon_protocol::method::XRAY_CONNECT,
                    net_manager_core::daemon_protocol::method::XRAY_DISCONNECT,
                    net_manager_core::daemon_protocol::method::XRAY_STATUS,
                ]
                .iter()
                .all(|method| result.capabilities.iter().any(|cap| cap == method))
            });
            #[cfg(target_arch = "x86_64")]
            let package_verified = {
                let root =
                    std::path::Path::new(net_manager_core::managed_xray::LINUX_XRAY_PACKAGE_ROOT);
                let executable =
                    net_manager_core::managed_xray::linux_managed_version_dir(root).join("xray");
                net_manager_core::managed_xray::verify_managed_linux_executable(root, &executable)
                    .is_ok()
            };
            #[cfg(not(target_arch = "x86_64"))]
            let package_verified = false;
            *entry = linux_xray_backend_availability(
                entry.clone(),
                &status,
                supported,
                package_verified,
            );
        }
    }
    Ok(availability)
}

fn backend_running_error(
    tunnels: &mut TunnelManager,
    profiles: &[Profile],
    backend: TunnelBackend,
) -> Result<(), String> {
    for profile in profiles.iter().filter(|p| p.backend == backend) {
        if tunnels.status(profile).state == TunnelState::Running {
            return Err(format!(
                "cannot change {backend:?} executable while profile '{}' is running",
                profile.name
            ));
        }
    }
    Ok(())
}

fn check_managed_replacement(
    current: Option<&BackendExecutableSetting>,
    managed_replacement_error: Option<&str>,
) -> Result<(), String> {
    if let Some(message) = managed_replacement_error {
        guard_managed_selection(current, message)?;
    }
    Ok(())
}

fn select_backend_executable(
    runtime: &mut RuntimeState,
    state: &AppState,
    backend: TunnelBackend,
    setting: Option<BackendExecutableSetting>,
    managed_replacement_error: Option<&str>,
) -> Result<(), String> {
    let current = state
        .backend_settings
        .get(backend)
        .map_err(|e| e.to_string())?;
    check_managed_replacement(current.as_ref(), managed_replacement_error)?;
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    backend_running_error(&mut runtime.tunnels, &profiles, backend)?;
    let executable = setting.as_ref().map(|s| s.path.clone());
    state
        .backend_settings
        .set(backend, setting)
        .map_err(|e| e.to_string())?;
    runtime.tunnels.set_executable(backend, executable);
    Ok(())
}

fn guard_managed_selection(
    setting: Option<&BackendExecutableSetting>,
    message: &str,
) -> Result<(), String> {
    if setting.is_some_and(|s| s.source == BackendExecutableSource::Managed) {
        return Err(message.to_string());
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn set_backend_executable(
    backend: TunnelBackend,
    path: PathBuf,
    state: State<'_, AppState>,
) -> Result<(), String> {
    resolve_backend_path(backend, Some(&path)).map_err(|e| e.to_string())?;
    let _install_guard = if backend == TunnelBackend::Xray {
        Some(state.backend_install_lock.lock().await)
    } else {
        None
    };
    let mut runtime = state.runtime.lock().await;
    select_backend_executable(
        &mut runtime,
        &state,
        backend,
        Some(BackendExecutableSetting {
            path,
            source: BackendExecutableSource::Configured,
            version: None,
        }),
        Some("remove the managed Xray installation before choosing another executable"),
    )
}

#[tauri::command]
pub(crate) async fn reset_backend_executable(
    backend: TunnelBackend,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let _install_guard = if backend == TunnelBackend::Xray {
        Some(state.backend_install_lock.lock().await)
    } else {
        None
    };
    let mut runtime = state.runtime.lock().await;
    select_backend_executable(
        &mut runtime,
        &state,
        backend,
        None,
        Some("remove the managed Xray installation instead of resetting it"),
    )
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ManagedXrayOffer {
    version: String,
    source_url: String,
    sha256: String,
    max_download_bytes: u64,
}

fn managed_xray_offer() -> ManagedXrayOffer {
    ManagedXrayOffer {
        version: MANAGED_XRAY_VERSION.to_string(),
        source_url: MANAGED_XRAY_URL.to_string(),
        sha256: managed_xray::MANAGED_XRAY_SHA256.to_string(),
        max_download_bytes: MAX_XRAY_ARCHIVE_BYTES as u64,
    }
}

#[tauri::command]
pub(crate) fn get_managed_xray_offer() -> ManagedXrayOffer {
    managed_xray_offer()
}

/// Which OS-specific features the frontend may offer on this platform.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlatformCapabilities {
    os: &'static str,
    system_proxy: bool,
    wireguard_standard_import: bool,
    managed_xray_install: bool,
    elevation_relaunch: bool,
    /// In-app updater: Windows and `.deb` installs; other Linux installs
    /// update through their package manager.
    app_updates: bool,
    /// File-picker extensions for backend executables; empty means no filter.
    executable_extensions: Vec<String>,
}

fn app_updates_available(windows: bool, bundle: Option<tauri::utils::config::BundleType>) -> bool {
    windows || matches!(bundle, Some(tauri::utils::config::BundleType::Deb))
}

fn platform_capabilities() -> PlatformCapabilities {
    let windows = cfg!(windows);
    PlatformCapabilities {
        os: std::env::consts::OS,
        system_proxy: windows,
        wireguard_standard_import: windows,
        managed_xray_install: cfg!(all(target_os = "windows", target_arch = "x86_64")),
        elevation_relaunch: windows,
        app_updates: app_updates_available(windows, tauri::utils::platform::bundle_type()),
        executable_extensions: if windows {
            vec!["exe".to_string()]
        } else {
            Vec::new()
        },
    }
}

#[tauri::command]
pub(crate) fn get_platform_capabilities() -> PlatformCapabilities {
    platform_capabilities()
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackendInstallProgress {
    backend: TunnelBackend,
    stage: String,
    downloaded: u64,
    total: Option<u64>,
}

// Used by `install_managed_xray_inner` on 64-bit Windows and directly by
// unit tests on every platform; never used by the plain (non-test,
// non-Windows) lib build, hence `any(test, ...)`.
#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
fn checked_download_len(current: usize, chunk_len: usize) -> io::Result<usize> {
    match current.checked_add(chunk_len) {
        Some(total) if total <= MAX_XRAY_ARCHIVE_BYTES => Ok(total),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed Xray download exceeds the maximum archive size",
        )),
    }
}

#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
fn append_download_chunk(buffer: &mut Vec<u8>, chunk: &[u8], cancelled: bool) -> io::Result<()> {
    if cancelled {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "managed Xray install cancelled",
        ));
    }
    checked_download_len(buffer.len(), chunk.len())?;
    buffer.extend_from_slice(chunk);
    Ok(())
}

#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
fn validate_download_length(actual: usize, declared: Option<u64>) -> io::Result<()> {
    if let Some(declared) = declared {
        if declared != actual as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "managed Xray download length did not match Content-Length",
            ));
        }
    }
    Ok(())
}

fn require_managed_xray_setting(
    setting: Option<BackendExecutableSetting>,
) -> Result<BackendExecutableSetting, String> {
    match setting {
        Some(setting)
            if setting.source == BackendExecutableSource::Managed
                && setting.version.as_deref() == Some(MANAGED_XRAY_VERSION) =>
        {
            Ok(setting)
        }
        Some(_) => Err("the selected Xray backend is not the managed installation".to_string()),
        None => Err("no managed Xray installation is selected".to_string()),
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn cleanup_created_installation(installation: &ManagedXrayInstallation) -> io::Result<()> {
    if installation.created {
        std::fs::remove_dir_all(&installation.version_dir)?;
    }
    Ok(())
}

#[cfg(any(test, all(target_os = "windows", target_arch = "x86_64")))]
fn install_failure_message(primary: String, cleanup: io::Result<()>) -> String {
    match cleanup {
        Ok(()) => primary,
        Err(err) => format!(
            "{primary}; cleanup of the created installation failed and files remain that require manual removal: {err}"
        ),
    }
}

#[tauri::command]
pub(crate) async fn install_managed_xray(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    install_managed_xray_inner(app, state.inner()).await
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
async fn install_managed_xray_inner(app: tauri::AppHandle, state: &AppState) -> Result<(), String> {
    use futures_util::StreamExt;
    use std::time::Duration;

    let _install_guard = state.backend_install_lock.lock().await;
    state.backend_install_cancel.store(false, Ordering::SeqCst);
    let progress = |stage: &str, downloaded: u64, total: Option<u64>| {
        let _ = app.emit(
            "backend-install-progress",
            BackendInstallProgress {
                backend: TunnelBackend::Xray,
                stage: stage.to_string(),
                downloaded,
                total,
            },
        );
    };

    {
        let mut runtime = state.runtime.lock().await;
        let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
        backend_running_error(&mut runtime.tunnels, &profiles, TunnelBackend::Xray)?;
    }

    progress("downloading", 0, None);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("Network-Orchestrator/0.1.0")
        .build()
        .map_err(|e| format!("cannot build download client: {e}"))?;
    let response = client
        .get(MANAGED_XRAY_URL)
        .send()
        .await
        .map_err(|e| format!("managed Xray download failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("managed Xray download failed: {e}"))?;
    let total = response.content_length();
    if total.is_some_and(|len| len > MAX_XRAY_ARCHIVE_BYTES as u64) {
        return Err("managed Xray archive is larger than the allowed maximum".to_string());
    }
    let mut buffer = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("managed Xray download failed: {e}"))?;
        match append_download_chunk(
            &mut buffer,
            &chunk,
            state.backend_install_cancel.load(Ordering::SeqCst),
        ) {
            Ok(()) => progress("downloading", buffer.len() as u64, total),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                progress("cancelled", buffer.len() as u64, total);
                return Err(err.to_string());
            }
            Err(err) => return Err(err.to_string()),
        }
    }
    validate_download_length(buffer.len(), total).map_err(|e| e.to_string())?;

    let downloaded = buffer.len() as u64;
    progress("verifying", downloaded, total);
    progress("installing", downloaded, total);
    let root = state.managed_xray_root.clone();
    let installation =
        tokio::task::spawn_blocking(move || managed_xray::install_verified_archive(&root, &buffer))
            .await
            .map_err(|e| format!("managed Xray install task failed: {e}"))?
            .map_err(|e| format!("managed Xray install failed: {e}"))?;

    progress("validating", downloaded, total);
    let validation = async {
        let output = tokio::process::Command::new(&installation.executable)
            .arg("version")
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| format!("cannot run managed Xray: {e}"))?;
        if !output.status.success() {
            return Err("managed Xray version check exited unsuccessfully".to_string());
        }
        let mut head = output.stdout;
        head.truncate(512);
        let text = String::from_utf8_lossy(&head);
        let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        if !first.to_lowercase().contains("xray") {
            return Err("installed binary did not report an Xray version".to_string());
        }
        Ok::<(), String>(())
    };
    match tokio::time::timeout(Duration::from_secs(10), validation).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            return Err(install_failure_message(
                err,
                cleanup_created_installation(&installation),
            ));
        }
        Err(_) => {
            return Err(install_failure_message(
                "managed Xray version check timed out".to_string(),
                cleanup_created_installation(&installation),
            ));
        }
    }

    if state.backend_install_cancel.load(Ordering::SeqCst) {
        progress("cancelled", downloaded, total);
        return Err(install_failure_message(
            "managed Xray install cancelled".to_string(),
            cleanup_created_installation(&installation),
        ));
    }

    let mut runtime = state.runtime.lock().await;
    let selection = select_backend_executable(
        &mut runtime,
        state,
        TunnelBackend::Xray,
        Some(BackendExecutableSetting {
            path: installation.executable.clone(),
            source: BackendExecutableSource::Managed,
            version: Some(MANAGED_XRAY_VERSION.to_string()),
        }),
        None,
    );
    if let Err(err) = selection {
        drop(runtime);
        return Err(install_failure_message(
            err,
            cleanup_created_installation(&installation),
        ));
    }
    drop(runtime);
    progress("ready", downloaded, total);
    Ok(())
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
async fn install_managed_xray_inner(
    _app: tauri::AppHandle,
    _state: &AppState,
) -> Result<(), String> {
    Err("managed Xray installation is only supported on 64-bit Windows".to_string())
}

#[tauri::command]
pub(crate) async fn cancel_managed_xray_install(state: State<'_, AppState>) -> Result<(), String> {
    state.backend_install_cancel.store(true, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
pub(crate) async fn remove_managed_xray(state: State<'_, AppState>) -> Result<(), String> {
    let _install_guard = state.backend_install_lock.lock().await;
    let mut runtime = state.runtime.lock().await;
    let profiles = state.profiles.load().map_err(|e| e.to_string())?.profiles;
    backend_running_error(&mut runtime.tunnels, &profiles, TunnelBackend::Xray)?;
    let setting = require_managed_xray_setting(
        state
            .backend_settings
            .get(TunnelBackend::Xray)
            .map_err(|e| e.to_string())?,
    )?;
    let managed =
        managed_xray::is_managed_executable_location(&state.managed_xray_root, &setting.path)
            .map_err(|e| format!("cannot verify managed Xray path: {e}"))?;
    if !managed {
        return Err("selected Xray executable is not inside the managed installation".to_string());
    }
    let version_dir = managed_xray::managed_version_dir(&state.managed_xray_root);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let quarantine = state.managed_xray_root.join(format!(
        "{MANAGED_XRAY_VERSION}.remove-{}-{nanos}",
        std::process::id()
    ));
    std::fs::rename(&version_dir, &quarantine)
        .map_err(|e| format!("cannot quarantine managed Xray: {e}"))?;
    if let Err(err) = state.backend_settings.set(TunnelBackend::Xray, None) {
        return Err(match std::fs::rename(&quarantine, &version_dir) {
            Ok(()) => format!("cannot clear managed Xray setting: {err}"),
            Err(rollback) => format!(
                "cannot clear managed Xray setting: {err}; rollback failed, quarantined files remain at '{}': {rollback}",
                quarantine.display()
            ),
        });
    }
    runtime.tunnels.set_executable(TunnelBackend::Xray, None);
    if let Err(err) = std::fs::remove_dir_all(&quarantine) {
        return Err(format!(
            "managed Xray backend was unselected, but quarantined files could not be removed: {err}"
        ));
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn restart_elevated(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if elevation::is_elevated().map_err(|e| e.to_string())? {
        return Ok(());
    }
    elevation::restart_elevated().map_err(|e| e.to_string())?;
    state.cleanup_complete.store(true, Ordering::SeqCst);
    app.exit(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{app_state, unique_dir};
    use std::io;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_capabilities_hide_windows_only_features() {
        let caps = platform_capabilities();
        assert_eq!(caps.os, "linux");
        assert!(!caps.system_proxy);
        assert!(!caps.wireguard_standard_import);
        assert!(!caps.managed_xray_install);
        assert!(!caps.elevation_relaunch);
        assert!(!caps.app_updates);
        assert!(caps.executable_extensions.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_wireguard_availability_tracks_daemon_without_executable_path() {
        use crate::daemon_client::{DaemonState, DaemonStatus};

        let dir = unique_dir("wg-availability");
        let state = app_state(&dir);
        let entry = collect_backend_availability(&state)
            .into_iter()
            .find(|entry| entry.backend == TunnelBackend::WireGuard)
            .unwrap();
        assert!(entry.path.is_none());
        assert!(!entry.message.contains("wireguard.exe"));

        let ready = linux_wireguard_backend_availability(
            DaemonStatus {
                state: DaemonState::Ready,
                message: "Network daemon is ready.".into(),
            },
            true,
        );
        assert!(ready.available);
        assert!(ready.path.is_none());
        let old = linux_wireguard_backend_availability(
            DaemonStatus {
                state: DaemonState::Ready,
                message: "Network daemon is ready.".into(),
            },
            false,
        );
        assert!(!old.available);
        assert!(old.message.contains("WireGuard"));
        let stopped = linux_wireguard_backend_availability(
            DaemonStatus {
                state: DaemonState::NotRunning,
                message: "Network daemon is not running.".into(),
            },
            false,
        );
        assert!(!stopped.available);
        assert!(stopped.message.contains("not running"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_openvpn_availability_tracks_daemon_without_executable_path() {
        use crate::daemon_client::{DaemonState, DaemonStatus};

        let dir = unique_dir("ovpn-availability");
        let state = app_state(&dir);
        let entry = collect_backend_availability(&state)
            .into_iter()
            .find(|entry| entry.backend == TunnelBackend::OpenVpn)
            .unwrap();
        assert!(entry.path.is_none());
        assert!(!entry.message.contains("openvpn.exe"));

        let ready = linux_openvpn_backend_availability(
            DaemonStatus {
                state: DaemonState::Ready,
                message: "Network daemon is ready.".into(),
            },
            true,
        );
        assert!(ready.available);
        assert!(ready.path.is_none());
        let old = linux_openvpn_backend_availability(
            DaemonStatus {
                state: DaemonState::Ready,
                message: "Network daemon is ready.".into(),
            },
            false,
        );
        assert!(!old.available);
        assert!(old.message.contains("OpenVPN"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_xray_tun_availability_requires_verified_package_and_daemon_methods() {
        let baseline = BackendAvailability {
            backend: TunnelBackend::Xray,
            available: false,
            path: None,
            source: None,
            version: None,
            message: "unavailable".into(),
        };
        let ready = crate::daemon_client::DaemonStatus {
            state: crate::daemon_client::DaemonState::Ready,
            message: "ready".into(),
        };
        let available = linux_xray_backend_availability(baseline.clone(), &ready, true, true);
        assert!(available.available);
        assert!(available.message.contains("TUN available"));
        assert!(!linux_xray_backend_availability(baseline.clone(), &ready, false, true).available);
        assert!(!linux_xray_backend_availability(baseline, &ready, true, false).available);
    }

    #[test]
    fn capabilities_serialize_with_frontend_field_names() {
        let value = serde_json::to_value(platform_capabilities()).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "appUpdates",
                "elevationRelaunch",
                "executableExtensions",
                "managedXrayInstall",
                "os",
                "systemProxy",
                "wireguardStandardImport",
            ]
        );
    }

    #[test]
    fn app_updates_follow_platform_and_deb_bundle() {
        use tauri::utils::config::BundleType;

        assert!(app_updates_available(true, None));
        assert!(app_updates_available(true, Some(BundleType::Nsis)));
        assert!(app_updates_available(false, Some(BundleType::Deb)));
        assert!(!app_updates_available(false, None));
        assert!(!app_updates_available(false, Some(BundleType::AppImage)));
        assert!(!app_updates_available(false, Some(BundleType::Rpm)));
    }

    #[cfg(windows)]
    #[test]
    fn windows_capabilities_expose_windows_features() {
        let caps = platform_capabilities();
        assert_eq!(caps.os, "windows");
        assert!(caps.system_proxy);
        assert!(caps.wireguard_standard_import);
        assert!(caps.elevation_relaunch);
        assert!(caps.app_updates);
        assert_eq!(caps.executable_extensions, vec!["exe".to_string()]);
    }

    #[test]
    fn backend_entry_maps_found_and_missing() {
        let found = backend_entry(
            TunnelBackend::WireGuard,
            Ok(ResolvedBackendExecutable {
                path: PathBuf::from(r"C:\tools\wireguard.exe"),
                source: BackendExecutableSource::AutoDetected,
                version: None,
            }),
            Ok(None),
        );
        assert!(found.available);
        assert_eq!(
            found.path.unwrap(),
            PathBuf::from(r"C:\tools\wireguard.exe")
        );

        let missing = backend_entry(
            TunnelBackend::Xray,
            Err(io::Error::new(io::ErrorKind::NotFound, "xray.exe missing")),
            Ok(None),
        );
        assert!(!missing.available);
        assert!(missing.path.is_none());
        assert!(missing.message.contains("xray.exe missing"));
    }

    #[test]
    fn availability_preserves_missing_configured_source() {
        let dir = unique_dir("avail-missing-cfg");
        let state = app_state(&dir);
        state
            .backend_settings
            .set(
                TunnelBackend::Xray,
                Some(BackendExecutableSetting {
                    path: PathBuf::from(r"C:\missing\xray.exe"),
                    source: BackendExecutableSource::Configured,
                    version: None,
                }),
            )
            .unwrap();

        let items = collect_backend_availability(&state);
        assert_eq!(
            items.iter().map(|i| i.backend).collect::<Vec<_>>(),
            vec![
                TunnelBackend::WireGuard,
                TunnelBackend::OpenVpn,
                TunnelBackend::Xray
            ]
        );

        let xray = items
            .iter()
            .find(|i| i.backend == TunnelBackend::Xray)
            .unwrap();
        assert!(!xray.available);
        assert_eq!(xray.path, Some(PathBuf::from(r"C:\missing\xray.exe")));
        assert_eq!(xray.source, Some(BackendExecutableSource::Configured));
        assert_eq!(xray.version, None);
        assert!(!xray.message.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn configured_selection_rejects_selected_managed_source() {
        let managed = Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\managed\v26.7.28\xray.exe"),
            source: BackendExecutableSource::Managed,
            version: Some(net_manager_core::managed_xray::MANAGED_XRAY_VERSION.to_string()),
        });
        let err = guard_managed_selection(
            managed.as_ref(),
            "remove the managed Xray installation before choosing another executable",
        )
        .unwrap_err();
        assert_eq!(
            err,
            "remove the managed Xray installation before choosing another executable"
        );

        let configured = Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\tools\xray.exe"),
            source: BackendExecutableSource::Configured,
            version: None,
        });
        assert!(guard_managed_selection(configured.as_ref(), "unused").is_ok());
        assert!(guard_managed_selection(None, "unused").is_ok());
    }

    #[test]
    fn reset_rejects_selected_managed_source() {
        let managed = Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\managed\v26.7.28\xray.exe"),
            source: BackendExecutableSource::Managed,
            version: Some(net_manager_core::managed_xray::MANAGED_XRAY_VERSION.to_string()),
        });
        let err = guard_managed_selection(
            managed.as_ref(),
            "remove the managed Xray installation instead of resetting it",
        )
        .unwrap_err();
        assert_eq!(
            err,
            "remove the managed Xray installation instead of resetting it"
        );
    }

    #[test]
    fn managed_install_is_the_only_allowed_managed_replacement() {
        let managed = Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\managed\v26.7.28\xray.exe"),
            source: BackendExecutableSource::Managed,
            version: Some(net_manager_core::managed_xray::MANAGED_XRAY_VERSION.to_string()),
        });
        assert!(
            check_managed_replacement(managed.as_ref(), None).is_ok(),
            "managed installer selection must be allowed to replace a managed setting"
        );
        assert!(check_managed_replacement(
            managed.as_ref(),
            Some("remove the managed Xray installation before choosing another executable")
        )
        .is_err());
        let configured = Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\tools\xray.exe"),
            source: BackendExecutableSource::Configured,
            version: None,
        });
        assert!(check_managed_replacement(configured.as_ref(), Some("any")).is_ok());
        assert!(check_managed_replacement(None, Some("any")).is_ok());
    }

    #[test]
    fn managed_offer_matches_pinned_core_constants() {
        let offer = managed_xray_offer();
        assert_eq!(
            offer.version,
            net_manager_core::managed_xray::MANAGED_XRAY_VERSION
        );
        assert_eq!(
            offer.source_url,
            net_manager_core::managed_xray::MANAGED_XRAY_URL
        );
        assert_eq!(
            offer.sha256,
            net_manager_core::managed_xray::MANAGED_XRAY_SHA256
        );
        assert_eq!(
            offer.max_download_bytes,
            net_manager_core::managed_xray::MAX_XRAY_ARCHIVE_BYTES as u64
        );
    }

    #[test]
    fn append_download_chunk_honors_cancel() {
        let mut buffer = Vec::new();
        let err = append_download_chunk(&mut buffer, b"chunk", true).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(buffer.is_empty());
    }

    #[test]
    fn append_download_chunk_enforces_limit() {
        let mut buffer = vec![0u8; net_manager_core::managed_xray::MAX_XRAY_ARCHIVE_BYTES];
        let err = append_download_chunk(&mut buffer, b"x", false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            buffer.len(),
            net_manager_core::managed_xray::MAX_XRAY_ARCHIVE_BYTES
        );

        let mut buffer = Vec::new();
        append_download_chunk(&mut buffer, b"abc", false).unwrap();
        assert_eq!(buffer, b"abc");
    }

    #[test]
    fn append_download_chunk_rejects_size_overflow() {
        let err = checked_download_len(usize::MAX, 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(checked_download_len(usize::MAX, 0).is_err());
        assert!(checked_download_len(0, 3).is_ok());
    }

    #[test]
    fn download_length_must_match_when_declared() {
        validate_download_length(10, None).unwrap();
        validate_download_length(10, Some(10)).unwrap();
        let err = validate_download_length(10, Some(20)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn cleanup_failure_is_reported_with_primary_error() {
        let message = install_failure_message(
            "primary failure".to_string(),
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
        );
        assert!(message.contains("primary failure"));
        assert!(message.contains("denied"));
        assert!(message.contains("manual"));

        let clean = install_failure_message("primary failure".to_string(), Ok(()));
        assert_eq!(clean, "primary failure");
    }

    #[test]
    fn managed_remove_rejects_configured_source() {
        let err = require_managed_xray_setting(Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\tools\xray.exe"),
            source: BackendExecutableSource::Configured,
            version: None,
        }))
        .unwrap_err();
        assert!(err.contains("managed"));

        assert!(require_managed_xray_setting(None).is_err());
    }
}
