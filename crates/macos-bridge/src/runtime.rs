//! Unprivileged runtime for the native client: Xray in loopback SOCKS/HTTP
//! mode plus the per-user macOS system proxy. Routes, interfaces and DNS stay
//! out of this crate; they belong to the privileged launchd helper (plan 14).
use net_manager_core::managed_xray;
use net_manager_core::models::{Profile, TunnelBackend, TunnelState, TunnelStatus, XrayMode};
use net_manager_core::profiles::ProfileStore;
use net_manager_core::system_proxy::SystemProxyManager;
use net_manager_core::vpn::TunnelManager;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

const HELPER_REQUIRED: &str =
    "This connection type needs the macOS privileged helper, which is not available yet";
const LOG_TAIL_BYTES: usize = 16 * 1024;

struct Session {
    tunnels: TunnelManager,
    proxy: SystemProxyManager,
}

/// One session per data root, so isolated QA directories never share state.
static SESSIONS: Mutex<Option<HashMap<PathBuf, Session>>> = Mutex::new(None);

fn xray_root(root: &Path) -> PathBuf {
    root.join("backends").join("xray")
}

pub(crate) fn managed_executable(root: &Path) -> Option<PathBuf> {
    let xray = xray_root(root);
    let executable = managed_xray::macos_managed_version_dir(&xray).join("xray");
    managed_xray::verify_managed_macos_executable(&xray, &executable)
        .ok()
        .map(|_| executable)
}

/// After a crash nothing we spawned can still be owned, so stale Xray
/// processes from our managed path are stopped and a proxy left pointing at
/// them is rolled back before anything else runs.
fn recover(root: &Path, proxy: &mut SystemProxyManager) {
    let executable = managed_xray::macos_managed_version_dir(&xray_root(root)).join("xray");
    if executable.is_file() {
        let _ = std::process::Command::new("/usr/bin/pkill")
            .arg("-f")
            .arg(stale_xray_pattern(&executable))
            .status();
    }
    let _ = proxy.restore_any();
}

/// Matches exactly the command line `TunnelManager` uses for our managed Xray,
/// so unrelated processes that merely mention the path are never signalled.
fn stale_xray_pattern(executable: &Path) -> String {
    let escaped: String = executable
        .to_string_lossy()
        .chars()
        .flat_map(|c| {
            let special = "\\^$.|?*+()[]{}".contains(c);
            special
                .then_some('\\')
                .into_iter()
                .chain(std::iter::once(c))
        })
        .collect();
    format!("^{escaped} run -config stdin:$")
}

fn with_session<T>(
    root: &Path,
    action: impl FnOnce(&mut Session) -> Result<T, String>,
) -> Result<T, String> {
    let mut sessions = SESSIONS
        .lock()
        .map_err(|_| "Connection service is unavailable".to_string())?;
    let sessions = sessions.get_or_insert_with(HashMap::new);
    if !sessions.contains_key(root) {
        let runtime = root.join("runtime");
        let mut proxy = SystemProxyManager::new(runtime.join("system-proxy.json"))
            .map_err(|_| "System proxy state could not be read".to_string())?;
        recover(root, &mut proxy);
        let session = Session {
            tunnels: TunnelManager::with_log_dir(runtime.join("logs")),
            proxy,
        };
        sessions.insert(root.to_path_buf(), session);
    }
    action(sessions.get_mut(root).expect("session inserted above"))
}

fn find(profiles: &[Profile], args: &Value) -> Result<Profile, String> {
    let id = args["id"].as_str().unwrap_or_default();
    profiles
        .iter()
        .find(|profile| profile.id == id)
        .cloned()
        .ok_or_else(|| "Profile not found".into())
}

fn statuses(session: &mut Session, profiles: &[Profile]) -> Vec<TunnelStatus> {
    profiles
        .iter()
        .map(|profile| session.tunnels.status(profile))
        .collect()
}

fn snapshot(root: &Path, session: &mut Session, profiles: &[Profile]) -> Value {
    json!({
        "xrayInstalled": managed_executable(root).is_some(),
        "xrayVersion": managed_xray::MACOS_XRAY_VERSION,
        "statuses": statuses(session, profiles),
        "systemProxyOwner": session.proxy.ownership().map(|owner| owner.profile_id.clone()),
    })
}

/// Local DNS search domains (e.g. corporate `*.corp.lan`) always bypass the
/// proxy so intranet names keep resolving through the local network.
fn search_domain_bypass() -> Vec<String> {
    std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.strip_prefix("search "))
        .flat_map(str::split_whitespace)
        .filter(|domain| {
            domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        })
        .map(|domain| format!("*.{domain}"))
        .collect()
}

fn failure_message(session: &TunnelManager, profile: &Profile) -> String {
    let tail = session
        .log_tail(&profile.id, LOG_TAIL_BYTES)
        .ok()
        .flatten()
        .and_then(|log| {
            log.lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(str::to_string)
        });
    match tail {
        Some(line) => format!("Xray stopped: {}", line.trim()),
        None => "Xray could not start".into(),
    }
}

/// Start a loopback Xray connection and confirm it survived startup.
fn start(root: &Path, profile: &Profile) -> Result<(), String> {
    if profile.backend != TunnelBackend::Xray || profile.xray_mode != XrayMode::Socks {
        return Err(HELPER_REQUIRED.into());
    }
    let executable = managed_executable(root).ok_or("Install Xray to start this connection")?;
    with_session(root, |session| {
        session
            .tunnels
            .set_executable(TunnelBackend::Xray, Some(executable));
        session.tunnels.connect(profile).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "The connection is already running".to_string()
            } else {
                failure_message(&session.tunnels, profile)
            }
        })?;
        // Xray exits immediately on a bad config or a busy port.
        std::thread::sleep(Duration::from_millis(600));
        if session.tunnels.status(profile).state != TunnelState::Running {
            return Err(failure_message(&session.tunnels, profile));
        }
        Ok(())
    })
}

/// Run a change to a profile's configuration (endpoint switch, refresh) and,
/// when the connection was running, restart it on the new configuration. The
/// system proxy ownership is kept across the restart.
pub(crate) fn restart_around(
    root: &Path,
    store: &ProfileStore,
    id: &str,
    change: impl FnOnce() -> Result<Value, String>,
) -> Result<Value, String> {
    let load = || {
        store
            .load()
            .map(|document| document.profiles)
            .map_err(|_| "Profiles could not be loaded".to_string())
    };
    let id_arg = json!({ "id": id });
    let before = find(&load()?, &id_arg)?;
    let was_running = with_session(root, |session| {
        Ok(session.tunnels.status(&before).state == TunnelState::Running)
    })?;
    if was_running {
        with_session(root, |session| {
            session
                .tunnels
                .disconnect(&before)
                .map(|_| ())
                .map_err(|_| "The connection could not be restarted".to_string())
        })?;
    }
    let result = change();
    if was_running {
        let after = find(&load()?, &id_arg)?;
        start(root, &after)?;
    }
    result
}

pub(crate) fn handle(
    root: &Path,
    store: &ProfileStore,
    method: &str,
    args: &Value,
) -> Option<Result<Value, String>> {
    let load = || {
        store
            .load()
            .map(|document| document.profiles)
            .map_err(|_| "Profiles could not be loaded".to_string())
    };
    let result = match method {
        "runtime" => load().and_then(|profiles| {
            with_session(root, |session| Ok(snapshot(root, session, &profiles)))
        }),
        "install_xray" => install_xray(root, args["archivePath"].as_str()),
        "connect" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            start(root, &profile)?;
            with_session(root, |session| Ok(snapshot(root, session, &profiles)))
        }),
        "disconnect" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            with_session(root, |session| {
                if session
                    .proxy
                    .ownership()
                    .is_some_and(|owner| owner.profile_id == profile.id)
                {
                    session.proxy.restore(&profile.id).map_err(|_| {
                        "The previous system proxy could not be restored".to_string()
                    })?;
                }
                session
                    .tunnels
                    .disconnect(&profile)
                    .map_err(|_| "The connection is not running".to_string())?;
                Ok(snapshot(root, session, &profiles))
            })
        }),
        "set_system_proxy" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            let enable = args["enabled"].as_str() == Some("true");
            with_session(root, |session| {
                if enable {
                    if session.tunnels.status(&profile).state != TunnelState::Running {
                        return Err("Start the connection first".into());
                    }
                    let socks = profile
                        .xray_socks_port
                        .ok_or("This connection has no local proxy port")?;
                    session
                        .proxy
                        .apply_with_http(
                            &profile.id,
                            socks,
                            profile.xray_http_port,
                            &search_domain_bypass(),
                        )
                        .map_err(|error| {
                            if error.kind() == std::io::ErrorKind::AlreadyExists {
                                "Another connection already owns the system proxy".to_string()
                            } else {
                                "The system proxy could not be changed".to_string()
                            }
                        })?;
                } else if session.proxy.ownership().is_some() {
                    session.proxy.restore(&profile.id).map_err(|_| {
                        "The previous system proxy could not be restored".to_string()
                    })?;
                }
                Ok(snapshot(root, session, &profiles))
            })
        }),
        "shutdown" => load().and_then(|profiles| {
            with_session(root, |session| {
                let restored = session.proxy.restore_any();
                for profile in &profiles {
                    if session.tunnels.status(profile).state == TunnelState::Running {
                        let _ = session.tunnels.disconnect(profile);
                    }
                }
                restored
                    .map_err(|_| "The previous system proxy could not be restored".to_string())?;
                Ok(json!({}))
            })
        }),
        "log" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            with_session(root, |session| {
                Ok(json!(session
                    .tunnels
                    .log_tail(&profile.id, LOG_TAIL_BYTES)
                    .ok()
                    .flatten()
                    .unwrap_or_default()))
            })
        }),
        _ => return None,
    };
    Some(result)
}

/// Installs the pinned Xray either by download or, for closed networks, from
/// a user-supplied copy of the same official zip; both paths are hash-checked.
fn install_xray(root: &Path, archive_path: Option<&str>) -> Result<Value, String> {
    if managed_executable(root).is_some() {
        return Ok(json!({"installed": true}));
    }
    let archive = match archive_path.filter(|path| !path.is_empty()) {
        Some(path) => {
            let metadata = std::fs::metadata(path)
                .map_err(|_| "The selected Xray archive could not be read".to_string())?;
            if metadata.len() > managed_xray::MAX_XRAY_ARCHIVE_BYTES as u64 {
                return Err("The downloaded Xray package failed verification".into());
            }
            std::fs::read(path)
                .map_err(|_| "The selected Xray archive could not be read".to_string())?
        }
        None => crate::runtime_executor()?
            .block_on(managed_xray::download_archive(managed_xray::MACOS_XRAY_URL))
            .map_err(|_| {
                "Xray could not be downloaded. Check the network connection.".to_string()
            })?,
    };
    let installed = managed_xray::install_verified_macos_archive(&xray_root(root), &archive)
        .map_err(|_| "The downloaded Xray package failed verification".to_string())?;
    let version = std::process::Command::new(&installed.executable)
        .arg("version")
        .output()
        .map_err(|_| "The installed Xray could not run".to_string())?;
    if !version.status.success() {
        return Err("The installed Xray could not run".into());
    }
    Ok(json!({"installed": true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_pattern_is_anchored_and_escaped() {
        let pattern = stale_xray_pattern(Path::new("/data/x.y/backends/xray/v26.7.28/xray"));
        assert_eq!(
            pattern,
            "^/data/x\\.y/backends/xray/v26\\.7\\.28/xray run -config stdin:$"
        );
    }
}
