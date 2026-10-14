//! Unprivileged runtime for the native client: Xray in loopback SOCKS/HTTP
//! mode plus the per-user macOS system proxy. Routes, interfaces and DNS stay
//! out of this crate; they belong to the privileged launchd helper (plan 14).
//! Xray TUN profiles are delegated to that helper over `daemon_protocol`
//! (`docs/plans/2026-10-14-16-macos-xray-tun.md`); this crate only asks.
use crate::vpn_backends;
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::daemon_protocol::{
    method, OpenVpnCredentials, XrayConnectParams, XrayConnectResult, XrayDisconnectResult,
    XrayProfileParams, XrayStatusResult,
};
use net_manager_core::helper_client::{HelperClient, HelperError};
use net_manager_core::managed_xray;
use net_manager_core::models::{
    Profile, TunnelBackend, TunnelRole, TunnelState, TunnelStatus, XrayMode,
};
use net_manager_core::profile_import;
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
const MAX_BYPASS_RESOLVERS: usize = 8;

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

fn is_tun(profile: &Profile) -> bool {
    profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Tun
}

fn helper() -> HelperClient {
    HelperClient::new(crate::helper_socket()).with_timeout(Duration::from_secs(20))
}

pub(crate) fn helper_error(error: HelperError) -> String {
    match error {
        HelperError::Unreachable(_) => {
            "The privileged helper is not running. Install it in Settings.".into()
        }
        HelperError::Rejected(body) => body.message,
        HelperError::Protocol(_) => "The privileged helper answered unexpectedly".into(),
    }
}

/// The helper owns the tunnel's Xray, which logs next to its socket.
fn tun_log_path() -> PathBuf {
    crate::helper_socket().with_file_name("xray-tun.log")
}

fn tun_log_tail() -> Option<String> {
    tail_of(&tun_log_path())
}

/// OpenVPN (run by the helper) logs next to the helper's socket.
fn openvpn_log_tail() -> Option<String> {
    tail_of(&crate::helper_socket().with_file_name("openvpn.log"))
}

fn tail_of(path: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(LOG_TAIL_BYTES as u64)))
        .ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn last_log_line(log: &str) -> Option<String> {
    log.lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
}

/// Live state of a TUN profile, from the helper. An unreachable helper owns
/// nothing, so the profile reads as stopped.
fn tun_status(profile: &Profile) -> TunnelStatus {
    tun_status_via(&helper(), profile)
}

fn tun_status_via(client: &HelperClient, profile: &Profile) -> TunnelStatus {
    let stopped = TunnelStatus {
        profile_id: profile.id.clone(),
        state: TunnelState::Stopped,
        message: None,
        interface_name: None,
    };
    match client.call::<_, XrayStatusResult>(
        method::XRAY_STATUS,
        XrayProfileParams {
            profile_id: profile.id.clone(),
        },
    ) {
        Ok(status) => TunnelStatus {
            message: (status.state == TunnelState::Failed)
                .then(|| tun_log_tail().and_then(|log| last_log_line(&log)))
                .flatten()
                .map(|line| format!("Xray stopped: {line}")),
            state: status.state,
            interface_name: status.interface_name,
            ..stopped
        },
        Err(_) => stopped,
    }
}

fn status_of(session: &mut Session, profile: &Profile) -> TunnelStatus {
    if is_tun(profile) {
        tun_status(profile)
    } else if vpn_backends::is_wireguard(profile) {
        vpn_backends::wireguard_status(&helper(), profile)
    } else if vpn_backends::is_openvpn(profile) {
        vpn_backends::openvpn_status(&helper(), profile)
    } else {
        session.tunnels.status(profile)
    }
}

fn running(session: &mut Session, profile: &Profile) -> bool {
    status_of(session, profile).state == TunnelState::Running
}

fn stop(session: &mut Session, profile: &Profile) -> Result<(), String> {
    if vpn_backends::is_wireguard(profile) || vpn_backends::is_openvpn(profile) {
        return vpn_backends::stop(&helper(), profile, helper_error);
    }
    if is_tun(profile) {
        let result: XrayDisconnectResult = helper()
            .call(
                method::XRAY_DISCONNECT,
                XrayProfileParams {
                    profile_id: profile.id.clone(),
                },
            )
            .map_err(helper_error)?;
        return result
            .stopped
            .then_some(())
            .ok_or_else(|| "The connection is not running".into());
    }
    session
        .tunnels
        .disconnect(profile)
        .map(|_| ())
        .map_err(|_| "The connection is not running".to_string())
}

fn statuses(session: &mut Session, profiles: &[Profile]) -> Vec<TunnelStatus> {
    profiles
        .iter()
        .map(|profile| status_of(session, profile))
        .collect()
}

/// IPv4 resolvers the machine currently uses; they keep a direct route
/// around the tunnel so name resolution survives while it captures traffic.
fn resolver_bypass() -> Vec<String> {
    let mut resolvers: Vec<String> = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.strip_prefix("nameserver "))
        .filter_map(|ip| ip.trim().parse::<std::net::Ipv4Addr>().ok())
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| ip.to_string())
        .collect();
    resolvers.dedup();
    resolvers.truncate(MAX_BYPASS_RESOLVERS);
    resolvers
}

/// Start a full-tunnel Xray through the privileged helper.
fn start_tun(root: &Path, profile: &Profile) -> Result<(), String> {
    vpn_backends::check_role(profile)?;
    let client = helper();
    let hello = client.hello().map_err(helper_error)?;
    if !hello
        .capabilities
        .iter()
        .any(|name| name == method::XRAY_CONNECT)
    {
        return Err(HELPER_REQUIRED.into());
    }
    let executable = managed_executable(root).ok_or("Install Xray to start this connection")?;
    let config = net_manager_core::vpn::prepare_xray_config_base(profile)
        .map_err(|_| "The Xray configuration could not be prepared".to_string())?;
    // Validated here, as the user: a tun inbound would need privileges, and
    // the helper adds it only after this passes.
    net_manager_core::vpn::run_xray_validation(&executable, &config)
        .map_err(|_| "The Xray configuration is invalid".to_string())?;
    request_tunnel(&client, root, profile, config, resolver_bypass())
}

/// The `xray.connect` request. The config carries no tun inbound: the helper
/// picks the uplink and adds it, so no caller can steer the binding.
fn request_tunnel(
    client: &HelperClient,
    root: &Path,
    profile: &Profile,
    config: Vec<u8>,
    dns_bypass: Vec<String>,
) -> Result<(), String> {
    let params = XrayConnectParams {
        profile_id: profile.id.clone(),
        config: String::from_utf8(config)
            .map_err(|_| "The Xray configuration could not be prepared".to_string())?,
        // A secondary connection carries only its own networks and leaves the
        // default route, the system DNS and the resolver bypasses to the primary.
        routes: if profile.tunnel_role == TunnelRole::Secondary {
            profile.secondary_routes()
        } else {
            Vec::new()
        },
        dns_servers: Vec::new(),
        dns_domains: Vec::new(),
        dns_bypass: if profile.tunnel_role == TunnelRole::Secondary {
            Vec::new()
        } else {
            dns_bypass
        },
        interface_name: None,
        geo_assets: None,
        macos_data_root: Some(root.to_string_lossy().into_owned()),
        role: profile.tunnel_role,
    };
    client
        .call::<_, XrayConnectResult>(method::XRAY_CONNECT, params)
        .map(|_| ())
        .map_err(helper_error)
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

pub(crate) fn is_running(root: &Path, profile: &Profile) -> Result<bool, String> {
    with_session(root, |session| Ok(running(session, profile)))
}

/// Move the profile off listener ports another process already holds; the
/// new ports are persisted so the system proxy and the UI follow them.
fn free_listener_ports(root: &Path, store: &ProfileStore, profile: &mut Profile) {
    let Ok(mut profiles) = store.load().map(|document| document.profiles) else {
        return;
    };
    let vault = ConfigVault::new(root.join("configs"));
    let _ = profile_import::prepare_connect_ports(&vault, store, profile, &mut profiles, |port| {
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok()
    });
}

/// Start a loopback Xray connection and confirm it survived startup.
fn start(
    root: &Path,
    store: &ProfileStore,
    profile: &Profile,
    credentials: Option<OpenVpnCredentials>,
) -> Result<(), String> {
    let mut profile = profile.clone();
    if vpn_backends::is_wireguard(&profile) || vpn_backends::is_openvpn(&profile) {
        let profile = &profile;
        return with_session(root, |session| {
            if running(session, profile) {
                return Err("The connection is already running".into());
            }
            let client = helper();
            if vpn_backends::is_wireguard(profile) {
                vpn_backends::start_wireguard(root, &client, profile)
            } else {
                vpn_backends::start_openvpn(root, &client, profile, credentials)
            }
        });
    }
    if is_tun(&profile) {
        let profile = &profile;
        return with_session(root, |session| {
            // The tunnel captures everything; a leftover per-app proxy for
            // this profile would point at a listener that no longer runs.
            if session
                .proxy
                .ownership()
                .is_some_and(|owner| owner.profile_id == profile.id)
            {
                session
                    .proxy
                    .restore(&profile.id)
                    .map_err(|_| "The previous system proxy could not be restored".to_string())?;
            }
            if running(session, profile) {
                return Err("The connection is already running".into());
            }
            start_tun(root, profile)
        });
    }
    if profile.backend != TunnelBackend::Xray {
        return Err(HELPER_REQUIRED.into());
    }
    let executable = managed_executable(root).ok_or("Install Xray to start this connection")?;
    free_listener_ports(root, store, &mut profile);
    let profile = &profile;
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
    let was_running = with_session(root, |session| Ok(running(session, &before)))?;
    if was_running {
        with_session(root, |session| {
            stop(session, &before).map_err(|_| "The connection could not be restarted".to_string())
        })?;
    }
    let result = change();
    if was_running {
        let after = find(&load()?, &id_arg)?;
        start(root, store, &after, None)?;
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
        "credential_requirements" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            let needs = vpn_backends::requirements(root, &profile)?;
            Ok(json!({"userPass": needs.user_pass, "keyPassphrase": needs.key_passphrase}))
        }),
        "connect" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            start(
                root,
                store,
                &profile,
                vpn_backends::credentials_from_args(args),
            )?;
            let profiles = load()?;
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
                stop(session, &profile)?;
                Ok(snapshot(root, session, &profiles))
            })
        }),
        "set_system_proxy" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            let enable = args["enabled"].as_str() == Some("true");
            with_session(root, |session| {
                if enable {
                    if is_tun(&profile) {
                        return Err("The system proxy is not used in tunnel mode".into());
                    }
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
                    if running(session, profile) {
                        let _ = stop(session, profile);
                    }
                }
                restored
                    .map_err(|_| "The previous system proxy could not be restored".to_string())?;
                Ok(json!({}))
            })
        }),
        "log" => load().and_then(|profiles| {
            let profile = find(&profiles, args)?;
            if is_tun(&profile) {
                return Ok(json!(tun_log_tail().unwrap_or_default()));
            }
            if vpn_backends::is_openvpn(&profile) {
                return Ok(json!(openvpn_log_tail().unwrap_or_default()));
            }
            if vpn_backends::is_wireguard(&profile) {
                // The engine keeps no text log; the status carries its notices.
                return Ok(json!(""));
            }
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
    use net_manager_core::daemon_protocol::{
        encode_line, ErrorCode, HelloResult, RequestFrame, ResponseFrame, PROTOCOL_VERSION,
    };
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

    #[test]
    fn stale_pattern_is_anchored_and_escaped() {
        let pattern = stale_xray_pattern(Path::new("/data/x.y/backends/xray/v26.7.28/xray"));
        assert_eq!(
            pattern,
            "^/data/x\\.y/backends/xray/v26\\.7\\.28/xray run -config stdin:$"
        );
    }

    fn tun_profile() -> Profile {
        Profile {
            id: "tun1".into(),
            name: "Tun".into(),
            backend: TunnelBackend::Xray,
            xray_mode: XrayMode::Tun,
            ..Default::default()
        }
    }

    /// Serves hello plus one request; reports the request it saw.
    fn fake_helper(
        dir: &Path,
        reply: impl FnOnce(&RequestFrame) -> ResponseFrame + Send + 'static,
    ) -> (HelperClient, mpsc::Receiver<RequestFrame>) {
        let socket = dir.join("h.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let hello: RequestFrame = serde_json::from_str(&line).unwrap();
            let result = HelloResult {
                protocol: PROTOCOL_VERSION,
                daemon_version: "t".into(),
                uid: 501,
                capabilities: vec![method::XRAY_CONNECT.into()],
                tools: Default::default(),
            };
            let ok = ResponseFrame::ok(hello.id, serde_json::to_value(result).unwrap());
            stream.write_all(&encode_line(&ok).unwrap()).unwrap();
            line.clear();
            if reader.read_line(&mut line).unwrap() > 0 {
                let request: RequestFrame = serde_json::from_str(&line).unwrap();
                let response = reply(&request);
                let _ = tx.send(request);
                stream.write_all(&encode_line(&response).unwrap()).unwrap();
            }
        });
        (HelperClient::new(socket), rx)
    }

    fn status_json(state: &str) -> Value {
        json!({"profileId":"tun1","state":state,"interfaceName":"utun10",
               "dnsApplied":true,"ipv4Covered":true,"ipv6Covered":true})
    }

    #[test]
    fn tunnel_request_carries_config_and_data_root_but_no_uplink_or_tun_inbound() {
        let dir = tempfile::tempdir().unwrap();
        let (client, seen) = fake_helper(dir.path(), |request| {
            ResponseFrame::ok(request.id, json!({"status": status_json("running")}))
        });
        let config = br#"{"inbounds":[{"protocol":"socks"}],"outbounds":[]}"#.to_vec();
        request_tunnel(
            &client,
            Path::new("/data/root"),
            &tun_profile(),
            config,
            vec!["192.168.1.1".into()],
        )
        .unwrap();
        let request = seen.recv().unwrap();
        assert_eq!(request.method, method::XRAY_CONNECT);
        assert_eq!(request.params["profileId"], "tun1");
        assert_eq!(request.params["macosDataRoot"], "/data/root");
        assert_eq!(request.params["dnsBypass"], json!(["192.168.1.1"]));
        let text = request.params["config"].as_str().unwrap();
        let sent: Value = serde_json::from_str(text).unwrap();
        assert!(!net_manager_core::xray::has_tun_inbound(&sent));
        assert!(!text.contains("autoOutboundsInterface"));
    }

    #[test]
    fn helper_refusals_reach_the_user_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let (client, _) = fake_helper(dir.path(), |request| {
            ResponseFrame::error(
                request.id,
                ErrorCode::Conflict,
                "another VPN already owns the default route",
            )
        });
        let error = request_tunnel(
            &client,
            Path::new("/d"),
            &tun_profile(),
            b"{}".to_vec(),
            vec![],
        )
        .unwrap_err();
        assert_eq!(error, "another VPN already owns the default route");
    }

    #[test]
    fn tun_status_maps_the_helper_state_and_an_absent_helper_reads_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let (client, _) = fake_helper(dir.path(), |request| {
            ResponseFrame::ok(request.id, status_json("running"))
        });
        let status = tun_status_via(&client, &tun_profile());
        assert_eq!(status.state, TunnelState::Running);
        assert_eq!(status.interface_name.as_deref(), Some("utun10"));
        let missing = HelperClient::new(dir.path().join("none.sock"));
        assert_eq!(
            tun_status_via(&missing, &tun_profile()).state,
            TunnelState::Stopped
        );
    }

    #[test]
    fn only_xray_tun_profiles_are_delegated() {
        assert!(is_tun(&tun_profile()));
        let mut socks = tun_profile();
        socks.xray_mode = XrayMode::Socks;
        assert!(!is_tun(&socks));
        let mut other = tun_profile();
        other.backend = TunnelBackend::WireGuard;
        assert!(!is_tun(&other));
    }

    #[test]
    fn unreachable_helper_gets_an_actionable_message() {
        let error = helper_error(HelperError::Unreachable(std::io::Error::other("x")));
        assert!(error.contains("Install it in Settings"));
    }
}
