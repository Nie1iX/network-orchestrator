//! `sudo netorch up`: the helper's executors run inside this process, so no
//! launchd helper is needed. They are the same executors, with the same rules
//! (Xray as the console user only, the pinned OpenVPN copy, WireGuard
//! in-process), and they use the helper's own journal for crash recovery.
//! The tunnel lives as long as this process; `Ctrl+C` tears it down.
use net_manager_core::daemon_protocol::{HelloResult, RequestFrame, PROTOCOL_VERSION};
use net_manager_core::helper_client::{HelperClient, HelperError};
use net_manager_engine::Privileged;
use network_orchestrator_macos_helper::journal::Journal;
use network_orchestrator_macos_helper::openvpn::OpenVpnExecutor;
use network_orchestrator_macos_helper::peer::{console_uid, Peer};
use network_orchestrator_macos_helper::platform::{RealOvpnPlatform, RealPlatform, RealWgPlatform};
use network_orchestrator_macos_helper::server::Handler;
use network_orchestrator_macos_helper::service::HelperService;
use network_orchestrator_macos_helper::sysexec::SystemRunner;
use network_orchestrator_macos_helper::wireguard::WireGuardExecutor;
use network_orchestrator_macos_helper::xray::XrayExecutor;
use network_orchestrator_macos_helper::{resolver, SOCKET_DIR, STATE_DIR};
use serde_json::Value;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct InProcess {
    service: HelperService,
    xray: Arc<XrayExecutor>,
    wireguard: Arc<WireGuardExecutor>,
    openvpn: Arc<OpenVpnExecutor>,
    uid: u32,
    log_dir: PathBuf,
    _lock: File,
}

/// Who the executors act for: the console user, like the helper's peer
/// policy. `sudo` from anybody else is refused.
fn invoking_uid(console: Option<u32>, sudo_uid: Option<u32>) -> Result<u32, String> {
    let console = console.ok_or("Nobody is logged in at the console")?;
    match sudo_uid {
        Some(sudo) if sudo != console => Err(
            "netorch runs tunnels only for the user logged in at the console; \
             run sudo from that account"
                .into(),
        ),
        _ => Ok(console),
    }
}

fn private_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|_| "A system directory could not be created".to_string())?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .map_err(|_| "A system directory could not be secured".to_string())
}

impl InProcess {
    /// Refuses when the launchd helper is up (two owners of the same tunnels
    /// would tear each other down) or another sudo netorch holds the lock.
    pub fn start(helper_socket: &Path) -> Result<Self, String> {
        // SAFETY: geteuid never fails.
        if unsafe { libc::geteuid() } != 0 {
            return Err("This mode needs root: run it with sudo".into());
        }
        if !matches!(
            HelperClient::new(helper_socket).hello(),
            Err(HelperError::Unreachable(_))
        ) {
            return Err(
                "The Network Orchestrator helper is running; use netorch without sudo".into(),
            );
        }
        let sudo_uid = std::env::var("SUDO_UID")
            .ok()
            .and_then(|uid| uid.parse().ok());
        let uid = invoking_uid(console_uid(), sudo_uid)?;
        let socket_dir = Path::new(SOCKET_DIR);
        private_dir(socket_dir)?;
        private_dir(Path::new(STATE_DIR))?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(socket_dir.join("netorch-inproc.lock"))
            .map_err(|_| "The tunnel lock could not be opened".to_string())?;
        // SAFETY: flock on a descriptor owned by `lock`.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("Another sudo netorch already runs the tunnels".into());
        }
        let state_dir = Path::new(STATE_DIR);
        let xray = Arc::new(XrayExecutor::new(
            Box::new(RealPlatform),
            Box::new(SystemRunner),
            Journal::new(state_dir),
            socket_dir.join("xray-tun.log"),
        ));
        let wireguard = Arc::new(WireGuardExecutor::new(
            Box::new(RealWgPlatform),
            Box::new(SystemRunner),
            Journal::named(state_dir, "wireguard.json"),
            PathBuf::from(resolver::DIR),
        ));
        let openvpn = Arc::new(OpenVpnExecutor::new(
            Box::new(RealOvpnPlatform {
                stage_dir: state_dir.join("backends"),
                log: socket_dir.join("openvpn.log"),
                bundle: None,
            }),
            Box::new(SystemRunner),
            Journal::named(state_dir, "openvpn.json"),
            PathBuf::from(network_orchestrator_macos_helper::openvpn::RUNTIME_ROOT),
            PathBuf::from(resolver::DIR),
        ));
        // What a crashed earlier run left behind must not outlive its owner.
        for (name, result) in [
            ("xray", xray.recover()),
            ("wireguard", wireguard.recover()),
            ("openvpn", openvpn.recover()),
        ] {
            if let Err(error) = result {
                eprintln!("netorch: {name} recovery failed: {error}");
            }
        }
        let watch = (xray.clone(), wireguard.clone(), openvpn.clone());
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            watch.0.reap();
            watch.1.reap();
            watch.2.reap();
        });
        Ok(Self {
            service: HelperService::new(xray.clone(), wireguard.clone(), openvpn.clone()),
            xray,
            wireguard,
            openvpn,
            uid,
            log_dir: socket_dir.to_path_buf(),
            _lock: lock,
        })
    }

    /// Tears every tunnel of this process down.
    pub fn shutdown(&self) {
        self.xray.shutdown();
        self.wireguard.shutdown();
        self.openvpn.shutdown();
    }
}

impl Privileged for InProcess {
    fn hello(&self) -> Result<HelloResult, HelperError> {
        Ok(HelloResult {
            protocol: PROTOCOL_VERSION,
            daemon_version: env!("NETORCH_VERSION").into(),
            uid: self.uid,
            capabilities: self.service.capabilities(),
            tools: self.service.tools(),
        })
    }

    fn call_raw(&self, method: &str, params: Value) -> Result<Value, HelperError> {
        let peer = Peer {
            uid: self.uid,
            pid: std::process::id(),
        };
        let response = self.service.handle(
            &peer,
            RequestFrame {
                id: 2,
                method: method.into(),
                params,
            },
        );
        response.outcome.map_err(HelperError::Rejected)
    }

    fn validates_locally(&self) -> bool {
        false
    }

    fn log_dir(&self) -> PathBuf {
        self.log_dir.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnels_run_only_for_the_console_user() {
        assert_eq!(invoking_uid(Some(501), Some(501)), Ok(501));
        assert_eq!(invoking_uid(Some(501), None), Ok(501));
        assert!(invoking_uid(Some(501), Some(502)).is_err());
        assert!(invoking_uid(None, Some(501)).is_err());
    }

    #[test]
    fn without_root_it_refuses_to_start() {
        // SAFETY: getuid never fails.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let error = InProcess::start(Path::new("/nonexistent.sock"))
            .err()
            .unwrap();
        assert!(error.contains("needs root"));
    }
}
