//! The real machine behind [`crate::xray::Platform`]: utun creation, the
//! hash-verified managed Xray, and launching it as the console user.

use crate::backends::{bundle_contents, Catalog};
use crate::openvpn::{OvpnPlatform, SpawnSpec as OvpnSpawn};
use crate::tun;
use crate::wg_engine::{PacketIo, UtunIo};
use crate::wireguard::WgPlatform;
use crate::xray::{Error, Platform, Process, SpawnSpec, TunDevice, CHILD_TUN_FD};
use std::ffi::{CStr, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Bundle-relative data folder of the native client, below the user's
/// `~/Library/Application Support`.
const APP_DATA_DIR: &str = "com.netmanager.app.macos";
const SETTLE: Duration = Duration::from_millis(700);
const MAX_RESOLVED_BYPASS: usize = 16;

pub struct RealPlatform;

struct Account {
    name: String,
    gid: u32,
    home: PathBuf,
}

fn account(uid: u32) -> io::Result<Account> {
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call; `result` points into them.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut passwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return Err(io::Error::other("the console user has no account"));
    }
    // SAFETY: getpwuid_r filled these C strings inside `buffer`.
    let (name, home) = unsafe {
        (
            CStr::from_ptr(passwd.pw_name)
                .to_string_lossy()
                .into_owned(),
            CStr::from_ptr(passwd.pw_dir).to_bytes().to_vec(),
        )
    };
    Ok(Account {
        name,
        gid: passwd.pw_gid,
        home: PathBuf::from(OsStr::from_bytes(&home)),
    })
}

fn denied(message: &str) -> Error {
    Error::Unavailable(message.into())
}

/// `<data root>/backends/xray/<pinned version>/xray`, proven genuine.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn verified_executable(root: &Path, uid: u32) -> Result<PathBuf, Error> {
    use net_manager_core::managed_xray;
    let owned_by_user = |path: &Path| {
        fs::symlink_metadata(path)
            .map(|meta| meta.uid() == uid && !meta.file_type().is_symlink())
            .unwrap_or(false)
    };
    let xray_root = root.join("backends").join("xray");
    let executable = managed_xray::macos_managed_version_dir(&xray_root).join("xray");
    if !owned_by_user(root) || !owned_by_user(&xray_root) || !owned_by_user(&executable) {
        return Err(denied("Install Xray to start this connection"));
    }
    managed_xray::verify_managed_macos_executable(&xray_root, &executable)
        .map_err(|_| denied("The installed Xray failed verification"))?;
    Ok(executable)
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn verified_executable(_: &Path, _: u32) -> Result<PathBuf, Error> {
    Err(denied("Xray tunnels are supported on Apple Silicon only"))
}

pub(crate) fn open_log(path: &Path, uid: u32, gid: u32) -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    // SAFETY: the fd is valid for the call.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

/// A spawned child as the executors see it.
pub(crate) struct ChildProcess {
    child: Child,
}

impl Process for ChildProcess {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn stop(&mut self, grace: Duration) {
        if !self.alive() {
            return;
        }
        // SAFETY: signalling our own child.
        unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if !self.alive() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Platform for RealPlatform {
    fn open_tun(&self, mtu: u32) -> io::Result<Box<dyn TunDevice>> {
        Ok(Box::new(tun::open(mtu)?))
    }

    fn verify_xray(&self, uid: u32, data_root: Option<&str>) -> Result<PathBuf, Error> {
        let account = account(uid).map_err(|_| denied("The console user could not be found"))?;
        let root = match data_root {
            Some(root) => PathBuf::from(root),
            None => account
                .home
                .join("Library/Application Support")
                .join(APP_DATA_DIR),
        };
        if !root.is_absolute() || root.components().any(|c| c == Component::ParentDir) {
            return Err(Error::Invalid("invalid app data location".into()));
        }
        verified_executable(&root, uid)
    }

    fn spawn(&self, tun: &dyn TunDevice, spec: &SpawnSpec) -> io::Result<Box<dyn Process>> {
        let account = account(spec.uid)?;
        let tun_fd = tun
            .raw_fd()
            .ok_or_else(|| io::Error::other("tunnel has no descriptor"))?;
        let log = open_log(spec.log, spec.uid, account.gid)?;
        let asset_dir = spec
            .executable
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let (uid, gid) = (spec.uid, account.gid);
        let mut command = Command::new(spec.executable);
        command
            .args(["run", "-config", "stdin:"])
            .env_clear()
            .env("HOME", &account.home)
            .env("USER", &account.name)
            .env("LOGNAME", &account.name)
            .env("PATH", "/usr/bin:/bin")
            .env("XRAY_TUN_FD", CHILD_TUN_FD.to_string())
            .env("XRAY_LOCATION_ASSET", asset_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        // SAFETY: only async-signal-safe libc calls run between fork and
        // exec. Privileges are dropped here (groups, gid, then uid) rather
        // than via `Command::uid`, which would keep root's supplementary
        // groups; the tun is dup'd onto the fixed fd Xray reads.
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(1, &gid) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::getuid() != uid || libc::setuid(0) == 0 {
                    // Dropping must be irreversible.
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                if tun_fd == CHILD_TUN_FD {
                    let flags = libc::fcntl(tun_fd, libc::F_GETFD);
                    libc::fcntl(tun_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                } else if libc::dup2(tun_fd, CHILD_TUN_FD) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            let config = spec.config.to_vec();
            // Xray reads the config at startup; never block the helper on it.
            std::thread::spawn(move || {
                let _ = stdin.write_all(&config);
            });
        }
        Ok(Box::new(ChildProcess { child }))
    }

    fn resolve(&self, host: &str) -> Vec<Ipv4Addr> {
        if host.is_empty() || host.len() > 253 {
            return Vec::new();
        }
        (host, 0)
            .to_socket_addrs()
            .map(|addrs| {
                addrs
                    .filter_map(|addr| match addr.ip() {
                        std::net::IpAddr::V4(ip) => Some(ip),
                        _ => None,
                    })
                    .take(MAX_RESOLVED_BYPASS)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn is_our_xray(&self, pid: u32) -> bool {
        crate::peer::process_path(pid)
            .map(|path| {
                path.file_name() == Some(OsStr::new("xray"))
                    && path.to_string_lossy().contains("/backends/xray/")
            })
            .unwrap_or(false)
    }

    fn kill(&self, pid: u32) {
        // SAFETY: plain signal; the pid was just checked to be our Xray.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }

    fn settle(&self) {
        std::thread::sleep(SETTLE);
    }
}

/// WireGuard on the real machine: a utun plus a second descriptor for the engine.
pub struct RealWgPlatform;

impl WgPlatform for RealWgPlatform {
    fn create_tun(&self, mtu: u32) -> io::Result<(Box<dyn TunDevice>, Box<dyn PacketIo>)> {
        let utun = tun::create(mtu)?;
        let io = UtunIo::new(utun.try_clone_fd()?)?;
        Ok((Box::new(utun), Box::new(io)))
    }

    fn resolve(&self, endpoint: &str) -> Option<std::net::SocketAddr> {
        let mut found: Vec<std::net::SocketAddr> = endpoint.to_socket_addrs().ok()?.collect();
        found.sort_by_key(|addr| addr.is_ipv6());
        found.into_iter().next()
    }
}

/// OpenVPN on the real machine: the pinned binary from the bundle, run as root.
pub struct RealOvpnPlatform {
    /// Root-owned directory the verified copy of the binary is staged in.
    pub stage_dir: PathBuf,
    /// Log file next to the helper's socket, owned by the console user.
    pub log: PathBuf,
    /// `Contents/` of the app bundle holding `Helpers/openvpn`, when the
    /// helper binary itself lives elsewhere (installed by `netorch`).
    pub bundle: Option<PathBuf>,
}

impl RealOvpnPlatform {
    /// Where the pinned backends are: the configured bundle, or the one the
    /// running executable sits in.
    fn contents(&self, exe: &Path) -> Option<PathBuf> {
        self.bundle.clone().or_else(|| bundle_contents(exe))
    }
}

impl OvpnPlatform for RealOvpnPlatform {
    fn stage_binary(&self) -> io::Result<PathBuf> {
        let helper = std::env::current_exe()?;
        let contents = self
            .contents(&helper)
            .ok_or_else(|| io::Error::other("the app bundle could not be located"))?;
        if !self.stage_dir.exists() {
            fs::create_dir_all(&self.stage_dir)?;
            fs::set_permissions(
                &self.stage_dir,
                std::os::unix::fs::PermissionsExt::from_mode(0o755),
            )?;
        }
        // SAFETY: geteuid never fails.
        let owner = unsafe { libc::geteuid() };
        Catalog::embedded()?.stage("openvpn", &contents, &self.stage_dir, owner)
    }

    fn free_unit(&self) -> io::Result<String> {
        let unit = tun::pick_free_unit(&tun::used_units()?)
            .ok_or_else(|| io::Error::other("no free utun unit"))?;
        Ok(format!("utun{unit}"))
    }

    fn spawn(&self, spec: &OvpnSpawn) -> io::Result<Box<dyn Process>> {
        let account = account(spec.uid)?;
        let log = open_log(&self.log, spec.uid, account.gid)?;
        let child = Command::new(spec.binary)
            .args(spec.args)
            .current_dir(spec.cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        Ok(Box::new(ChildProcess { child }))
    }

    fn resolve(&self, host: &str) -> Vec<std::net::IpAddr> {
        if host.is_empty() || host.len() > 253 {
            return Vec::new();
        }
        (host, 0)
            .to_socket_addrs()
            .map(|addrs| {
                addrs
                    .map(|addr| addr.ip())
                    .take(MAX_RESOLVED_BYPASS)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn resolve_direct(&self, host: &str, servers: &[std::net::IpAddr]) -> Vec<std::net::IpAddr> {
        if host.is_empty() || host.len() > 253 {
            return Vec::new();
        }
        for server in servers {
            if let Ok(found) = crate::dnsquery::resolve_a(host, *server) {
                if !found.is_empty() {
                    return found
                        .into_iter()
                        .map(std::net::IpAddr::V4)
                        .take(MAX_RESOLVED_BYPASS)
                        .collect();
                }
            }
        }
        Vec::new()
    }

    fn is_our_openvpn(&self, pid: u32) -> bool {
        crate::peer::process_path(pid)
            .map(|path| path.starts_with(&self.stage_dir))
            .unwrap_or(false)
    }

    fn kill(&self, pid: u32) {
        // SAFETY: plain signal; the pid was just checked to be our OpenVPN.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backends_come_from_the_configured_bundle_or_the_executables_own() {
        let platform = |bundle: Option<&str>| RealOvpnPlatform {
            stage_dir: PathBuf::from("/stage"),
            log: PathBuf::from("/log"),
            bundle: bundle.map(PathBuf::from),
        };
        let exe = Path::new("/A.app/Contents/MacOS/netorch");
        assert_eq!(
            platform(None).contents(exe),
            Some(PathBuf::from("/A.app/Contents"))
        );
        let installed = Path::new("/Library/PrivilegedHelperTools/helper");
        assert_eq!(
            platform(Some("/B.app/Contents")).contents(installed),
            Some(PathBuf::from("/B.app/Contents"))
        );
    }

    #[test]
    fn account_of_the_current_user_resolves() {
        // SAFETY: getuid never fails.
        let account = account(unsafe { libc::getuid() }).unwrap();
        assert!(!account.name.is_empty());
        assert!(account.home.is_absolute());
    }

    #[test]
    fn relative_and_traversing_data_roots_are_refused() {
        // SAFETY: getuid never fails.
        let uid = unsafe { libc::getuid() };
        for root in ["relative/path", "/Users/x/../../etc"] {
            assert!(matches!(
                RealPlatform.verify_xray(uid, Some(root)),
                Err(Error::Invalid(_))
            ));
        }
    }

    #[test]
    fn missing_install_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: getuid never fails.
        let uid = unsafe { libc::getuid() };
        let err = RealPlatform
            .verify_xray(uid, Some(dir.path().to_str().unwrap()))
            .unwrap_err();
        assert!(matches!(err, Error::Unavailable(_)), "{err}");
    }

    #[test]
    fn log_is_private_and_symlinks_are_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: getuid/getgid never fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let log = dir.path().join("xray.log");
        open_log(&log, uid, gid).unwrap();
        assert_eq!(fs::metadata(&log).unwrap().mode() & 0o777, 0o600);
        let target = dir.path().join("target");
        fs::write(&target, b"keep").unwrap();
        let link = dir.path().join("link.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_log(&link, uid, gid).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn launch_without_root_fails_closed() {
        // Dropping privileges needs root. An unprivileged helper (tests,
        // misinstall) must refuse to launch rather than run Xray with
        // whatever it has; the root path is covered on a live machine only.
        // SAFETY: getuid never fails.
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            return;
        }
        struct Dev(File);
        impl TunDevice for Dev {
            fn name(&self) -> &str {
                "utunX"
            }
            fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
                Some(self.0.as_raw_fd())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fake-xray");
        fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let dev = Dev(File::open("/dev/null").unwrap());
        let log = dir.path().join("out.log");
        let result = RealPlatform.spawn(
            &dev,
            &SpawnSpec {
                executable: &script,
                uid,
                config: b"{}",
                log: &log,
            },
        );
        assert!(result.is_err());
    }
}
