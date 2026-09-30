use std::io;

#[cfg(target_os = "linux")]
use crate::xray::MAX_XRAY_CONFIG_BYTES;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fs::{self, DirBuilder, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const RUNTIME_ROOT: &str = "/run/network-orchestrator";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const BINARY_ROOT: &str = "/usr/lib/network-orchestrator/xray";
#[cfg(target_os = "linux")]
const LINK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

pub trait XrayProcessRunner: Send {
    fn verify_binary(&self) -> io::Result<()>;
    fn link_index(&self, name: &str) -> io::Result<Option<u32>>;
    fn start(&mut self, uid: u32, name: &str, config: &str) -> io::Result<()>;
    fn health(&mut self, name: &str) -> io::Result<bool>;
    fn stop(&mut self, name: &str) -> io::Result<()>;
    fn cleanup(&mut self, uid: u32, name: &str) -> io::Result<()>;
}

#[cfg(target_os = "linux")]
pub struct TrustedXrayProcess {
    children: HashMap<String, (u32, Child)>,
}

#[cfg(target_os = "linux")]
impl TrustedXrayProcess {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
        }
    }
}

#[cfg(target_os = "linux")]
impl Default for TrustedXrayProcess {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl XrayProcessRunner for TrustedXrayProcess {
    fn verify_binary(&self) -> io::Result<()> {
        trusted_binary().map(|_| ())
    }

    fn link_index(&self, name: &str) -> io::Result<Option<u32>> {
        if !valid_tun_name(name) {
            return Err(invalid_input());
        }
        let name = CString::new(name).map_err(|_| invalid_input())?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        Ok((index != 0).then_some(index))
    }

    fn start(&mut self, uid: u32, name: &str, config: &str) -> io::Result<()> {
        if !valid_tun_name(name) || config.len() > MAX_XRAY_CONFIG_BYTES {
            return Err(invalid_input());
        }
        if self.children.contains_key(name) || self.link_index(name)?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Xray interface exists",
            ));
        }
        let binary = trusted_binary()?;
        ensure_runtime_root()?;
        let directory = stage_config_at(Path::new(RUNTIME_ROOT), uid, name, config)?;
        let config_path = directory.join("config.json");
        let mut child = match Command::new(&binary)
            .args(xray_args(&config_path))
            .env_clear()
            .env(
                "XRAY_LOCATION_ASSET",
                binary.parent().expect("fixed managed binary"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir(&directory)
            .spawn()
        {
            Ok(child) => child,
            Err(_) => {
                let _ = cleanup_stage_at(Path::new(RUNTIME_ROOT), uid, name);
                return Err(io::Error::other("Xray launch failed"));
            }
        };
        let started = (|| {
            let starttime = read_starttime(child.id())?;
            write_private_file(
                &directory.join("process"),
                format!("{} {starttime}\n", child.id()).as_bytes(),
            )?;
            let deadline = Instant::now() + LINK_TIMEOUT;
            loop {
                if child
                    .try_wait()
                    .map_err(|_| io::Error::other("Xray child check failed"))?
                    .is_some()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "Xray exited before interface appeared",
                    ));
                }
                if self.link_index(name)?.is_some() {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Xray interface did not appear",
                    ));
                }
                thread::sleep(Duration::from_millis(25));
            }
        })();
        if let Err(error) = started {
            let _ = terminate_child(&mut child);
            let _ = cleanup_stage_at(Path::new(RUNTIME_ROOT), uid, name);
            return Err(error);
        }
        self.children.insert(name.to_owned(), (uid, child));
        Ok(())
    }

    fn health(&mut self, name: &str) -> io::Result<bool> {
        let (_, child) = self
            .children
            .get_mut(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Xray child is not tracked"))?;
        Ok(child
            .try_wait()
            .map_err(|_| io::Error::other("Xray child check failed"))?
            .is_none()
            && self.link_index(name)?.is_some())
    }

    fn stop(&mut self, name: &str) -> io::Result<()> {
        let (_, child) = self
            .children
            .get_mut(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Xray child is not tracked"))?;
        terminate_child(child)?;
        self.children.remove(name);
        Ok(())
    }

    fn cleanup(&mut self, uid: u32, name: &str) -> io::Result<()> {
        if !valid_tun_name(name) {
            return Err(invalid_input());
        }
        if let Some((owner, _)) = self.children.get(name) {
            if *owner != uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Xray process ownership mismatch",
                ));
            }
            self.stop(name)?;
        } else {
            recover_child(uid, name)?;
        }
        ensure_runtime_root()?;
        cleanup_stage_at(Path::new(RUNTIME_ROOT), uid, name)
    }
}

#[cfg(target_os = "linux")]
fn invalid_input() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid Xray process input")
}

#[cfg(target_os = "linux")]
fn valid_tun_name(name: &str) -> bool {
    name.starts_with("xray-")
        && (6..=15).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn trusted_binary() -> io::Result<PathBuf> {
    let root = Path::new(BINARY_ROOT);
    let binary = net_manager_core::managed_xray::linux_managed_version_dir(root).join("xray");
    if !safe_root_owned_path(&binary)
        || ["geoip.dat", "geosite.dat"].iter().any(|name| {
            !safe_owned_file(
                &binary.parent().expect("fixed managed binary").join(name),
                0,
                false,
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed Xray installation is unsafe",
        ));
    }
    net_manager_core::managed_xray::verify_managed_linux_executable(root, &binary).map_err(
        |_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed Xray verification failed",
            )
        },
    )?;
    Ok(binary)
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn trusted_binary() -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "managed Xray is not supported on this architecture",
    ))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn safe_root_owned_path(path: &Path) -> bool {
    if !safe_owned_file(path, 0, true) {
        return false;
    }
    let mut parent = path.parent();
    while let Some(directory) = parent {
        let Ok(metadata) = fs::symlink_metadata(directory) else {
            return false;
        };
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return false;
        }
        if directory == Path::new("/") {
            return true;
        }
        parent = directory.parent();
    }
    false
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", test)))]
fn safe_owned_file(path: &Path, owner: u32, executable: bool) -> bool {
    let Ok(file) = fs::symlink_metadata(path) else {
        return false;
    };
    file.is_file()
        && file.uid() == owner
        && file.mode() & 0o022 == 0
        && (!executable || file.mode() & 0o111 != 0)
}

#[cfg(target_os = "linux")]
fn ensure_runtime_root() -> io::Result<()> {
    let root = Path::new(RUNTIME_ROOT);
    let metadata = fs::symlink_metadata(root)
        .map_err(|_| io::Error::other("Xray runtime directory unavailable"))?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray runtime directory is unsafe",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn xray_args(config: &Path) -> Vec<String> {
    vec![
        "run".into(),
        "-config".into(),
        config.to_string_lossy().into_owned(),
    ]
}

#[cfg(target_os = "linux")]
fn stage_config_at(root: &Path, uid: u32, name: &str, config: &str) -> io::Result<PathBuf> {
    if !valid_tun_name(name) || config.len() > MAX_XRAY_CONFIG_BYTES {
        return Err(invalid_input());
    }
    let metadata =
        fs::symlink_metadata(root).map_err(|_| io::Error::other("Xray staging failed"))?;
    if !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray runtime directory is unsafe",
        ));
    }
    let owner = metadata.uid();
    let user_dir = root.join(uid.to_string());
    if !user_dir.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(&user_dir)
            .map_err(|_| io::Error::other("Xray staging failed"))?;
    }
    let user =
        fs::symlink_metadata(&user_dir).map_err(|_| io::Error::other("Xray staging failed"))?;
    if !user.is_dir() || user.uid() != owner || user.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray staging directory is unsafe",
        ));
    }
    let directory = user_dir.join(name);
    DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Xray staging directory already exists",
            )
        })?;
    if let Err(error) = write_private_file(&directory.join("config.json"), config.as_bytes()) {
        let _ = cleanup_stage_at(root, uid, name);
        return Err(error);
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| io::Error::other("Xray staging file creation failed"))?;
    file.write_all(bytes)
        .map_err(|_| io::Error::other("Xray staging file write failed"))?;
    file.sync_all()
        .map_err(|_| io::Error::other("Xray staging file sync failed"))
}

#[cfg(target_os = "linux")]
fn cleanup_stage_at(root: &Path, uid: u32, name: &str) -> io::Result<()> {
    if !valid_tun_name(name) {
        return Err(invalid_input());
    }
    let root_metadata =
        fs::symlink_metadata(root).map_err(|_| io::Error::other("Xray staging cleanup failed"))?;
    let owner = root_metadata.uid();
    let user_dir = root.join(uid.to_string());
    let user = match fs::symlink_metadata(&user_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(io::Error::other("Xray staging cleanup failed")),
    };
    if !user.is_dir() || user.uid() != owner || user.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray staging directory is unsafe",
        ));
    }
    let directory = user_dir.join(name);
    let stage = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(io::Error::other("Xray staging cleanup failed")),
    };
    if !stage.is_dir() || stage.uid() != owner || stage.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray staging directory is unsafe",
        ));
    }
    for entry in
        fs::read_dir(&directory).map_err(|_| io::Error::other("Xray staging cleanup failed"))?
    {
        let entry = entry.map_err(|_| io::Error::other("Xray staging cleanup failed"))?;
        let filename = entry.file_name();
        if filename != "config.json" && filename != "process" {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Xray staging contains unknown file",
            ));
        }
        let file = fs::symlink_metadata(entry.path())
            .map_err(|_| io::Error::other("Xray staging cleanup failed"))?;
        if !file.is_file() || file.uid() != owner || file.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Xray staging file is unsafe",
            ));
        }
        fs::remove_file(entry.path())
            .map_err(|_| io::Error::other("Xray staging cleanup failed"))?;
    }
    fs::remove_dir(&directory).map_err(|_| io::Error::other("Xray staging cleanup failed"))?;
    let _ = fs::remove_dir(&user_dir);
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_starttime(stat: &str) -> Option<u64> {
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn read_starttime(pid: u32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| io::Error::other("Xray process identity unavailable"))?;
    parse_starttime(&stat).ok_or_else(|| io::Error::other("Xray process identity invalid"))
}

#[cfg(target_os = "linux")]
fn recover_child(uid: u32, name: &str) -> io::Result<()> {
    ensure_runtime_root()?;
    let directory = Path::new(RUNTIME_ROOT).join(uid.to_string()).join(name);
    for path in [
        directory.parent().expect("fixed runtime path"),
        directory.as_path(),
    ] {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(io::Error::other("Xray staging directory unavailable")),
        };
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Xray staging directory is unsafe",
            ));
        }
    }
    let record_path = directory.join("process");
    let record_metadata = match fs::symlink_metadata(&record_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(io::Error::other("Xray process record invalid")),
    };
    if !record_metadata.is_file()
        || record_metadata.uid() != 0
        || record_metadata.mode() & 0o077 != 0
        || record_metadata.len() > 64
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Xray process record is unsafe",
        ));
    }
    let record = match fs::read_to_string(&record_path) {
        Ok(record) if record.len() <= 64 => record,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        _ => return Err(io::Error::other("Xray process record invalid")),
    };
    let mut parts = record.split_whitespace();
    let pid: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("Xray process record invalid"))?;
    let starttime: u64 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("Xray process record invalid"))?;
    if parts.next().is_some() || pid == 0 {
        return Err(io::Error::other("Xray process record invalid"));
    }
    let binary = trusted_binary()?;
    let config = directory.join("config.json");
    if !same_process(pid, starttime, &binary, &config)? {
        return Ok(());
    }
    let pidfd = open_pidfd(pid)?;
    if !same_process(pid, starttime, &binary, &config)? {
        return Ok(());
    }
    signal_pidfd(&pidfd, libc::SIGTERM)?;
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if pidfd_exited(&pidfd)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    signal_pidfd(&pidfd, libc::SIGKILL)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn same_process(pid: u32, starttime: u64, binary: &Path, config: &Path) -> io::Result<bool> {
    let current = match read_starttime(pid) {
        Ok(current) => current,
        Err(_) => return Ok(false),
    };
    if current != starttime {
        return Ok(false);
    }
    let executable = match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(executable) => executable,
        Err(_) => return Ok(false),
    };
    if executable != binary {
        return Ok(false);
    }
    let mut cmdline = Vec::new();
    fs::File::open(format!("/proc/{pid}/cmdline"))
        .and_then(|file| file.take(4096).read_to_end(&mut cmdline))
        .map_err(|_| io::Error::other("Xray process command unavailable"))?;
    let args: Vec<&[u8]> = cmdline
        .split(|b| *b == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    Ok(args.len() == 4
        && args[1] == b"run"
        && args[2] == b"-config"
        && args[3] == config.as_os_str().as_encoded_bytes())
}

#[cfg(target_os = "linux")]
fn terminate_child(child: &mut Child) -> io::Result<()> {
    if child
        .try_wait()
        .map_err(|_| io::Error::other("Xray child check failed"))?
        .is_some()
    {
        return Ok(());
    }
    let pidfd = open_pidfd(child.id())?;
    signal_pidfd(&pidfd, libc::SIGTERM)?;
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if child
            .try_wait()
            .map_err(|_| io::Error::other("Xray child check failed"))?
            .is_some()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    signal_pidfd(&pidfd, libc::SIGKILL)?;
    child
        .wait()
        .map_err(|_| io::Error::other("Xray child wait failed"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: u32) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if raw < 0 {
        return Err(io::Error::other("Xray pidfd unavailable"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw as i32) })
}

#[cfg(target_os = "linux")]
fn signal_pidfd(pidfd: &OwnedFd, signal: i32) -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        return Err(io::Error::other("Xray process signal failed"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn pidfd_exited(pidfd: &OwnedFd) -> io::Result<bool> {
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
    if result < 0 {
        return Err(io::Error::other("Xray process check failed"));
    }
    Ok(result > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn temp_root() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "netmgr-xray-process-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn stage_keeps_config_private_and_cleanup_removes_it() {
        let root = temp_root();
        let uid = unsafe { libc::getuid() };
        let dir = stage_config_at(&root, uid, "xray-abcd", "{\"secret\":\"hidden\"}").unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("config.json")).unwrap(),
            "{\"secret\":\"hidden\"}"
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(dir.join("config.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        cleanup_stage_at(&root, uid, "xray-abcd").unwrap();
        assert!(!dir.exists());
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn stage_rejects_name_traversal_and_oversized_config() {
        let root = temp_root();
        let uid = unsafe { libc::getuid() };
        assert!(stage_config_at(&root, uid, "../xray", "{}").is_err());
        assert!(stage_config_at(
            &root,
            uid,
            "xray-abcd",
            &"x".repeat(MAX_XRAY_CONFIG_BYTES + 1)
        )
        .is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn cleanup_refuses_unexpected_file() {
        let root = temp_root();
        let uid = unsafe { libc::getuid() };
        let dir = stage_config_at(&root, uid, "xray-abcd", "{}").unwrap();
        fs::write(dir.join("unexpected"), b"data").unwrap();
        assert_eq!(
            cleanup_stage_at(&root, uid, "xray-abcd")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn process_identity_parser_handles_parentheses() {
        let stat = "123 (xray (worker)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 8675309 21";
        assert_eq!(parse_starttime(stat), Some(8675309));
        assert_eq!(parse_starttime("bad"), None);
    }

    #[test]
    fn launch_arguments_never_run_tun_test() {
        let args = xray_args(Path::new(
            "/run/network-orchestrator/1000/xray-abcd/config.json",
        ));
        assert_eq!(args[0], "run");
        assert!(!args.iter().any(|arg| arg == "-test"));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn trusted_xray_is_loaded_from_package_owned_directory() {
        assert_eq!(BINARY_ROOT, "/usr/lib/network-orchestrator/xray");
        assert_eq!(
            net_manager_core::managed_xray::linux_managed_version_dir(Path::new(BINARY_ROOT))
                .join("xray"),
            Path::new("/usr/lib/network-orchestrator/xray/v26.3.27/xray")
        );
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn unsupported_architecture_rejects_managed_xray_without_starting_it() {
        assert_eq!(
            trusted_binary().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn geo_assets_must_not_be_writable_by_unprivileged_users() {
        let root = temp_root();
        let geo = root.join("geoip.dat");
        fs::write(&geo, b"fake").unwrap();
        let owner = unsafe { libc::getuid() };
        fs::set_permissions(&geo, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!safe_owned_file(&geo, owner, false));
        fs::set_permissions(&geo, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(safe_owned_file(&geo, owner, false));
        fs::remove_dir_all(root).unwrap();
    }
}
