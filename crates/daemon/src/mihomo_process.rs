use std::io;

#[cfg(target_os = "linux")]
use std::{
    collections::HashMap,
    ffi::CString,
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
const MAX_CONFIG_BYTES: usize = 8 * 1024 * 1024;
#[cfg(target_os = "linux")]
const LINK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const STOP_TIMEOUT: Duration = Duration::from_secs(2);
pub trait MihomoProcessRunner: Send {
    fn verify_binary(&self) -> io::Result<()>;
    fn link_index(&self, name: &str) -> io::Result<Option<u32>>;
    fn start(
        &mut self,
        uid: u32,
        name: &str,
        config: &str,
        selections: &std::collections::BTreeMap<String, String>,
    ) -> io::Result<()>;
    fn health(&mut self, name: &str) -> io::Result<bool>;
    fn stop(&mut self, name: &str) -> io::Result<()>;
    fn cleanup(&mut self, uid: u32, name: &str) -> io::Result<()>;
}

#[cfg(target_os = "linux")]
pub struct TrustedMihomoProcess {
    children: HashMap<String, (u32, Child)>,
}

#[cfg(target_os = "linux")]
impl TrustedMihomoProcess {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
        }
    }

    fn spawn(
        &self,
        binary: &Path,
        directory: &Path,
        name: &str,
        selections: &std::collections::BTreeMap<String, String>,
    ) -> io::Result<Child> {
        let config = directory.join("config.json");
        let mut child = Command::new(binary)
            .args([
                "-d",
                directory.to_str().ok_or_else(invalid_input)?,
                "-f",
                config.to_str().ok_or_else(invalid_input)?,
            ])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir(directory)
            .spawn()
            .map_err(|_| io::Error::other("Mihomo launch failed"))?;
        let started = (|| {
            let starttime = process_starttime(child.id())?;
            write_private(
                &directory.join("process"),
                format!("{} {starttime}\n", child.id()).as_bytes(),
            )?;
            let deadline = Instant::now() + LINK_TIMEOUT;
            loop {
                if child
                    .try_wait()
                    .map_err(|_| io::Error::other("Mihomo child check failed"))?
                    .is_some()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "Mihomo exited during startup",
                    ));
                }
                if self.link_index(name)?.is_some() {
                    net_manager_core::mihomo_control::apply_group_selections(
                        &directory.join("controller.sock"),
                        selections,
                    )
                    .map_err(|_| io::Error::other("Mihomo group selection failed"))?;
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Mihomo interface did not appear",
                    ));
                }
                thread::sleep(Duration::from_millis(25));
            }
        })();
        if let Err(error) = started {
            if terminate(&mut child).is_err() {
                return Err(io::Error::other("Mihomo process stop failed"));
            }
            let _ = fs::remove_file(directory.join("process"));
            return Err(error);
        }
        Ok(child)
    }
}

#[cfg(target_os = "linux")]
impl Default for TrustedMihomoProcess {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl MihomoProcessRunner for TrustedMihomoProcess {
    fn verify_binary(&self) -> io::Result<()> {
        trusted_binary().map(|_| ())
    }

    fn link_index(&self, name: &str) -> io::Result<Option<u32>> {
        if !valid_name(name) {
            return Err(invalid_input());
        }
        let name = CString::new(name).map_err(|_| invalid_input())?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        Ok((index != 0).then_some(index))
    }

    fn start(
        &mut self,
        uid: u32,
        name: &str,
        config: &str,
        selections: &std::collections::BTreeMap<String, String>,
    ) -> io::Result<()> {
        if !valid_name(name) || !validate_config(config) {
            return Err(invalid_input());
        }
        if self.children.contains_key(name) || self.link_index(name)?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Mihomo interface exists",
            ));
        }
        let binary = trusted_binary()?;
        let root = crate::openvpn::runtime_root();
        ensure_root(&root)?;
        let directory = root.join(format!("mihomo-{uid}")).join(name);
        DirBuilder::new()
            .mode(0o700)
            .create(directory.parent().unwrap())
            .or_else(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(|_| io::Error::other("Mihomo staging failed"))?;
        verify_private_dir(directory.parent().unwrap())?;
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Mihomo staging directory exists",
                )
            })?;
        let providers = directory.join("providers");
        if DirBuilder::new().mode(0o700).create(&providers).is_err() {
            let _ = fs::remove_dir_all(&directory);
            return Err(io::Error::other("Mihomo provider staging failed"));
        }
        if let Err(error) = verify_private_dir(&providers) {
            let _ = fs::remove_dir_all(&directory);
            return Err(error);
        }
        let mut config_value: serde_json::Value =
            serde_json::from_str(config).map_err(|_| invalid_input())?;
        let config_root = config_value.as_object_mut().ok_or_else(invalid_input)?;
        for key in [
            "external-controller",
            "external-controller-pipe",
            "secret",
            "external-ui",
        ] {
            config_root.remove(key);
        }
        config_root.insert(
            "external-controller-unix".into(),
            serde_json::json!(directory.join("controller.sock").display().to_string()),
        );
        let config = serde_json::to_vec(&config_value).map_err(|_| invalid_input())?;
        if let Err(error) = write_private(
            &directory.join("owner"),
            format!("network-orchestrator:mihomo:{uid}\n").as_bytes(),
        )
        .and_then(|_| write_private(&directory.join("config.json"), &config))
        {
            let _ = fs::remove_dir_all(&directory);
            return Err(error);
        }
        match self.spawn(&binary, &directory, name, selections) {
            Ok(child) => {
                self.children.insert(name.to_owned(), (uid, child));
                Ok(())
            }
            Err(error) => {
                if !directory.join("process").exists() {
                    let _ = fs::remove_dir_all(&directory);
                }
                Err(error)
            }
        }
    }

    fn health(&mut self, name: &str) -> io::Result<bool> {
        let Some((_, child)) = self.children.get_mut(name) else {
            return Ok(false);
        };
        if child
            .try_wait()
            .map_err(|_| io::Error::other("Mihomo child check failed"))?
            .is_some()
        {
            return Ok(false);
        }
        Ok(self.link_index(name)?.is_some())
    }

    fn stop(&mut self, name: &str) -> io::Result<()> {
        let Some((_, child)) = self.children.get_mut(name) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Mihomo child is not tracked",
            ));
        };
        terminate(child)?;
        self.children.remove(name);
        Ok(())
    }

    fn cleanup(&mut self, uid: u32, name: &str) -> io::Result<()> {
        if !valid_name(name) {
            return Err(invalid_input());
        }
        if let Some((owner, _)) = self.children.get(name) {
            if *owner != uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Mihomo process ownership mismatch",
                ));
            }
            self.stop(name)?;
        } else {
            recover(uid, name)?;
        }
        let directory = crate::openvpn::runtime_root()
            .join(format!("mihomo-{uid}"))
            .join(name);
        match fs::remove_dir_all(directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(io::Error::other("Mihomo staging cleanup failed")),
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn trusted_binary() -> io::Result<PathBuf> {
    let root = Path::new(net_manager_core::managed_mihomo::LINUX_MIHOMO_PACKAGE_ROOT);
    let binary = root
        .join(net_manager_core::managed_mihomo::LINUX_MIHOMO_VERSION)
        .join("mihomo");
    net_manager_core::managed_mihomo::verify_managed_linux_executable(root, &binary).map_err(
        |_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Managed Mihomo is missing or untrusted; install the optional Mihomo component",
            )
        },
    )?;
    Ok(binary)
}
#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn trusted_binary() -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "managed Mihomo is unsupported on this architecture",
    ))
}

#[cfg(target_os = "linux")]
fn validate_config(config: &str) -> bool {
    if config.len() > MAX_CONFIG_BYTES {
        return false;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(config) else {
        return false;
    };
    validate_provider_paths(&value)
}
#[cfg(target_os = "linux")]
fn validate_provider_paths(config: &serde_json::Value) -> bool {
    for (key, prefix, extensions) in [
        ("proxy-providers", "proxy-", &["yaml"][..]),
        ("rule-providers", "rule-", &["yaml", "mrs", "text"][..]),
    ] {
        let Some(providers) = config.get(key) else {
            continue;
        };
        let Some(providers) = providers.as_object() else {
            return false;
        };
        for provider in providers.values() {
            let Some(provider) = provider.as_object() else {
                return false;
            };
            if key == "proxy-providers"
                && (provider.get("type").and_then(serde_json::Value::as_str) != Some("inline")
                    || provider.contains_key("path")
                    || provider.contains_key("url"))
            {
                return false;
            }
            if let Some(path) = provider.get("path") {
                let Some(path) = path.as_str() else {
                    return false;
                };
                if key != "rule-providers" || !valid_provider_path(path, prefix, extensions) {
                    return false;
                }
            }
        }
    }
    true
}
#[cfg(target_os = "linux")]
fn valid_provider_path(path: &str, prefix: &str, extensions: &[&str]) -> bool {
    let Some(filename) = path.strip_prefix("providers/") else {
        return false;
    };
    let Some(filename) = filename.strip_prefix(prefix) else {
        return false;
    };
    let Some((index, extension)) = filename.split_once('.') else {
        return false;
    };
    index.len() == 4
        && index.bytes().all(|byte| byte.is_ascii_digit())
        && extensions.contains(&extension)
}
#[cfg(not(target_os = "linux"))]
fn validate_config(_: &str) -> bool {
    false
}
#[cfg(target_os = "linux")]
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
#[cfg(target_os = "linux")]
fn invalid_input() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid Mihomo process input")
}
#[cfg(target_os = "linux")]
fn ensure_root(path: &Path) -> io::Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| io::Error::other("Mihomo runtime unavailable"))?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Mihomo runtime is unsafe",
        ));
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn verify_private_dir(path: &Path) -> io::Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| io::Error::other("Mihomo staging unavailable"))?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Mihomo staging is unsafe",
        ));
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| io::Error::other("Mihomo staging failed"))?;
    file.write_all(bytes)
        .map_err(|_| io::Error::other("Mihomo staging failed"))?;
    file.sync_all()
        .map_err(|_| io::Error::other("Mihomo staging failed"))
}
#[cfg(target_os = "linux")]
fn process_starttime(pid: u32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| io::Error::other("Mihomo process identity unavailable"))?;
    let end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("Mihomo process identity invalid"))?;
    stat[end + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("Mihomo process identity invalid"))
}
#[cfg(target_os = "linux")]
fn recover(uid: u32, name: &str) -> io::Result<()> {
    let directory = crate::openvpn::runtime_root()
        .join(format!("mihomo-{uid}"))
        .join(name);
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(io::Error::other("Mihomo staging unavailable")),
        Ok(_) => {}
    }
    verify_private_dir(directory.parent().ok_or_else(invalid_input)?)?;
    verify_private_dir(&directory)?;
    let owner = fs::read_to_string(directory.join("owner"))
        .map_err(|_| io::Error::other("Mihomo ownership marker unavailable"))?;
    if owner != format!("network-orchestrator:mihomo:{uid}\n") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Mihomo ownership marker invalid",
        ));
    }
    let record = match fs::read_to_string(directory.join("process")) {
        Ok(record) => record,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(io::Error::other("Mihomo process record invalid")),
    };
    let mut fields = record.split_whitespace();
    let pid: u32 = fields
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(invalid_input)?;
    let start: u64 = fields
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(invalid_input)?;
    if fields.next().is_some() {
        return Ok(());
    }
    let binary = trusted_binary()?;
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
    if pidfd < 0 {
        return if process_starttime(pid).is_err() {
            Ok(())
        } else {
            Err(io::Error::other("Mihomo process recovery failed"))
        };
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd) };
    if process_starttime(pid).ok() != Some(start) {
        return Ok(());
    }
    let actual = fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|_| io::Error::other("Mihomo process identity unavailable"))?;
    if actual != binary || !command_uses_config(pid, &directory.join("config.json"))? {
        return Ok(());
    }
    if process_starttime(pid).ok() != Some(start) {
        return Ok(());
    }
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGTERM,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if process_starttime(pid).ok() != Some(start) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if process_starttime(pid).ok() != Some(start) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "Mihomo process did not exit",
    ))
}
#[cfg(target_os = "linux")]
fn command_uses_config(pid: u32, config: &Path) -> io::Result<bool> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(format!("/proc/{pid}/cmdline"))
        .and_then(|file| file.take(4097).read_to_end(&mut bytes))
        .map_err(|_| io::Error::other("Mihomo process identity unavailable"))?;
    if bytes.len() > 4096 {
        return Ok(false);
    }
    let args: Vec<&[u8]> = bytes
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    let config = config.as_os_str().as_encoded_bytes();
    Ok(args
        .windows(2)
        .any(|pair| pair[0] == b"-f" && pair[1] == config))
}

#[cfg(target_os = "linux")]
fn terminate(child: &mut Child) -> io::Result<()> {
    if child
        .try_wait()
        .map_err(|_| io::Error::other("Mihomo child check failed"))?
        .is_some()
    {
        return Ok(());
    }
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) as i32 };
    if pidfd < 0 {
        return Err(io::Error::other("Mihomo process stop failed"));
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd) };
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGTERM,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if child
            .try_wait()
            .map_err(|_| io::Error::other("Mihomo child check failed"))?
            .is_some()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        return Err(io::Error::other("Mihomo process stop failed"));
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if child
            .try_wait()
            .map_err(|_| io::Error::other("Mihomo child wait failed"))?
            .is_some()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "Mihomo child did not exit",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct FakeRunner {
        started: bool,
        stopped: bool,
    }
    impl MihomoProcessRunner for FakeRunner {
        fn verify_binary(&self) -> io::Result<()> {
            Ok(())
        }
        fn link_index(&self, _: &str) -> io::Result<Option<u32>> {
            Ok(None)
        }
        fn start(
            &mut self,
            _: u32,
            _: &str,
            _: &str,
            _: &std::collections::BTreeMap<String, String>,
        ) -> io::Result<()> {
            self.started = true;
            Ok(())
        }
        fn health(&mut self, _: &str) -> io::Result<bool> {
            Ok(self.started && !self.stopped)
        }
        fn stop(&mut self, _: &str) -> io::Result<()> {
            self.stopped = true;
            Ok(())
        }
        fn cleanup(&mut self, _: u32, _: &str) -> io::Result<()> {
            self.stopped = true;
            Ok(())
        }
    }
    #[test]
    fn injected_runner_exposes_lifecycle_without_process_side_effects() {
        let mut runner = FakeRunner {
            started: false,
            stopped: false,
        };
        runner.verify_binary().unwrap();
        runner
            .start(1000, "mihomo0", "{}", &std::collections::BTreeMap::new())
            .unwrap();
        assert!(runner.health("mihomo0").unwrap());
        runner.stop("mihomo0").unwrap();
        assert!(!runner.health("mihomo0").unwrap());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn terminate_escalates_to_sigkill_and_reaps_term_ignoring_child() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; while :; do :; done"])
            .spawn()
            .unwrap();
        let started = Instant::now();
        terminate(&mut child).unwrap();
        assert!(started.elapsed() < STOP_TIMEOUT + STOP_TIMEOUT);
        assert!(child.try_wait().unwrap().is_some());
    }
    #[test]
    fn config_size_is_bounded_before_staging() {
        assert!(validate_config("{}"));
        assert!(!validate_config(&"x".repeat(MAX_CONFIG_BYTES + 1)));
    }
    #[test]
    fn provider_cache_paths_must_use_the_private_canonical_namespace() {
        let safe = r#"{"proxy-providers":{"p":{"type":"inline","payload":[]}},"rule-providers":{"r":{"url":"https://rules.example/rules.yaml","path":"providers/rule-0001.mrs"}}}"#;
        let unsafe_path = r#"{"proxy-providers":{"p":{"type":"http","url":"https://provider.invalid/p.yaml","path":"providers/proxy-0000.yaml"}}}"#;
        assert!(validate_config(safe));
        assert!(!validate_config(unsafe_path));
        assert!(valid_provider_path(
            "providers/rule-0001.mrs",
            "rule-",
            &["yaml", "mrs", "text"]
        ));
    }
}
