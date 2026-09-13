use crate::models::{Profile, TunnelBackend, TunnelState, TunnelStatus};
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::OsString;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use windows::core::{HRESULT, PCWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
#[cfg(windows)]
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
    SERVICE_STOPPED,
};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(windows)]
struct ServiceHandle(SC_HANDLE);

#[cfg(windows)]
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn wireguard_service_running(profile: &Profile) -> io::Result<bool> {
    let service_name = wireguard_service_name(profile)?;
    let wide: Vec<u16> = service_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let scm = ServiceHandle(
            OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
                .map_err(|e| io::Error::from_raw_os_error(e.code().0))?,
        );
        let service =
            match OpenServiceW(scm.0, PCWSTR::from_raw(wide.as_ptr()), SERVICE_QUERY_STATUS) {
                Ok(handle) => ServiceHandle(handle),
                Err(e) if e.code() == HRESULT::from_win32(ERROR_SERVICE_DOES_NOT_EXIST.0) => {
                    return Ok(false);
                }
                Err(e) => return Err(io::Error::from_raw_os_error(e.code().0)),
            };
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0u32;
        let buffer = core::slice::from_raw_parts_mut(
            &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
            core::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        );
        QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(buffer), &mut needed)
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        Ok(status.dwCurrentState != SERVICE_STOPPED)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CommandSpec {
    program: PathBuf,
    args: Vec<OsString>,
}

fn wireguard_connect_spec(exe: &Path, profile: &Profile) -> io::Result<CommandSpec> {
    Ok(CommandSpec {
        program: exe.to_path_buf(),
        args: vec![
            OsString::from("/installtunnelservice"),
            std::path::absolute(&profile.config_path)?.into_os_string(),
        ],
    })
}

fn wireguard_disconnect_spec(exe: &Path, profile: &Profile) -> io::Result<CommandSpec> {
    Ok(CommandSpec {
        program: exe.to_path_buf(),
        args: vec![
            OsString::from("/uninstalltunnelservice"),
            OsString::from(wireguard_tunnel_name(&profile.config_path)?),
        ],
    })
}

fn openvpn_connect_spec(exe: &Path, profile: &Profile) -> io::Result<CommandSpec> {
    let mut args = vec![
        OsString::from("--config"),
        std::path::absolute(&profile.config_path)?.into_os_string(),
    ];
    if !profile.routes.is_empty() {
        args.push(OsString::from("--route-nopull"));
    }
    Ok(CommandSpec {
        program: exe.to_path_buf(),
        args,
    })
}

#[cfg(any(windows, test))]
fn wireguard_service_name(profile: &Profile) -> io::Result<String> {
    Ok(format!(
        "WireGuardTunnel${}",
        wireguard_tunnel_name(&profile.config_path)?
    ))
}

pub fn wireguard_tunnel_name(config_path: &Path) -> io::Result<String> {
    let file_name = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid_data("config path has no usable file name"))?;
    let lower = file_name.to_lowercase();
    let suffix_len = if lower.ends_with(".conf.dpapi") {
        ".conf.dpapi".len()
    } else if lower.ends_with(".conf") {
        ".conf".len()
    } else {
        return Err(invalid_data(format!(
            "unsupported WireGuard config name '{file_name}' (expected .conf or .conf.dpapi)"
        )));
    };
    let stem = &file_name[..file_name.len() - suffix_len];
    if stem.is_empty() {
        return Err(invalid_data("WireGuard config name has no tunnel name"));
    }
    Ok(stem.to_string())
}

pub fn resolve_wireguard_executable(configured: Option<&Path>) -> io::Result<PathBuf> {
    resolve_executable(
        configured,
        "wireguard.exe",
        "WireGuard",
        &wireguard_standard_paths(),
    )
}

pub fn resolve_openvpn_executable(configured: Option<&Path>) -> io::Result<PathBuf> {
    resolve_executable(
        configured,
        "openvpn.exe",
        "OpenVPN",
        &openvpn_standard_paths(),
    )
}

pub fn resolve_xray_executable(configured: Option<&Path>) -> io::Result<PathBuf> {
    resolve_executable(configured, "xray.exe", "Xray", &xray_standard_paths())
}

fn resolve_executable(
    configured: Option<&Path>,
    exe_name: &str,
    display_name: &str,
    standard_paths: &[PathBuf],
) -> io::Result<PathBuf> {
    if let Some(path) = configured {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "configured {display_name} executable '{}' is not an existing file",
                path.display()
            ),
        ));
    }
    for candidate in standard_paths {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            let candidate = dir.join(exe_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{display_name} executable '{exe_name}' not found; install {display_name} or configure its path"
        ),
    ))
}

#[cfg(windows)]
fn wireguard_standard_paths() -> Vec<PathBuf> {
    env::var_os("ProgramFiles")
        .map(|root| vec![PathBuf::from(root).join("WireGuard").join("wireguard.exe")])
        .unwrap_or_default()
}

#[cfg(not(windows))]
fn wireguard_standard_paths() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(windows)]
fn openvpn_standard_paths() -> Vec<PathBuf> {
    env::var_os("ProgramFiles")
        .map(|root| {
            vec![PathBuf::from(root)
                .join("OpenVPN")
                .join("bin")
                .join("openvpn.exe")]
        })
        .unwrap_or_default()
}

#[cfg(not(windows))]
fn openvpn_standard_paths() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(windows)]
fn xray_standard_paths() -> Vec<PathBuf> {
    env::var_os("ProgramFiles")
        .map(|root| vec![PathBuf::from(root).join("Xray").join("xray.exe")])
        .unwrap_or_default()
}

#[cfg(not(windows))]
fn xray_standard_paths() -> Vec<PathBuf> {
    Vec::new()
}

fn xray_command_spec(exe: &Path, test_only: bool) -> CommandSpec {
    let mut args = vec![OsString::from("run")];
    if test_only {
        args.push(OsString::from("-test"));
    }
    args.push(OsString::from("-config"));
    args.push(OsString::from("stdin:"));
    CommandSpec {
        program: exe.to_path_buf(),
        args,
    }
}

fn prepare_xray_config(profile: &Profile) -> io::Result<Vec<u8>> {
    let raw = std::fs::read(&profile.config_path)?;
    let base: serde_json::Value = serde_json::from_slice(&raw).map_err(|err| {
        invalid_data(format!(
            "profile config '{}' is not valid JSON: {err}",
            profile.config_path.display()
        ))
    })?;
    let merged =
        crate::xray::apply_domain_policies(&base, &profile.domain_policies).map_err(|err| {
            invalid_data(format!(
                "failed to apply domain policies to '{}': {err}",
                profile.config_path.display()
            ))
        })?;
    serde_json::to_vec(&merged).map_err(|err| {
        invalid_data(format!(
            "failed to serialize xray config for '{}': {err}",
            profile.config_path.display()
        ))
    })
}

fn run_xray_validation(exe: &Path, config: &[u8]) -> io::Result<()> {
    let spec = xray_command_spec(exe, true);
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(err) = stdin.write_all(config) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    let message = if detail.is_empty() {
        format!("'{}' exited with {}", spec.program.display(), output.status)
    } else {
        detail
    };
    Err(io::Error::other(message))
}

fn spawn_xray(exe: &Path, config: &[u8]) -> io::Result<Child> {
    let spec = xray_command_spec(exe, false);
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command.spawn()?;
    match child.stdin.take() {
        Some(mut stdin) => {
            if let Err(err) = stdin.write_all(config) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
        }
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("failed to open xray stdin"));
        }
    }
    Ok(child)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn status_for(profile_id: &str, state: TunnelState, message: Option<String>) -> TunnelStatus {
    TunnelStatus {
        profile_id: profile_id.to_string(),
        state,
        message,
    }
}

fn run_service_command(spec: &CommandSpec) -> io::Result<()> {
    let output = Command::new(&spec.program).args(&spec.args).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    let message = if detail.is_empty() {
        format!("'{}' exited with {}", spec.program.display(), output.status)
    } else {
        detail
    };
    Err(io::Error::other(message))
}

pub struct TunnelManager {
    wireguard_exe: Option<PathBuf>,
    openvpn_exe: Option<PathBuf>,
    xray_exe: Option<PathBuf>,
    wireguard_services: HashSet<String>,
    openvpn_children: HashMap<String, Child>,
    xray_children: HashMap<String, Child>,
    failures: HashMap<String, String>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self::with_all_executables(None, None, None)
    }

    pub fn with_executables(wireguard: Option<PathBuf>, openvpn: Option<PathBuf>) -> Self {
        Self::with_all_executables(wireguard, openvpn, None)
    }

    pub fn with_all_executables(
        wireguard: Option<PathBuf>,
        openvpn: Option<PathBuf>,
        xray: Option<PathBuf>,
    ) -> Self {
        Self {
            wireguard_exe: wireguard,
            openvpn_exe: openvpn,
            xray_exe: xray,
            wireguard_services: HashSet::new(),
            openvpn_children: HashMap::new(),
            xray_children: HashMap::new(),
            failures: HashMap::new(),
        }
    }

    fn reap_child_if_exited(
        children: &mut HashMap<String, Child>,
        profile_id: &str,
    ) -> io::Result<bool> {
        let Some(child) = children.get_mut(profile_id) else {
            return Ok(false);
        };
        match child.try_wait() {
            Ok(None) => Ok(false),
            Ok(Some(_)) => {
                children.remove(profile_id);
                Ok(true)
            }
            Err(err) => {
                children.remove(profile_id);
                Err(err)
            }
        }
    }

    pub fn connect(&mut self, profile: &Profile) -> io::Result<TunnelStatus> {
        Self::reap_child_if_exited(&mut self.openvpn_children, &profile.id)?;
        Self::reap_child_if_exited(&mut self.xray_children, &profile.id)?;
        if self.wireguard_services.contains(&profile.id)
            || self.openvpn_children.contains_key(&profile.id)
            || self.xray_children.contains_key(&profile.id)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("profile '{}' is already running", profile.id),
            ));
        }
        if !profile.config_path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "profile config '{}' does not exist",
                    profile.config_path.display()
                ),
            ));
        }
        match profile.backend {
            TunnelBackend::WireGuard => {
                let exe = resolve_wireguard_executable(self.wireguard_exe.as_deref())?;
                if self.query_wireguard_service(profile)? {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!(
                            "WireGuard tunnel service for profile '{}' is already installed",
                            profile.id
                        ),
                    ));
                }
                let spec = wireguard_connect_spec(&exe, profile)?;
                run_service_command(&spec)?;
                self.wireguard_services.insert(profile.id.clone());
                self.failures.remove(&profile.id);
                Ok(status_for(&profile.id, TunnelState::Running, None))
            }
            TunnelBackend::OpenVpn => {
                let exe = resolve_openvpn_executable(self.openvpn_exe.as_deref())?;
                let spec = openvpn_connect_spec(&exe, profile)?;
                let mut command = Command::new(&spec.program);
                command
                    .args(&spec.args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                #[cfg(windows)]
                command.creation_flags(CREATE_NO_WINDOW);
                let child = command.spawn()?;
                self.openvpn_children.insert(profile.id.clone(), child);
                self.failures.remove(&profile.id);
                Ok(status_for(&profile.id, TunnelState::Running, None))
            }
            TunnelBackend::Xray => {
                let exe = resolve_xray_executable(self.xray_exe.as_deref())?;
                let config = prepare_xray_config(profile)?;
                run_xray_validation(&exe, &config)?;
                let child = spawn_xray(&exe, &config)?;
                self.xray_children.insert(profile.id.clone(), child);
                self.failures.remove(&profile.id);
                Ok(status_for(&profile.id, TunnelState::Running, None))
            }
        }
    }

    pub fn disconnect(&mut self, profile: &Profile) -> io::Result<TunnelStatus> {
        match profile.backend {
            TunnelBackend::WireGuard => {
                let exe = resolve_wireguard_executable(self.wireguard_exe.as_deref())?;
                let spec = wireguard_disconnect_spec(&exe, profile)?;
                run_service_command(&spec)?;
                self.wireguard_services.remove(&profile.id);
                self.failures.remove(&profile.id);
                Ok(status_for(&profile.id, TunnelState::Stopped, None))
            }
            TunnelBackend::OpenVpn => {
                Self::disconnect_child(&mut self.openvpn_children, &mut self.failures, profile)
            }
            TunnelBackend::Xray => {
                Self::disconnect_child(&mut self.xray_children, &mut self.failures, profile)
            }
        }
    }

    fn disconnect_child(
        children: &mut HashMap<String, Child>,
        failures: &mut HashMap<String, String>,
        profile: &Profile,
    ) -> io::Result<TunnelStatus> {
        let mut child = children.remove(&profile.id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("profile '{}' is not running", profile.id),
            )
        })?;
        child.kill()?;
        child.wait()?;
        failures.remove(&profile.id);
        Ok(status_for(&profile.id, TunnelState::Stopped, None))
    }

    fn query_wireguard_service(&self, profile: &Profile) -> io::Result<bool> {
        #[cfg(windows)]
        let running = wireguard_service_running(profile);
        #[cfg(not(windows))]
        let running = Ok(self.wireguard_services.contains(&profile.id));
        running
    }

    pub fn status(&mut self, profile: &Profile) -> TunnelStatus {
        match profile.backend {
            TunnelBackend::WireGuard => match self.query_wireguard_service(profile) {
                Ok(true) => status_for(&profile.id, TunnelState::Running, None),
                Ok(false) => {
                    self.wireguard_services.remove(&profile.id);
                    status_for(&profile.id, TunnelState::Stopped, None)
                }
                Err(err) => status_for(&profile.id, TunnelState::Failed, Some(err.to_string())),
            },
            TunnelBackend::OpenVpn => Self::child_status(
                &mut self.openvpn_children,
                &mut self.failures,
                &profile.id,
                "openvpn",
            ),
            TunnelBackend::Xray => Self::child_status(
                &mut self.xray_children,
                &mut self.failures,
                &profile.id,
                "xray",
            ),
        }
    }

    fn child_status(
        children: &mut HashMap<String, Child>,
        failures: &mut HashMap<String, String>,
        profile_id: &str,
        name: &str,
    ) -> TunnelStatus {
        if let Some(child) = children.get_mut(profile_id) {
            match child.try_wait() {
                Ok(None) => {
                    return status_for(profile_id, TunnelState::Running, None);
                }
                Ok(Some(exit)) => {
                    let message = format!("{name} exited with {exit}");
                    children.remove(profile_id);
                    failures.insert(profile_id.to_string(), message.clone());
                    return status_for(profile_id, TunnelState::Failed, Some(message));
                }
                Err(err) => {
                    let message = format!("failed to query {name} process: {err}");
                    children.remove(profile_id);
                    failures.insert(profile_id.to_string(), message.clone());
                    return status_for(profile_id, TunnelState::Failed, Some(message));
                }
            }
        }
        if let Some(message) = failures.get(profile_id) {
            return status_for(profile_id, TunnelState::Failed, Some(message.clone()));
        }
        status_for(profile_id, TunnelState::Stopped, None)
    }
}

impl Drop for TunnelManager {
    fn drop(&mut self) {
        for (_, mut child) in self
            .openvpn_children
            .drain()
            .chain(self.xray_children.drain())
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DomainPolicy, DomainRouteTarget, PolicyRoute};
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-vpn-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn wg_profile() -> Profile {
        Profile {
            id: "work-wg".into(),
            name: "Work WireGuard".into(),
            backend: TunnelBackend::WireGuard,
            config_path: PathBuf::from(r"C:\configs\work.conf"),
            interface_name: "wg-work".into(),
            routes: vec![],
            auto_connect: false,
            domain_policies: vec![],
            xray_socks_port: None,
        }
    }

    fn xray_profile() -> Profile {
        Profile {
            id: "work-xray".into(),
            name: "Work Xray".into(),
            backend: TunnelBackend::Xray,
            config_path: PathBuf::from(r"C:\configs\node.json"),
            interface_name: String::new(),
            routes: vec![],
            auto_connect: false,
            domain_policies: vec![],
            xray_socks_port: Some(10808),
        }
    }

    fn ovpn_profile() -> Profile {
        Profile {
            id: "home-ovpn".into(),
            name: "Home OpenVPN".into(),
            backend: TunnelBackend::OpenVpn,
            config_path: PathBuf::from(r"C:\configs\home.ovpn"),
            interface_name: "ovpn-home".into(),
            routes: vec![],
            auto_connect: false,
            domain_policies: vec![],
            xray_socks_port: None,
        }
    }

    #[test]
    fn tunnel_name_strips_conf_and_conf_dpapi_case_insensitively() {
        assert_eq!(
            wireguard_tunnel_name(Path::new(r"C:\c\work.conf")).unwrap(),
            "work"
        );
        assert_eq!(
            wireguard_tunnel_name(Path::new(r"C:\c\work.conf.dpapi")).unwrap(),
            "work"
        );
        assert_eq!(
            wireguard_tunnel_name(Path::new(r"C:\c\WORK.CONF.DPAPI")).unwrap(),
            "WORK"
        );
    }

    #[test]
    fn wireguard_connect_spec_is_install_service_with_config_path() {
        let spec =
            wireguard_connect_spec(Path::new(r"C:\wg\wireguard.exe"), &wg_profile()).unwrap();
        assert_eq!(spec.program, PathBuf::from(r"C:\wg\wireguard.exe"));
        assert_eq!(
            spec.args,
            vec![
                OsString::from("/installtunnelservice"),
                OsString::from(r"C:\configs\work.conf"),
            ]
        );
    }

    #[test]
    fn wireguard_disconnect_spec_is_uninstall_service_with_tunnel_name() {
        let spec =
            wireguard_disconnect_spec(Path::new(r"C:\wg\wireguard.exe"), &wg_profile()).unwrap();
        assert_eq!(spec.program, PathBuf::from(r"C:\wg\wireguard.exe"));
        assert_eq!(
            spec.args,
            vec![
                OsString::from("/uninstalltunnelservice"),
                OsString::from("work"),
            ]
        );
    }

    #[test]
    fn openvpn_spec_is_config_only_when_routes_empty() {
        let spec =
            openvpn_connect_spec(Path::new(r"C:\ovpn\openvpn.exe"), &ovpn_profile()).unwrap();
        assert_eq!(spec.program, PathBuf::from(r"C:\ovpn\openvpn.exe"));
        assert_eq!(
            spec.args,
            vec![
                OsString::from("--config"),
                OsString::from(r"C:\configs\home.ovpn"),
            ]
        );
    }

    #[test]
    fn openvpn_spec_appends_route_nopull_when_routes_exist() {
        let mut profile = ovpn_profile();
        profile.routes = vec![PolicyRoute {
            destination: "10.8.0.0/24".parse().unwrap(),
            metric: 10,
        }];
        let spec = openvpn_connect_spec(Path::new(r"C:\ovpn\openvpn.exe"), &profile).unwrap();
        assert_eq!(
            spec.args,
            vec![
                OsString::from("--config"),
                OsString::from(r"C:\configs\home.ovpn"),
                OsString::from("--route-nopull"),
            ]
        );
    }

    #[test]
    fn tunnel_name_rejects_unsupported_or_missing_name() {
        assert!(wireguard_tunnel_name(Path::new(r"C:\c\work.txt")).is_err());
        assert!(wireguard_tunnel_name(Path::new(r"C:\c\")).is_err());
        assert!(wireguard_tunnel_name(Path::new(".conf")).is_err());
        let mut bad = wg_profile();
        bad.config_path = PathBuf::from(r"C:\configs\work.txt");
        assert!(wireguard_disconnect_spec(Path::new(r"C:\wg\wireguard.exe"), &bad).is_err());
    }

    #[test]
    fn connect_reaps_stale_exited_openvpn_child() {
        let dir = unique_dir("reap-stale");
        let mut profile = ovpn_profile();
        profile.config_path = dir.join("definitely-absent.ovpn");
        let mut manager = TunnelManager::with_executables(None, Some(dir.join("openvpn.exe")));

        #[cfg(windows)]
        let child = {
            let mut command = Command::new("cmd");
            command
                .args(["/C", "exit 0"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW);
            command.spawn().unwrap()
        };
        #[cfg(not(windows))]
        let child = Command::new("sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        manager.openvpn_children.insert(profile.id.clone(), child);

        for _ in 0..20 {
            let exited = manager
                .openvpn_children
                .get_mut(&profile.id)
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some();
            if exited {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let err = manager.connect(&profile).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(!manager.openvpn_children.contains_key(&profile.id));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_service_name_wraps_tunnel_name() {
        assert_eq!(
            wireguard_service_name(&wg_profile()).unwrap(),
            "WireGuardTunnel$work"
        );
        let mut dpapi = wg_profile();
        dpapi.config_path = PathBuf::from(r"C:\configs\site.conf.dpapi");
        assert_eq!(
            wireguard_service_name(&dpapi).unwrap(),
            "WireGuardTunnel$site"
        );
        let mut bad = wg_profile();
        bad.config_path = PathBuf::from(r"C:\configs\work.txt");
        assert!(wireguard_service_name(&bad).is_err());
    }

    #[test]
    fn openvpn_status_persists_failure_after_child_exit() {
        let dir = unique_dir("persist-fail");
        let profile = ovpn_profile();
        let mut manager = TunnelManager::with_executables(None, None);

        #[cfg(windows)]
        let child = {
            let mut command = Command::new("cmd");
            command
                .args(["/C", "exit 7"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW);
            command.spawn().unwrap()
        };
        #[cfg(not(windows))]
        let child = Command::new("sh")
            .args(["-c", "exit 7"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        manager.openvpn_children.insert(profile.id.clone(), child);

        for _ in 0..20 {
            let exited = manager
                .openvpn_children
                .get_mut(&profile.id)
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some();
            if exited {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let first = manager.status(&profile);
        assert_eq!(first.state, TunnelState::Failed);
        assert!(!first.message.as_deref().unwrap_or_default().is_empty());
        assert!(!manager.openvpn_children.contains_key(&profile.id));

        let second = manager.status(&profile);
        assert_eq!(second.state, TunnelState::Failed);
        assert_eq!(second.message, first.message);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xray_command_spec_uses_run_and_stdin_config() {
        let validation = xray_command_spec(Path::new(r"C:\xray\xray.exe"), true);
        assert_eq!(validation.program, PathBuf::from(r"C:\xray\xray.exe"));
        assert_eq!(
            validation.args,
            vec![
                OsString::from("run"),
                OsString::from("-test"),
                OsString::from("-config"),
                OsString::from("stdin:"),
            ]
        );

        let runtime = xray_command_spec(Path::new(r"C:\xray\xray.exe"), false);
        assert_eq!(
            runtime.args,
            vec![
                OsString::from("run"),
                OsString::from("-config"),
                OsString::from("stdin:"),
            ]
        );
    }

    #[test]
    fn prepare_xray_config_applies_domain_policies() {
        let dir = unique_dir("xray-prepare");
        let path = dir.join("node.json");
        fs::write(
            &path,
            r#"{"outbounds":[{"tag":"proxy","protocol":"vless"}],"routing":{"rules":[]}}"#,
        )
        .unwrap();
        let mut profile = xray_profile();
        profile.config_path = path.clone();
        profile.domain_policies = vec![
            DomainPolicy {
                domains: vec![" example.com ".into()],
                target: DomainRouteTarget::Proxy,
            },
            DomainPolicy {
                domains: vec!["internal.lan".into()],
                target: DomainRouteTarget::Direct,
            },
        ];

        let bytes = prepare_xray_config(&profile).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let rules = doc["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["domain"], serde_json::json!(["example.com"]));
        assert_eq!(rules[0]["outboundTag"], "proxy");
        assert_eq!(rules[1]["outboundTag"], "network-orchestrator-direct");
        assert!(!String::from_utf8_lossy(&bytes).contains(&path.display().to_string()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn prepare_xray_config_rejects_malformed_json_without_echoing_content() {
        let dir = unique_dir("xray-badjson");
        let path = dir.join("node.json");
        let sentinel = "UUID-SENTINEL-12345";
        fs::write(&path, format!("{{\"id\":\"{sentinel}\",broken")).unwrap();
        let mut profile = xray_profile();
        profile.config_path = path.clone();

        let err = prepare_xray_config(&profile).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("node.json"));
        assert!(!err.to_string().contains(sentinel));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_xray_executable_rejects_missing_configured_path() {
        let dir = unique_dir("xray-exe");
        let err = resolve_xray_executable(Some(&dir.join("missing-xray.exe"))).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xray_connect_rejects_missing_config_before_process() {
        let dir = unique_dir("xray-missing-config");
        let fake_exe = dir.join("xray.exe");
        fs::write(&fake_exe, b"not a real exe").unwrap();
        let mut profile = xray_profile();
        profile.config_path = dir.join("definitely-absent.json");

        let mut manager = TunnelManager::with_all_executables(None, None, Some(fake_exe));
        let err = manager.connect(&profile).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("definitely-absent.json"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xray_status_persists_failure_after_child_exit() {
        let dir = unique_dir("xray-persist-fail");
        let profile = xray_profile();
        let mut manager = TunnelManager::with_all_executables(None, None, None);

        #[cfg(windows)]
        let child = {
            let mut command = Command::new("cmd");
            command
                .args(["/C", "exit 8"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW);
            command.spawn().unwrap()
        };
        #[cfg(not(windows))]
        let child = Command::new("sh")
            .args(["-c", "exit 8"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        manager.xray_children.insert(profile.id.clone(), child);

        for _ in 0..20 {
            let exited = manager
                .xray_children
                .get_mut(&profile.id)
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some();
            if exited {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let first = manager.status(&profile);
        assert_eq!(first.state, TunnelState::Failed);
        assert!(!first.message.as_deref().unwrap_or_default().is_empty());
        assert!(!manager.xray_children.contains_key(&profile.id));

        let second = manager.status(&profile);
        assert_eq!(second.state, TunnelState::Failed);
        assert_eq!(second.message, first.message);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn connect_rejects_missing_config_before_spawning() {
        let dir = unique_dir("missing-config");
        let fake_exe = dir.join("wireguard.exe");
        fs::write(&fake_exe, b"not a real exe").unwrap();
        let mut profile = wg_profile();
        profile.config_path = dir.join("definitely-absent.conf");

        let mut manager = TunnelManager::with_executables(Some(fake_exe), None);
        let err = manager.connect(&profile).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(&dir).unwrap();
    }
}
