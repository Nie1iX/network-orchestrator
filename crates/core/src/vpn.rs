use crate::models::{
    Profile, ProtocolHealth, ProtocolHealthState, TunnelBackend, TunnelState, TunnelStatus,
};
use crate::windows_job::ChildJob;
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
    let raw = crate::config_security::read_xray_config(&profile.config_path, &profile.id)?;
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

fn spawn_xray(exe: &Path, config: &[u8], stdout: Stdio, stderr: Stdio) -> io::Result<Child> {
    let spec = xray_command_spec(exe, false);
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(stdout)
        .stderr(stderr);
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

const LOG_TAIL_BYTES: usize = 16 * 1024;
const SENSITIVE_KEYS: &[&str] = &["privatekey", "password", "token", "authorization"];

fn starts_with_ascii_ci(bytes: &[u8], i: usize, pattern: &str) -> bool {
    let pat = pattern.as_bytes();
    i + pat.len() <= bytes.len()
        && bytes[i..i + pat.len()]
            .iter()
            .zip(pat)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

pub fn redact_runtime_log(text: &str) -> String {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        if starts_with_ascii_ci(bytes, i, "vless://") {
            let mut j = i + "vless://".len();
            while j < n && !bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            out.push_str("[redacted]");
            i = j;
            continue;
        }
        let mut redacted = false;
        for key in SENSITIVE_KEYS {
            if starts_with_ascii_ci(bytes, i, key)
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            {
                let mut j = i + key.len();
                while j < n && matches!(bytes[j], b' ' | b'\t') {
                    j += 1;
                }
                if j < n && matches!(bytes[j], b'=' | b':') {
                    j += 1;
                    while j < n && matches!(bytes[j], b' ' | b'\t') {
                        j += 1;
                    }
                    let mut k = j;
                    while k < n && bytes[k] != b'\n' && bytes[k] != b'\r' {
                        k += 1;
                    }
                    out.push_str(&text[i..j]);
                    out.push_str("[redacted]");
                    i = k;
                    redacted = true;
                    break;
                }
            }
        }
        if redacted {
            continue;
        }
        if is_uuid_at(bytes, i)
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            && (i + 36 >= n || !bytes[i + 36].is_ascii_alphanumeric())
        {
            out.push_str("[redacted]");
            i += 36;
            continue;
        }
        let len = utf8_len(bytes[i]);
        out.push_str(&text[i..i + len]);
        i += len;
    }
    out
}

fn utf8_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead < 0xE0 {
        2
    } else if lead < 0xF0 {
        3
    } else {
        4
    }
}

fn is_uuid_at(bytes: &[u8], i: usize) -> bool {
    if i + 36 > bytes.len() {
        return false;
    }
    for (offset, b) in bytes[i..i + 36].iter().enumerate() {
        let expected_dash = matches!(offset, 8 | 13 | 18 | 23);
        if expected_dash {
            if *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn health(state: ProtocolHealthState, summary: impl Into<String>) -> ProtocolHealth {
    ProtocolHealth {
        state,
        summary: summary.into(),
        last_handshake_unix: None,
        rx_bytes: None,
        tx_bytes: None,
        log_tail: None,
    }
}

fn openvpn_health(status: &TunnelStatus, log: Option<String>) -> ProtocolHealth {
    let tail = log.filter(|t| !t.trim().is_empty());
    let state = match status.state {
        TunnelState::Stopped => return health(ProtocolHealthState::Unknown, "not running"),
        TunnelState::Failed => ProtocolHealthState::Failed,
        TunnelState::Running => match &tail {
            Some(t) if t.contains("AUTH_FAILED") => ProtocolHealthState::Failed,
            Some(t) if t.contains("Initialization Sequence Completed") => {
                ProtocolHealthState::Healthy
            }
            _ => ProtocolHealthState::Degraded,
        },
    };
    let summary = match state {
        ProtocolHealthState::Failed => status
            .message
            .clone()
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| "authentication or startup failure (see runtime log)".into()),
        ProtocolHealthState::Healthy => "initialization sequence completed".into(),
        ProtocolHealthState::Degraded => "process running; connection not confirmed".into(),
        ProtocolHealthState::Unknown => "not running".into(),
    };
    ProtocolHealth {
        state,
        summary,
        log_tail: tail,
        ..health(state, "")
    }
}

fn xray_health(status: &TunnelStatus, log: Option<String>) -> ProtocolHealth {
    let tail = log.filter(|t| !t.trim().is_empty());
    let (state, summary) = match status.state {
        TunnelState::Stopped => return health(ProtocolHealthState::Unknown, "not running"),
        TunnelState::Failed => (
            ProtocolHealthState::Failed,
            status
                .message
                .clone()
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| "xray process failed".into()),
        ),
        TunnelState::Running => (
            ProtocolHealthState::Degraded,
            "process running; outbound connectivity is not handshake-verified".to_string(),
        ),
    };
    ProtocolHealth {
        state,
        summary,
        log_tail: tail,
        ..health(state, "")
    }
}

fn parse_wg_dump(dump: &str) -> (u64, u64, u64) {
    let mut max_handshake = 0u64;
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in dump.lines().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 7 {
            continue;
        }
        if let Ok(handshake) = fields[4].trim().parse::<u64>() {
            max_handshake = max_handshake.max(handshake);
        }
        rx = rx.saturating_add(fields[5].trim().parse::<u64>().unwrap_or(0));
        tx = tx.saturating_add(fields[6].trim().parse::<u64>().unwrap_or(0));
    }
    (max_handshake, rx, tx)
}

fn wireguard_health_from_dump(dump: &str) -> ProtocolHealth {
    let (handshake, rx, tx) = parse_wg_dump(dump);
    let (state, summary) = if handshake > 0 {
        (
            ProtocolHealthState::Healthy,
            format!("latest handshake at unix {handshake}"),
        )
    } else {
        (
            ProtocolHealthState::Degraded,
            "no WireGuard handshake recorded yet".to_string(),
        )
    };
    ProtocolHealth {
        state,
        summary,
        last_handshake_unix: (handshake > 0).then_some(handshake),
        rx_bytes: Some(rx),
        tx_bytes: Some(tx),
        log_tail: None,
    }
}

pub struct TunnelManager {
    wireguard_exe: Option<PathBuf>,
    openvpn_exe: Option<PathBuf>,
    xray_exe: Option<PathBuf>,
    log_dir: Option<PathBuf>,
    wireguard_services: HashSet<String>,
    openvpn_children: HashMap<String, Child>,
    xray_children: HashMap<String, Child>,
    failures: HashMap<String, String>,
    child_job: Option<ChildJob>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self::with_all_executables(None, None, None)
    }

    pub fn with_log_dir(log_dir: PathBuf) -> Self {
        let mut manager = Self::with_all_executables(None, None, None);
        manager.log_dir = Some(log_dir);
        manager
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
            log_dir: None,
            wireguard_services: HashSet::new(),
            openvpn_children: HashMap::new(),
            xray_children: HashMap::new(),
            failures: HashMap::new(),
            child_job: None,
        }
    }

    fn child_log_stdio(&self, profile_id: &str, tag: &str) -> io::Result<(Stdio, Stdio)> {
        let Some(dir) = &self.log_dir else {
            return Ok((Stdio::null(), Stdio::null()));
        };
        std::fs::create_dir_all(dir)?;
        crate::config_security::protect_path(dir)?;
        let path = dir.join(format!(
            "{}-{tag}.log",
            crate::config_vault::sanitize_profile_id(profile_id)?
        ));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        crate::config_security::protect_path(&path)?;
        let err = file.try_clone()?;
        Ok((Stdio::from(file), Stdio::from(err)))
    }

    fn log_tail_for_tag(
        &self,
        profile_id: &str,
        tag: &str,
        max_bytes: usize,
    ) -> io::Result<Option<String>> {
        if max_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_bytes must be nonzero",
            ));
        }
        let Some(dir) = &self.log_dir else {
            return Ok(None);
        };
        let safe = crate::config_vault::sanitize_profile_id(profile_id)?;
        let path = dir.join(format!("{safe}-{tag}.log"));
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        let mut slice = &bytes[bytes.len().saturating_sub(max_bytes)..];
        while !slice.is_empty() && (slice[0] & 0b1100_0000) == 0b1000_0000 {
            slice = &slice[1..];
        }
        let text = String::from_utf8_lossy(slice);
        if text.trim().is_empty() {
            Ok(None)
        } else {
            Ok(Some(redact_runtime_log(&text)))
        }
    }

    pub fn log_tail(&self, profile_id: &str, max_bytes: usize) -> io::Result<Option<String>> {
        let mut combined = String::new();
        for tag in ["openvpn", "xray"] {
            if let Some(tail) = self.log_tail_for_tag(profile_id, tag, max_bytes)? {
                if !combined.is_empty() {
                    combined.push('\n');
                }
                combined.push_str(&tail);
            }
        }
        if combined.is_empty() {
            Ok(None)
        } else {
            Ok(Some(combined))
        }
    }

    pub fn protocol_health(&mut self, profile: &Profile) -> ProtocolHealth {
        let status = self.status(profile);
        match profile.backend {
            TunnelBackend::OpenVpn => {
                let log = self
                    .log_tail_for_tag(&profile.id, "openvpn", LOG_TAIL_BYTES)
                    .ok()
                    .flatten();
                openvpn_health(&status, log)
            }
            TunnelBackend::Xray => {
                let log = self
                    .log_tail_for_tag(&profile.id, "xray", LOG_TAIL_BYTES)
                    .ok()
                    .flatten();
                xray_health(&status, log)
            }
            TunnelBackend::WireGuard => match status.state {
                TunnelState::Stopped => health(ProtocolHealthState::Unknown, "not running"),
                TunnelState::Failed => ProtocolHealth {
                    state: ProtocolHealthState::Failed,
                    summary: status
                        .message
                        .unwrap_or_else(|| "wireguard service check failed".into()),
                    ..health(ProtocolHealthState::Failed, "")
                },
                TunnelState::Running => match self.wg_dump(profile) {
                    Ok(dump) => wireguard_health_from_dump(&dump),
                    Err(err) => health(
                        ProtocolHealthState::Degraded,
                        format!("WireGuard statistics unavailable: {err}"),
                    ),
                },
            },
        }
    }

    fn wg_dump(&self, profile: &Profile) -> io::Result<String> {
        let exe = self.wg_query_exe()?;
        let name = wireguard_tunnel_name(&profile.config_path)?;
        let output = Command::new(&exe)
            .args([
                OsString::from("show"),
                OsString::from(&name),
                OsString::from("dump"),
            ])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "wg show failed with {}",
                output.status
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| invalid_data("wg dump output was not valid UTF-8"))
    }

    fn wg_query_exe(&self) -> io::Result<PathBuf> {
        #[cfg(windows)]
        {
            if let Ok(service_exe) = resolve_wireguard_executable(self.wireguard_exe.as_deref()) {
                if let Some(dir) = service_exe.parent() {
                    let sibling = dir.join("wg.exe");
                    if sibling.is_file() {
                        return Ok(sibling);
                    }
                }
            }
            if let Some(root) = env::var_os("ProgramFiles") {
                let candidate = PathBuf::from(root).join("WireGuard").join("wg.exe");
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
            if let Some(path_var) = env::var_os("PATH") {
                for dir in env::split_paths(&path_var) {
                    let candidate = dir.join("wg.exe");
                    if candidate.is_file() {
                        return Ok(candidate);
                    }
                }
            }
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "wg.exe not found next to wireguard.exe, in Program Files, or on PATH",
            ))
        }
        #[cfg(not(windows))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WireGuard statistics query is only supported on Windows",
            ))
        }
    }

    fn ensure_child_job(&mut self) -> io::Result<&ChildJob> {
        if self.child_job.is_none() {
            self.child_job = Some(ChildJob::new()?);
        }
        Ok(self.child_job.as_ref().unwrap())
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
                let (out, err) = self.child_log_stdio(&profile.id, "openvpn")?;
                let mut command = Command::new(&spec.program);
                command
                    .args(&spec.args)
                    .stdin(Stdio::null())
                    .stdout(out)
                    .stderr(err);
                #[cfg(windows)]
                command.creation_flags(CREATE_NO_WINDOW);
                let mut child = command.spawn()?;
                if let Err(err) = self.ensure_child_job().and_then(|job| job.assign(&child)) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(err);
                }
                self.openvpn_children.insert(profile.id.clone(), child);
                self.failures.remove(&profile.id);
                Ok(status_for(&profile.id, TunnelState::Running, None))
            }
            TunnelBackend::Xray => {
                let exe = resolve_xray_executable(self.xray_exe.as_deref())?;
                let config = prepare_xray_config(profile)?;
                run_xray_validation(&exe, &config)?;
                let (out, err) = self.child_log_stdio(&profile.id, "xray")?;
                let mut child = spawn_xray(&exe, &config, out, err)?;
                if let Err(err) = self.ensure_child_job().and_then(|job| job.assign(&child)) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(err);
                }
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

    #[cfg(windows)]
    #[test]
    fn prepare_xray_config_decrypts_dpapi_config() {
        let dir = unique_dir("xray-dpapi-prepare");
        let path = dir.join("node.json.dpapi");
        let ciphertext = crate::config_security::protect_user_data(
            br#"{"outbounds":[{"tag":"proxy","protocol":"vless"}],"routing":{"rules":[]}}"#,
            &crate::config_security::xray_context("node-dpapi"),
        )
        .unwrap();
        fs::write(&path, &ciphertext).unwrap();
        let mut profile = xray_profile();
        profile.id = "node-dpapi".into();
        profile.config_path = path;

        let bytes = prepare_xray_config(&profile).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["outbounds"][0]["protocol"], "vless");
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

    #[test]
    fn redact_runtime_log_strips_all_secret_classes() {
        let text = concat!(
            "connecting vless://550e8400-e29b-41d4-a716-446655440000@host:443?sni=x ok\n",
            "password=hunter2 end\n",
            "PASSWORD: hunter3\n",
            "PrivateKey = PRIVVAL-1\n",
            "Authorization: Bearer SECRET-TOKEN-9\n",
            "plain uuid 123e4567-e89b-12d3-a456-426614174000 tail\n",
            "useful line kept\n",
        );
        let out = redact_runtime_log(text);
        for sentinel in [
            "550e8400-e29b-41d4-a716-446655440000",
            "hunter2",
            "hunter3",
            "PRIVVAL-1",
            "SECRET-TOKEN-9",
            "123e4567-e89b-12d3-a456-426614174000",
            "vless://",
        ] {
            assert!(!out.contains(sentinel), "leaked {sentinel}: {out}");
        }
        assert!(out.contains("[redacted]"));
        assert!(out.contains("useful line kept"));
        assert!(out.contains("password=[redacted]"));
    }

    #[test]
    fn redact_runtime_log_preserves_unicode_and_still_redacts() {
        let text = concat!(
            "Привет ✓ İ юникод ✓ password=секрет-ЗНАЧ\n",
            "vless://550e8400-e29b-41d4-a716-446655440000@хост:443\n",
            "uuid 123e4567-e89b-12d3-a456-426614174000 ✓\n",
        );
        let out = redact_runtime_log(text);
        for sentinel in [
            "секрет-ЗНАЧ",
            "550e8400-e29b-41d4-a716-446655440000",
            "123e4567-e89b-12d3-a456-426614174000",
            "vless://",
        ] {
            assert!(!out.contains(sentinel), "leaked {sentinel}: {out}");
        }
        assert!(out.contains("Привет ✓ İ юникод ✓"));
        assert!(out.contains("✓\n"));
    }

    #[test]
    fn child_log_stdio_creates_protected_log_file() {
        let dir = unique_dir("logs");
        let manager = TunnelManager::with_log_dir(dir.join("logs"));
        let (out, err) = manager.child_log_stdio("p1", "openvpn").unwrap();
        drop((out, err));
        let path = dir.join("logs").join("p1-openvpn.log");
        assert!(path.is_file());
        #[cfg(windows)]
        {
            let protection = crate::config_security::inspect_path_protection(&path).unwrap();
            assert!(protection.protected_dacl && protection.current_user);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_tail_returns_redacted_tail() {
        let dir = unique_dir("tail");
        let logs = dir.join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(
            logs.join("p1-openvpn.log"),
            "line1\npassword=sentinel-x\nline3",
        )
        .unwrap();
        let manager = TunnelManager::with_log_dir(logs);

        let tail = manager.log_tail("p1", 1024).unwrap().unwrap();
        assert!(!tail.contains("sentinel-x"));
        assert!(tail.contains("line3"));

        let short = manager.log_tail("p1", 5).unwrap().unwrap();
        assert!(!short.contains("line1"));

        assert!(manager.log_tail("p1", 0).is_err());
        assert!(manager.log_tail("nobody", 100).unwrap().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn openvpn_health_maps_status_and_log_markers() {
        let running = status_for("p", TunnelState::Running, None);
        assert_eq!(
            openvpn_health(
                &running,
                Some("note\nInitialization Sequence Completed".into())
            )
            .state,
            ProtocolHealthState::Healthy
        );
        assert_eq!(
            openvpn_health(
                &running,
                Some("Initialization Sequence Completed\nAUTH_FAILED".into())
            )
            .state,
            ProtocolHealthState::Failed
        );
        assert_eq!(
            openvpn_health(&running, Some("connecting...".into())).state,
            ProtocolHealthState::Degraded
        );
        assert_eq!(
            openvpn_health(&running, None).state,
            ProtocolHealthState::Degraded
        );
        let failed = status_for("p", TunnelState::Failed, Some("exited".into()));
        assert_eq!(
            openvpn_health(&failed, Some("tail".into())).state,
            ProtocolHealthState::Failed
        );
        let stopped = status_for("p", TunnelState::Stopped, None);
        assert_eq!(
            openvpn_health(&stopped, None).state,
            ProtocolHealthState::Unknown
        );
    }

    #[test]
    fn xray_health_uses_not_handshake_verified_wording() {
        let running = status_for("p", TunnelState::Running, None);
        let health = xray_health(&running, Some("tail".into()));
        assert_eq!(health.state, ProtocolHealthState::Degraded);
        assert_eq!(
            health.summary,
            "process running; outbound connectivity is not handshake-verified"
        );
        assert_eq!(health.log_tail.as_deref(), Some("tail"));
        assert_eq!(
            xray_health(&status_for("p", TunnelState::Stopped, None), None).state,
            ProtocolHealthState::Unknown
        );
        let failed = status_for("p", TunnelState::Failed, Some("xray exited".into()));
        let health = xray_health(&failed, Some("tail".into()));
        assert_eq!(health.state, ProtocolHealthState::Failed);
        assert!(health.summary.contains("xray exited"));
    }

    #[test]
    fn parse_wg_dump_sums_peers_without_echoing_keys() {
        let dump = concat!(
            "IFACEKEY\tPUB\t9000\t0\n",
            "PEERKEY-ONE\tpsk\t(none)\t10.0.0.0/24\t1700000000\t100\t200\toff\n",
            "PEERKEY-TWO\tpsk\t10.1.2.3:51820\t10.1.0.0/24\t1700000100\t300\t400\toff\n",
        );
        let (handshake, rx, tx) = parse_wg_dump(dump);
        assert_eq!(handshake, 1700000100);
        assert_eq!(rx, 400);
        assert_eq!(tx, 600);

        let health = wireguard_health_from_dump(dump);
        assert_eq!(health.state, ProtocolHealthState::Healthy);
        assert_eq!(health.last_handshake_unix, Some(1700000100));
        assert_eq!(health.rx_bytes, Some(400));
        assert!(!health.summary.contains("PEERKEY"));
        assert!(!health.summary.contains("10.1.2.3"));

        let zero = "IFACE\tPUB\t0\t0\nPEER\tpsk\t(none)\tip\t0\t0\t0\toff\n";
        assert_eq!(
            wireguard_health_from_dump(zero).state,
            ProtocolHealthState::Degraded
        );
        assert_eq!(
            wireguard_health_from_dump("garbage\n\n").state,
            ProtocolHealthState::Degraded
        );
    }

    #[test]
    fn log_tail_for_tag_reads_only_matching_backend_log() {
        let dir = unique_dir("tag-logs");
        let logs = dir.join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("p-openvpn.log"), "AUTH_FAILED: bad creds\n").unwrap();
        fs::write(logs.join("p-xray.log"), "xray started\n").unwrap();
        let manager = TunnelManager::with_log_dir(logs);

        let xray_tail = manager
            .log_tail_for_tag("p", "xray", 1024)
            .unwrap()
            .unwrap();
        assert!(!xray_tail.contains("AUTH_FAILED"), "{xray_tail}");
        let openvpn_tail = manager
            .log_tail_for_tag("p", "openvpn", 1024)
            .unwrap()
            .unwrap();
        assert!(openvpn_tail.contains("AUTH_FAILED"));
        let combined = manager.log_tail("p", 4096).unwrap().unwrap();
        assert!(combined.contains("AUTH_FAILED"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn protocol_health_uses_backend_specific_log() {
        let dir = unique_dir("health-logs");
        let logs = dir.join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("p-openvpn.log"), "AUTH_FAILED\n").unwrap();
        fs::write(logs.join("p-xray.log"), "xray started\n").unwrap();
        let mut manager = TunnelManager::with_log_dir(logs);

        let mut xray = xray_profile();
        xray.id = "p".into();
        let child = Command::new("cmd")
            .args(["/C", "ping", "-n", "30", "127.0.0.1", ">NUL"])
            .spawn()
            .unwrap();
        manager.xray_children.insert("p".into(), child);
        let health = manager.protocol_health(&xray);
        assert_ne!(health.state, ProtocolHealthState::Failed);
        let tail = health.log_tail.unwrap_or_default();
        assert!(!tail.contains("AUTH_FAILED"), "{tail}");

        let mut ovpn = ovpn_profile();
        ovpn.id = "p".into();
        let child = Command::new("cmd")
            .args(["/C", "ping", "-n", "30", "127.0.0.1", ">NUL"])
            .spawn()
            .unwrap();
        manager.openvpn_children.insert("p".into(), child);
        let health = manager.protocol_health(&ovpn);
        assert_eq!(health.state, ProtocolHealthState::Failed);
        assert!(health.log_tail.unwrap().contains("AUTH_FAILED"));

        fs::remove_dir_all(&dir).unwrap();
    }
}
