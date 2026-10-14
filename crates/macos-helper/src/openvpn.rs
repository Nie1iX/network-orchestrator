//! OpenVPN executor. The helper stages a sanitized copy of the config in a
//! root-only directory, runs the pinned self-contained `openvpn` binary as
//! root with every dangerous behaviour switched off (no pulled routes, no
//! scripts, no DNS hooks), and drives it through its management socket:
//! password prompts are answered from the request, and when the server's push
//! arrives the helper — not OpenVPN — installs the routes and DNS, with a
//! bypass for the server itself. Everything is journaled and undone when the
//! session ends, however it ends.

use crate::dns;
use crate::journal::{Journal, Record};
use crate::routes::{self, RouteOp, Target, Uplink};
use crate::sysexec::Runner;
use crate::xray::{Error, Process};
use base64::Engine as _;
use ipnet::IpNet;
use net_manager_core::daemon_protocol::{
    OpenVpnConnectRequest, OpenVpnConnectResult, OpenVpnConnectionState, OpenVpnCredentials,
    OpenVpnDisconnectResult, OpenVpnFailure, OpenVpnStatusResult, OpenVpnWarning,
};
use net_manager_core::openvpn_config::{
    sanitize_openvpn_config, SanitizedOpenVpnConfig, MAX_ASSET_BYTES, MAX_CONFIG_BYTES,
};
use net_manager_core::openvpn_management::{
    management_password_reply, parse_management_line, state_failure_detail, ManagementEvent,
    ManagementSnapshot, OpenVpnState,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Where staged configs live (cleared at boot); also the path the sanitizer
/// embeds into the config for staged assets.
pub const RUNTIME_ROOT: &str = "/var/run/network-orchestrator/openvpn";
const MANAGEMENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const TERM_GRACE: Duration = Duration::from_secs(3);
const MAX_MANAGEMENT_LINE: usize = 16 * 1024;
const MAX_REMOTES: usize = 8;
const MAX_ASSETS: usize = 32;

pub struct SpawnSpec<'a> {
    pub binary: &'a Path,
    pub args: &'a [String],
    pub cwd: &'a Path,
    pub uid: u32,
}

/// Everything that needs root or a real machine.
pub trait OvpnPlatform: Send + Sync {
    /// The verified private copy of the pinned binary.
    fn stage_binary(&self) -> io::Result<PathBuf>;
    /// A free `utunN` for OpenVPN to open.
    fn free_unit(&self) -> io::Result<String>;
    fn spawn(&self, spec: &SpawnSpec) -> io::Result<Box<dyn Process>>;
    fn resolve(&self, host: &str) -> Vec<IpAddr>;
    /// Whether `pid` is still an OpenVPN of ours (recovery only).
    fn is_our_openvpn(&self, pid: u32) -> bool;
    fn kill(&self, pid: u32);
}

struct Active {
    profile_id: String,
    owner_uid: u32,
    tun: String,
    uplink: Uplink,
    record: Record,
    child: Box<dyn Process>,
    stage: PathBuf,
    snapshot: ManagementSnapshot,
    credentials: Option<OpenVpnCredentials>,
    management: UnixStream,
    remotes: Vec<IpAddr>,
    policy_networks: Vec<IpNet>,
    /// Signature of the push the installed network state came from.
    applied: Option<String>,
    applied_nets: Vec<IpNet>,
    warnings: Vec<OpenVpnWarning>,
    stop: Arc<AtomicBool>,
    monitor: Option<JoinHandle<()>>,
}

/// What a finished (failed) session left to report.
struct Finished {
    profile_id: String,
    owner_uid: u32,
    status: OpenVpnStatusResult,
}

struct Inner {
    platform: Box<dyn OvpnPlatform>,
    runner: Box<dyn Runner>,
    journal: Journal,
    staging_root: PathBuf,
    active: Mutex<Option<Active>>,
    finished: Mutex<Option<Finished>>,
}

pub struct OpenVpnExecutor(Arc<Inner>);

fn io_err(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn stage_name(profile_id: &str) -> String {
    let digest = Sha256::digest(profile_id.as_bytes());
    let hex: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("ovpn-{hex}")
}

fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| io_err("OpenVPN staging file creation failed"))?;
    file.write_all(bytes)
        .map_err(|_| io_err("OpenVPN staging file write failed"))?;
    file.sync_all()
        .map_err(|_| io_err("OpenVPN staging file sync failed"))
}

/// Creates `<root>/<uid>/<name>` (root-only at every level) and writes the
/// sanitized config and assets into it.
fn stage_config(
    root: &Path,
    uid: u32,
    name: &str,
    config: &SanitizedOpenVpnConfig,
) -> io::Result<PathBuf> {
    if config.config.len() > MAX_CONFIG_BYTES || config.assets.len() > MAX_ASSETS {
        return Err(io_err("invalid OpenVPN staging input"));
    }
    for dir in [root.parent().filter(|p| !p.exists()), Some(root)]
        .into_iter()
        .flatten()
    {
        if !dir.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|_| io_err("OpenVPN staging failed"))?;
        }
    }
    let root_uid = fs::symlink_metadata(root)
        .map_err(|_| io_err("OpenVPN staging failed"))?
        .uid();
    let user_dir = root.join(uid.to_string());
    if !user_dir.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(&user_dir)
            .map_err(|_| io_err("OpenVPN staging failed"))?;
    }
    let metadata = fs::symlink_metadata(&user_dir).map_err(|_| io_err("OpenVPN staging failed"))?;
    if !metadata.is_dir() || metadata.uid() != root_uid || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "OpenVPN staging directory is unsafe",
        ));
    }
    let directory = user_dir.join(name);
    // A leftover from a crash lives only inside this root-only tree.
    if directory.exists() {
        let _ = fs::remove_dir_all(&directory);
    }
    DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|_| io_err("OpenVPN staging directory could not be created"))?;
    let result = (|| {
        write_private_file(&directory.join("config.ovpn"), config.config.as_bytes())?;
        for (index, asset) in config.assets.iter().enumerate() {
            if asset.name != format!("asset-{index}")
                || asset.bytes.is_empty()
                || asset.bytes.len() > MAX_ASSET_BYTES
            {
                return Err(io_err("invalid OpenVPN asset"));
            }
            write_private_file(&directory.join(&asset.name), &asset.bytes)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&directory);
        return Err(error);
    }
    Ok(directory)
}

/// Fixed flags that follow (and so override) anything the config says.
pub fn openvpn_args(config: &Path, unit: &str, socket: &Path) -> Vec<String> {
    [
        "--config",
        config.to_str().expect("fixed runtime config path"),
        "--dev",
        unit,
        "--dev-type",
        "tun",
        "--disable-dco",
        // The helper owns routes and DNS: nothing pulled, nothing executed.
        "--route-nopull",
        "--route-noexec",
        "--script-security",
        "1",
        "--ignore-unknown-option",
        "dns-updown",
        "--dns-updown",
        "disable",
        "--management",
        socket.to_str().expect("fixed management socket path"),
        "unix",
        "--management-client-user",
        "root",
        "--management-query-passwords",
        "--management-hold",
        "--auth-nocache",
        "--verb",
        "3",
    ]
    .iter()
    .map(|arg| (*arg).to_owned())
    .collect()
}

/// `remote` hosts of the (sanitized) config, outside inline blocks.
pub fn remote_hosts(config: &str) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    let mut in_block = false;
    for line in config.lines() {
        let line = line.trim();
        if in_block {
            if line.starts_with("</") && !line.starts_with("</connection") {
                in_block = false;
            }
            continue;
        }
        if line.starts_with('<') && !line.starts_with("</") && !line.starts_with("<connection") {
            in_block = true;
            continue;
        }
        let mut tokens = line.split_whitespace();
        if tokens.next() == Some("remote") {
            if let Some(host) = tokens.next() {
                if !hosts.iter().any(|known| known == host) && hosts.len() < MAX_REMOTES {
                    hosts.push(host.to_string());
                }
            }
        }
    }
    hosts
}

/// The server address in a `>STATE:` line (field 5 after the timestamp).
pub fn remote_ip_of_state(line: &str) -> Option<IpAddr> {
    let data = line
        .strip_prefix(">STATE:")
        .or_else(|| line.strip_prefix("STATE:"))?;
    data.split(',').nth(4)?.parse().ok()
}

fn connection_state(state: Option<OpenVpnState>) -> OpenVpnConnectionState {
    match state {
        None => OpenVpnConnectionState::Connecting,
        Some(OpenVpnState::Connected) => OpenVpnConnectionState::Connected,
        Some(OpenVpnState::Reconnecting) => OpenVpnConnectionState::Reconnecting,
        Some(OpenVpnState::Exiting) => OpenVpnConnectionState::Failed,
        Some(_) => OpenVpnConnectionState::Connecting,
    }
}

fn push_signature(routes: &[IpNet], dns: &[IpAddr]) -> String {
    format!("{routes:?}|{dns:?}")
}

impl Inner {
    fn lock_active(&self) -> std::sync::MutexGuard<'_, Option<Active>> {
        self.active.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn status_of(active: &Active) -> OpenVpnStatusResult {
        let failed = active.snapshot.state == Some(OpenVpnState::Exiting);
        OpenVpnStatusResult {
            profile_id: active.profile_id.clone(),
            state: connection_state(active.snapshot.state),
            interface_name: Some(active.tun.clone()),
            rx_bytes: active.snapshot.received,
            tx_bytes: active.snapshot.sent,
            applied_routes: active.applied_nets.clone(),
            warnings: active.warnings.clone(),
            failure_reason: if failed {
                active.snapshot.last_failure
            } else {
                None
            },
        }
    }

    /// Undo everything; remember a failure so the UI can still show why.
    fn teardown(&self, mut active: Active, failure: Option<OpenVpnFailure>, join_monitor: bool) {
        active.stop.store(true, Ordering::SeqCst);
        active.child.stop(TERM_GRACE);
        if join_monitor {
            if let Some(handle) = active.monitor.take() {
                let _ = handle.join();
            }
        }
        let dns_ok = match &active.record.dns {
            Some(snapshot) => dns::restore(&*self.runner, snapshot).is_ok(),
            None => true,
        };
        routes::remove(&*self.runner, &active.record.routes);
        let _ = fs::remove_dir_all(&active.stage);
        if dns_ok {
            let _ = self.journal.clear();
        }
        let reason = failure.or(active.snapshot.last_failure);
        if let Some(reason) = reason {
            let mut status = Self::status_of(&active);
            status.state = OpenVpnConnectionState::Failed;
            status.failure_reason = Some(reason);
            status.applied_routes.clear();
            *self.finished.lock().unwrap_or_else(|e| e.into_inner()) = Some(Finished {
                profile_id: active.profile_id.clone(),
                owner_uid: active.owner_uid,
                status,
            });
        }
    }

    /// Install what the server pushed (or re-install if it changed).
    fn apply_network(&self, active: &mut Active) -> Result<(), String> {
        let Some(push) = active.snapshot.active_push.as_ref() else {
            return Ok(());
        };
        let mut networks: Vec<IpNet> = push.routes.clone();
        networks.extend(active.policy_networks.iter().copied());
        let mut dns_servers: Vec<IpAddr> = push.legacy_dns_servers.clone();
        for server in &push.dns_servers {
            for address in &server.addresses {
                if !dns_servers.contains(address) {
                    dns_servers.push(*address);
                }
            }
        }
        let signature = push_signature(&networks, &dns_servers);
        if active.applied.as_deref() == Some(signature.as_str()) {
            return Ok(());
        }
        // A changed push replaces the earlier state; DNS is only snapshotted once.
        routes::remove(&*self.runner, &active.record.routes);
        active.record.routes.clear();

        let mut ops: Vec<RouteOp> = Vec::new();
        if let Some(gateway) = active.uplink.gateway {
            for ip in &active.remotes {
                if let IpAddr::V4(v4) = ip {
                    if *v4 != gateway {
                        ops.push(RouteOp {
                            network: *ip,
                            prefix: 32,
                            target: Target::Gateway {
                                address: IpAddr::V4(gateway),
                            },
                            optional: true,
                        });
                    }
                }
            }
        }
        ops.extend(routes::interface_routes(&active.tun, &networks));
        // Write-ahead only for what the tunnel cannot do without.
        active.record.routes = ops.iter().filter(|op| !op.optional).cloned().collect();
        let _ = self.journal.save(&active.record);
        match routes::apply(&*self.runner, &ops) {
            Ok(installed) => {
                active.applied_nets = installed
                    .iter()
                    .filter(|op| matches!(op.target, Target::Interface { .. }))
                    .filter_map(|op| IpNet::new(op.network, op.prefix).ok())
                    .collect();
                active.record.routes = installed;
            }
            Err(err) => {
                active.record.routes.clear();
                let _ = self.journal.save(&active.record);
                return Err(format!("The tunnel routes could not be installed ({err})"));
            }
        }
        active
            .warnings
            .retain(|w| *w != OpenVpnWarning::DnsNotApplied);
        if !dns_servers.is_empty() {
            let snapshot = match &active.record.dns {
                Some(existing) => Some(existing.clone()),
                None => dns::snapshot(&*self.runner, &active.uplink.interface).ok(),
            };
            match snapshot {
                Some(snapshot) => {
                    // Journal before touching DNS, like the other executors.
                    active.record.dns = Some(snapshot.clone());
                    let _ = self.journal.save(&active.record);
                    if dns::apply(&*self.runner, &snapshot, &dns_servers).is_err() {
                        let _ = dns::restore(&*self.runner, &snapshot);
                        active.record.dns = None;
                        active.warnings.push(OpenVpnWarning::DnsNotApplied);
                    }
                }
                None => active.warnings.push(OpenVpnWarning::DnsNotApplied),
            }
        }
        active
            .warnings
            .retain(|w| *w != OpenVpnWarning::Ipv6NotCovered);
        let v4_default = active
            .applied_nets
            .iter()
            .any(|n| n.prefix_len() == 1 && n.addr().is_ipv4());
        let v6_default = active
            .applied_nets
            .iter()
            .any(|n| n.prefix_len() == 1 && n.addr().is_ipv6());
        if v4_default && !v6_default {
            active.warnings.push(OpenVpnWarning::Ipv6NotCovered);
        }
        active.applied = Some(signature);
        let _ = self.journal.save(&active.record);
        Ok(())
    }

    fn handle_events(
        &self,
        profile_id: &str,
        events: Vec<ManagementEvent>,
        remote: Option<IpAddr>,
    ) {
        let mut guard = self.lock_active();
        let Some(active) = guard.as_mut().filter(|a| a.profile_id == profile_id) else {
            return;
        };
        if let Some(ip) = remote {
            if !active.remotes.contains(&ip) {
                active.remotes.push(ip);
            }
        }
        let mut credential_failure = false;
        for event in events {
            match event {
                ManagementEvent::PasswordPrompt(prompt) => {
                    let reply = management_password_reply(prompt, active.credentials.as_ref());
                    let written = reply
                        .ok()
                        .and_then(|text| active.management.write_all(text.as_bytes()).ok());
                    if written.is_none() {
                        credential_failure = true;
                    }
                }
                other => active.snapshot.apply(other),
            }
        }
        if credential_failure {
            let active = guard.take().expect("checked above");
            drop(guard);
            self.teardown(active, Some(OpenVpnFailure::CredentialsRequired), false);
            return;
        }
        if active.snapshot.state == Some(OpenVpnState::Connected)
            && active.snapshot.active_push.is_some()
        {
            if let Err(message) = self.apply_network(active) {
                eprintln!("network-orchestrator-helper: openvpn: {message}");
                let active = guard.take().expect("checked above");
                drop(guard);
                self.teardown(active, Some(OpenVpnFailure::ExitWithError), false);
                return;
            }
        }
        if active.snapshot.state == Some(OpenVpnState::Exiting) {
            let active = guard.take().expect("checked above");
            drop(guard);
            self.teardown(active, None, false);
        }
    }
}

/// Reads management lines until the session ends or `stop` is set.
fn monitor(inner: Arc<Inner>, profile_id: String, mut stream: UnixStream, stop: Arc<AtomicBool>) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let read = stream.read(&mut chunk);
        let mut events = Vec::new();
        let mut remote = None;
        let mut closed = false;
        match read {
            Ok(0) => closed = true,
            Ok(n) => {
                pending.extend_from_slice(&chunk[..n]);
                while let Some(end) = pending.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = pending.drain(..=end).collect();
                    let Ok(text) = std::str::from_utf8(&line[..end]) else {
                        continue;
                    };
                    let text = text.strip_suffix('\r').unwrap_or(text);
                    if let Some(ip) = remote_ip_of_state(text) {
                        remote = Some(ip);
                    }
                    if let Ok(Some(event)) = parse_management_line(text) {
                        if let Some(detail) = state_failure_detail(text) {
                            events.push(ManagementEvent::FailureDetail(detail));
                        }
                        events.push(event);
                    }
                }
                if pending.len() > MAX_MANAGEMENT_LINE {
                    closed = true;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => closed = true,
        }
        if !events.is_empty() || remote.is_some() {
            inner.handle_events(&profile_id, events, remote);
        }
        // The child may be gone without a management goodbye.
        let gone = {
            let mut guard = inner.lock_active();
            match guard.as_mut().filter(|a| a.profile_id == profile_id) {
                None => return,
                Some(active) => closed || !active.child.alive(),
            }
        };
        if gone {
            let taken = {
                let mut guard = inner.lock_active();
                if guard.as_ref().is_some_and(|a| a.profile_id == profile_id) {
                    guard.take()
                } else {
                    None
                }
            };
            if let Some(mut active) = taken {
                // A clean exit after an AuthenticationFailed event keeps its reason.
                let failure = active
                    .snapshot
                    .last_failure
                    .or(Some(OpenVpnFailure::ConnectionLost));
                active.monitor = None;
                inner.teardown(active, failure, false);
            }
            return;
        }
    }
}

impl OpenVpnExecutor {
    pub fn new(
        platform: Box<dyn OvpnPlatform>,
        runner: Box<dyn Runner>,
        journal: Journal,
        staging_root: PathBuf,
    ) -> Self {
        Self(Arc::new(Inner {
            platform,
            runner,
            journal,
            staging_root,
            active: Mutex::new(None),
            finished: Mutex::new(None),
        }))
    }

    fn stopped(profile_id: &str) -> OpenVpnStatusResult {
        OpenVpnStatusResult {
            profile_id: profile_id.into(),
            state: OpenVpnConnectionState::Stopped,
            interface_name: None,
            rx_bytes: 0,
            tx_bytes: 0,
            applied_routes: Vec::new(),
            warnings: Vec::new(),
            failure_reason: None,
        }
    }

    pub fn connect(
        &self,
        uid: u32,
        request: OpenVpnConnectRequest,
    ) -> Result<OpenVpnConnectResult, Error> {
        let inner = &self.0;
        let params = request.profile;
        if params.profile_id.is_empty() || params.profile_id.len() > 128 {
            return Err(Error::Invalid("invalid profile id".into()));
        }
        if let Some(credentials) = &request.credentials {
            net_manager_core::openvpn_management::validate_openvpn_credentials(credentials)
                .map_err(|_| Error::Invalid("OpenVPN credentials are invalid".into()))?;
        }
        let mut assets: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (name, encoded) in &params.assets {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| Error::Invalid("an OpenVPN asset is not valid base64".into()))?;
            assets.insert(name.clone(), bytes);
        }

        self.reap();
        let mut guard = inner.lock_active();
        if let Some(active) = guard.as_ref() {
            return Err(Error::Conflict(if active.profile_id == params.profile_id {
                "this connection is already running".into()
            } else {
                "another OpenVPN connection already owns the tunnel".into()
            }));
        }
        *inner.finished.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.recover_locked()?;

        let name = stage_name(&params.profile_id);
        // The sanitizer embeds this path for staged assets; it is the real
        // path in production and a stand-in under test.
        let logical = Path::new(RUNTIME_ROOT).join(uid.to_string()).join(&name);
        let sanitized = sanitize_openvpn_config(&params.config, &assets, &logical)
            .map_err(|_| Error::Invalid("the OpenVPN configuration is not accepted".into()))?;
        let remotes = remote_hosts(&sanitized.config)
            .iter()
            .flat_map(|host| match host.parse::<IpAddr>() {
                Ok(ip) => vec![ip],
                Err(_) => inner.platform.resolve(host),
            })
            .collect::<Vec<_>>();
        let uplink = routes::detect_uplink(&*inner.runner).map_err(|err| {
            if err.kind() == io::ErrorKind::AlreadyExists {
                Error::Conflict(err.to_string())
            } else {
                Error::Unavailable("There is no network connection to use".into())
            }
        })?;
        let binary = inner.platform.stage_binary().map_err(|err| {
            eprintln!("network-orchestrator-helper: openvpn binary: {err}");
            Error::Unavailable(
                "The bundled OpenVPN could not be verified; reinstall the app".into(),
            )
        })?;
        let unit = inner
            .platform
            .free_unit()
            .map_err(|_| Error::Unavailable("No tunnel device number is free".into()))?;

        let mut record = Record {
            profile_id: params.profile_id.clone(),
            interface: unit.clone(),
            pid: 0,
            routes: Vec::new(),
            dns: None,
        };
        inner
            .journal
            .save(&record)
            .map_err(|_| Error::Unavailable("The tunnel state could not be recorded".into()))?;
        let cleanup = |dir: Option<&Path>| {
            if let Some(dir) = dir {
                let _ = fs::remove_dir_all(dir);
            }
            let _ = inner.journal.clear();
        };
        let stage = stage_config(&inner.staging_root, uid, &name, &sanitized).map_err(|err| {
            eprintln!("network-orchestrator-helper: openvpn staging: {err}");
            cleanup(None);
            Error::Unavailable("The OpenVPN configuration could not be staged".into())
        })?;
        let socket = stage.join("management.sock");
        let args = openvpn_args(&stage.join("config.ovpn"), &unit, &socket);
        let mut child = inner
            .platform
            .spawn(&SpawnSpec {
                binary: &binary,
                args: &args,
                cwd: &stage,
                uid,
            })
            .map_err(|err| {
                eprintln!("network-orchestrator-helper: openvpn spawn: {err}");
                cleanup(Some(&stage));
                Error::Unavailable("OpenVPN could not start".into())
            })?;
        record.pid = child.pid();
        let _ = inner.journal.save(&record);

        let deadline = Instant::now() + MANAGEMENT_CONNECT_TIMEOUT;
        let management = loop {
            match UnixStream::connect(&socket) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline && child.alive() => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => {
                    child.stop(TERM_GRACE);
                    cleanup(Some(&stage));
                    return Err(Error::Unavailable(
                        "OpenVPN exited before it could be controlled".into(),
                    ));
                }
            }
        };
        let mut writer = management.try_clone().map_err(|_| {
            Error::Unavailable("The OpenVPN control channel could not be opened".into())
        })?;
        if writer
            .write_all(b"state on\nbytecount 1\nlog on all\nhold release\n")
            .is_err()
        {
            child.stop(TERM_GRACE);
            cleanup(Some(&stage));
            return Err(Error::Unavailable(
                "The OpenVPN control channel could not be opened".into(),
            ));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut active = Active {
            profile_id: params.profile_id.clone(),
            owner_uid: uid,
            tun: unit,
            uplink,
            record,
            child,
            stage,
            snapshot: ManagementSnapshot::default(),
            credentials: request.credentials,
            management: writer,
            remotes,
            policy_networks: params
                .routes
                .iter()
                .map(|route| route.destination)
                .collect(),
            applied: None,
            applied_nets: Vec::new(),
            warnings: Vec::new(),
            stop: stop.clone(),
            monitor: None,
        };
        let status = Inner::status_of(&active);
        let inner_for_thread = self.0.clone();
        let profile_id = params.profile_id;
        active.monitor = Some(
            std::thread::Builder::new()
                .name("openvpn".into())
                .spawn(move || monitor(inner_for_thread, profile_id, management, stop))
                .map_err(|_| Error::Unavailable("OpenVPN could not be supervised".into()))?,
        );
        *guard = Some(active);
        Ok(OpenVpnConnectResult { status })
    }

    pub fn status(&self, uid: u32, profile_id: &str) -> OpenVpnStatusResult {
        self.reap();
        {
            let guard = self.0.lock_active();
            if let Some(active) = guard.as_ref() {
                if active.profile_id == profile_id && active.owner_uid == uid {
                    return Inner::status_of(active);
                }
                return Self::stopped(profile_id);
            }
        }
        let finished = self.0.finished.lock().unwrap_or_else(|e| e.into_inner());
        match finished.as_ref() {
            Some(f) if f.profile_id == profile_id && f.owner_uid == uid => f.status.clone(),
            _ => Self::stopped(profile_id),
        }
    }

    pub fn disconnect(&self, uid: u32, profile_id: &str) -> Result<OpenVpnDisconnectResult, Error> {
        let taken = {
            let mut guard = self.0.lock_active();
            match guard.as_ref() {
                Some(active) if active.profile_id == profile_id && active.owner_uid == uid => {
                    guard.take()
                }
                _ => None,
            }
        };
        // A finished failure is dismissed by an explicit disconnect.
        {
            let mut finished = self.0.finished.lock().unwrap_or_else(|e| e.into_inner());
            if finished
                .as_ref()
                .is_some_and(|f| f.profile_id == profile_id && f.owner_uid == uid)
            {
                *finished = None;
            }
        }
        match taken {
            Some(active) => {
                self.0.teardown(active, None, true);
                *self.0.finished.lock().unwrap_or_else(|e| e.into_inner()) = None;
                Ok(OpenVpnDisconnectResult { stopped: true })
            }
            None => Ok(OpenVpnDisconnectResult { stopped: false }),
        }
    }

    /// Cleans up a session whose child is gone and whose monitor did not.
    pub fn reap(&self) {
        let taken = {
            let mut guard = self.0.lock_active();
            if guard.as_mut().is_some_and(|a| !a.child.alive()) {
                guard.take()
            } else {
                None
            }
        };
        if let Some(active) = taken {
            let failure = active
                .snapshot
                .last_failure
                .or(Some(OpenVpnFailure::ConnectionLost));
            self.0.teardown(active, failure, true);
        }
    }

    pub fn active(&self) -> bool {
        self.0.lock_active().is_some()
    }

    pub fn owned(&self) -> Option<Record> {
        let guard = self.0.lock_active();
        guard
            .as_ref()
            .map(|active| active.record.clone())
            .or_else(|| self.0.journal.load().ok().flatten())
    }

    pub fn recover(&self) -> io::Result<bool> {
        let _guard = self.0.lock_active();
        self.recover_locked_io()
    }

    fn recover_locked(&self) -> Result<(), Error> {
        self.recover_locked_io()
            .map(|_| ())
            .map_err(|_| Error::Unavailable("A previous tunnel could not be cleaned up".into()))
    }

    fn recover_locked_io(&self) -> io::Result<bool> {
        let Some(record) = self.0.journal.load()? else {
            return Ok(false);
        };
        if record.pid != 0 && self.0.platform.is_our_openvpn(record.pid) {
            self.0.platform.kill(record.pid);
        }
        let dns_ok = match &record.dns {
            Some(snapshot) => dns::restore(&*self.0.runner, snapshot).is_ok(),
            None => true,
        };
        routes::remove(&*self.0.runner, &record.routes);
        // Only one session exists at a time; every staged secret is stale.
        if let Ok(entries) = fs::read_dir(&self.0.staging_root) {
            for entry in entries.flatten() {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
        if dns_ok {
            self.0.journal.clear()?;
            Ok(true)
        } else {
            Err(io::Error::other("system DNS could not be restored"))
        }
    }

    pub fn shutdown(&self) {
        let taken = self.0.lock_active().take();
        if let Some(active) = taken {
            self.0.teardown(active, None, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Snapshot;
    use crate::sysexec::fake::FakeRunner;
    use net_manager_core::daemon_protocol::{OpenVpnConnectParams, OpenVpnUserPass};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::AtomicUsize;

    #[derive(Clone, Copy, PartialEq)]
    enum Behavior {
        /// Asks for credentials, then connects with a full-tunnel push.
        Connects,
        /// Asks for credentials and is refused.
        AuthFails,
        /// Connects, then dies without a goodbye.
        DiesAfterConnect,
    }

    struct FakeChild {
        alive: Arc<AtomicBool>,
    }
    impl Process for FakeChild {
        fn pid(&self) -> u32 {
            7777
        }
        fn alive(&mut self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }
        fn stop(&mut self, _: Duration) {
            self.alive.store(false, Ordering::SeqCst);
        }
    }

    struct FakePlatform {
        behavior: Behavior,
        spawned: AtomicUsize,
        received: Arc<Mutex<String>>,
        killed: AtomicUsize,
    }

    const PUSH: &str = ">LOG:1700000002,I,PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.8.0.1,route 10.9.0.0 255.255.0.0,ifconfig 10.8.0.2 10.8.0.1'\n";

    impl OvpnPlatform for FakePlatform {
        fn stage_binary(&self) -> io::Result<PathBuf> {
            Ok(PathBuf::from("/stage/openvpn"))
        }
        fn free_unit(&self) -> io::Result<String> {
            Ok("utun12".into())
        }
        fn spawn(&self, spec: &SpawnSpec) -> io::Result<Box<dyn Process>> {
            self.spawned.fetch_add(1, Ordering::SeqCst);
            // The fixed safety flags are always present.
            assert!(spec
                .args
                .windows(2)
                .any(|w| w == ["--route-nopull", "--route-noexec"]));
            assert!(spec
                .args
                .windows(2)
                .any(|w| w == ["--script-security", "1"]));
            assert!(spec.args.windows(2).any(|w| w == ["--dev", "utun12"]));
            let socket = spec
                .args
                .iter()
                .position(|a| a == "--management")
                .map(|i| PathBuf::from(&spec.args[i + 1]))
                .unwrap();
            let listener = UnixListener::bind(&socket)?;
            let alive = Arc::new(AtomicBool::new(true));
            let (alive_t, behavior, received) =
                (alive.clone(), self.behavior, self.received.clone());
            std::thread::spawn(move || {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                stream
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .ok();
                let read_some = |stream: &mut UnixStream, received: &Mutex<String>| {
                    let mut tmp = [0u8; 4096];
                    if let Ok(n) = stream.read(&mut tmp) {
                        received
                            .lock()
                            .unwrap()
                            .push_str(&String::from_utf8_lossy(&tmp[..n]));
                    }
                };
                // Wait for `hold release`, then start "connecting".
                for _ in 0..50 {
                    read_some(&mut stream, &received);
                    if received.lock().unwrap().contains("hold release") {
                        break;
                    }
                }
                let _ = stream.write_all(b">STATE:1700000001,CONNECTING,,,,,,\n");
                let _ = stream.write_all(b">PASSWORD:Need 'Auth' username/password\n");
                if behavior == Behavior::AuthFails {
                    std::thread::sleep(Duration::from_millis(200));
                    let _ = stream.write_all(b">PASSWORD:Verification Failed: 'Auth'\n");
                    let _ = stream.write_all(b">STATE:1700000009,EXITING,auth-failure,,,,,\n");
                    std::thread::sleep(Duration::from_millis(300));
                    alive_t.store(false, Ordering::SeqCst);
                    return;
                }
                // Let the credential reply arrive before "connecting".
                for _ in 0..30 {
                    read_some(&mut stream, &received);
                    if received.lock().unwrap().contains("password") {
                        break;
                    }
                }
                let _ = stream.write_all(PUSH.as_bytes());
                let _ = stream.write_all(
                    b">STATE:1700000003,CONNECTED,SUCCESS,10.8.0.2,203.0.113.5,1194,192.168.1.5,54321,\n",
                );
                let _ = stream.write_all(b">BYTECOUNT:111,222\n");
                if behavior == Behavior::DiesAfterConnect {
                    std::thread::sleep(Duration::from_millis(500));
                    alive_t.store(false, Ordering::SeqCst);
                    return;
                }
                while alive_t.load(Ordering::SeqCst) {
                    read_some(&mut stream, &received);
                }
            });
            Ok(Box::new(FakeChild { alive }))
        }
        fn resolve(&self, host: &str) -> Vec<IpAddr> {
            if host == "vpn.example" {
                vec!["203.0.113.5".parse().unwrap()]
            } else {
                vec![]
            }
        }
        fn is_our_openvpn(&self, _: u32) -> bool {
            true
        }
        fn kill(&self, _: u32) {
            self.killed.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Fixture {
        executor: OpenVpnExecutor,
        runner: Arc<FakeRunner>,
        platform: Arc<FakePlatform>,
        dir: tempfile::TempDir,
    }

    struct SharedRunner(Arc<FakeRunner>);
    impl Runner for SharedRunner {
        fn run(&self, program: &str, args: &[String]) -> io::Result<String> {
            self.0.run(program, args)
        }
    }
    struct SharedPlatform(Arc<FakePlatform>);
    impl OvpnPlatform for SharedPlatform {
        fn stage_binary(&self) -> io::Result<PathBuf> {
            self.0.stage_binary()
        }
        fn free_unit(&self) -> io::Result<String> {
            self.0.free_unit()
        }
        fn spawn(&self, spec: &SpawnSpec) -> io::Result<Box<dyn Process>> {
            self.0.spawn(spec)
        }
        fn resolve(&self, host: &str) -> Vec<IpAddr> {
            self.0.resolve(host)
        }
        fn is_our_openvpn(&self, pid: u32) -> bool {
            self.0.is_our_openvpn(pid)
        }
        fn kill(&self, pid: u32) {
            self.0.kill(pid)
        }
    }

    fn fixture(behavior: Behavior) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let runner = Arc::new(FakeRunner::default());
        runner.reply(
            "route -n get default",
            "gateway: 192.168.1.1\n interface: en0\n",
        );
        runner.reply(
            "networksetup -listnetworkserviceorder",
            "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n",
        );
        runner.reply("networksetup -getdnsservers", "1.1.1.1\n");
        let platform = Arc::new(FakePlatform {
            behavior,
            spawned: AtomicUsize::new(0),
            received: Arc::new(Mutex::new(String::new())),
            killed: AtomicUsize::new(0),
        });
        let executor = OpenVpnExecutor::new(
            Box::new(SharedPlatform(platform.clone())),
            Box::new(SharedRunner(runner.clone())),
            Journal::named(dir.path(), "openvpn.json"),
            dir.path().join("run"),
        );
        Fixture {
            executor,
            runner,
            platform,
            dir,
        }
    }

    fn request(creds: bool) -> OpenVpnConnectRequest {
        OpenVpnConnectRequest {
            profile: OpenVpnConnectParams {
                profile_id: "office".into(),
                config: "client\ndev tun\nremote vpn.example 1194 udp\nauth-user-pass\n".into(),
                assets: BTreeMap::new(),
                routes: vec![],
                interface_name: None,
            },
            credentials: creds.then(|| OpenVpnCredentials {
                auth_user_pass: Some(OpenVpnUserPass {
                    username: "u1".into(),
                    password: "p1".into(),
                }),
                private_key_passphrase: None,
            }),
        }
    }

    fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
        for _ in 0..200 {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("timed out waiting for {what}");
    }

    #[test]
    fn a_full_tunnel_connects_installs_the_push_and_disconnect_undoes_it() {
        let f = fixture(Behavior::Connects);
        let first = f.executor.connect(501, request(true)).unwrap();
        assert_eq!(first.status.state, OpenVpnConnectionState::Connecting);
        wait_for("connected", || {
            f.executor.status(501, "office").state == OpenVpnConnectionState::Connected
        });
        wait_for("routes", || {
            f.runner
                .calls()
                .iter()
                .any(|c| c.starts_with("networksetup -setdnsservers Wi-Fi 10.8.0.1"))
        });
        let calls = f.runner.calls();
        let bypass = calls
            .iter()
            .position(|c| c == "route -n add -host 203.0.113.5 -gateway 192.168.1.1")
            .expect("server bypass");
        let capture = calls
            .iter()
            .position(|c| c == "route -n add -net 0.0.0.0 -netmask 128.0.0.0 -interface utun12")
            .expect("capture");
        assert!(bypass < capture, "the server must stay reachable first");
        assert!(calls.contains(
            &"route -n add -net 10.9.0.0 -netmask 255.255.0.0 -interface utun12".to_string()
        ));
        // The prompt was answered from the request, never from anywhere else.
        let received = f.platform.received.lock().unwrap().clone();
        assert!(
            received.contains("u1") && received.contains("p1"),
            "{received}"
        );

        let status = f.executor.status(501, "office");
        assert_eq!(status.interface_name.as_deref(), Some("utun12"));
        assert_eq!((status.rx_bytes, status.tx_bytes), (111, 222));
        assert!(status.warnings.contains(&OpenVpnWarning::Ipv6NotCovered));
        assert!(!status.applied_routes.is_empty());
        assert!(f.dir.path().join("run/501").read_dir().unwrap().count() == 1);

        assert!(f.executor.disconnect(501, "office").unwrap().stopped);
        let calls = f.runner.calls();
        assert!(calls.contains(&"networksetup -setdnsservers Wi-Fi 1.1.1.1".to_string()));
        assert!(calls
            .iter()
            .any(|c| c.starts_with("route -n delete -net 0.0.0.0")));
        assert!(calls.contains(&"route -n delete -host 203.0.113.5".to_string()));
        // Secrets are gone and nothing is owned.
        assert_eq!(f.dir.path().join("run/501").read_dir().unwrap().count(), 0);
        assert!(f.executor.owned().is_none());
        assert_eq!(
            f.executor.status(501, "office").state,
            OpenVpnConnectionState::Stopped
        );
    }

    #[test]
    fn a_refused_login_reports_why_and_leaves_the_system_untouched() {
        let f = fixture(Behavior::AuthFails);
        f.executor.connect(501, request(true)).unwrap();
        wait_for("failure", || {
            f.executor.status(501, "office").state == OpenVpnConnectionState::Failed
        });
        let status = f.executor.status(501, "office");
        assert_eq!(
            status.failure_reason,
            Some(OpenVpnFailure::AuthenticationFailure)
        );
        assert!(!f
            .runner
            .calls()
            .iter()
            .any(|c| c.starts_with("route -n add")));
        assert!(!f
            .runner
            .calls()
            .iter()
            .any(|c| c.contains("-setdnsservers")));
        assert!(f.executor.owned().is_none());
        assert_eq!(f.dir.path().join("run/501").read_dir().unwrap().count(), 0);
        // A new attempt clears the old failure.
        assert!(f.executor.disconnect(501, "office").is_ok());
        assert_eq!(
            f.executor.status(501, "office").state,
            OpenVpnConnectionState::Stopped
        );
    }

    #[test]
    fn a_prompt_without_credentials_fails_with_credentials_required() {
        let f = fixture(Behavior::Connects);
        f.executor.connect(501, request(false)).unwrap();
        wait_for("failure", || {
            f.executor.status(501, "office").state == OpenVpnConnectionState::Failed
        });
        assert_eq!(
            f.executor.status(501, "office").failure_reason,
            Some(OpenVpnFailure::CredentialsRequired)
        );
        assert!(!f
            .runner
            .calls()
            .iter()
            .any(|c| c.starts_with("route -n add")));
    }

    #[test]
    fn a_child_that_dies_mid_session_is_cleaned_up() {
        let f = fixture(Behavior::DiesAfterConnect);
        f.executor.connect(501, request(true)).unwrap();
        wait_for("installed", || {
            f.runner
                .calls()
                .iter()
                .any(|c| c.starts_with("networksetup -setdnsservers Wi-Fi 10.8.0.1"))
        });
        wait_for("cleanup", || f.executor.owned().is_none());
        let calls = f.runner.calls();
        assert!(calls.contains(&"networksetup -setdnsservers Wi-Fi 1.1.1.1".to_string()));
        assert!(calls
            .iter()
            .any(|c| c.starts_with("route -n delete -net 0.0.0.0")));
        assert_eq!(
            f.executor.status(501, "office").failure_reason,
            Some(OpenVpnFailure::ConnectionLost)
        );
    }

    #[test]
    fn configs_that_could_run_code_never_reach_a_process() {
        let f = fixture(Behavior::Connects);
        let mut bad = request(true);
        bad.profile.config =
            "client\nremote vpn.example\nup /tmp/evil.sh\nscript-security 2\n".into();
        assert!(matches!(
            f.executor.connect(501, bad),
            Err(Error::Invalid(_))
        ));
        assert_eq!(f.platform.spawned.load(Ordering::SeqCst), 0);
        assert!(f.executor.owned().is_none());
        let mut bad = request(true);
        bad.profile.assets.insert("assets/x".into(), "!!!".into());
        assert!(matches!(
            f.executor.connect(501, bad),
            Err(Error::Invalid(_))
        ));
        let mut bad = request(true);
        bad.profile.profile_id = String::new();
        assert!(matches!(
            f.executor.connect(501, bad),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn only_one_session_and_only_its_owner_may_control_it() {
        let f = fixture(Behavior::Connects);
        f.executor.connect(501, request(true)).unwrap();
        assert!(matches!(
            f.executor.connect(501, request(true)),
            Err(Error::Conflict(_))
        ));
        assert_eq!(
            f.executor.status(502, "office").state,
            OpenVpnConnectionState::Stopped
        );
        assert!(!f.executor.disconnect(502, "office").unwrap().stopped);
        assert!(f.executor.disconnect(501, "office").unwrap().stopped);
    }

    #[test]
    fn recovery_kills_the_orphan_and_removes_what_it_left() {
        let f = fixture(Behavior::Connects);
        let record = Record {
            profile_id: "office".into(),
            interface: "utun12".into(),
            pid: 4242,
            routes: routes::interface_routes("utun12", &["0.0.0.0/0".parse().unwrap()]),
            dns: Some(Snapshot {
                service: "Wi-Fi".into(),
                servers: vec![],
            }),
        };
        Journal::named(f.dir.path(), "openvpn.json")
            .save(&record)
            .unwrap();
        let stale = f.dir.path().join("run/501/ovpn-old");
        fs::create_dir_all(&stale).unwrap();
        assert!(f.executor.recover().unwrap());
        assert_eq!(f.platform.killed.load(Ordering::SeqCst), 1);
        assert!(!stale.exists());
        assert!(f
            .runner
            .calls()
            .contains(&"networksetup -setdnsservers Wi-Fi Empty".to_string()));
        assert!(!f.executor.recover().unwrap());
    }

    #[test]
    fn remote_hosts_and_state_lines_are_parsed() {
        let config = "client\nremote a.example 1194\nremote 192.0.2.7\n<connection>\nremote b.example 443 tcp\n</connection>\n<ca>\nremote evil\n</ca>\n";
        assert_eq!(
            remote_hosts(config),
            ["a.example", "192.0.2.7", "b.example"]
        );
        assert_eq!(
            remote_ip_of_state(">STATE:1,CONNECTED,SUCCESS,10.8.0.2,203.0.113.5,1194,1.2.3.4,5,"),
            Some("203.0.113.5".parse().unwrap())
        );
        assert_eq!(remote_ip_of_state(">STATE:1,CONNECTING,,,,,,"), None);
        assert_eq!(remote_ip_of_state("garbage"), None);
    }

    #[test]
    fn staged_files_are_private_and_named_by_a_hash() {
        let dir = tempfile::tempdir().unwrap();
        let sanitized = sanitize_openvpn_config(
            "client\nremote vpn.example\n",
            &BTreeMap::new(),
            Path::new("/var/run/network-orchestrator/openvpn/1/ovpn-x"),
        )
        .unwrap();
        let name = stage_name("my profile / with spaces");
        assert!(name.starts_with("ovpn-") && name.len() == 5 + 12);
        let staged = stage_config(&dir.path().join("run"), 1, &name, &sanitized).unwrap();
        let mode = fs::metadata(staged.join("config.ovpn")).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::metadata(&staged).unwrap().mode() & 0o777, 0o700);
    }
}
