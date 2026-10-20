//! The user's own Tailscale, next to whatever primary tunnel is running.
//!
//! Tailscale is a foreign daemon (the Mac app's Network Extension or a
//! `tailscaled`) that owns its interface, routes and MagicDNS. The app drives
//! it through its CLI exactly as `tailscale status|up|down` in a terminal
//! would, so nothing here is privileged and no second daemon is started.
//!
//! What the app adds is the guard that keeps the tailnet reachable while a
//! full tunnel is up: it reads Tailscale's own addresses and the remote hosts
//! its traffic uses, and asks the privileged helper to pin the tailnet
//! prefixes if something else wins them and to route those hosts around the
//! tunnel (`tailscale.protect`). The helper validates and applies; see
//! `crates/macos-helper/src/tailscale.rs`.
use crate::privileged::Privileged;
use net_manager_core::daemon_protocol::{
    method, ErrorCode, OwnedListResult, TailscaleProtectParams, TailscaleProtectResult,
    TailscaleReleaseResult,
};
use net_manager_core::helper_client::HelperError;
use serde_json::{json, Value};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Where the CLI lives: the Mac app's "Install CLI", Homebrew, or inside the app.
const CLI_CANDIDATES: [&str; 4] = [
    "/usr/local/bin/tailscale",
    "/opt/homebrew/bin/tailscale",
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/usr/bin/tailscale",
];
const STATUS_TIMEOUT: Duration = Duration::from_secs(6);
const DOWN_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OUTPUT: u64 = 8 * 1024 * 1024;
/// Tailscale's coordination server, which its own traffic reaches directly.
const CONTROL_HOST: &str = "controlplane.tailscale.com:443";
const MAX_ENDPOINTS: usize = 64;

/// A `tailscale up` that is still waiting (typically for the browser login).
static PENDING: Mutex<Option<Child>> = Mutex::new(None);

pub struct Tailscale {
    pub cli: Option<PathBuf>,
    /// Coordination server (`host:port`) whose addresses are bypassed too;
    /// `None` skips the lookup (tests never touch the network).
    pub control: Option<&'static str>,
}

fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Runs `command`, killing it after `limit`; stdout is capped. Returns
/// whether it exited successfully and what it printed.
fn run_with_timeout(mut command: Command, limit: Duration) -> Result<(bool, String), String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Tailscale could not be started".to_string())?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    // Read on a thread: a grandchild holding the pipe open must not be able to
    // hold this call hostage.
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stdout).take(MAX_OUTPUT).read_to_string(&mut text);
        let _ = sender.send(text);
    });
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(40));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    match status {
        Some(status) => Ok((
            status.success(),
            receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_default(),
        )),
        None => Err("Tailscale did not answer in time".into()),
    }
}

/// The compact, UI-facing view of `tailscale status --json`: no keys, no
/// peer names, no health text.
pub fn summarize(raw: &Value, pending: bool) -> Value {
    let backend = raw["BackendState"].as_str().unwrap_or("");
    let state = match backend {
        "Running" => "connected",
        "Starting" => "connecting",
        "NeedsLogin" | "NeedsMachineAuth" => "needsLogin",
        _ => "disconnected",
    };
    // A browser login in flight is "connecting", not "needs login".
    let state = if pending && matches!(state, "disconnected" | "needsLogin") {
        "connecting"
    } else {
        state
    };
    let peers = raw["Peer"].as_object();
    let online = peers.map_or(0, |peers| {
        peers
            .values()
            .filter(|peer| peer["Online"].as_bool().unwrap_or(false))
            .count()
    });
    let ips = ips_of(&raw["Self"]["TailscaleIPs"]);
    json!({
        "installed": true,
        "state": state,
        "backendState": backend,
        "ip": ips.iter().find(|ip| ip.is_ipv4()).map(IpAddr::to_string),
        "tailnet": raw["CurrentTailnet"]["Name"].as_str().filter(|n| !n.is_empty()),
        "host": raw["Self"]["HostName"].as_str().filter(|n| !n.is_empty()),
        "version": raw["Version"].as_str().filter(|n| !n.is_empty()),
        "peersOnline": online,
        "peersTotal": peers.map_or(0, |peers| peers.len()),
        "exitNode": peers.is_some_and(|peers| {
            peers.values().any(|peer| peer["ExitNode"].as_bool().unwrap_or(false))
        }),
        "authUrl": raw["AuthURL"].as_str().filter(|url| url.starts_with("https://")),
    })
}

fn ips_of(value: &Value) -> Vec<IpAddr> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|ip| ip.as_str()?.parse().ok())
        .collect()
}

/// The address in `ip:port`, `[ip6]:port` or `ip:port:vni` text.
fn leading_ip(text: &str) -> Option<IpAddr> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    text.split(':')
        .next()?
        .parse::<Ipv4Addr>()
        .ok()
        .map(IpAddr::V4)
}

/// What the helper needs to guard Tailscale: its own addresses and the remote
/// hosts its traffic uses right now (direct peers, relays, the control server).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Discovery {
    pub self_ips: Vec<IpAddr>,
    /// Region codes of the DERP relays in use, resolved to addresses by
    /// [`relay_addresses`].
    pub relay_regions: Vec<String>,
    pub endpoints: Vec<IpAddr>,
}

pub fn discover(raw: &Value) -> Discovery {
    let mut found = Discovery {
        self_ips: ips_of(&raw["Self"]["TailscaleIPs"]),
        ..Default::default()
    };
    let mut region = |code: &Value| {
        if let Some(code) = code.as_str().filter(|code| !code.is_empty()) {
            if !found.relay_regions.iter().any(|known| known == code) {
                found.relay_regions.push(code.to_string());
            }
        }
    };
    region(&raw["Self"]["Relay"]);
    let mut endpoints: Vec<IpAddr> = Vec::new();
    for peer in raw["Peer"].as_object().into_iter().flat_map(|p| p.values()) {
        if !peer["Online"].as_bool().unwrap_or(false) {
            continue;
        }
        region(&peer["Relay"]);
        for field in ["CurAddr", "PeerRelay"] {
            if let Some(ip) = peer[field].as_str().and_then(leading_ip) {
                endpoints.push(ip);
            }
        }
    }
    found.endpoints = endpoints;
    found
}

/// IPv4 addresses of the relay nodes in `regions`, from `tailscale debug
/// derp-map` (the tailnet's own map, so custom relays are covered).
pub fn relay_addresses(derp_map: &Value, regions: &[String]) -> Vec<IpAddr> {
    derp_map["Regions"]
        .as_object()
        .into_iter()
        .flat_map(|all| all.values())
        .filter(|region| {
            region["RegionCode"]
                .as_str()
                .is_some_and(|code| regions.iter().any(|wanted| wanted == code))
        })
        .flat_map(|region| region["Nodes"].as_array().into_iter().flatten())
        .filter_map(|node| node["IPv4"].as_str()?.parse::<Ipv4Addr>().ok())
        .map(IpAddr::V4)
        .collect()
}

fn pending_alive() -> bool {
    let mut guard = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(child) = guard.as_mut() else {
        return false;
    };
    match child.try_wait() {
        Ok(None) => true,
        _ => {
            *guard = None;
            false
        }
    }
}

fn cancel_pending() {
    let taken = PENDING.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(mut child) = taken {
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Tailscale {
    /// The installed CLI; `NETORCH_TAILSCALE_CLI` points elsewhere for tests.
    pub fn detect() -> Self {
        let cli = std::env::var_os("NETORCH_TAILSCALE_CLI")
            .map(PathBuf::from)
            .into_iter()
            .chain(CLI_CANDIDATES.iter().map(PathBuf::from))
            .find(|path| executable(path));
        Self {
            cli,
            control: Some(CONTROL_HOST),
        }
    }

    fn raw_status(&self) -> Result<Value, String> {
        let cli = self.cli.as_ref().ok_or("Tailscale is not installed")?;
        let mut command = Command::new(cli);
        command.args(["status", "--json"]);
        match run_with_timeout(command, STATUS_TIMEOUT)? {
            (true, text) => serde_json::from_str(&text)
                .map_err(|_| "Tailscale answered unexpectedly".to_string()),
            _ => Err("Tailscale is not responding".into()),
        }
    }

    pub fn status(&self) -> Value {
        if self.cli.is_none() {
            return json!({"installed": false, "state": "notInstalled"});
        }
        match self.raw_status() {
            Ok(raw) => summarize(&raw, pending_alive()),
            Err(_) => json!({"installed": true, "state": "unavailable"}),
        }
    }

    /// Starts `tailscale up` and returns at once; the status shows how it
    /// goes. A browser login is handled by the CLI itself.
    pub fn up(&self) -> Result<Value, String> {
        let cli = self.cli.as_ref().ok_or("Tailscale is not installed")?;
        cancel_pending();
        let child = Command::new(cli)
            .arg("up")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Tailscale could not be started".to_string())?;
        *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
        Ok(self.status())
    }

    pub fn down(&self) -> Result<Value, String> {
        let cli = self.cli.as_ref().ok_or("Tailscale is not installed")?;
        cancel_pending();
        let mut command = Command::new(cli);
        command.arg("down");
        run_with_timeout(command, DOWN_TIMEOUT)
            .map_err(|_| "Tailscale could not be disconnected".to_string())?;
        Ok(self.status())
    }

    /// Everything the helper is told about Tailscale. Not only while it runs:
    /// a Tailscale that cannot reach its relay through the tunnel sits in
    /// "Starting"/"Stopped", and that is exactly when its bypass is needed.
    /// `None` only when its identity is unknown (never signed in).
    fn discovery(&self) -> Option<Discovery> {
        let raw = self.raw_status().ok()?;
        let mut found = discover(&raw);
        if found.self_ips.is_empty() {
            return None;
        }
        if !found.relay_regions.is_empty() {
            if let Some(cli) = &self.cli {
                let mut command = Command::new(cli);
                command.args(["debug", "derp-map"]);
                if let Ok((true, text)) = run_with_timeout(command, STATUS_TIMEOUT) {
                    if let Ok(map) = serde_json::from_str::<Value>(&text) {
                        found
                            .endpoints
                            .extend(relay_addresses(&map, &found.relay_regions));
                    }
                }
            }
        }
        if let Some(host) = self.control {
            found.endpoints.extend(resolve(host));
        }
        found.endpoints.sort();
        found.endpoints.dedup();
        found.endpoints.truncate(MAX_ENDPOINTS);
        Some(found)
    }
}

/// The coordination server's IPv4 addresses; a slow resolver is not waited for.
fn resolve(host: &'static str) -> Vec<IpAddr> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let found: Vec<IpAddr> = host
            .to_socket_addrs()
            .map(|addrs| {
                addrs
                    .map(|addr| addr.ip())
                    .filter(IpAddr::is_ipv4)
                    .collect()
            })
            .unwrap_or_default();
        let _ = sender.send(found);
    });
    receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_default()
}

fn unsupported(error: &HelperError) -> bool {
    matches!(error, HelperError::Rejected(body) if body.code == ErrorCode::UnsupportedMethod)
}

/// Bring the helper's Tailscale guard in line with reality: protected while a
/// tunnel the helper owns and a running Tailscale coexist, released
/// otherwise. Best effort; the answer is for the UI and the logs, never fatal.
///
/// States: `protected`, `idle` (no tunnel to protect against), `off`
/// (Tailscale is not running), `unsupported` (an older helper) and
/// `unavailable` (the helper cannot be reached).
pub fn sync(privileged: &dyn Privileged, tailscale: &Tailscale) -> Value {
    let owners: OwnedListResult = match privileged.call(method::OWNED_LIST, json!({})) {
        Ok(owners) => owners,
        Err(error) if unsupported(&error) => return json!({"state": "unsupported"}),
        Err(_) => return json!({"state": "unavailable"}),
    };
    let release = |state: &str| match privileged
        .call::<_, TailscaleReleaseResult>(method::TAILSCALE_RELEASE, json!({}))
    {
        Ok(_) => json!({"state": state}),
        Err(error) if unsupported(&error) => json!({"state": "unsupported"}),
        Err(_) => json!({"state": "unavailable"}),
    };
    if owners.owners.is_empty() {
        return release("idle");
    }
    let Some(found) = tailscale.discovery() else {
        return release("off");
    };
    let params = TailscaleProtectParams {
        self_ips: found.self_ips,
        endpoints: found.endpoints,
    };
    match privileged.call::<_, TailscaleProtectResult>(method::TAILSCALE_PROTECT, params) {
        Ok(result) => json!({
            "state": "protected",
            "interface": result.interface,
            "pinned": result.pinned,
            "bypassed": result.bypassed,
        }),
        Err(error) if unsupported(&error) => json!({"state": "unsupported"}),
        Err(_) => json!({"state": "unavailable"}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{HelloResult, OwnedEntry, OwnedState};
    use std::os::unix::fs::PermissionsExt;

    const STATUS: &str = r#"{"Version":"1.102.4","BackendState":"Running","AuthURL":"",
        "Self":{"HostName":"mac","TailscaleIPs":["100.115.39.70","fd7a:115c:a1e0::c82f:2747"],"Relay":"kzn3"},
        "CurrentTailnet":{"Name":"example.ts.net"},
        "Peer":{
          "k1":{"HostName":"a","Online":true,"Relay":"kzn3","CurAddr":"203.0.113.7:41641","ExitNode":false,"PublicKey":"SECRETKEY"},
          "k2":{"HostName":"b","Online":true,"Relay":"fra","CurAddr":"[2001:db8::5]:41641","PeerRelay":"198.51.100.9:3478:7"},
          "k3":{"HostName":"c","Online":false,"Relay":"nyc","CurAddr":"192.0.2.99:1"}}}"#;

    const DERP: &str = r#"{"Regions":{
        "900":{"RegionCode":"kzn3","Nodes":[{"IPv4":"198.51.100.20","IPv6":"2001:db8::20"}]},
        "1":{"RegionCode":"nyc","Nodes":[{"IPv4":"209.177.145.120"}]},
        "2":{"RegionCode":"fra","Nodes":[{"IPv4":"192.0.2.50"},{"HostName":"no-ip"}]}}}"#;

    fn status() -> Value {
        serde_json::from_str(STATUS).unwrap()
    }

    #[test]
    fn the_summary_is_compact_and_carries_no_keys_or_peer_names() {
        let summary = summarize(&status(), false);
        assert_eq!(summary["state"], "connected");
        assert_eq!(summary["ip"], "100.115.39.70");
        assert_eq!(summary["tailnet"], "example.ts.net");
        assert_eq!(summary["peersOnline"], 2);
        assert_eq!(summary["peersTotal"], 3);
        assert_eq!(summary["exitNode"], false);
        assert_eq!(summary["authUrl"], Value::Null);
        let text = summary.to_string();
        assert!(!text.contains("SECRETKEY") && !text.contains("\"a\""));
    }

    #[test]
    fn backend_states_map_to_the_ui_states() {
        for (backend, expected) in [
            ("Running", "connected"),
            ("Starting", "connecting"),
            ("NeedsLogin", "needsLogin"),
            ("NeedsMachineAuth", "needsLogin"),
            ("Stopped", "disconnected"),
            ("NoState", "disconnected"),
            ("", "disconnected"),
        ] {
            let raw = json!({"BackendState": backend});
            assert_eq!(summarize(&raw, false)["state"], expected, "{backend}");
        }
        assert_eq!(
            summarize(&json!({"BackendState": "NeedsLogin"}), true)["state"],
            "connecting"
        );
        // Only an https page is ever offered for sign-in.
        let raw =
            json!({"BackendState": "NeedsLogin", "AuthURL": "https://login.tailscale.com/a/1"});
        assert_eq!(
            summarize(&raw, false)["authUrl"],
            "https://login.tailscale.com/a/1"
        );
        let raw = json!({"BackendState": "NeedsLogin", "AuthURL": "file:///etc/passwd"});
        assert_eq!(summarize(&raw, false)["authUrl"], Value::Null);
    }

    #[test]
    fn discovery_collects_online_peers_endpoints_and_relay_regions() {
        let found = discover(&status());
        assert_eq!(found.self_ips.len(), 2);
        assert_eq!(found.relay_regions, ["kzn3", "fra"]);
        // The offline peer contributes nothing; ports and the vni are dropped.
        assert_eq!(
            found.endpoints,
            [
                "203.0.113.7".parse::<IpAddr>().unwrap(),
                "2001:db8::5".parse().unwrap(),
                "198.51.100.9".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn relay_addresses_come_from_the_tailnets_own_map() {
        let map: Value = serde_json::from_str(DERP).unwrap();
        let wanted = ["kzn3".to_string(), "fra".to_string()];
        let mut addresses = relay_addresses(&map, &wanted);
        addresses.sort();
        assert_eq!(
            addresses,
            [
                "192.0.2.50".parse::<IpAddr>().unwrap(),
                "198.51.100.20".parse().unwrap()
            ]
        );
        assert!(relay_addresses(&map, &[]).is_empty());
        assert!(relay_addresses(&json!({}), &wanted).is_empty());
    }

    /// A stand-in CLI answering the three commands the engine uses.
    fn fake_cli(dir: &Path) -> Tailscale {
        std::fs::write(dir.join("status.json"), STATUS).unwrap();
        std::fs::write(dir.join("derp.json"), DERP).unwrap();
        let cli = dir.join("tailscale");
        std::fs::write(
            &cli,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\ncase \"$*\" in\n  'status --json') cat '{status}' ;;\n  'debug derp-map') cat '{derp}' ;;\n  *) : ;;\nesac\n",
                log = dir.join("calls.log").display(),
                status = dir.join("status.json").display(),
                derp = dir.join("derp.json").display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
        Tailscale {
            cli: Some(cli),
            control: None,
        }
    }

    #[test]
    fn a_missing_cli_is_reported_without_running_anything() {
        let none = Tailscale {
            cli: None,
            control: None,
        };
        assert_eq!(none.status()["state"], "notInstalled");
        assert!(none.up().is_err() && none.down().is_err());
        assert!(none.discovery().is_none());
    }

    #[test]
    fn status_and_down_go_through_the_cli() {
        let dir = tempfile::tempdir().unwrap();
        let ts = fake_cli(dir.path());
        assert_eq!(ts.status()["state"], "connected");
        ts.down().unwrap();
        let calls = std::fs::read_to_string(dir.path().join("calls.log")).unwrap();
        assert!(
            calls.contains("status --json") && calls.contains("down"),
            "{calls}"
        );
    }

    /// Records the requests and answers like the helper would.
    struct FakeHelper {
        owners: bool,
        calls: Mutex<Vec<(String, Value)>>,
        unsupported: bool,
    }

    impl Privileged for FakeHelper {
        fn hello(&self) -> Result<HelloResult, HelperError> {
            unreachable!()
        }
        fn call_raw(&self, method: &str, params: Value) -> Result<Value, HelperError> {
            self.calls.lock().unwrap().push((method.into(), params));
            if self.unsupported && method != method::OWNED_LIST {
                return Err(HelperError::Rejected(
                    net_manager_core::daemon_protocol::ErrorBody {
                        code: ErrorCode::UnsupportedMethod,
                        message: "no".into(),
                    },
                ));
            }
            Ok(match method {
                method::OWNED_LIST => serde_json::to_value(OwnedListResult {
                    owners: if self.owners {
                        vec![OwnedEntry {
                            owner: "xray:p".into(),
                            state: OwnedState::Applied,
                            resources: Vec::new(),
                        }]
                    } else {
                        Vec::new()
                    },
                })
                .unwrap(),
                method::TAILSCALE_PROTECT => {
                    json!({"interface": "utun12", "pinned": [], "bypassed": 3})
                }
                _ => json!({"released": false}),
            })
        }
        fn log_dir(&self) -> PathBuf {
            PathBuf::new()
        }
    }

    fn helper(owners: bool, unsupported: bool) -> FakeHelper {
        FakeHelper {
            owners,
            calls: Mutex::new(Vec::new()),
            unsupported,
        }
    }

    fn methods(helper: &FakeHelper) -> Vec<String> {
        helper
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|(m, _)| m.clone())
            .collect()
    }

    #[test]
    fn a_running_tailscale_next_to_a_tunnel_is_protected_with_its_endpoints() {
        let dir = tempfile::tempdir().unwrap();
        let ts = fake_cli(dir.path());
        let helper = helper(true, false);
        let outcome = sync(&helper, &ts);
        assert_eq!(outcome["state"], "protected");
        assert_eq!(outcome["bypassed"], 3);
        let calls = helper.calls.lock().unwrap();
        let (name, params) = calls.last().unwrap();
        assert_eq!(name, method::TAILSCALE_PROTECT);
        assert_eq!(params["selfIps"][0], "100.115.39.70");
        let endpoints = params["endpoints"].as_array().unwrap();
        // Direct peers, the relays of the regions in use, and nothing twice.
        for expected in ["203.0.113.7", "198.51.100.9", "198.51.100.20", "192.0.2.50"] {
            assert!(endpoints.iter().any(|ip| ip == expected), "{expected}");
        }
        assert!(!endpoints.iter().any(|ip| ip == "209.177.145.120"));
        assert!(!endpoints.iter().any(|ip| ip == "192.0.2.99"));
    }

    #[test]
    fn a_tailscale_cut_off_from_its_relay_is_protected_too() {
        let dir = tempfile::tempdir().unwrap();
        let ts = fake_cli(dir.path());
        // The tunnel swallowed its relay traffic, so it never got to "Running".
        std::fs::write(
            dir.path().join("status.json"),
            STATUS.replace("\"Running\"", "\"Stopped\""),
        )
        .unwrap();
        let helper = helper(true, false);
        assert_eq!(sync(&helper, &ts)["state"], "protected");
        let calls = helper.calls.lock().unwrap();
        let endpoints = calls.last().unwrap().1["endpoints"]
            .as_array()
            .unwrap()
            .clone();
        assert!(endpoints.iter().any(|ip| ip == "198.51.100.20"));
    }

    #[test]
    fn without_a_tunnel_or_without_tailscale_the_guard_is_released() {
        let dir = tempfile::tempdir().unwrap();
        let ts = fake_cli(dir.path());
        let helper_idle = helper(false, false);
        assert_eq!(sync(&helper_idle, &ts)["state"], "idle");
        assert_eq!(
            methods(&helper_idle),
            [method::OWNED_LIST, method::TAILSCALE_RELEASE]
        );
        let helper_off = helper(true, false);
        assert_eq!(
            sync(
                &helper_off,
                &Tailscale {
                    cli: None,
                    control: None,
                }
            )["state"],
            "off"
        );
        assert_eq!(
            methods(&helper_off).last().unwrap(),
            method::TAILSCALE_RELEASE
        );
    }

    #[test]
    fn an_older_helper_is_reported_not_treated_as_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let ts = fake_cli(dir.path());
        assert_eq!(sync(&helper(true, true), &ts)["state"], "unsupported");
    }
}
