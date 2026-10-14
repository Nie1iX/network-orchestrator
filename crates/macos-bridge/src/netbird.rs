//! NetBird: the app drives the user's own NetBird daemon through its CLI,
//! exactly as `netbird up` / `down` / `status` in a terminal would. The daemon
//! (a system service, root) creates its interface, routes and DNS itself, so
//! nothing here is privileged and no second daemon is started. NetBird routes
//! only its own networks, which win over a primary tunnel's capture because
//! they are more specific.
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) const DEFAULT_SOCKET: &str = "/var/run/netbird.sock";
/// Where the CLI lives when NetBird was installed by Homebrew or the package.
const CLI_CANDIDATES: [&str; 4] = [
    "/opt/homebrew/bin/netbird",
    "/usr/local/bin/netbird",
    "/usr/local/sbin/netbird",
    "/Applications/NetBird.app/Contents/MacOS/netbird",
];
const STATUS_TIMEOUT: Duration = Duration::from_secs(6);
const DOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// A `netbird up` that is still waiting (typically for the browser login).
struct Pending {
    child: Child,
    key_file: Option<PathBuf>,
}

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

pub(crate) struct NetBird {
    pub cli: Option<PathBuf>,
    pub socket: PathBuf,
}

fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

impl NetBird {
    /// The installed CLI and the daemon socket; both can be pointed elsewhere
    /// for tests and unusual installs.
    pub(crate) fn detect() -> Self {
        let cli = std::env::var_os("NETORCH_NETBIRD_CLI")
            .map(PathBuf::from)
            .into_iter()
            .chain(CLI_CANDIDATES.iter().map(PathBuf::from))
            .find(|path| executable(path));
        let socket = std::env::var_os("NETORCH_NETBIRD_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
        Self { cli, socket }
    }

    fn command(&self, cli: &Path) -> Command {
        let mut command = Command::new(cli);
        command
            .arg("--daemon-addr")
            .arg(format!("unix://{}", self.socket.display()))
            .stdin(Stdio::null());
        command
    }
}

/// Runs `command`, killing it after `limit`. Output is capped.
fn run_with_timeout(mut command: Command, limit: Duration) -> Result<(bool, String), String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "NetBird could not be started".to_string())?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    // Read on a thread and collect through a channel: a grandchild that keeps
    // the pipe open must not be able to hold this call hostage.
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stdout)
            .take(2 * 1024 * 1024)
            .read_to_string(&mut text);
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
        Some(status) => {
            let text = receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_default();
            Ok((status.success(), text))
        }
        None => Err("NetBird did not answer in time".into()),
    }
}

fn first_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(key)?;
    }
    current.as_str().filter(|text| !text.is_empty())
}

/// The compact, UI-facing view of `netbird status --json`. No keys, no event
/// log, no peer details beyond counts and the networks they route.
pub(crate) fn summarize(raw: &Value, pending: bool) -> Value {
    let daemon = raw["daemonStatus"].as_str().unwrap_or("");
    let state = match daemon {
        "Connected" => "connected",
        "Connecting" => "connecting",
        "NeedsLogin" | "LoginFailed" | "SessionExpired" => "needsLogin",
        "Idle" | "Disconnected" | "" => "disconnected",
        _ => "disconnected",
    };
    // A browser login in flight is "connecting", not "disconnected".
    let state = if pending && matches!(state, "disconnected" | "needsLogin") {
        "connecting"
    } else {
        state
    };
    let mut networks: Vec<String> = Vec::new();
    for peer in raw["peers"]["details"].as_array().into_iter().flatten() {
        for network in peer["networks"].as_array().into_iter().flatten() {
            if let Some(network) = network.as_str() {
                if !networks.iter().any(|known| known == network) && networks.len() < 64 {
                    networks.push(network.to_string());
                }
            }
        }
    }
    json!({
        "installed": true,
        "state": state,
        "daemonStatus": daemon,
        "ip": first_str(raw, &["netbirdIp"]),
        "fqdn": first_str(raw, &["fqdn"]),
        "version": first_str(raw, &["daemonVersion"]),
        "profile": first_str(raw, &["profileName"]),
        "managementUrl": first_str(raw, &["management", "url"]),
        "managementConnected": raw["management"]["connected"].as_bool().unwrap_or(false),
        "peersConnected": raw["peers"]["connected"].as_u64().unwrap_or(0),
        "peersTotal": raw["peers"]["total"].as_u64().unwrap_or(0),
        "sessionExpiresAt": first_str(raw, &["sessionExpiresAt"]),
        "networks": networks,
    })
}

fn pending_alive() -> bool {
    let mut guard = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(pending) = guard.as_mut() else {
        return false;
    };
    match pending.child.try_wait() {
        Ok(None) => true,
        _ => {
            if let Some(file) = pending.key_file.take() {
                let _ = std::fs::remove_file(file);
            }
            *guard = None;
            false
        }
    }
}

fn cancel_pending() {
    let taken = PENDING.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(mut pending) = taken {
        let _ = pending.child.kill();
        let _ = pending.child.wait();
        if let Some(file) = pending.key_file {
            let _ = std::fs::remove_file(file);
        }
    }
}

impl NetBird {
    pub(crate) fn status(&self) -> Value {
        let Some(cli) = &self.cli else {
            return json!({"installed": false, "state": "notInstalled"});
        };
        if !self.socket.exists() {
            // The CLI would wait ten seconds for a daemon that is not there.
            return json!({"installed": true, "state": "daemonStopped"});
        }
        let mut command = self.command(cli);
        command.args(["status", "--json"]);
        match run_with_timeout(command, STATUS_TIMEOUT) {
            Ok((true, text)) => match serde_json::from_str::<Value>(&text) {
                Ok(raw) => summarize(&raw, pending_alive()),
                Err(_) => json!({"installed": true, "state": "unavailable"}),
            },
            _ => json!({"installed": true, "state": "unavailable"}),
        }
    }

    /// Starts `netbird up` and returns at once; the status shows how it goes.
    /// A browser login (SSO) is handled by the CLI itself.
    pub(crate) fn up(
        &self,
        runtime: &Path,
        management_url: Option<&str>,
        setup_key: Option<&str>,
    ) -> Result<Value, String> {
        let cli = self.cli.clone().ok_or("NetBird is not installed")?;
        if !self.socket.exists() {
            return Err("The NetBird service is not running".into());
        }
        if let Some(url) = management_url {
            validate_url(url)?;
        }
        if let Some(key) = setup_key {
            validate_setup_key(key)?;
        }
        cancel_pending();
        let dir = runtime.join("netbird");
        std::fs::create_dir_all(&dir)
            .map_err(|_| "NetBird state could not be prepared".to_string())?;
        set_mode(&dir, 0o700);
        let mut key_file = None;
        let mut command = self.command(&cli);
        if let Some(url) = management_url {
            command.arg("--management-url").arg(url);
        }
        if let Some(key) = setup_key {
            // Never on the command line: other processes can read argv.
            let path = dir.join("setup-key");
            write_private(&path, key.as_bytes())
                .map_err(|_| "The setup key could not be prepared".to_string())?;
            command.arg("--setup-key-file").arg(&path);
            key_file = Some(path);
        }
        let log = std::fs::File::create(dir.join("up.log"))
            .map_err(|_| "NetBird state could not be prepared".to_string())?;
        set_mode(&dir.join("up.log"), 0o600);
        command
            .arg("up")
            .stdout(Stdio::from(
                log.try_clone()
                    .map_err(|_| "NetBird could not be started".to_string())?,
            ))
            .stderr(Stdio::from(log));
        let child = command.spawn().map_err(|_| {
            if let Some(file) = &key_file {
                let _ = std::fs::remove_file(file);
            }
            "NetBird could not be started".to_string()
        })?;
        *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = Some(Pending { child, key_file });
        Ok(self.status())
    }

    pub(crate) fn down(&self) -> Result<Value, String> {
        let cli = self.cli.clone().ok_or("NetBird is not installed")?;
        cancel_pending();
        if !self.socket.exists() {
            return Ok(self.status());
        }
        let mut command = self.command(&cli);
        command.arg("down");
        run_with_timeout(command, DOWN_TIMEOUT)
            .map_err(|_| "NetBird could not be disconnected".to_string())?;
        Ok(self.status())
    }
}

fn validate_url(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or("The NetBird server address must start with https://")?;
    let host = rest.split('/').next().unwrap_or("");
    if url.len() > 200
        || host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
        || rest
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("The NetBird server address is not valid".into());
    }
    Ok(())
}

fn validate_setup_key(key: &str) -> Result<(), String> {
    if (8..=200).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'='))
    {
        Ok(())
    } else {
        Err("The setup key is not valid".into())
    }
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

/// The tail of what `netbird up` printed (a login URL, an error).
pub(crate) fn log_tail(runtime: &Path) -> String {
    let text = std::fs::read_to_string(runtime.join("netbird/up.log")).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex as StdMutex;

    /// The pending-`up` slot is process-global; tests that touch it take turns.
    static SERIAL: StdMutex<()> = StdMutex::new(());

    const STATUS: &str = r#"{"peers":{"total":2,"connected":1,"details":[
        {"fqdn":"a","netbirdIp":"10.85.1.1","publicKey":"SECRETKEYMATERIAL","status":"Connected","networks":["10.10.40.0/24","10.10.30.155/32"]},
        {"fqdn":"b","netbirdIp":"10.85.1.2","publicKey":"SECRETKEYMATERIAL2","status":"Idle","networks":["10.10.40.0/24"]}]},
        "daemonVersion":"0.80.0","daemonStatus":"Connected",
        "management":{"url":"https://nb.example:443","connected":true,"error":""},
        "netbirdIp":"10.85.18.199/16","fqdn":"mac.netbird.selfhosted","profileName":"default",
        "sessionExpiresAt":"2026-10-15T09:10:41Z","events":[{"message":"private event text"}]}"#;

    /// A stand-in CLI: prints canned status and records what it was asked to do.
    fn fake_cli(dir: &Path, status: &str, up_sleep: &str) -> NetBird {
        let cli = dir.join("netbird");
        let log = dir.join("calls.log");
        std::fs::write(dir.join("status.json"), status).unwrap();
        std::fs::write(
            &cli,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\ncase \"$*\" in\n  *status*) cat '{status}' ;;\n  *' up'*) for f in \"$@\"; do case \"$prev\" in --setup-key-file) cat \"$f\" > '{dir}/key-seen' ;; esac; prev=\"$f\"; done; sleep {up_sleep} ;;\n  *down*) : ;;\nesac\n",
                log = log.display(),
                status = dir.join("status.json").display(),
                dir = dir.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
        let socket = dir.join("nb.sock");
        std::fs::write(&socket, b"").unwrap();
        NetBird {
            cli: Some(cli),
            socket,
        }
    }

    fn calls(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("calls.log")).unwrap_or_default()
    }

    #[test]
    fn status_is_a_compact_summary_without_keys_or_events() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), STATUS, "0");
        let status = nb.status();
        assert_eq!(status["state"], "connected");
        assert_eq!(status["ip"], "10.85.18.199/16");
        assert_eq!(status["peersConnected"], 1);
        assert_eq!(status["peersTotal"], 2);
        assert_eq!(status["managementUrl"], "https://nb.example:443");
        assert_eq!(
            status["networks"],
            json!(["10.10.40.0/24", "10.10.30.155/32"])
        );
        let text = status.to_string();
        assert!(!text.contains("SECRETKEYMATERIAL") && !text.contains("private event"));
        assert!(calls(dir.path()).contains("--daemon-addr unix://"));
        assert!(calls(dir.path()).contains("status --json"));
    }

    #[test]
    fn daemon_states_map_to_the_ui_states() {
        for (daemon, expected) in [
            ("Connected", "connected"),
            ("Connecting", "connecting"),
            ("NeedsLogin", "needsLogin"),
            ("LoginFailed", "needsLogin"),
            ("SessionExpired", "needsLogin"),
            ("Idle", "disconnected"),
            ("", "disconnected"),
            ("Weird", "disconnected"),
        ] {
            let raw = json!({"daemonStatus": daemon});
            assert_eq!(summarize(&raw, false)["state"], expected, "{daemon}");
        }
        // A login in progress is not "disconnected".
        assert_eq!(
            summarize(&json!({"daemonStatus": "NeedsLogin"}), true)["state"],
            "connecting"
        );
        assert_eq!(
            summarize(&json!({"daemonStatus": "Connected"}), true)["state"],
            "connected"
        );
    }

    #[test]
    fn missing_cli_or_daemon_is_reported_without_running_anything() {
        let dir = tempfile::tempdir().unwrap();
        let none = NetBird {
            cli: None,
            socket: dir.path().join("nb.sock"),
        };
        assert_eq!(none.status()["state"], "notInstalled");
        assert!(none.up(dir.path(), None, None).is_err());
        let stopped = {
            let mut nb = fake_cli(dir.path(), STATUS, "0");
            std::fs::remove_file(&nb.socket).unwrap();
            nb.socket = dir.path().join("nb.sock");
            nb
        };
        assert_eq!(stopped.status()["state"], "daemonStopped");
        assert!(calls(dir.path()).is_empty());
        assert!(stopped
            .up(dir.path(), None, None)
            .unwrap_err()
            .contains("not running"));
    }

    #[test]
    fn up_passes_the_setup_key_by_file_and_removes_it_afterwards() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), STATUS, "0");
        let runtime = dir.path().join("runtime");
        nb.up(&runtime, Some("https://nb.example"), Some("ABCD-1234-EFGH"))
            .unwrap();
        for _ in 0..100 {
            if !pending_alive() {
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        let log = calls(dir.path());
        assert!(log.contains("--management-url https://nb.example"), "{log}");
        assert!(log.contains("--setup-key-file"), "{log}");
        // The secret is never on a command line…
        assert!(!log.contains("ABCD-1234-EFGH"), "{log}");
        // …it reached the CLI through the file, which is gone now.
        assert_eq!(
            std::fs::read_to_string(dir.path().join("key-seen")).unwrap(),
            "ABCD-1234-EFGH"
        );
        assert!(!runtime.join("netbird/setup-key").exists());
    }

    #[test]
    fn a_login_in_flight_reads_as_connecting_and_down_cancels_it() {
        let _turn = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        cancel_pending();
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), r#"{"daemonStatus":"NeedsLogin"}"#, "30");
        nb.up(&dir.path().join("rt"), None, None).unwrap();
        assert!(pending_alive());
        assert_eq!(nb.status()["state"], "connecting");
        nb.down().unwrap();
        assert!(!pending_alive());
        assert!(calls(dir.path()).contains(" down"));
        assert_eq!(nb.status()["state"], "needsLogin");
    }

    #[test]
    fn server_addresses_and_keys_are_validated() {
        for ok in [
            "https://nb.example",
            "https://nb.example:443/",
            "http://10.0.0.5:33073",
        ] {
            assert!(validate_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "nb.example",
            "ftp://x",
            "https://",
            "https://a b",
            "https://a;b",
            "https://x/\n",
        ] {
            assert!(validate_url(bad).is_err(), "{bad}");
        }
        assert!(validate_setup_key("ABCD-1234-EFGH").is_ok());
        for bad in ["short", "has space 1234", "semi;colon1234", ""] {
            assert!(validate_setup_key(bad).is_err(), "{bad}");
        }
        let dir = tempfile::tempdir().unwrap();
        let nb = fake_cli(dir.path(), STATUS, "0");
        assert!(nb.up(dir.path(), Some("javascript:x"), None).is_err());
        assert!(nb.up(dir.path(), None, Some("bad key!")).is_err());
        assert!(calls(dir.path()).is_empty());
    }

    #[test]
    fn a_hanging_cli_is_cut_off() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("slow");
        std::fs::write(&script, "#!/bin/sh\nsleep 20\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let started = Instant::now();
        let result = run_with_timeout(Command::new(&script), Duration::from_millis(300));
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
