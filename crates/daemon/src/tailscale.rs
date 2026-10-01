//! Minimal LocalAPI client for the system `tailscaled`.
//!
//! Tailscale is a *foreign* daemon: it owns its process, TUN and policy
//! routing (table 52), so nothing here is journaled — we only proxy the
//! LocalAPI status plus the `WantRunning` pref (`tailscale up/down`).
//! The daemon runs as root, so the operator socket needs no ACL setup.

use net_manager_core::daemon_protocol::{TailscalePeer, TailscaleStatusResult};
use serde_json::Value;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_SOCKET: &str = "/run/tailscale/tailscaled.sock";
/// Test/E2E override for the LocalAPI socket location.
pub const SOCKET_ENV: &str = "NETWORK_ORCHESTRATOR_TAILSCALED_SOCK";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Status payloads scale with tailnet size; bound well above real responses
/// so a misbehaving endpoint cannot make us buffer unbounded data.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub fn socket_path() -> PathBuf {
    std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

fn invalid_data() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "tailscaled answered badly")
}

/// One synchronous HTTP/1.1 exchange over the LocalAPI unix socket.
/// `Connection: close` makes the end of the body unambiguous even when the
/// server neither sets Content-Length nor uses chunked encoding.
fn localapi(socket: &Path, verb: &str, path: &str, body: &str) -> io::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let request = format!(
        "{verb} {path} HTTP/1.1\r\nHost: local-tailscaled.sock\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|_| io::Error::other("tailscaled request failed"))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > MAX_RESPONSE_BYTES {
            return Err(invalid_data());
        }
    }
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(invalid_data)?;
    let head = std::str::from_utf8(&raw[..head_end]).map_err(|_| invalid_data())?;
    let status_line = head.lines().next().ok_or_else(invalid_data)?;
    if status_line.split_whitespace().nth(1) != Some("200") {
        return Err(io::Error::other("tailscaled refused the request"));
    }
    let chunked = head
        .lines()
        .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"));
    let body = &raw[head_end + 4..];
    if chunked {
        decode_chunked(body)
    } else {
        Ok(body.to_vec())
    }
}

fn decode_chunked(mut input: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(invalid_data)?;
        let size_text = std::str::from_utf8(&input[..line_end]).map_err(|_| invalid_data())?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| invalid_data())?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if input.len() < size + 2 || out.len() + size > MAX_RESPONSE_BYTES {
            return Err(invalid_data());
        }
        out.extend_from_slice(&input[..size]);
        input = &input[size + 2..]; // chunk + trailing CRLF
    }
}

/// Project `ipnstate` JSON into the protocol shape. `AllowedIPs` on a node
/// carries both its own /32,/128 addresses and, for subnet routers or exit
/// nodes, the advertised prefixes — the latter are the "routes" we show.
pub fn parse_status(value: &Value) -> TailscaleStatusResult {
    let mut status = TailscaleStatusResult {
        available: true,
        backend_state: value["BackendState"].as_str().unwrap_or("").to_string(),
        magic_dns_suffix: value["MagicDNSSuffix"].as_str().map(str::to_owned),
        ..Default::default()
    };
    status.tailnet = value["CurrentTailnet"]["Name"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| status.magic_dns_suffix.clone());
    let self_node = &value["Self"];
    if self_node.is_object() {
        status.self_host_name = self_node["HostName"].as_str().map(str::to_owned);
        status.self_dns_name = self_node["DNSName"].as_str().map(str::to_owned);
        status.self_ips = ip_list(&self_node["TailscaleIPs"]);
    }
    if let Some(peers) = value["Peer"].as_object() {
        for peer in peers.values() {
            let own_ips: Vec<&str> = peer["TailscaleIPs"]
                .as_array()
                .map(|ips| ips.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let routes = peer["AllowedIPs"]
                .as_array()
                .map(|allowed| {
                    allowed
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|prefix| {
                            // Drop host routes pointing at the node's own
                            // addresses; what remains is what it advertises.
                            let own = own_ips.iter().any(|ip| {
                                prefix.strip_suffix("/32") == Some(*ip)
                                    || prefix.strip_suffix("/128") == Some(*ip)
                            });
                            !own
                        })
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            status.peers.push(TailscalePeer {
                host_name: peer["HostName"].as_str().unwrap_or("").to_string(),
                dns_name: peer["DNSName"].as_str().map(str::to_owned),
                tailscale_ips: ip_list(&peer["TailscaleIPs"]),
                routes,
                exit_node: peer["ExitNode"].as_bool().unwrap_or(false),
                exit_node_option: peer["ExitNodeOption"].as_bool().unwrap_or(false),
                online: peer["Online"].as_bool().unwrap_or(false),
                os: peer["OS"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    status.peers.sort_by(|a, b| a.host_name.cmp(&b.host_name));
    status.exit_node_active = status.peers.iter().any(|peer| peer.exit_node);
    status
}

fn ip_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|ips| {
            ips.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// GET /localapi/v0/status → projected result. An absent or refusing socket
/// is a state (`available: false`), not an RPC error.
pub fn status(socket: &Path) -> io::Result<TailscaleStatusResult> {
    match localapi(socket, "GET", "/localapi/v0/status", "") {
        Ok(body) => {
            let value: Value = serde_json::from_slice(&body).map_err(|_| invalid_data())?;
            Ok(parse_status(&value))
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(TailscaleStatusResult {
                backend_state: "Unavailable".into(),
                ..Default::default()
            })
        }
        Err(err) => Err(err),
    }
}

/// `tailscale up`/`down` without login flags: flip the daemon's WantRunning
/// preference. Login itself stays tailscaled's business (`AuthURL` in the
/// status carries the interactive flow when it is needed).
pub fn set_running(socket: &Path, running: bool) -> io::Result<()> {
    let body = if running {
        r#"{"WantRunning":true}"#
    } else {
        r#"{"WantRunning":false}"#
    };
    localapi(socket, "PATCH", "/localapi/v0/prefs", body).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn fixture_status() -> Value {
        serde_json::json!({
            "BackendState": "Running",
            "MagicDNSSuffix": "tailnet.test.ts.net",
            "CurrentTailnet": {"Name": "tailnet.test"},
            "Self": {
                "HostName": "fedora",
                "DNSName": "fedora.tailnet.test.ts.net.",
                "TailscaleIPs": ["100.78.82.81", "fd7a:115c:a1e0::fd2f:5252"],
                "AllowedIPs": ["100.78.82.81/32", "fd7a:115c:a1e0::fd2f:5252/128"],
            },
            "Peer": {
                "p1": {
                    "HostName": "kzn1",
                    "DNSName": "kzn1.tailnet.test.ts.net.",
                    "TailscaleIPs": ["100.85.160.64"],
                    "AllowedIPs": ["100.85.160.64/32", "192.168.9.0/24"],
                    "Online": true,
                    "OS": "linux",
                    "ExitNode": false,
                    "ExitNodeOption": false,
                },
                "p2": {
                    "HostName": "exiter",
                    "TailscaleIPs": ["100.64.0.7"],
                    "AllowedIPs": ["100.64.0.7/32", "0.0.0.0/0", "::/0"],
                    "Online": false,
                    "OS": "linux",
                    "ExitNode": true,
                    "ExitNodeOption": true,
                },
            },
        })
    }

    #[test]
    fn status_parses_self_peers_and_advertised_routes() {
        let status = parse_status(&fixture_status());
        assert_eq!(status.backend_state, "Running");
        assert_eq!(status.tailnet.as_deref(), Some("tailnet.test"));
        assert_eq!(status.self_host_name.as_deref(), Some("fedora"));
        assert_eq!(status.self_ips.len(), 2);
        assert_eq!(status.peers.len(), 2);
        let exiter = &status.peers[0]; // sorted by host name
        assert_eq!(exiter.routes, vec!["0.0.0.0/0", "::/0"]);
        assert!(exiter.exit_node && exiter.exit_node_option && !exiter.online);
        let kzn1 = &status.peers[1];
        assert_eq!(kzn1.routes, vec!["192.168.9.0/24"]);
        assert_eq!(kzn1.tailscale_ips, vec!["100.85.160.64"]);
        assert!(status.exit_node_active);
    }

    #[test]
    fn status_tolerates_empty_and_partial_payloads() {
        let status = parse_status(&serde_json::json!({"BackendState": "NeedsLogin"}));
        assert_eq!(status.backend_state, "NeedsLogin");
        assert!(status.peers.is_empty() && !status.exit_node_active);
        let status = parse_status(&serde_json::json!({}));
        assert!(status.backend_state.is_empty() && status.tailnet.is_none());
    }

    fn serve_once(response: &'static str) -> (PathBuf, thread::JoinHandle<String>) {
        let dir = std::env::temp_dir().join(format!("netmgr-ts-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let socket = dir.join(format!("tsd-{}.sock", uuid_like()));
        let listener = UnixListener::bind(&socket).unwrap();
        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = conn.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            conn.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&request).into_owned()
        });
        (socket, handle)
    }

    fn uuid_like() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!(
            "{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[test]
    fn localapi_decodes_chunked_bodies() {
        let (socket, server) = serve_once(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1a\r\n{\"BackendState\":\"Stopped\"}\r\n0\r\n\r\n",
        );
        let body = localapi(&socket, "GET", "/localapi/v0/status", "").unwrap();
        server.join().unwrap();
        assert_eq!(body, b"{\"BackendState\":\"Stopped\"}");
        let _ = std::fs::remove_file(&socket);
    }

    #[test]
    fn localapi_rejects_non_200_status() {
        let (socket, server) = serve_once("HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\n{}");
        let err = localapi(&socket, "GET", "/localapi/v0/status", "").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        server.join().unwrap();
        let _ = std::fs::remove_file(&socket);
    }

    #[test]
    fn set_running_patches_the_wantrunning_pref() {
        let (socket, server) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        set_running(&socket, false).unwrap();
        let request = server.join().unwrap();
        assert!(request.starts_with("PATCH /localapi/v0/prefs "));
        assert!(request.contains(r#"{"WantRunning":false}"#));
        let _ = std::fs::remove_file(&socket);
    }

    #[test]
    fn status_maps_a_missing_socket_to_unavailable() {
        let status = status(Path::new("/nonexistent/tailscaled.sock")).unwrap();
        assert!(!status.available);
        assert_eq!(status.backend_state, "Unavailable");
    }

    /// Read-only smoke against a real `tailscaled` — skipped unless the
    /// LocalAPI socket exists on this machine. No mutations.
    #[test]
    fn real_localapi_status_is_parseable() {
        let socket = Path::new(DEFAULT_SOCKET);
        if !socket.exists() {
            return;
        }
        let status = status(socket).unwrap();
        assert!(status.available);
        assert!(!status.backend_state.is_empty());
    }
}
