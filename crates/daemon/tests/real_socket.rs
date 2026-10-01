//! Binds a real unix socket in a temp dir. Needs no root and mutates
//! nothing: executors refuse every call and polkit is never consulted.
#![cfg(target_os = "linux")]

use net_manager_core::journal::{JournalStore, JOURNAL_FILE};
use net_manager_core::models::AppliedRoute;
use net_manager_core::policy::RouteExecutor;
use network_orchestrator_daemon::auth::{Action, AuthDecision, Authorizer, PeerIdentity};
use network_orchestrator_daemon::core::{DaemonCore, ExternalLinkKind, LinkExecutor};
use network_orchestrator_daemon::server::{bind_socket, serve, ServerContext};
use serde_json::{json, Value};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

struct NoRoutes;

impl RouteExecutor for NoRoutes {
    fn add_route(&mut self, _route: &AppliedRoute) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "test never mutates",
        ))
    }

    fn remove_route(&mut self, _route: &AppliedRoute) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "test never mutates",
        ))
    }
}

struct NoLinks;

impl LinkExecutor for NoLinks {
    fn set_link_state(&mut self, _name: &str, _up: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "test never mutates",
        ))
    }

    fn remove_link(&mut self, _name: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "test never mutates",
        ))
    }

    fn link_kind(&mut self, _name: &str) -> io::Result<ExternalLinkKind> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "test never mutates",
        ))
    }
}

struct DenyAll;

impl Authorizer for DenyAll {
    async fn check(&self, _peer: &PeerIdentity, _action: Action) -> io::Result<AuthDecision> {
        Ok(AuthDecision::Denied)
    }
}

fn unique_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "netmgr-daemon-socket-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn real_socket_reports_own_uid_via_peercred() {
    let dir = unique_dir("peercred");
    let socket = dir.join("daemon.sock");
    // A socket file left behind by a previous run must be replaced.
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());

    // systemd runs the daemon with UMask=0077; bind would create 0600.
    // SAFETY: umask only swaps the process file mode mask.
    let previous = unsafe { libc::umask(0o077) };
    let listener = bind_socket(&socket);
    unsafe { libc::umask(previous) };
    let listener = listener.unwrap();
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o666);

    let core = DaemonCore::open(
        JournalStore::new(dir.join(JOURNAL_FILE)),
        Box::new(NoRoutes),
        Box::new(NoLinks),
    )
    .unwrap();
    let ctx = Arc::new(ServerContext::new(core, DenyAll));
    tokio::spawn(serve(listener, ctx));

    let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
    let (read, mut write) = stream.into_split();
    write
        .write_all(
            b"{\"id\":1,\"method\":\"hello\",\"params\":{\"protocol\":1,\"client\":\"test\"}}\n",
        )
        .await
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        BufReader::new(read).read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    // SAFETY: getuid never fails.
    let uid = unsafe { libc::getuid() };
    assert_eq!(reply["ok"], json!(true), "{reply}");
    assert_eq!(reply["result"]["uid"], json!(uid));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn bind_refuses_to_replace_a_regular_file() {
    let dir = unique_dir("regular");
    let path = dir.join("daemon.sock");
    std::fs::write(&path, b"not a socket").unwrap();
    let err = bind_socket(&path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
    std::fs::remove_dir_all(&dir).unwrap();
}
