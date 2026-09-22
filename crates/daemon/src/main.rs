use std::process::ExitCode;

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("network-orchestrator-daemon runs on Linux only");
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    linux::main()
}

#[cfg(target_os = "linux")]
mod linux {
    use net_manager_core::daemon_protocol::{DEFAULT_SOCKET_PATH, SOCKET_ENV};
    use network_orchestrator_daemon::auth::PolkitAuthorizer;
    use network_orchestrator_daemon::core::DaemonCore;
    use network_orchestrator_daemon::journal::{JournalStore, JOURNAL_FILE};
    use network_orchestrator_daemon::netlink::NetlinkExecutor;
    use network_orchestrator_daemon::server::{bind_socket, serve, ServerContext};
    use std::io;
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::Arc;
    use tokio::signal::unix::{signal, SignalKind};

    const DEFAULT_STATE_DIR: &str = "/var/lib/network-orchestrator";
    const USAGE: &str = "usage: network-orchestrator-daemon [--socket PATH] [--state-dir DIR]";

    #[derive(Debug)]
    struct Options {
        socket: PathBuf,
        state_dir: PathBuf,
    }

    /// `--socket` beats `$NETWORK_ORCHESTRATOR_SOCKET` beats the default.
    fn parse_args(args: Vec<String>, env_socket: Option<String>) -> Result<Options, String> {
        let mut socket = env_socket.map(PathBuf::from);
        let mut state_dir = None;
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            let slot = match flag.as_str() {
                "--socket" => &mut socket,
                "--state-dir" => &mut state_dir,
                _ => return Err(format!("unknown argument '{flag}'\n{USAGE}")),
            };
            let value = args
                .next()
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
            *slot = Some(PathBuf::from(value));
        }
        Ok(Options {
            socket: socket.unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH)),
            state_dir: state_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR)),
        })
    }

    pub fn main() -> ExitCode {
        let args = std::env::args().skip(1).collect();
        let options = match parse_args(args, std::env::var(SOCKET_ENV).ok()) {
            Ok(options) => options,
            Err(err) => {
                eprintln!("network-orchestrator-daemon: {err}");
                return ExitCode::from(2);
            }
        };
        let result = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .and_then(|runtime| runtime.block_on(run(options)));
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("network-orchestrator-daemon: {err}");
                ExitCode::FAILURE
            }
        }
    }

    async fn run(options: Options) -> io::Result<()> {
        let netlink = NetlinkExecutor::spawn()?;
        let store = JournalStore::new(options.state_dir.join(JOURNAL_FILE));
        // Recovery runs before the socket exists, so no client can observe
        // (or race with) leftovers from a previous run.
        let core = tokio::task::spawn_blocking(move || {
            DaemonCore::open(store, Box::new(netlink.clone()), Box::new(netlink))
        })
        .await
        .map_err(io::Error::other)??;
        let listener = bind_socket(&options.socket)?;
        let ctx = Arc::new(ServerContext::new(core, PolkitAuthorizer::default()));
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        eprintln!(
            "network-orchestrator-daemon: listening on {}",
            options.socket.display()
        );
        tokio::select! {
            () = serve(listener, ctx.clone()) => {}
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
        let _ = std::fs::remove_file(&options.socket);
        let core = ctx.core.clone();
        let result = tokio::task::spawn_blocking(move || {
            core.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .shutdown()
        })
        .await
        .map_err(io::Error::other)??;
        eprintln!(
            "network-orchestrator-daemon: shutdown removed {} owner(s), {} stale",
            result.removed_owners.len(),
            result.failed.len()
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(items: &[&str]) -> Vec<String> {
            items.iter().map(|s| s.to_string()).collect()
        }

        #[test]
        fn defaults_apply_without_flags_or_env() {
            let options = parse_args(args(&[]), None).unwrap();
            assert_eq!(options.socket, PathBuf::from(DEFAULT_SOCKET_PATH));
            assert_eq!(options.state_dir, PathBuf::from(DEFAULT_STATE_DIR));
        }

        #[test]
        fn socket_flag_beats_env_and_env_beats_default() {
            let from_env = parse_args(args(&[]), Some("/tmp/env.sock".into())).unwrap();
            assert_eq!(from_env.socket, PathBuf::from("/tmp/env.sock"));
            let from_flag = parse_args(
                args(&["--socket", "/tmp/flag.sock", "--state-dir", "/tmp/state"]),
                Some("/tmp/env.sock".into()),
            )
            .unwrap();
            assert_eq!(from_flag.socket, PathBuf::from("/tmp/flag.sock"));
            assert_eq!(from_flag.state_dir, PathBuf::from("/tmp/state"));
        }

        #[test]
        fn rejects_unknown_and_incomplete_flags() {
            assert!(parse_args(args(&["--bogus"]), None).is_err());
            assert!(parse_args(args(&["--socket"]), None).is_err());
        }
    }
}
