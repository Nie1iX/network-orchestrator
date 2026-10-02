use network_orchestrator_macos_helper::peer::{sibling_client, AppClientPolicy};
use network_orchestrator_macos_helper::server::{bind_socket, serve, ServerContext};
use network_orchestrator_macos_helper::service::HelperService;
use network_orchestrator_macos_helper::SOCKET_PATH;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};

const USAGE: &str = "usage: network-orchestrator-helper [--socket PATH] [--client PATH]";

struct Options {
    socket: PathBuf,
    client: PathBuf,
}

fn parse_args(args: Vec<String>, helper: &std::path::Path) -> Result<Options, String> {
    let mut socket = None;
    let mut client = None;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--socket" => &mut socket,
            "--client" => &mut client,
            _ => return Err(format!("unknown argument '{flag}'\n{USAGE}")),
        };
        *slot = Some(PathBuf::from(
            args.next()
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?,
        ));
    }
    Ok(Options {
        socket: socket.unwrap_or_else(|| PathBuf::from(SOCKET_PATH)),
        client: client
            .or_else(|| sibling_client(helper))
            .ok_or("the app executable could not be located")?,
    })
}

fn main() -> ExitCode {
    let helper = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("network-orchestrator-helper: {err}");
            return ExitCode::FAILURE;
        }
    };
    let options = match parse_args(std::env::args().skip(1).collect(), &helper) {
        Ok(options) => options,
        Err(err) => {
            eprintln!("network-orchestrator-helper: {err}");
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
            eprintln!("network-orchestrator-helper: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(options: Options) -> std::io::Result<()> {
    let listener = bind_socket(&options.socket)?;
    let ctx = Arc::new(ServerContext::new(
        Box::new(AppClientPolicy::new(options.client)),
        Arc::new(HelperService),
        env!("CARGO_PKG_VERSION"),
    ));
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = serve(listener, ctx) => {}
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    let _ = std::fs::remove_file(&options.socket);
    Ok(())
}
