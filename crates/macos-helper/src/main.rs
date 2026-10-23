use network_orchestrator_macos_helper::event_log::EventLog;
use network_orchestrator_macos_helper::journal::Journal;
use network_orchestrator_macos_helper::openvpn::OpenVpnExecutor;
use network_orchestrator_macos_helper::peer::{sibling_clients, AppClientPolicy};
use network_orchestrator_macos_helper::platform::{RealOvpnPlatform, RealPlatform, RealWgPlatform};
use network_orchestrator_macos_helper::server::{bind_socket, serve, ServerContext};
use network_orchestrator_macos_helper::service::HelperService;
use network_orchestrator_macos_helper::sysexec::SystemRunner;
use network_orchestrator_macos_helper::tailscale::TailscaleGuard;
use network_orchestrator_macos_helper::wireguard::WireGuardExecutor;
use network_orchestrator_macos_helper::xray::XrayExecutor;
use network_orchestrator_macos_helper::{SOCKET_DIR, SOCKET_PATH, STATE_DIR};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};

const USAGE: &str =
    "usage: network-orchestrator-helper [--socket PATH] [--client PATH]... [--bundle CONTENTS]";

struct Options {
    socket: PathBuf,
    clients: Vec<PathBuf>,
    /// `Contents/` holding `Helpers/openvpn` when this binary is not inside
    /// the bundle (a copy installed by `netorch service install`).
    bundle: Option<PathBuf>,
}

/// `--client` may repeat; without it the programs next to the helper are used.
fn parse_args(args: Vec<String>, helper: &std::path::Path) -> Result<Options, String> {
    let mut socket = None;
    let mut clients = Vec::new();
    let mut bundle = None;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let value = |args: &mut std::vec::IntoIter<String>| {
            args.next()
                .map(PathBuf::from)
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
        };
        match flag.as_str() {
            "--socket" => socket = Some(value(&mut args)?),
            "--client" => clients.push(value(&mut args)?),
            "--bundle" => {
                let path = value(&mut args)?;
                if !path.is_absolute()
                    || path.file_name().and_then(|n| n.to_str()) != Some("Contents")
                {
                    return Err(format!(
                        "--bundle must be an absolute .../Contents path\n{USAGE}"
                    ));
                }
                bundle = Some(path);
            }
            _ => return Err(format!("unknown argument '{flag}'\n{USAGE}")),
        }
    }
    if clients.is_empty() {
        clients = sibling_clients(helper).ok_or("the app executable could not be located")?;
    }
    Ok(Options {
        socket: socket.unwrap_or_else(|| PathBuf::from(SOCKET_PATH)),
        clients,
        bundle,
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
    let xray = Arc::new(XrayExecutor::new(
        Box::new(RealPlatform),
        Box::new(SystemRunner),
        Journal::new(std::path::Path::new(STATE_DIR)),
        std::path::Path::new(SOCKET_DIR).join("xray-tun.log"),
    ));
    let state_dir = std::path::Path::new(STATE_DIR);
    let wireguard = Arc::new(
        WireGuardExecutor::new(
            Box::new(RealWgPlatform),
            Box::new(SystemRunner),
            Journal::named(state_dir, "wireguard.json"),
            std::path::PathBuf::from(network_orchestrator_macos_helper::resolver::DIR),
        )
        .with_log(EventLog::at(
            std::path::Path::new(SOCKET_DIR).join("wireguard.log"),
        )),
    );
    let openvpn = Arc::new(OpenVpnExecutor::new(
        Box::new(RealOvpnPlatform {
            stage_dir: state_dir.join("backends"),
            log: std::path::Path::new(SOCKET_DIR).join("openvpn.log"),
            bundle: options.bundle.clone(),
        }),
        Box::new(SystemRunner),
        Journal::named(state_dir, "openvpn.json"),
        std::path::PathBuf::from(network_orchestrator_macos_helper::openvpn::RUNTIME_ROOT),
        std::path::PathBuf::from(network_orchestrator_macos_helper::resolver::DIR),
    ));
    let tailscale = Arc::new(TailscaleGuard::new(
        Box::new(SystemRunner),
        Journal::named(state_dir, "tailscale.json"),
    ));
    // A tunnel a previous helper left behind must not outlive its owner.
    for (name, result) in [
        ("xray", xray.recover()),
        ("wireguard", wireguard.recover()),
        ("openvpn", openvpn.recover()),
        ("tailscale", tailscale.recover()),
    ] {
        if let Err(err) = result {
            eprintln!("network-orchestrator-helper: {name} recovery failed: {err}");
        }
    }
    // A tunnel dying on its own is noticed within seconds and cleaned up.
    let (watch_xray, watch_wg, watch_ovpn) = (xray.clone(), wireguard.clone(), openvpn.clone());
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
        watch_xray.reap();
        watch_wg.reap();
        watch_ovpn.reap();
    });
    let ctx = Arc::new(ServerContext::new(
        Box::new(AppClientPolicy::new(options.clients)),
        Arc::new(
            HelperService::new(xray.clone(), wireguard.clone(), openvpn.clone())
                .with_tailscale(tailscale.clone())
                .with_links(Arc::new(SystemRunner)),
        ),
        env!("CARGO_PKG_VERSION"),
    ));
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = serve(listener, ctx) => {}
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    xray.shutdown();
    wireguard.shutdown();
    openvpn.shutdown();
    let _ = tailscale.release();
    let _ = std::fs::remove_file(&options.socket);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn parse(args: &[&str]) -> Result<Options, String> {
        parse_args(
            args.iter().map(|arg| arg.to_string()).collect(),
            Path::new("/A.app/Contents/MacOS/network-orchestrator-helper"),
        )
    }

    #[test]
    fn without_flags_the_programs_next_to_the_helper_are_the_clients() {
        let options = parse(&[]).unwrap();
        assert_eq!(options.clients.len(), 2);
        assert!(options.bundle.is_none());
    }

    #[test]
    fn an_installed_copy_names_its_clients_and_bundle() {
        let options = parse(&[
            "--client",
            "/Applications/N.app/Contents/MacOS/netorch",
            "--bundle",
            "/Applications/N.app/Contents",
        ])
        .unwrap();
        assert_eq!(options.clients.len(), 1);
        assert_eq!(
            options.bundle.as_deref(),
            Some(Path::new("/Applications/N.app/Contents"))
        );
    }

    #[test]
    fn a_bundle_that_is_not_an_absolute_contents_directory_is_refused() {
        assert!(parse(&["--bundle", "Contents"]).is_err());
        assert!(parse(&["--bundle", "/Applications/N.app"]).is_err());
        assert!(parse(&["--bundle"]).is_err());
    }
}
