//! `up` and `down`.
use crate::args::{Mode, Role, UpArgs};
use crate::ctx::Ctx;
use crate::inproc::InProcess;
use crate::library::{self, add_input};
use crate::lock::{self, InstanceLock};
use crate::prompt;
use crate::route::runs_locally;
use crate::runstate::{self, RunState};
use crate::target::{self, Input};
use net_manager_core::models::{Profile, TunnelBackend, TunnelRole, TunnelState, XrayMode};
use net_manager_engine::Engine;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: the handler only stores to an atomic, which is signal-safe.
        unsafe { libc::signal(signal, on_signal as usize as libc::sighandler_t) };
    }
}

fn resolve_or_add(ctx: &Ctx, args: &UpArgs) -> Result<Profile, String> {
    match target::classify(&args.target, |path| path.is_file()) {
        Input::Saved(query) => ctx.find(&query),
        _ => {
            let profile = add_input(ctx, &args.target, args.name.as_deref())?;
            ctx.note(&format!("Saved \"{}\" ({})", profile.name, profile.id));
            Ok(profile)
        }
    }
}

fn join_networks(profile: &Profile) -> String {
    profile
        .tunnel_networks
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Applies the flags that change the saved profile. Mutations of a profile
/// that restarts through this process need the data directory's lock.
fn apply_settings(ctx: &Ctx, profile: &Profile, args: &UpArgs) -> Result<(), String> {
    if let Some(mode) = args.mode {
        if profile.backend != TunnelBackend::Xray {
            return Err("--mode applies to Xray connections only".into());
        }
        let wanted = match mode {
            Mode::Socks => XrayMode::Socks,
            Mode::Tun => XrayMode::Tun,
        };
        if profile.xray_mode != wanted {
            ctx.app(
                "set_xray_mode",
                json!({"id": profile.id, "mode": match mode { Mode::Socks => "socks", Mode::Tun => "tun" }}),
            )?;
        }
    }
    if let Some(role) = args.role {
        let wanted = match role {
            Role::Primary => TunnelRole::Primary,
            Role::Secondary => TunnelRole::Secondary,
        };
        if profile.tunnel_role != wanted {
            ctx.app(
                "set_tunnel_role",
                json!({"id": profile.id, "role": match role { Role::Primary => "primary", Role::Secondary => "secondary" }}),
            )?;
        }
    }
    if args.networks.is_some() || args.dns_domains.is_some() {
        ctx.app(
            "set_tunnel_networks",
            json!({
                "id": profile.id,
                "networks": args.networks.clone().unwrap_or_else(|| join_networks(profile)),
                "dnsDomains": args.dns_domains.clone()
                    .unwrap_or_else(|| profile.tunnel_dns_domains.join(",")),
            }),
        )?;
    }
    Ok(())
}

/// `sudo netorch up <saved profile>`: the tunnel's executors run in this
/// process instead of the launchd helper (`inproc`).
fn up_as_root(ctx: &Ctx, args: UpArgs) -> Result<(), String> {
    if args.mode.is_some()
        || args.role.is_some()
        || args.networks.is_some()
        || args.dns_domains.is_some()
        || args.system_proxy
    {
        return Err(
            "Change settings without sudo first (`netorch up --mode ...`), then run \
             `sudo netorch up <name>`"
                .into(),
        );
    }
    let Input::Saved(query) = target::classify(&args.target, |path| path.is_file()) else {
        return Err("Import it without sudo first (`netorch add ...`)".into());
    };
    let profile = ctx.find(&query)?;
    if runs_locally(&profile) || profile.backend == TunnelBackend::None {
        return Err("This connection runs as your user: run it without sudo".into());
    }
    if library::is_running_anywhere(ctx, &profile) {
        return Err("The connection is already running".into());
    }
    let inproc = Arc::new(InProcess::start(&net_manager_engine::helper_socket())?);
    let engine = Engine::with_privileged(&ctx.root, inproc.clone());
    if profile.backend == TunnelBackend::Xray && engine.managed_executable().is_none() {
        return Err("Install Xray first, without sudo: `netorch backend install`".into());
    }
    let credentials = if profile.backend == TunnelBackend::OpenVpn {
        let needs = engine.credential_requirements(&profile)?;
        prompt::collect(
            needs.user_pass,
            needs.key_passphrase,
            args.auth_stdin,
            args.passphrase_stdin,
        )?
    } else {
        None
    };
    install_signal_handlers();
    if let Err(error) = engine.connect(&ctx.store(), &profile, credentials) {
        inproc.shutdown();
        return Err(error);
    }
    runstate::write(
        &ctx.root,
        &RunState {
            profile_id: profile.id.clone(),
            pid: std::process::id(),
            socks_port: None,
            http_port: None,
            system_proxy: false,
        },
    )
    .map_err(|_| "The run state could not be saved".to_string())?;
    let interface = engine
        .remote_status(&profile)
        .and_then(|status| status.interface_name);
    ctx.emit(
        json!({"id": profile.id, "state": "running", "interface": interface}),
        || {
            format!(
                "Connected \"{}\"{}\nPress Ctrl+C to disconnect.",
                profile.name,
                interface
                    .as_deref()
                    .map(|name| format!(" on {name}"))
                    .unwrap_or_default()
            )
        },
    );
    while !STOP.load(Ordering::SeqCst)
        && engine
            .remote_status(&profile)
            .is_some_and(|status| status.state == TunnelState::Running)
    {
        std::thread::sleep(Duration::from_millis(500));
    }
    let interrupted = STOP.load(Ordering::SeqCst);
    runstate::remove(&ctx.root, &profile.id);
    let _ = engine.disconnect_remote(&profile);
    inproc.shutdown();
    ctx.note("Disconnected.");
    if interrupted {
        Ok(())
    } else {
        Err("The connection stopped unexpectedly. `netorch logs` shows why.".into())
    }
}

pub fn up(ctx: &Ctx, args: UpArgs) -> Result<(), String> {
    if crate::ctx::is_root() {
        return up_as_root(ctx, args);
    }
    let profile = resolve_or_add(ctx, &args)?;
    let final_mode = match (args.mode, profile.backend) {
        (Some(Mode::Socks), _) => XrayMode::Socks,
        (Some(Mode::Tun), _) => XrayMode::Tun,
        (None, _) => profile.xray_mode,
    };
    let will_run_locally = profile.backend == TunnelBackend::Xray && final_mode == XrayMode::Socks;
    let changes_settings = args.mode.is_some()
        || args.role.is_some()
        || args.networks.is_some()
        || args.dns_domains.is_some();
    let guard: Option<InstanceLock> =
        if will_run_locally || (changes_settings && runs_locally(&profile)) {
            Some(lock::acquire(&ctx.root)?)
        } else {
            None
        };
    if library::is_running_anywhere(ctx, &profile) {
        return Err("The connection is already running".into());
    }
    apply_settings(ctx, &profile, &args)?;
    let profile = ctx.find(&profile.id)?;
    if args.system_proxy && !runs_locally(&profile) {
        return Err("--system-proxy applies to the local proxy (Xray --mode socks)".into());
    }
    let engine = ctx.engine();
    if profile.backend == TunnelBackend::Xray && engine.managed_executable().is_none() {
        ctx.note("Installing the pinned Xray (hash-checked)...");
        engine.install_xray(None)?;
    }
    let credentials = if profile.backend == TunnelBackend::OpenVpn {
        let needs = engine.credential_requirements(&profile)?;
        prompt::collect(
            needs.user_pass,
            needs.key_passphrase,
            args.auth_stdin,
            args.passphrase_stdin,
        )?
    } else {
        None
    };
    if runs_locally(&profile) {
        let guard = guard.ok_or("Internal error: the runtime lock is missing")?;
        return up_local(ctx, &profile, args.system_proxy, guard);
    }
    engine.connect(&ctx.store(), &profile, credentials)?;
    let state = library::state_of(ctx, &profile);
    ctx.emit(state.clone(), || {
        format!(
            "Connected \"{}\"{}",
            profile.name,
            state["interface"]
                .as_str()
                .map(|name| format!(" on {name}"))
                .unwrap_or_default()
        )
    });
    Ok(())
}

/// Loopback Xray lives and dies with this process.
fn up_local(
    ctx: &Ctx,
    profile: &Profile,
    system_proxy: bool,
    _guard: InstanceLock,
) -> Result<(), String> {
    install_signal_handlers();
    let engine = ctx.engine();
    let store = ctx.store();
    engine.connect(&store, profile, None)?;
    let profiles = ctx.profiles()?;
    // Busy ports are replaced while connecting; read the ports actually used.
    let profile = profiles
        .iter()
        .find(|candidate| candidate.id == profile.id)
        .cloned()
        .ok_or("Profile not found")?;
    if system_proxy {
        if let Err(error) = engine.set_system_proxy(&profile, &profiles, true) {
            let _ = engine.disconnect(&profile, &profiles);
            return Err(error);
        }
    }
    runstate::write(
        &ctx.root,
        &RunState {
            profile_id: profile.id.clone(),
            pid: std::process::id(),
            socks_port: profile.xray_socks_port,
            http_port: profile.xray_http_port,
            system_proxy,
        },
    )
    .map_err(|_| "The run state could not be saved".to_string())?;
    ctx.emit(
        json!({
            "id": profile.id, "state": "running",
            "socksPort": profile.xray_socks_port, "httpPort": profile.xray_http_port,
            "systemProxy": system_proxy,
        }),
        || {
            let mut text = format!("Connected \"{}\"", profile.name);
            if let Some(port) = profile.xray_socks_port {
                text.push_str(&format!("\n  SOCKS 127.0.0.1:{port}"));
            }
            if let Some(port) = profile.xray_http_port {
                text.push_str(&format!("\n  HTTP  127.0.0.1:{port}"));
            }
            if system_proxy {
                text.push_str("\n  system proxy: on");
            }
            text.push_str("\nPress Ctrl+C to disconnect.");
            text
        },
    );
    while !STOP.load(Ordering::SeqCst) && engine.is_running(&profile).unwrap_or(false) {
        std::thread::sleep(Duration::from_millis(300));
    }
    let interrupted = STOP.load(Ordering::SeqCst);
    runstate::remove(&ctx.root, &profile.id);
    let profiles = ctx.profiles().unwrap_or(profiles);
    // Gives the system proxy back even when Xray already died.
    let _ = engine.disconnect(&profile, &profiles);
    ctx.note("Disconnected.");
    if interrupted {
        Ok(())
    } else {
        Err("The connection stopped unexpectedly. `netorch logs` shows why.".into())
    }
}

/// Ends a run of this program, whichever kind: loopback Xray or a
/// `sudo netorch` tunnel. Both leave a state file with the owning pid.
fn stop_run(ctx: &Ctx, profile: &Profile) -> Result<bool, String> {
    let Some(run) = runstate::read(&ctx.root, &profile.id) else {
        return Ok(false);
    };
    // SAFETY: plain signal delivery to the pid recorded by our own run.
    if unsafe { libc::kill(run.pid as libc::pid_t, libc::SIGTERM) } != 0 {
        return Err(
            "That connection was started with sudo: run `sudo netorch down` to stop it".into(),
        );
    }
    for _ in 0..50 {
        if !runstate::pid_alive(run.pid) {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err("The connection did not stop in time".into())
}

pub fn down(ctx: &Ctx, target: Option<&str>, all: bool) -> Result<(), String> {
    let profiles = if all {
        ctx.profiles()?
    } else {
        vec![ctx.find(target.ok_or("Name a connection or use --all")?)?]
    };
    let engine = ctx.engine();
    let mut stopped = Vec::new();
    for profile in &profiles {
        let done = if stop_run(ctx, profile)? {
            true
        } else if !crate::ctx::is_root()
            && engine
                .remote_status(profile)
                .is_some_and(|status| status.state == TunnelState::Running)
        {
            engine.disconnect_remote(profile)?;
            true
        } else {
            false
        };
        if done {
            stopped.push(profile.name.clone());
        } else if !all {
            return Err(format!("\"{}\" is not running", profile.name));
        }
    }
    ctx.emit(json!({"stopped": stopped}), || {
        if stopped.is_empty() {
            "Nothing was running.".to_string()
        } else {
            format!("Disconnected: {}", stopped.join(", "))
        }
    });
    Ok(())
}
