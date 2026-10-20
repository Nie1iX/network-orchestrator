//! `doctor`, `backend` and `service`.
use crate::args::{BackendCommand, ServiceCommand};
use crate::ctx::Ctx;
use crate::render::table;
use crate::runstate;
use crate::service;
use net_manager_core::helper_client::{is_denied, HelperError};
use net_manager_core::system_proxy::SystemProxyManager;
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
}

fn check(name: &'static str, level: Level, detail: impl Into<String>) -> Check {
    Check {
        name,
        level,
        detail: detail.into(),
    }
}

/// How the helper answers; shared by `doctor` and `service status`.
pub fn helper_check(ctx: &Ctx) -> Check {
    match ctx.engine().privileged().hello() {
        Ok(hello) => check(
            "helper",
            Level::Ok,
            format!(
                "version {}, {} methods",
                hello.daemon_version,
                hello.capabilities.len()
            ),
        ),
        Err(error) if is_denied(&error) => check(
            "helper",
            Level::Fail,
            "the helper refuses this program; reinstall it from the app's Settings",
        ),
        Err(HelperError::Unreachable(_)) => check(
            "helper",
            Level::Warn,
            "not running: tunnels (TUN, WireGuard, OpenVPN) are unavailable, the local proxy works",
        ),
        Err(error) => check("helper", Level::Fail, error.to_string()),
    }
}

pub fn checks(ctx: &Ctx) -> Vec<Check> {
    let mut out = Vec::new();
    out.push(match std::fs::create_dir_all(&ctx.root) {
        Ok(()) => check("data", Level::Ok, "the data directory is writable"),
        Err(_) => check("data", Level::Fail, "the data directory is not writable"),
    });
    out.push(match ctx.profiles() {
        Ok(profiles) => check("profiles", Level::Ok, format!("{} saved", profiles.len())),
        Err(error) => check("profiles", Level::Fail, error),
    });
    out.push(match ctx.engine().managed_executable() {
        Some(_) => check(
            "xray",
            Level::Ok,
            format!(
                "installed ({})",
                net_manager_core::managed_xray::MACOS_XRAY_VERSION
            ),
        ),
        None => check(
            "xray",
            Level::Warn,
            "not installed: `netorch backend install` (or `netorch up` does it)",
        ),
    });
    out.push(helper_check(ctx));
    // SAFETY: geteuid never fails.
    if unsafe { libc::geteuid() } == 0 {
        out.push(check("privileges", Level::Ok, "running as root"));
    }
    match SystemProxyManager::new(ctx.root.join("runtime").join("system-proxy.json")) {
        Ok(proxy) => out.push(match proxy.ownership() {
            None => check("proxy", Level::Ok, "the system proxy is not ours"),
            Some(owner) => {
                let live = runstate::read(&ctx.root, &owner.profile_id).is_some();
                if live {
                    check("proxy", Level::Ok, format!("held by {}", owner.profile_id))
                } else {
                    check(
                        "proxy",
                        Level::Warn,
                        "the system proxy still points at a connection that is gone; \
                         Network Orchestrator or the next `netorch up` gives it back",
                    )
                }
            }
        }),
        Err(_) => out.push(check(
            "proxy",
            Level::Fail,
            "the proxy state could not be read",
        )),
    }
    out
}

pub fn doctor(ctx: &Ctx) -> Result<(), String> {
    let checks = checks(ctx);
    let failed = checks.iter().any(|check| check.level == Level::Fail);
    let value = serde_json::to_value(&checks).map_err(|_| "Could not encode the report")?;
    ctx.emit(value, || {
        table(
            &["CHECK", "RESULT", "DETAIL"],
            &checks
                .iter()
                .map(|check| {
                    vec![
                        check.name.to_string(),
                        match check.level {
                            Level::Ok => "ok",
                            Level::Warn => "warn",
                            Level::Fail => "FAIL",
                        }
                        .to_string(),
                        check.detail.clone(),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    });
    if failed {
        Err("Some checks failed".into())
    } else {
        Ok(())
    }
}

pub fn backend(ctx: &Ctx, command: BackendCommand) -> Result<(), String> {
    match command {
        BackendCommand::Install { archive } => {
            ctx.require_user()?;
            let engine = ctx.engine();
            if engine.managed_executable().is_none() {
                ctx.note("Installing the pinned Xray (hash-checked)...");
            }
            engine.install_xray(archive.as_deref().and_then(|path| path.to_str()))?;
            ctx.emit(json!({"installed": true}), || "Xray is installed.".into());
            Ok(())
        }
    }
}

fn installer() -> service::Installer<'static> {
    service::Installer {
        prefix: std::path::PathBuf::from("/"),
        launchctl: &service::SystemLaunchctl,
    }
}

fn need_root() -> Result<(), String> {
    if crate::ctx::is_root() {
        Ok(())
    } else {
        Err("This changes the system: run it with sudo".into())
    }
}

/// Alive means it answered, even if it refused us (root is refused).
fn helper_alive(ctx: &Ctx) -> bool {
    !matches!(
        ctx.engine().privileged().hello(),
        Err(HelperError::Unreachable(_))
    )
}

pub fn service(ctx: &Ctx, command: ServiceCommand) -> Result<(), String> {
    match command {
        ServiceCommand::Install => {
            need_root()?;
            let exe = std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .map_err(|_| "netorch could not locate itself".to_string())?;
            let layout = service::layout_of(&exe)?;
            let installer = installer();
            if helper_alive(ctx) {
                return Err(if installer.is_installed() {
                    "The helper is already installed and running".into()
                } else {
                    "A helper is already running (installed by the app). \
                     Remove it in the app's Settings first"
                        .to_string()
                });
            }
            installer.install(&layout, true)?;
            for _ in 0..25 {
                if helper_alive(ctx) {
                    ctx.emit(json!({"installed": true}), || {
                        "The helper is installed and running.".into()
                    });
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err("The helper was registered but did not start; see /var/log/network-orchestrator-helper.log".into())
        }
        ServiceCommand::Remove => {
            need_root()?;
            let removed = installer().remove()?;
            ctx.emit(json!({"removed": removed}), || {
                if removed {
                    "The helper is removed.".into()
                } else {
                    "No helper installed by netorch was found.".into()
                }
            });
            Ok(())
        }
        ServiceCommand::Status => {
            let result = helper_check(ctx);
            let failed = result.level == Level::Fail;
            ctx.emit(
                serde_json::to_value(&result).map_err(|_| "Could not encode the result")?,
                || format!("{}: {}", result.name, result.detail),
            );
            if failed {
                Err("The helper is not usable".into())
            } else {
                Ok(())
            }
        }
    }
}
