//! `netorch version` and the compatibility check run before commands that
//! talk to the network daemon. The CLI and the daemon are separate packages
//! and can be at different versions; see `net_manager_engine::linux_compat`.
use super::commands::Output;
use super::ctx::Ctx;
use net_manager_engine::linux_compat::{check, Verdict};
use net_manager_engine::linux_engine::daemon_error;
use serde_json::json;

/// The version of this netorch.
pub const CLIENT_VERSION: &str = env!("NETORCH_VERSION");

/// Refuses an incompatible daemon; prints a warning once for an older one.
pub fn guard(ctx: &Ctx) -> Result<(), String> {
    let hello = ctx.engine.privileged().hello().map_err(daemon_error)?;
    match check(&hello, CLIENT_VERSION) {
        Verdict::Compatible => Ok(()),
        Verdict::Warning(text) => {
            eprintln!("netorch: warning: {text}");
            Ok(())
        }
        Verdict::Incompatible(text) => Err(text),
    }
}

pub fn version(ctx: &Ctx) -> Result<Output, String> {
    let mut value = json!({
        "netorch": CLIENT_VERSION,
        "core": net_manager_core::VERSION,
        "protocol": net_manager_core::daemon_protocol::PROTOCOL_VERSION,
        "daemon": null,
    });
    let mut text = format!(
        "netorch {CLIENT_VERSION} (core {}, daemon protocol {})",
        net_manager_core::VERSION,
        net_manager_core::daemon_protocol::PROTOCOL_VERSION
    );
    match ctx.engine.privileged().hello() {
        Ok(hello) => {
            let verdict = check(&hello, CLIENT_VERSION);
            let (state, message) = match &verdict {
                Verdict::Compatible => ("compatible", None),
                Verdict::Warning(text) => ("warning", Some(text.clone())),
                Verdict::Incompatible(text) => ("incompatible", Some(text.clone())),
            };
            value["daemon"] = json!({
                "version": hello.daemon_version,
                "protocol": hello.protocol,
                "compatibility": state,
                "message": message,
            });
            text.push_str(&format!(
                "\ndaemon {} (protocol {}): {state}",
                hello.daemon_version, hello.protocol
            ));
            if let Some(message) = message {
                text.push_str(&format!("\n{message}"));
            }
        }
        Err(error) => {
            let message = daemon_error(error);
            value["daemonError"] = json!(message);
            text.push_str(&format!("\ndaemon: {message}"));
        }
    }
    Ok((value, text))
}
