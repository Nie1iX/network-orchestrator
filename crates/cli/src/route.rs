//! Routing rules and route lookups.
use crate::args::RouteCommand;
use crate::ctx::Ctx;
use crate::lock;
use net_manager_core::models::{Profile, TunnelBackend, XrayMode};
use serde_json::{json, Value};

/// Loopback Xray is a child of whoever started it; changing such a profile
/// restarts it, which only the owner of the data directory may do.
pub fn runs_locally(profile: &Profile) -> bool {
    profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Socks
}

pub fn run(ctx: &Ctx, command: RouteCommand) -> Result<(), String> {
    match command {
        RouteCommand::Lookup { address } => {
            let result = ctx.app("lookup", json!({"destination": address}))?;
            ctx.emit(result.clone(), || {
                format!(
                    "{} -> {} (route {}/{}{})",
                    result["destination"].as_str().unwrap_or(&address),
                    result["interfaceName"].as_str().unwrap_or("?"),
                    result["matchedRoute"]["destination"]
                        .as_str()
                        .unwrap_or("?"),
                    result["matchedRoute"]["prefixLen"],
                    result["matchedRoute"]["gateway"]
                        .as_str()
                        .map(|gateway| format!(" via {gateway}"))
                        .unwrap_or_default()
                )
            });
            Ok(())
        }
        RouteCommand::Show { profile } => {
            let profile = ctx.find(&profile)?;
            let options = ctx.app("routing_options", json!({"id": profile.id}))?;
            ctx.emit(options.clone(), || {
                let mut out = String::new();
                for key in ["block", "proxy", "direct"] {
                    let rules = options[key].as_str().unwrap_or_default();
                    out.push_str(&format!(
                        "{key}: {}\n",
                        if rules.is_empty() {
                            "-".to_string()
                        } else {
                            rules.replace('\n', ", ")
                        }
                    ));
                }
                out.push_str(&format!(
                    "lan-direct: {}",
                    options["privateLanDirect"].as_bool().unwrap_or(false)
                ));
                out
            });
            Ok(())
        }
        RouteCommand::Set {
            profile,
            block,
            proxy,
            direct,
            lan_direct,
        } => {
            ctx.require_user()?;
            let profile = ctx.find(&profile)?;
            let _guard = if runs_locally(&profile) {
                Some(lock::acquire(&ctx.root)?)
            } else {
                None
            };
            ctx.app(
                "set_routing_rules",
                json!({
                    "id": profile.id,
                    "block": block.join("\n"),
                    "proxy": proxy.join("\n"),
                    "direct": direct.join("\n"),
                    "privateLanDirect": if lan_direct { "true" } else { "false" },
                }),
            )?;
            ctx.emit(crate::ctx::ok_json(), || {
                format!("Rules of \"{}\" saved", profile.name)
            });
            Ok(())
        }
        RouteCommand::Check { target, profile } => {
            let profile = ctx.find(&profile)?;
            let mut args = ctx.app("routing_options", json!({"id": profile.id}))?;
            args["target"] = json!(target);
            args["privateLanDirect"] = json!(args["privateLanDirect"]
                .as_bool()
                .unwrap_or(false)
                .to_string());
            let result = ctx.app("check_route", args)?;
            ctx.emit(result.clone(), || describe_check(&result));
            Ok(())
        }
    }
}

fn describe_check(result: &Value) -> String {
    let mut out = format!(
        "{} -> {} ({}{})",
        result["target"].as_str().unwrap_or_default(),
        result["outbound"].as_str().unwrap_or("?"),
        result["source"].as_str().unwrap_or("?"),
        result["matchedSelector"]
            .as_str()
            .map(|selector| format!(": {selector}"))
            .unwrap_or_default()
    );
    if result["certainty"] == "probable" {
        out.push_str("\n  probable: some selectors could not be evaluated locally");
    }
    for note in result["notes"].as_array().into_iter().flatten() {
        out.push_str(&format!("\n  note: {}", note.as_str().unwrap_or_default()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verdict_names_the_outbound_and_the_deciding_rule() {
        let text = describe_check(&json!({
            "target": "example.com", "outbound": "direct", "source": "policy",
            "matchedSelector": "domain:example.com", "certainty": "certain", "notes": []
        }));
        assert_eq!(text, "example.com -> direct (policy: domain:example.com)");
        let text = describe_check(&json!({
            "target": "a.b", "outbound": "proxy", "source": "default",
            "certainty": "probable", "notes": ["geo assets missing"]
        }));
        assert!(text.contains("probable"));
        assert!(text.contains("note: geo assets missing"));
    }

    #[test]
    fn only_loopback_xray_counts_as_local() {
        let mut profile = Profile {
            backend: TunnelBackend::Xray,
            xray_mode: XrayMode::Socks,
            ..Default::default()
        };
        assert!(runs_locally(&profile));
        profile.xray_mode = XrayMode::Tun;
        assert!(!runs_locally(&profile));
        profile.backend = TunnelBackend::WireGuard;
        assert!(!runs_locally(&profile));
    }
}
