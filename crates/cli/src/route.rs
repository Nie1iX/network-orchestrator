//! Typed routing configuration, imports and native lookups.
use crate::{args::RouteCommand, ctx::Ctx, input};
use net_manager_core::models::{
    DomainRouteTarget, RoutingLayer, RoutingPolicy, RoutingRule, RoutingTarget, TunnelBackend,
    XrayMode,
};
use net_manager_engine::macos_services::ProfileRoutingUpdate;
use serde_json::{json, Value};
pub fn runs_locally(profile: &net_manager_core::models::Profile) -> bool {
    profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Socks
}
fn target(target: DomainRouteTarget) -> RoutingTarget {
    match target {
        DomainRouteTarget::Block => RoutingTarget::Block,
        DomainRouteTarget::Proxy => RoutingTarget::Proxy,
        DomainRouteTarget::Direct => RoutingTarget::Direct,
    }
}
fn save(
    ctx: &Ctx,
    profile: &net_manager_core::models::Profile,
    mut current: net_manager_engine::macos_services::ProfileRouting,
    routing: RoutingPolicy,
    advanced: Option<Value>,
    geo: Option<Value>,
) -> Result<(), String> {
    current.routing = routing;
    let services = ctx.services()?;
    let revision = net_manager_core::profiles::profile_edit_revision(profile)
        .map_err(|_| "Could not compute profile revision")?;
    services.set_profile_routing(
        &profile.id,
        &revision,
        ProfileRoutingUpdate {
            routing: current.routing,
            private_lan_direct: current.private_lan_direct,
            advanced: advanced
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| "Invalid advanced routing")?,
            geo_urls: geo
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| "Invalid geo URLs")?,
        },
    )?;
    Ok(())
}
fn row_index(index: usize, len: usize) -> Result<usize, String> {
    if index == 0 || index > len {
        Err("Row index is out of range".into())
    } else {
        Ok(index - 1)
    }
}
pub fn run(ctx: &Ctx, command: RouteCommand) -> Result<(), String> {
    let services = ctx.services()?;
    match command {
        RouteCommand::Lookup { address } => ctx.output(
            &ctx.network().lookup_route(
                address
                    .parse()
                    .map_err(|_| "Enter an IPv4 or IPv6 address")?,
            )?,
        ),
        RouteCommand::Show { profile } => {
            let p = ctx.find(&profile)?;
            ctx.output(&services.profile_routing(&p.id)?)
        }
        RouteCommand::Set {
            profile,
            block,
            proxy,
            direct,
            lan_direct,
            layer,
            advanced,
            geo,
        } => {
            ctx.require_user()?;
            let p = ctx.find(&profile)?;
            let p = services.profile(&p.id)?;
            let mut current = net_manager_engine::macos_services::ProfileRouting::from(&p);
            let layer: RoutingLayer = layer.into();
            let rows = current.routing.layer_mut(layer);
            rows.clear();
            for (selectors, choice) in [
                (block, DomainRouteTarget::Block),
                (proxy, DomainRouteTarget::Proxy),
                (direct, DomainRouteTarget::Direct),
            ] {
                if !selectors.is_empty() {
                    rows.push(RoutingRule {
                        selectors,
                        target: target(choice),
                        ..Default::default()
                    });
                }
            }
            current.private_lan_direct = lan_direct;
            let revision = net_manager_core::profiles::profile_edit_revision(&p)
                .map_err(|_| "Could not compute profile revision")?;
            services.set_profile_routing(
                &p.id,
                &revision,
                ProfileRoutingUpdate {
                    routing: current.routing,
                    private_lan_direct: lan_direct,
                    advanced: advanced
                        .as_deref()
                        .map(|path| input::json(path, false))
                        .transpose()?
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|_| "Invalid advanced routing")?,
                    geo_urls: geo
                        .as_deref()
                        .map(|path| input::json(path, false))
                        .transpose()?
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|_| "Invalid geo URLs")?,
                },
            )?;
            ctx.emit(crate::ctx::ok_json(), || {
                format!("Rules of \"{}\" saved", p.name)
            });
            Ok(())
        }
        RouteCommand::Add {
            profile,
            block,
            proxy,
            direct,
            layer,
        } => edit(ctx, profile, block, proxy, direct, layer.into(), false),
        RouteCommand::Rm {
            profile,
            block,
            proxy,
            direct,
            layer,
        } => edit(ctx, profile, block, proxy, direct, layer.into(), true),
        RouteCommand::Move {
            profile,
            index,
            to,
            layer,
        } => {
            ctx.require_user()?;
            let p = ctx.find(&profile)?;
            let p = services.profile(&p.id)?;
            let mut current = net_manager_engine::macos_services::ProfileRouting::from(&p);
            let rows = current.routing.layer_mut(layer.into());
            let from = row_index(index, rows.len())?;
            let to = row_index(to, rows.len())?;
            let row = rows.remove(from);
            rows.insert(to, row);
            save(
                ctx,
                &p,
                current.clone(),
                current.routing.clone(),
                None,
                None,
            )?;
            ctx.emit(crate::ctx::ok_json(), || {
                format!("Rules of \"{}\" saved", p.name)
            });
            Ok(())
        }
        RouteCommand::Layer {
            profile,
            index,
            from,
            to,
        } => {
            ctx.require_user()?;
            let p = ctx.find(&profile)?;
            let p = services.profile(&p.id)?;
            let mut current = net_manager_engine::macos_services::ProfileRouting::from(&p);
            let from: RoutingLayer = from.into();
            let to: RoutingLayer = to.into();
            if from == to {
                return Err("Choose different layers".into());
            }
            let rows = current.routing.layer_mut(from);
            let index = row_index(index, rows.len())?;
            let row = rows.remove(index);
            current.routing.layer_mut(to).push(row);
            save(
                ctx,
                &p,
                current.clone(),
                current.routing.clone(),
                None,
                None,
            )?;
            ctx.emit(crate::ctx::ok_json(), || {
                format!("Rules of \"{}\" saved", p.name)
            });
            Ok(())
        }
        RouteCommand::Check { target, profile } => {
            let p = ctx.find(&profile)?;
            let result = services.check_routing(&target, &services.profile_routing(&p.id)?)?;
            let value =
                serde_json::to_value(result).map_err(|_| "Could not encode route verdict")?;
            ctx.emit(value.clone(), || describe_check(&value));
            Ok(())
        }
        RouteCommand::Import { profile, file } => {
            ctx.require_user()?;
            let p = ctx.find(&profile)?;
            services.import_happ_routing(&p.id, &input::text(&file, false)?)?;
            ctx.output(&services.profile_routing(&p.id)?)
        }
    }
}
fn edit(
    ctx: &Ctx,
    profile: String,
    block: Vec<String>,
    proxy: Vec<String>,
    direct: Vec<String>,
    layer: RoutingLayer,
    remove: bool,
) -> Result<(), String> {
    ctx.require_user()?;
    let p = ctx.find(&profile)?;
    let p = ctx.services()?.profile(&p.id)?;
    let mut current = net_manager_engine::macos_services::ProfileRouting::from(&p);
    let rows = current.routing.layer_mut(layer);
    let mut changed = false;
    for (selectors, target) in [
        (block, RoutingTarget::Block),
        (proxy, RoutingTarget::Proxy),
        (direct, RoutingTarget::Direct),
    ] {
        for selector in selectors {
            if remove {
                for row in rows.iter_mut().filter(|row| row.target == target) {
                    let before = row.selectors.len();
                    row.selectors.retain(|value| value != &selector);
                    changed |= before != row.selectors.len();
                }
                rows.retain(|row| !row.selectors.is_empty());
            } else if let Some(row) = rows
                .iter_mut()
                .find(|row| row.target == target && row.port.is_none() && row.network.is_none())
            {
                if !row.selectors.contains(&selector) {
                    row.selectors.push(selector);
                    changed = true;
                }
            } else {
                rows.push(RoutingRule {
                    selectors: vec![selector],
                    target: target.clone(),
                    ..Default::default()
                });
                changed = true;
            }
        }
    }
    if !changed {
        return Err("No routing rules changed".into());
    }
    save(
        ctx,
        &p,
        current.clone(),
        current.routing.clone(),
        None,
        None,
    )?;
    ctx.emit(crate::ctx::ok_json(), || {
        format!("Rules of \"{}\" saved", p.name)
    });
    Ok(())
}
fn describe_check(result: &Value) -> String {
    let mut out = format!(
        "{} -> {} ({}{})",
        result["target"].as_str().unwrap_or_default(),
        result["outbound"].as_str().unwrap_or("?"),
        result["source"].as_str().unwrap_or("?"),
        result["matchedSelector"]
            .as_str()
            .map(|s| format!(": {s}"))
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
    fn verdict_names_outbound_and_rule() {
        assert_eq!(
            describe_check(
                &json!({"target":"example.com","outbound":"direct","source":"policy","matchedSelector":"domain:example.com","certainty":"certain","notes":[]})
            ),
            "example.com -> direct (policy: domain:example.com)"
        );
    }
}
