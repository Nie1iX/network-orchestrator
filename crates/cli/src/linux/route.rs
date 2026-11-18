//! Ordered routing rules of Xray profiles.
use super::args::{RouteCommand, RuleArgs};
use super::commands::Output;
use super::ctx::Ctx;
use super::endpoints;
use super::library::require_user;
use net_manager_core::models::{DomainPolicy, DomainRouteTarget};
use net_manager_core::models::{
    Profile, RoutingLayer, RoutingPolicy, RoutingRule, RoutingTarget, TunnelBackend, TunnelState,
};
use net_manager_core::route_check::{check_route, GeoDbs};
#[cfg(not(target_os = "linux"))]
use net_manager_core::route_check::{GeoIpDb, GeoSiteDb};
use net_manager_core::xray::{self, ProfileRoutingOptions};
use net_manager_engine::linux_engine::LinuxEngine;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::Path;

/// Where the daemon's package keeps the pinned Xray and its geo lists.
const XRAY_DIR: &str = "/usr/lib/network-orchestrator/xray";
/// The core's `LINUX_XRAY_VERSION`, which only exists in Linux builds.
const XRAY_VERSION: &str = "v26.10.31";
#[cfg(not(target_os = "linux"))]
const MAX_GEO_ASSET_BYTES: u64 = 64 * 1024 * 1024;

const LISTS: [(&str, DomainRouteTarget); 3] = [
    ("block", DomainRouteTarget::Block),
    ("proxy", DomainRouteTarget::Proxy),
    ("direct", DomainRouteTarget::Direct),
];

pub fn run(ctx: &Ctx, command: RouteCommand) -> Result<Output, String> {
    match command {
        RouteCommand::Show { profile } => show(ctx, profile.as_deref()),
        RouteCommand::Set {
            profile,
            rules,
            lan_direct,
        } => set(ctx, &profile, &rules, lan_direct),
        RouteCommand::Add { profile, rules } => edit(ctx, &profile, &rules, Edit::Add),
        RouteCommand::Rm { profile, rules } => edit(ctx, &profile, &rules, Edit::Remove),
        RouteCommand::Check {
            target,
            profile,
            live,
            port,
            udp,
            protocol,
        } => {
            if live {
                live_check(
                    ctx,
                    &target,
                    &profile,
                    port.unwrap_or(443),
                    udp,
                    protocol.as_deref(),
                )
            } else {
                check(
                    ctx,
                    &target,
                    &profile,
                    &Path::new(XRAY_DIR).join(XRAY_VERSION),
                )
            }
        }
        RouteCommand::Pin {
            profile,
            via,
            selector,
        } => pin(ctx, &profile, &via, &selector),
        RouteCommand::Unpin {
            profile,
            via,
            selector,
        } => unpin(ctx, &profile, &via, &selector),
        RouteCommand::Move {
            profile,
            layer,
            from,
            to,
        } => move_rule(ctx, &profile, layer.into(), from, to),
        RouteCommand::Layer {
            profile,
            index,
            from,
            to,
        } => change_layer(ctx, &profile, index, from.into(), to.into()),
        RouteCommand::Quic { profile, enabled } => quic(ctx, &profile, enabled),
    }
}

fn xray_profile(ctx: &Ctx, query: &str) -> Result<Profile, String> {
    let profile = ctx.find(query)?;
    if profile.backend != TunnelBackend::Xray {
        return Err("Routing rules are available for Xray profiles".into());
    }
    Ok(profile)
}

fn target_of(target: DomainRouteTarget) -> RoutingTarget {
    match target {
        DomainRouteTarget::Block => RoutingTarget::Block,
        DomainRouteTarget::Proxy => RoutingTarget::Proxy,
        DomainRouteTarget::Direct => RoutingTarget::Direct,
    }
}

#[cfg(test)]
fn selectors_of(policies: &[RoutingRule], target: DomainRouteTarget) -> Vec<String> {
    policies
        .iter()
        .filter(|row| row.target == target_of(target))
        .flat_map(|row| row.selectors.iter().cloned())
        .collect()
}

fn rules_json(profile: &Profile) -> Value {
    json!({
        "id": profile.id,
        "name": profile.name,
        "routing": profile.routing,
        "privateLanDirect": profile.private_lan_direct,
        "quicReject": profile.xray_quic_reject
    })
}

fn rules_text(rules: &Value) -> String {
    let mut out = format!(
        "{} ({})",
        rules["name"].as_str().unwrap_or_default(),
        rules["id"].as_str().unwrap_or_default()
    );
    for layer in ["user", "base"] {
        out.push_str(&format!("\n  {layer}:"));
        for (index, row) in rules["routing"][layer]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            out.push_str(&format!(
                "\n    {}. {} -> {}",
                index + 1,
                row["selectors"],
                row["target"]
            ));
        }
    }
    out.push_str(&format!(
        "\n  lan-direct  {}\n  quic-reject {}",
        rules["privateLanDirect"].as_bool().unwrap_or(false),
        rules["quicReject"].as_bool().unwrap_or(false)
    ));
    out
}

fn show(ctx: &Ctx, profile: Option<&str>) -> Result<Output, String> {
    let profiles = match profile {
        Some(query) => vec![xray_profile(ctx, query)?],
        None => ctx
            .profiles()?
            .into_iter()
            .filter(|profile| profile.backend == TunnelBackend::Xray)
            .collect(),
    };
    if profiles.is_empty() {
        return Ok((json!([]), "No Xray profiles".into()));
    }
    let rules: Vec<Value> = profiles.iter().map(rules_json).collect();
    let text = rules
        .iter()
        .map(rules_text)
        .collect::<Vec<_>>()
        .join("\n\n");
    Ok((Value::Array(rules), text))
}

/// One selector as the daemon and the app accept it; comments and blanks are
/// editor annotations that make no sense on a command line.
fn valid_selector(selector: &str) -> Result<String, String> {
    let selector = selector.trim();
    let invalid = || format!("Invalid routing selector ({selector})");
    if selector.is_empty() || selector.starts_with('#') {
        return Err(invalid());
    }
    xray::validate_routing_policy_selectors(&[DomainPolicy {
        domains: vec![selector.to_string()],
        target: DomainRouteTarget::Direct,
    }])
    .map_err(|_| invalid())?;
    Ok(selector.to_string())
}

fn is_address(selector: &str) -> bool {
    let (address, prefix) = selector.split_once('/').unwrap_or((selector, ""));
    address.parse::<IpAddr>().is_ok() && (prefix.is_empty() || prefix.parse::<u8>().is_ok())
}

/// A bare name is a substring match in Xray, so `ru` also catches `trulia.com`.
fn hints(selectors: &[String]) -> Vec<String> {
    selectors
        .iter()
        .filter(|selector| !selector.contains(':') && !is_address(selector))
        .map(|selector| {
            format!(
                "\"{selector}\" matches any name that contains it; write domain:{selector} \
                 to match only that domain and its subdomains"
            )
        })
        .collect()
}

/// The selectors of one list given on the command line, checked and unique.
struct Wanted {
    target: DomainRouteTarget,
    name: &'static str,
    selectors: Vec<String>,
}

fn wanted(rules: &RuleArgs) -> Result<Vec<Wanted>, String> {
    let mut lists = Vec::new();
    for (name, target) in LISTS {
        let given = match target {
            DomainRouteTarget::Block => &rules.block,
            DomainRouteTarget::Proxy => &rules.proxy,
            DomainRouteTarget::Direct => &rules.direct,
        };
        let mut checked = Vec::new();
        for selector in given {
            let selector = valid_selector(selector)?;
            if !checked.contains(&selector) {
                checked.push(selector);
            }
        }
        lists.push(Wanted {
            target,
            name,
            selectors: checked,
        });
    }
    Ok(lists)
}

fn save(
    ctx: &Ctx,
    profile: &Profile,
    routing: RoutingPolicy,
    private_lan_direct: bool,
    extra: Vec<String>,
) -> Result<Output, String> {
    let revision = net_manager_core::profiles::profile_edit_revision(profile)
        .map_err(|error| error.to_string())?;
    #[cfg(target_os = "linux")]
    let document = net_manager_engine::linux_profiles::ProfileService::new(
        ctx.root.clone(),
        ctx.engine.clone(),
    )
    .set_routing(&profile.id, routing, private_lan_direct, &revision)?;
    #[cfg(not(target_os = "linux"))]
    let document = {
        let mut candidate = profile.clone();
        candidate.routing = routing;
        candidate.private_lan_direct = private_lan_direct;
        ctx.store()
            .compare_upsert(candidate, Some(&revision))
            .map_err(|error| error.to_string())?
    };
    let saved = document
        .profiles
        .into_iter()
        .find(|stored| stored.id == profile.id)
        .ok_or("Profile not found")?;
    Ok(saved_output(&saved, extra))
}

fn saved_output(profile: &Profile, extra: Vec<String>) -> Output {
    let rules = rules_json(profile);
    let name = &profile.name;
    let mut text = if cfg!(target_os = "linux")
        && profile.xray_mode == net_manager_core::models::XrayMode::Tun
    {
        format!(
            "Rules of {name:?} saved. They apply on connect. For a running tunnel, \
             use `netorch reload {name:?}` or reconnect if network settings changed."
        )
    } else {
        format!(
            "Rules of {name:?} saved. They apply on connect. If it is already up, \
             use `netorch down {name:?}` then `netorch up {name:?}`."
        )
    };
    for hint in extra {
        text.push_str(&format!("\n  note: {hint}"));
    }
    (rules, text)
}

/// Replace only the user layer.
fn set(ctx: &Ctx, query: &str, rules: &RuleArgs, lan_direct: bool) -> Result<Output, String> {
    require_user(ctx)?;
    let profile = xray_profile(ctx, query)?;
    let mut routing = profile.routing.clone();
    routing.user.clear();
    let mut notes = Vec::new();
    for Wanted {
        target, selectors, ..
    } in wanted(rules)?
    {
        notes.extend(hints(&selectors));
        if !selectors.is_empty() {
            routing.user.push(RoutingRule {
                selectors,
                target: target_of(target),
                ..Default::default()
            });
        }
    }
    save(ctx, &profile, routing, lan_direct, notes)
}

#[derive(Clone, Copy, PartialEq)]
enum Edit {
    Add,
    Remove,
}

/// Adds or removes selectors in the user layer without regrouping existing rows.
fn edit(ctx: &Ctx, query: &str, rules: &RuleArgs, how: Edit) -> Result<Output, String> {
    require_user(ctx)?;
    let profile = xray_profile(ctx, query)?;
    let lists = wanted(rules)?;
    if lists.iter().all(|list| list.selectors.is_empty()) {
        return Err("Name at least one selector with --block, --proxy or --direct".into());
    }
    let mut routing = profile.routing.clone();
    let mut notes = Vec::new();
    for Wanted {
        target,
        name,
        selectors,
    } in lists
    {
        let target = target_of(target);
        for selector in selectors {
            match how {
                Edit::Add => {
                    if routing.user.iter().any(|row| {
                        row.target == target
                            && row.port.is_none()
                            && row.network.is_none()
                            && row.selectors.contains(&selector)
                    }) {
                        continue;
                    }
                    notes.extend(hints(std::slice::from_ref(&selector)));
                    routing.user.push(RoutingRule {
                        selectors: vec![selector],
                        target: target.clone(),
                        ..Default::default()
                    });
                }
                Edit::Remove => {
                    let mut found = false;
                    for row in routing.user.iter_mut().filter(|row| row.target == target) {
                        let before = row.selectors.len();
                        row.selectors.retain(|s| s != &selector);
                        found |= before != row.selectors.len();
                    }
                    if !found {
                        return Err(format!("{selector} is not in the {name} list"));
                    }
                    routing.user.retain(|row| !row.selectors.is_empty());
                }
            }
        }
    }
    save(ctx, &profile, routing, profile.private_lan_direct, notes)
}

fn row_index(index: usize, len: usize) -> Result<usize, String> {
    if index == 0 || index > len {
        Err("Row index is out of range".into())
    } else {
        Ok(index - 1)
    }
}

fn move_rule(
    ctx: &Ctx,
    query: &str,
    layer: RoutingLayer,
    from: usize,
    to: usize,
) -> Result<Output, String> {
    require_user(ctx)?;
    let profile = xray_profile(ctx, query)?;
    let mut routing = profile.routing.clone();
    let rows = routing.layer_mut(layer);
    let from = row_index(from, rows.len())?;
    let to = row_index(to, rows.len())?;
    let row = rows.remove(from);
    rows.insert(to, row);
    save(
        ctx,
        &profile,
        routing,
        profile.private_lan_direct,
        Vec::new(),
    )
}

fn change_layer(
    ctx: &Ctx,
    query: &str,
    index: usize,
    from: RoutingLayer,
    to: RoutingLayer,
) -> Result<Output, String> {
    require_user(ctx)?;
    if from == to {
        return Err("Choose different layers".into());
    }
    let profile = xray_profile(ctx, query)?;
    let mut routing = profile.routing.clone();
    let rows = routing.layer_mut(from);
    let index = row_index(index, rows.len())?;
    let row = rows.remove(index);
    routing.layer_mut(to).push(row);
    save(
        ctx,
        &profile,
        routing,
        profile.private_lan_direct,
        Vec::new(),
    )
}

/// The node a pin targets: a server of the subscription (number, name part)
/// or a raw key — a node that left the list may still be pinned so its
/// selectors wake up when it comes back.
fn pin_key(ctx: &Ctx, profile: &Profile, via: &str) -> Result<(String, String), String> {
    if profile.subscription.is_none() {
        return Err("Pinned rules need a subscription profile".into());
    }
    let rows = endpoints::list_rows(ctx, profile)?;
    let key = endpoints::backup_key(&rows, via)?;
    let name = rows
        .iter()
        .find(|row| row.key == key)
        .map(|row| row.name.clone())
        .unwrap_or_else(|| key.clone());
    Ok((key, name))
}

/// Whether the tunnel is up: changes are stored either way, the notice tells
/// the user a reconnect puts them into effect. A daemon error counts as
/// "unknown" → treat as running so the notice is always safe.
fn running(ctx: &Ctx, profile: &Profile) -> bool {
    !LinuxEngine::handles(profile)
        || ctx
            .engine
            .status(profile)
            .map(|status| status.state != TunnelState::Stopped)
            .unwrap_or(true)
}

/// The notice that a stored change reaches the tunnel only on reconnect.
fn apply_note(running: bool) -> &'static str {
    if running {
        "\nSaved; reconnect to apply (`netorch down` then `netorch up`)."
    } else {
        ""
    }
}

/// Pins selectors to one node: while that node is down or gone from the
/// subscription the selectors are blocked — never sent direct or through
/// another server.
fn pin(ctx: &Ctx, query: &str, via: &str, selectors: &[String]) -> Result<Output, String> {
    require_user(ctx)?;
    let profile = xray_profile(ctx, query)?;
    let (key, name) = pin_key(ctx, &profile, via)?;
    let mut checked = Vec::new();
    for selector in selectors {
        let selector = valid_selector(selector)?;
        if !checked.contains(&selector) {
            checked.push(selector);
        }
    }
    let mut routing = profile.routing.clone();
    for selector in &checked {
        if !routing.user.iter().any(|row| {
            row.target.endpoint_key() == Some(key.as_str()) && row.selectors.contains(selector)
        }) {
            routing.user.push(RoutingRule {
                selectors: vec![selector.clone()],
                target: RoutingTarget::Node {
                    endpoint_key: key.clone(),
                    missing: false,
                },
                ..Default::default()
            });
        }
    }
    let running = running(ctx, &profile);
    save(
        ctx,
        &profile,
        routing,
        profile.private_lan_direct,
        Vec::new(),
    )?;
    Ok((
        json!({"id": profile.id, "server": name, "selectors": checked,
            "requiresReconnect": running}),
        format!(
            "{} now go through {} of \"{}\", nowhere else{}",
            checked.join(", "),
            name,
            profile.name,
            apply_note(running)
        ),
    ))
}

/// Removes pinned selectors — or the whole pinned route when none are named.
fn unpin(ctx: &Ctx, query: &str, via: &str, selectors: &[String]) -> Result<Output, String> {
    require_user(ctx)?;
    let profile = xray_profile(ctx, query)?;
    let (key, name) = pin_key(ctx, &profile, via)?;
    let mut routing = profile.routing.clone();
    if !routing
        .user
        .iter()
        .any(|row| row.target.endpoint_key() == Some(key.as_str()))
    {
        return Err(format!("Nothing is pinned to {name}"));
    }
    for selector in selectors {
        if !routing.user.iter().any(|row| {
            row.target.endpoint_key() == Some(key.as_str())
                && row.selectors.iter().any(|s| s == selector.trim())
        }) {
            return Err(format!("{selector} is not pinned to {name}"));
        }
    }
    for row in routing
        .user
        .iter_mut()
        .filter(|row| row.target.endpoint_key() == Some(key.as_str()))
    {
        if selectors.is_empty() {
            row.selectors.clear();
        } else {
            row.selectors
                .retain(|s| !selectors.iter().any(|selected| selected.trim() == s));
        }
    }
    routing.user.retain(|row| !row.selectors.is_empty());
    let running = running(ctx, &profile);
    save(
        ctx,
        &profile,
        routing,
        profile.private_lan_direct,
        Vec::new(),
    )?;
    Ok((
        json!({"id": profile.id, "server": name, "requiresReconnect": running}),
        format!(
            "Unpinned {} of \"{}\"{}",
            name,
            profile.name,
            apply_note(running)
        ),
    ))
}

/// `route quic`: the daemon's kernel-level QUIC handling for the tunnel.
/// `on` answers outbound UDP/443 with a rejection so browsers fall back to
/// TCP at once; `off` removes this rule without changing other routing policy.
/// A profile setting, applied at connect — a running tunnel is unaffected
/// until it reconnects.
fn quic(ctx: &Ctx, query: &str, enabled: Option<super::args::BoolOnOff>) -> Result<Output, String> {
    let profile = xray_profile(ctx, query)?;
    let Some(enabled) = enabled else {
        return Ok((
            json!({"id": profile.id, "quicReject": profile.xray_quic_reject}),
            format!(
                "QUIC reject is {} for \"{}\"",
                if profile.xray_quic_reject {
                    "on"
                } else {
                    "off"
                },
                profile.name
            ),
        ));
    };
    require_user(ctx)?;
    let on = matches!(enabled, super::args::BoolOnOff::On);
    let running = running(ctx, &profile);
    #[cfg(target_os = "linux")]
    net_manager_engine::linux_profiles::ProfileService::new(ctx.root.clone(), ctx.engine.clone())
        .set_quic(&profile.id, on)?;
    #[cfg(not(target_os = "linux"))]
    ctx.store()
        .update_profile(&profile.id, |current| {
            if current.backend != TunnelBackend::Xray {
                return Err(std::io::Error::other(
                    "Profile is no longer an Xray profile",
                ));
            }
            current.xray_quic_reject = on;
            Ok(())
        })
        .map_err(|_| "The QUIC rejection setting could not be saved".to_string())?;
    Ok((
        json!({"id": profile.id, "quicReject": on, "requiresReconnect": running}),
        format!(
            "QUIC reject is {} for \"{}\"{}",
            if on { "on" } else { "off" },
            profile.name,
            apply_note(running)
        ),
    ))
}

#[cfg(not(target_os = "linux"))]
fn load_asset<T>(dir: &Path, name: &str, parse: fn(&[u8]) -> std::io::Result<T>) -> Option<T> {
    let path = dir.join(name);
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_GEO_ASSET_BYTES {
        return None;
    }
    parse(&std::fs::read(path).ok()?).ok()
}

/// Which rule of the profile decides a host or address, replayed offline.
fn check(ctx: &Ctx, target: &str, query: &str, geo_dir: &Path) -> Result<Output, String> {
    let profile = xray_profile(ctx, query)?;
    #[cfg(target_os = "linux")]
    let (geo_site, geo_ip) = {
        let mut dirs = net_manager_engine::linux_network::geo_asset_dirs(
            &ctx.root,
            profile.xray_geoip_url.as_deref(),
            profile.xray_geosite_url.as_deref(),
        );
        // The CLI's selected stock directory replaces the managed-package default.
        dirs.pop();
        dirs.push(geo_dir.to_path_buf());
        net_manager_engine::linux_network::load_geo_assets(&dirs)
    };
    #[cfg(not(target_os = "linux"))]
    let (geo_site, geo_ip) = (
        load_asset(geo_dir, "geosite.dat", GeoSiteDb::parse),
        load_asset(geo_dir, "geoip.dat", GeoIpDb::parse),
    );
    let geo = GeoDbs {
        geo_site: geo_site.as_ref(),
        geo_ip: geo_ip.as_ref(),
    };
    let options = ProfileRoutingOptions::from(&profile);
    let result =
        check_route(&profile.routing, &options, target, &geo).map_err(|error| error.to_string())?;
    let value = serde_json::to_value(&result).map_err(|_| "The route check failed".to_string())?;
    let text = describe_check(&value);
    Ok((value, text))
}

/// Ask the peer-UID-bound daemon to test the currently applied Xray route.
fn live_check(
    ctx: &Ctx,
    target: &str,
    query: &str,
    port: u16,
    udp: bool,
    protocol: Option<&str>,
) -> Result<Output, String> {
    let profile = xray_profile(ctx, query)?;
    if profile.xray_mode != net_manager_core::models::XrayMode::Tun {
        return Err("Live route checks require an Xray TUN profile".into());
    }
    let result =
        ctx.engine
            .xray_test_route(&profile.id, target, port, udp, protocol.map(str::to_owned))?;
    let value = serde_json::to_value(&result).map_err(|_| "The live route check failed")?;
    let transport = if udp { "UDP" } else { "TCP" };
    let text = format!(
        "Xray live test: {target} port {port} {transport} -> {}{}",
        result.outbound_tag,
        if result.matched { "" } else { " (default)" }
    );
    Ok((value, text))
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
    use net_manager_core::models::XrayMode;
    use net_manager_engine::linux_engine::LinuxEngine;

    fn policy(target: DomainRouteTarget, domains: &[&str]) -> DomainPolicy {
        DomainPolicy {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            target,
        }
    }

    fn setup(policies: Vec<DomainPolicy>) -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = Ctx::new(dir.path().to_path_buf(), LinuxEngine::new("test")).unwrap();
        ctx.root_user = false;
        ctx.store()
            .upsert(Profile {
                id: "x1".into(),
                name: "Work".into(),
                backend: TunnelBackend::Xray,
                xray_mode: XrayMode::Tun,
                xray_socks_port: Some(10808),
                xray_http_port: Some(10809),
                config_path: "x1.json".into(),
                routing: RoutingPolicy {
                    user: policies.into_iter().map(Into::into).collect(),
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        ctx.store()
            .upsert(Profile {
                id: "static1".into(),
                name: "Static".into(),
                backend: TunnelBackend::None,
                ..Default::default()
            })
            .unwrap();
        (dir, ctx)
    }

    fn rules(block: &[&str], proxy: &[&str], direct: &[&str]) -> RuleArgs {
        let own = |list: &[&str]| list.iter().map(|s| s.to_string()).collect();
        RuleArgs {
            block: own(block),
            proxy: own(proxy),
            direct: own(direct),
        }
    }

    fn direct_of(ctx: &Ctx) -> Vec<String> {
        selectors_of(
            &ctx.find("x1").unwrap().routing.user,
            DomainRouteTarget::Direct,
        )
    }

    #[test]
    fn stale_routing_edit_is_rejected() {
        let (_dir, ctx) = setup(Vec::new());
        let snapshot = ctx.find("x1").unwrap();
        edit(
            &ctx,
            "x1",
            &rules(&[], &[], &["domain:new.test"]),
            Edit::Add,
        )
        .unwrap();
        assert!(save(&ctx, &snapshot, snapshot.routing.clone(), false, vec![]).is_err());
        assert_eq!(direct_of(&ctx), vec!["domain:new.test"]);
    }

    #[test]
    fn show_lists_every_xray_profile_and_skips_the_rest() {
        let (_dir, ctx) = setup(vec![policy(
            DomainRouteTarget::Direct,
            &["domain:a.test", "10.0.0.0/8"],
        )]);
        let (value, text) = show(&ctx, None).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 1);
        assert_eq!(
            value[0]["routing"]["user"][0]["selectors"],
            json!(["domain:a.test", "10.0.0.0/8"])
        );
        assert!(text.contains("direct") && text.contains("domain:a.test"));
        assert!(text.contains("base:"));
        assert!(show(&ctx, Some("static1")).is_err());
    }

    #[test]
    fn set_replaces_all_lists_and_the_lan_flag() {
        let (_dir, ctx) = setup(vec![policy(
            DomainRouteTarget::Direct,
            &["domain:old.test"],
        )]);
        let (value, _) = set(
            &ctx,
            "x1",
            &rules(&["geosite:category-ads"], &["domain:p.test"], &[]),
            true,
        )
        .unwrap();
        assert_eq!(
            value["routing"]["user"][0]["selectors"],
            json!(["geosite:category-ads"])
        );
        assert_eq!(value["routing"]["user"].as_array().unwrap().len(), 2);
        assert_eq!(value["privateLanDirect"], true);
        let saved = ctx.find("x1").unwrap();
        assert_eq!(saved.routing.user.len(), 2);
        assert!(saved.private_lan_direct);
    }

    #[test]
    fn invalid_selectors_are_refused_and_nothing_is_saved() {
        let (_dir, ctx) = setup(vec![policy(
            DomainRouteTarget::Direct,
            &["domain:keep.test"],
        )]);
        for bad in ["", "# note", "geosite:", "geoip:no way"] {
            let error = set(&ctx, "x1", &rules(&[], &[], &[bad]), false).unwrap_err();
            assert!(error.contains("Invalid routing selector"), "{bad}: {error}");
        }
        assert_eq!(direct_of(&ctx), vec!["domain:keep.test".to_string()]);
    }

    #[test]
    fn add_appends_without_reordering_and_allows_explicit_conflicts() {
        let (_dir, ctx) = setup(vec![
            policy(DomainRouteTarget::Direct, &["domain:a.test"]),
            policy(DomainRouteTarget::Proxy, &["domain:p.test"]),
        ]);
        add_direct(&ctx, &["domain:a.test", "178.72.138.220", "178.72.138.220"]);
        assert_eq!(
            direct_of(&ctx),
            vec!["domain:a.test".to_string(), "178.72.138.220".into()]
        );
        let saved = ctx.find("x1").unwrap();
        assert_eq!(saved.routing.user[1].target, RoutingTarget::Proxy);
        edit(&ctx, "x1", &rules(&[], &[], &["domain:p.test"]), Edit::Add).unwrap();
        assert_eq!(
            ctx.find("x1").unwrap().routing.user.last().unwrap().target,
            RoutingTarget::Direct
        );
    }

    fn add_direct(ctx: &Ctx, selectors: &[&str]) {
        edit(ctx, "x1", &rules(&[], &[], selectors), Edit::Add).unwrap();
    }

    #[test]
    fn rm_removes_selectors_drops_empty_rules_and_names_a_missing_one() {
        let (_dir, ctx) = setup(vec![policy(
            DomainRouteTarget::Direct,
            &["domain:a.test", "domain:b.test"],
        )]);
        edit(
            &ctx,
            "x1",
            &rules(&[], &[], &["domain:a.test"]),
            Edit::Remove,
        )
        .unwrap();
        assert_eq!(direct_of(&ctx), vec!["domain:b.test".to_string()]);
        edit(
            &ctx,
            "x1",
            &rules(&[], &[], &["domain:b.test"]),
            Edit::Remove,
        )
        .unwrap();
        assert!(ctx.find("x1").unwrap().routing.user.is_empty());
        let error = edit(
            &ctx,
            "x1",
            &rules(&[], &[], &["domain:b.test"]),
            Edit::Remove,
        )
        .unwrap_err();
        assert!(error.contains("not in the direct list"), "{error}");
        let error = edit(&ctx, "x1", &rules(&[], &[], &[]), Edit::Add).unwrap_err();
        assert!(error.contains("at least one selector"));
    }

    #[test]
    fn writes_need_a_user_and_an_xray_profile() {
        let (_dir, mut ctx) = setup(vec![]);
        assert!(edit(
            &ctx,
            "static1",
            &rules(&[], &[], &["domain:a.test"]),
            Edit::Add
        )
        .is_err());
        ctx.root_user = true;
        let error = set(&ctx, "x1", &rules(&[], &[], &["domain:a.test"]), false).unwrap_err();
        assert!(error.contains("without sudo"), "{error}");
        assert!(direct_of(&ctx).is_empty());
    }

    #[test]
    fn a_bare_name_gets_a_hint_but_prefixed_selectors_and_addresses_do_not() {
        let (_dir, ctx) = setup(vec![]);
        let (_, text) = set(
            &ctx,
            "x1",
            &rules(&[], &[], &["ru", "domain:a.test", "10.0.0.0/8", "::1"]),
            false,
        )
        .unwrap();
        assert!(
            text.contains("\"ru\" matches any name that contains it"),
            "{text}"
        );
        assert_eq!(text.matches("note:").count(), 1);
    }

    #[test]
    fn check_respects_explicit_exception_without_replaying_pins() {
        let (_dir, ctx) = setup(vec![policy(
            DomainRouteTarget::Direct,
            &["domain:github.com"],
        )]);
        let mut profile = ctx.find("x1").unwrap();
        profile.routing.user.push(RoutingRule {
            selectors: vec!["domain:com".into()],
            target: RoutingTarget::Node {
                endpoint_key: "aabb001122334455".into(),
                missing: true,
            },
            ..Default::default()
        });
        ctx.store().upsert(profile).unwrap();
        let nowhere = Path::new("/nonexistent/geo");
        let (github, _) = check(&ctx, "api.github.com", "x1", nowhere).unwrap();
        assert_eq!(github["outbound"], "direct");
        assert_eq!(github["layer"], "user");
        assert!(github.get("endpointKey").is_none());
        let (other, _) = check(&ctx, "other.com", "x1", nowhere).unwrap();
        assert_eq!(other["outbound"], "block");
        assert_eq!(other["endpointKey"], "aabb001122334455");
        assert_eq!(other["layer"], "user");
        assert_eq!(other["ruleIndex"], 1);
        assert_eq!(other["policyPath"], "/profile/routing/user/1");
    }

    #[test]
    fn check_names_the_rule_that_decides_a_host() {
        let (_dir, ctx) = setup(vec![policy(
            DomainRouteTarget::Direct,
            &["domain:ds-mind-lab.ru", "178.72.138.220"],
        )]);
        let nowhere = Path::new("/nonexistent/geo");
        let (value, text) = check(&ctx, "git.ds-mind-lab.ru", "x1", nowhere).unwrap();
        assert_eq!(value["outbound"], "direct");
        assert!(text.contains("domain:ds-mind-lab.ru"), "{text}");
        let (value, _) = check(&ctx, "178.72.138.220", "x1", nowhere).unwrap();
        assert_eq!(value["outbound"], "direct");
        let (value, _) = check(&ctx, "example.com", "x1", nowhere).unwrap();
        assert_eq!(value["outbound"], "unknown");
        assert_eq!(value["layer"], "user");
        assert_eq!(value["ruleIndex"], 0);
        assert_eq!(value["policyPath"], "/profile/routing/user/0");
    }
}
