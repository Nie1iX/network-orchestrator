//! Profiles: list, add, remove, rename, status, logs and tests.
use crate::args::{AddArgs, TestArgs};
use crate::ctx::{self, Ctx};
use crate::render::{row_of, table};
use crate::runstate;
use crate::target::{self, Input};
use net_manager_core::models::{Profile, TunnelBackend, TunnelState, XrayMode};
use net_manager_core::vpn::TunnelManager;
use serde_json::{json, Value};

pub const LOG_TAIL_BYTES: usize = 16 * 1024;

pub fn ls(ctx: &Ctx) -> Result<(), String> {
    let rows: Vec<_> = ctx.profiles()?.iter().map(row_of).collect();
    let value = serde_json::to_value(&rows).map_err(|_| "Could not encode the list")?;
    ctx.emit(value, || {
        if rows.is_empty() {
            return "No profiles yet. `netorch add <link|url|file>` saves one.".into();
        }
        table(
            &["ID", "NAME", "KIND", "ROLE"],
            &rows
                .iter()
                .map(|row| {
                    vec![
                        row.id.clone(),
                        row.name.clone(),
                        row.kind.into(),
                        row.role.into(),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    });
    Ok(())
}

/// Saves what `input` points at and returns the new profile.
pub fn add_input(ctx: &Ctx, input: &str, name: Option<&str>) -> Result<Profile, String> {
    ctx.require_user()?;
    let classified = target::classify(input, |path| path.is_file());
    let suffix = ctx::random_suffix()?;
    match classified {
        Input::Saved(_) => Err(
            "That is not a vless:// / hysteria2:// link, an https:// subscription URL \
             or an existing .conf / .ovpn file."
                .into(),
        ),
        Input::ShareLink(link) => {
            let name = name
                .map(str::to_string)
                .or_else(|| target::link_name(&link))
                .unwrap_or_else(|| "Imported".into());
            let id = target::make_id(&name, &suffix);
            ctx.app(
                "import_share_link",
                json!({"id": id, "name": name, "link": link}),
            )?;
            ctx.find(&id)
        }
        Input::Subscription(url) => {
            let name = name.unwrap_or("Subscription");
            let id = target::make_id(name, &suffix);
            let hwid = ctx.app("generate_hwid", json!({}))?;
            let result = ctx.app(
                "import_subscription",
                json!({"id": id, "url": url, "hwid": hwid, "name": name}),
            )?;
            let skipped = result["skippedCount"].as_u64().unwrap_or(0);
            if skipped > 0 {
                ctx.note(&format!("{skipped} entries were skipped (unsupported)."));
            }
            ctx.find(&id)
        }
        Input::File { path, backend } => {
            let name = name.map(str::to_string).unwrap_or_else(|| {
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("Imported")
                    .to_string()
            });
            let id = target::make_id(&name, &suffix);
            ctx.app(
                "import",
                json!({
                    "id": id, "name": name, "backend": backend,
                    "path": path.to_string_lossy(),
                }),
            )?;
            ctx.find(&id)
        }
    }
}

pub fn add(ctx: &Ctx, args: AddArgs) -> Result<(), String> {
    let profile = add_input(ctx, &args.input, args.name.as_deref())?;
    ctx.emit(
        serde_json::to_value(row_of(&profile)).unwrap_or(Value::Null),
        || format!("Saved \"{}\" ({})", profile.name, profile.id),
    );
    Ok(())
}

pub fn is_running_anywhere(ctx: &Ctx, profile: &Profile) -> bool {
    if runstate::read(&ctx.root, &profile.id).is_some() {
        return true;
    }
    // Root has no helper to ask: its own runs are the state files above.
    !ctx::is_root()
        && ctx
            .engine()
            .remote_status(profile)
            .is_some_and(|status| status.state == TunnelState::Running)
}

pub fn rm(ctx: &Ctx, target: &str) -> Result<(), String> {
    ctx.require_user()?;
    let profile = ctx.find(target)?;
    if is_running_anywhere(ctx, &profile) {
        return Err("The connection is running. `netorch down` first.".into());
    }
    ctx.app("delete", json!({"id": profile.id}))?;
    ctx.emit(ctx::ok_json(), || format!("Removed \"{}\"", profile.name));
    Ok(())
}

pub fn rename(ctx: &Ctx, target: &str, name: &str) -> Result<(), String> {
    ctx.require_user()?;
    let profile = ctx.find(target)?;
    ctx.app("rename", json!({"id": profile.id, "name": name}))?;
    ctx.emit(ctx::ok_json(), || format!("Renamed to \"{}\"", name.trim()));
    Ok(())
}

/// One profile's state without starting any session of this process: the
/// privileged side answers for tunnels, the run-state file for local Xray.
pub fn state_of(ctx: &Ctx, profile: &Profile) -> Value {
    let (state, interface, message, pid) = match ctx.engine().remote_status(profile) {
        Some(status) => (status.state, status.interface_name, status.message, None),
        None => match runstate::read(&ctx.root, &profile.id) {
            Some(run) => (TunnelState::Running, None, None, Some(run.pid)),
            None => (TunnelState::Stopped, None, None, None),
        },
    };
    json!({
        "id": profile.id,
        "name": profile.name,
        "kind": crate::render::kind_of(profile),
        "state": state,
        "interface": interface,
        "message": message,
        "pid": pid,
    })
}

pub fn status(ctx: &Ctx, target: Option<&str>) -> Result<(), String> {
    let profiles = match target {
        Some(query) => vec![ctx.find(query)?],
        None => ctx.profiles()?,
    };
    let states: Vec<Value> = profiles.iter().map(|p| state_of(ctx, p)).collect();
    ctx.emit(Value::Array(states.clone()), || {
        if states.is_empty() {
            return "No profiles yet.".into();
        }
        table(
            &["ID", "NAME", "STATE", "DETAIL"],
            &states
                .iter()
                .map(|state| {
                    let detail = state["interface"]
                        .as_str()
                        .map(str::to_string)
                        .or_else(|| state["pid"].as_u64().map(|pid| format!("pid {pid}")))
                        .or_else(|| state["message"].as_str().map(str::to_string))
                        .unwrap_or_default();
                    vec![
                        state["id"].as_str().unwrap_or_default().into(),
                        state["name"].as_str().unwrap_or_default().into(),
                        state["state"].as_str().unwrap_or_default().into(),
                        detail,
                    ]
                })
                .collect::<Vec<_>>(),
        )
    });
    Ok(())
}

pub fn logs(ctx: &Ctx, target: &str) -> Result<(), String> {
    let profile = ctx.find(target)?;
    let text = if ctx.engine().remote_status(&profile).is_some() {
        ctx.engine().log(&profile)?
    } else {
        // Reading a log must not start a session, which would stop the Xray
        // another netorch is running.
        TunnelManager::with_log_dir(ctx.root.join("runtime").join("logs"))
            .log_tail(&profile.id, LOG_TAIL_BYTES)
            .ok()
            .flatten()
            .unwrap_or_default()
    };
    ctx.emit(json!({"log": text}), || text.clone());
    Ok(())
}

pub fn test(ctx: &Ctx, args: TestArgs) -> Result<(), String> {
    match (&args.target, args.ip) {
        (Some(target), false) => delays(ctx, target),
        (target, _) => exit_ip(ctx, target.as_deref()),
    }
}

fn delays(ctx: &Ctx, target: &str) -> Result<(), String> {
    let profile = ctx.find(target)?;
    if profile.subscription.is_none() {
        return Err("Delay checks are available for subscriptions".into());
    }
    let endpoints = ctx.app("subscription_endpoints", json!({"id": profile.id}))?;
    let results = ctx.app("measure_delays", json!({"id": profile.id}))?;
    let rows: Vec<Value> = results
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|result| {
            let index = result["index"].as_u64().unwrap_or(0) as usize;
            json!({
                "index": index,
                "name": endpoints[index]["name"],
                "protocol": endpoints[index]["protocol"],
                "active": endpoints[index]["active"],
                "delayMs": result["delayMs"],
            })
        })
        .collect();
    ctx.emit(Value::Array(rows.clone()), || {
        table(
            &["#", "NAME", "PROTOCOL", "DELAY"],
            &rows
                .iter()
                .map(|row| {
                    let mark = if row["active"] == true { "*" } else { "" };
                    vec![
                        format!("{}{mark}", row["index"]),
                        row["name"].as_str().unwrap_or_default().into(),
                        row["protocol"].as_str().unwrap_or_default().into(),
                        row["delayMs"]
                            .as_u64()
                            .map(|ms| format!("{ms} ms"))
                            .unwrap_or_else(|| "timeout".into()),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    });
    Ok(())
}

fn exit_ip(ctx: &Ctx, target: Option<&str>) -> Result<(), String> {
    let socks = match target {
        None => None,
        Some(query) => {
            let profile = ctx.find(query)?;
            if profile.backend == TunnelBackend::Xray && profile.xray_mode == XrayMode::Socks {
                let run = runstate::read(&ctx.root, &profile.id)
                    .ok_or("Start the connection first (`netorch up`)")?;
                Some(
                    run.socks_port
                        .ok_or("This connection has no local proxy port")?,
                )
            } else {
                if !is_running_anywhere(ctx, &profile) {
                    return Err("Start the connection first (`netorch up`)".into());
                }
                None
            }
        }
    };
    let client = net_manager_core::exit_ip::client(socks)
        .map_err(|_| "The exit IP check could not start".to_string())?;
    let entries = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "The exit IP check could not start".to_string())?
        .block_on(net_manager_core::exit_ip::check_all(client));
    let value = serde_json::to_value(&entries).map_err(|_| "Could not encode the result")?;
    ctx.emit(value, || {
        table(
            &["CHECKER", "IP", "COUNTRY"],
            &entries
                .iter()
                .map(|entry| {
                    vec![
                        entry.name.clone(),
                        entry
                            .ip
                            .clone()
                            .or_else(|| entry.error.clone())
                            .unwrap_or_default(),
                        entry.country.clone().unwrap_or_default(),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    });
    Ok(())
}
