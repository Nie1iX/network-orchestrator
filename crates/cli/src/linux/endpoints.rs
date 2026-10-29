//! The servers inside a subscription: list them, pick one, switch the running
//! connection to another, refresh the list and measure delays. The app keeps
//! the same data (`subscription.json` in the vault); share links never reach
//! the terminal, only the names the provider gave them.
use super::auth;
use super::commands::{self, Output};
use super::ctx::Ctx;
use super::library;
use net_manager_core::backend_settings::BackendSettingsStore;
use net_manager_core::config_vault::SubscriptionEndpoint;
use net_manager_core::models::{Profile, TunnelBackend, TunnelState};
use net_manager_core::{subscription, vpn, xray};
use net_manager_engine::linux_engine::LinuxEngine;
use serde_json::{json, Value};
use std::io::{BufRead, IsTerminal, Write};

/// How many delay probes run at once; each starts its own Xray.
const PROBE_PARALLELISM: usize = 8;
/// Servers shown in a text ranking unless `--all`.
pub const DEFAULT_TOP: usize = 10;
/// Lines of the interactive list before it asks to narrow down.
const PICKER_LINES: usize = 20;

/// One server as listed: 1-based number, display name, protocol, active flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub number: usize,
    pub name: String,
    pub protocol: String,
    pub active: bool,
}

/// Provider names carry stray spaces around flags; collapse them for display.
fn clean(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn rows(endpoints: &[SubscriptionEndpoint], active: usize) -> Vec<Row> {
    endpoints
        .iter()
        .enumerate()
        .map(|(index, endpoint)| Row {
            number: index + 1,
            name: clean(&endpoint.name),
            protocol: xray::endpoint_protocol(&endpoint.url).unwrap_or_default(),
            active: index == active,
        })
        .collect()
}

pub fn active_index(profile: &Profile) -> usize {
    profile
        .subscription
        .as_ref()
        .map(|meta| meta.active_index)
        .unwrap_or(0)
}

fn subscription_profile(ctx: &Ctx, target: &str) -> Result<Profile, String> {
    let profile = ctx.find(target)?;
    if profile.subscription.is_none() {
        return Err(format!("\"{}\" is not a subscription", profile.name));
    }
    Ok(profile)
}

fn read_endpoints(ctx: &Ctx, profile: &Profile) -> Result<Vec<SubscriptionEndpoint>, String> {
    ctx.vault()
        .read_subscription_endpoints(&profile.id)
        .map_err(|_| "The subscription's server list could not be read".to_string())
}

/// The active server's name, for profiles that are subscriptions.
pub fn active_name(ctx: &Ctx, profile: &Profile) -> Option<String> {
    profile.subscription.as_ref()?;
    let endpoints = ctx.vault().read_subscription_endpoints(&profile.id).ok()?;
    endpoints
        .get(active_index(profile))
        .map(|endpoint| clean(&endpoint.name))
}

/// A server by 1-based number, exact name or unique part of a name (any case).
pub fn pick(rows: &[Row], query: &str) -> Result<usize, String> {
    let query = query.trim();
    if let Ok(number) = query.parse::<usize>() {
        return match rows.iter().find(|row| row.number == number) {
            Some(row) => Ok(row.number - 1),
            None => Err(format!("There is no server number {number}")),
        };
    }
    let lower = query.to_lowercase();
    if lower.is_empty() {
        return Err("Name a server or give its number".into());
    }
    let exact: Vec<&Row> = rows
        .iter()
        .filter(|row| row.name.to_lowercase() == lower)
        .collect();
    if let [one] = exact.as_slice() {
        return Ok(one.number - 1);
    }
    let found: Vec<&Row> = rows
        .iter()
        .filter(|row| row.name.to_lowercase().contains(&lower))
        .collect();
    match found.as_slice() {
        [] => Err(format!("No server matches \"{query}\"")),
        [one] => Ok(one.number - 1),
        many => Err(format!(
            "\"{query}\" matches {} servers; give a number or more of the name:\n{}",
            many.len(),
            many.iter()
                .take(10)
                .map(|row| format!("  {:>3}  {}", row.number, row.name))
                .collect::<Vec<_>>()
                .join("\n")
        )),
    }
}

/// Asks on the terminal: a number picks, text narrows the list, a single match
/// is taken at once, Enter keeps the current server, `q` cancels.
pub fn choose(
    rows: &[Row],
    input: &mut impl BufRead,
    out: &mut impl Write,
) -> Result<usize, String> {
    let active = rows.iter().position(|row| row.active).unwrap_or(0);
    let mut filter = String::new();
    loop {
        let shown: Vec<&Row> = rows
            .iter()
            .filter(|row| row.name.to_lowercase().contains(&filter.to_lowercase()))
            .collect();
        if shown.is_empty() {
            let _ = writeln!(out, "No server matches \"{filter}\".");
            filter.clear();
            continue;
        }
        for row in shown.iter().take(PICKER_LINES) {
            let _ = writeln!(
                out,
                "{} {:>3}  {}{}",
                if row.active { "*" } else { " " },
                row.number,
                row.name,
                if row.protocol.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", row.protocol)
                }
            );
        }
        if shown.len() > PICKER_LINES {
            let _ = writeln!(
                out,
                "  … {} more: type part of a name to narrow the list",
                shown.len() - PICKER_LINES
            );
        }
        let _ = write!(
            out,
            "Number or text to filter (Enter keeps {}, q cancels): ",
            rows[active].number
        );
        let _ = out.flush();
        let mut line = String::new();
        let read = input
            .read_line(&mut line)
            .map_err(|_| "Could not read from the terminal".to_string())?;
        let answer = line.trim();
        if read == 0 || answer.eq_ignore_ascii_case("q") {
            return Err("Cancelled".into());
        }
        if answer.is_empty() {
            return Ok(active);
        }
        if let Ok(number) = answer.parse::<usize>() {
            if rows.iter().any(|row| row.number == number) {
                return Ok(number - 1);
            }
            let _ = writeln!(out, "There is no server number {number}.");
            continue;
        }
        filter = answer.to_string();
        let narrowed: Vec<&Row> = rows
            .iter()
            .filter(|row| row.name.to_lowercase().contains(&filter.to_lowercase()))
            .collect();
        if let [one] = narrowed.as_slice() {
            return Ok(one.number - 1);
        }
    }
}

fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// The server the user means: the argument, or a question on a terminal.
fn select(rows: &[Row], query: Option<&str>) -> Result<usize, String> {
    match query {
        Some(query) => pick(rows, query),
        None if interactive() => choose(rows, &mut std::io::stdin().lock(), &mut std::io::stderr()),
        None => Err("Name a server or give its number (`netorch endpoints` lists them)".into()),
    }
}

pub fn list(ctx: &Ctx, target: &str) -> Result<Output, String> {
    let profile = subscription_profile(ctx, target)?;
    let rows = rows(&read_endpoints(ctx, &profile)?, active_index(&profile));
    let value = Value::Array(
        rows.iter()
            .map(|row| {
                json!({"number": row.number, "name": row.name,
                    "protocol": row.protocol, "active": row.active})
            })
            .collect(),
    );
    let text = crate::render::table(
        &["", "NO", "SERVER", "PROTOCOL"],
        &rows
            .iter()
            .map(|row| {
                vec![
                    if row.active { "*" } else { "" }.into(),
                    row.number.to_string(),
                    row.name.clone(),
                    row.protocol.clone(),
                ]
            })
            .collect::<Vec<_>>(),
    );
    Ok((value, text))
}

fn is_running(ctx: &Ctx, profile: &Profile) -> Result<bool, String> {
    Ok(LinuxEngine::handles(profile) && ctx.engine.status(profile)?.state != TunnelState::Stopped)
}

/// Makes `index` the profile's server; the connection must be down.
fn apply(ctx: &Ctx, profile: &Profile, index: usize) -> Result<Profile, String> {
    subscription::switch_endpoint(&ctx.vault(), &ctx.store(), &profile.id, index, |port| {
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok()
    })
    .map_err(|error| match error.kind() {
        std::io::ErrorKind::InvalidInput => error.to_string(),
        _ => "The server could not be switched. Check file permissions.".into(),
    })?;
    ctx.find(&profile.id)
}

fn chosen(ctx: &Ctx, profile: &Profile, query: Option<&str>) -> Result<(usize, Vec<Row>), String> {
    let rows = rows(&read_endpoints(ctx, profile)?, active_index(profile));
    let index = select(&rows, query)?;
    Ok((index, rows))
}

pub fn use_endpoint(ctx: &Ctx, target: &str, query: Option<&str>) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    let (index, rows) = chosen(ctx, &profile, query)?;
    if is_running(ctx, &profile)? {
        return Err(format!(
            "\"{}\" is connected; use `netorch switch` to change the server and reconnect",
            profile.name
        ));
    }
    let name = rows[index].name.clone();
    if index != active_index(&profile) {
        apply(ctx, &profile, index)?;
    }
    Ok((
        json!({"id": profile.id, "server": name, "number": index + 1}),
        format!("\"{}\" now uses {name}", profile.name),
    ))
}

/// Changes the server and, when the connection was up, reconnects; if the new
/// server does not come up the previous one is restored.
pub fn switch(ctx: &Ctx, target: &str, query: Option<&str>) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    let (index, rows) = chosen(ctx, &profile, query)?;
    let previous = active_index(&profile);
    let was_running = is_running(ctx, &profile)?;
    if was_running {
        auth::run(ctx.root_user, || ctx.engine.disconnect(&profile))?;
    }
    let outcome = apply(ctx, &profile, index).and_then(|updated| {
        if was_running {
            commands::connect(ctx, &updated, None).map(|_| ())
        } else {
            Ok(())
        }
    });
    if let Err(error) = outcome {
        // Put the old server back, and the connection with it.
        if let Ok(restored) = apply(ctx, &profile, previous) {
            if was_running {
                let _ = commands::connect(ctx, &restored, None);
            }
        }
        return Err(format!("{error}. The previous server was restored"));
    }
    let name = rows[index].name.clone();
    Ok((
        json!({"id": profile.id, "server": name, "number": index + 1,
            "connected": was_running}),
        if was_running {
            format!("Switched \"{}\" to {name} and reconnected", profile.name)
        } else {
            format!("\"{}\" now uses {name}", profile.name)
        },
    ))
}

pub fn refresh(ctx: &Ctx, target: &str) -> Result<Output, String> {
    library::require_user(ctx)?;
    let profile = subscription_profile(ctx, target)?;
    if is_running(ctx, &profile)? {
        return Err(format!(
            "\"{}\" is connected; run `netorch down` first",
            profile.name
        ));
    }
    let meta = profile.subscription.clone().ok_or("Not a subscription")?;
    let fetched = block_on(subscription::fetch(
        &subscription::http_client().map_err(|error| error.to_string())?,
        &meta.url,
        &meta.hwid,
    ))?
    .map_err(|error| error.to_string())?;
    let outcome = subscription::refresh_body(
        &ctx.vault(),
        &ctx.store(),
        &profile.id,
        &fetched.body,
        fetched.meta,
        |port| std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok(),
    )
    .map_err(|error| match error.kind() {
        std::io::ErrorKind::InvalidInput => error.to_string(),
        _ => "The subscription could not be refreshed. Check file permissions.".into(),
    })?;
    Ok((
        json!({"id": profile.id, "servers": outcome.endpoint_count,
            "skipped": outcome.skipped_count}),
        format!(
            "Refreshed \"{}\": {} servers{}",
            profile.name,
            outcome.endpoint_count,
            if outcome.skipped_count > 0 {
                format!(" ({} unsupported skipped)", outcome.skipped_count)
            } else {
                String::new()
            }
        ),
    ))
}

fn block_on<F: std::future::Future>(future: F) -> Result<F::Output, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Could not start the network runtime".to_string())
        .map(|runtime| runtime.block_on(future))
}

/// The Xray `test` runs probes with: the configured or managed one.
fn xray_executable(ctx: &Ctx) -> Result<std::path::PathBuf, String> {
    let setting = BackendSettingsStore::new(ctx.root.join("backend-settings.json"))
        .get(TunnelBackend::Xray)
        .map_err(|_| "The backend settings could not be read".to_string())?;
    vpn::resolve_xray_executable(setting.as_ref().map(|s| s.path.as_path()))
        .map_err(|_| "Xray was not found. Install it in the Network Orchestrator app.".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub number: usize,
    pub name: String,
    pub delay_ms: Option<u64>,
    /// Why there is no delay (never contains the share link).
    pub error: Option<String>,
}

/// Fastest first; servers that did not answer go last in list order.
pub fn rank(mut probes: Vec<Probe>) -> Vec<Probe> {
    probes.sort_by_key(|probe| (probe.delay_ms.is_none(), probe.delay_ms, probe.number));
    probes
}

/// Which servers `test` measures: those matching `query`, else all.
fn select_for_test(rows: &[Row], query: Option<&str>) -> Result<Vec<usize>, String> {
    let Some(query) = query else {
        return Ok((0..rows.len()).collect());
    };
    let lower = query.trim().to_lowercase();
    let found: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.name.to_lowercase().contains(&lower))
        .map(|(index, _)| index)
        .collect();
    if found.is_empty() {
        return Err(format!("No server matches \"{query}\""));
    }
    Ok(found)
}

/// The config a probe runs: for a profile the daemon runs, the reduced one a
/// connection would send, so the result says whether the server can work.
fn probe_config(url: &str, port: u16, as_tunnel: bool) -> Result<Value, String> {
    let config = xray::generate_share_link_config(url, port)
        .map_err(|_| "invalid subscription endpoint".to_string())?;
    if as_tunnel {
        xray::tun_compatible_config(&config).map_err(str::to_string)
    } else {
        Ok(config)
    }
}

pub fn test(
    ctx: &Ctx,
    target: &str,
    query: Option<&str>,
    all: bool,
    top: usize,
) -> Result<Output, String> {
    let profile = subscription_profile(ctx, target)?;
    let endpoints = read_endpoints(ctx, &profile)?;
    let rows = rows(&endpoints, active_index(&profile));
    let indexes = select_for_test(&rows, query)?;
    let executable = xray_executable(ctx)?;
    eprintln!("Measuring {} servers...", indexes.len());
    let as_tunnel = LinuxEngine::handles(&profile);
    let jobs: Vec<(usize, String)> = indexes
        .iter()
        .map(|&index| (index, endpoints[index].url.clone()))
        .collect();
    let results = block_on(async move {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(PROBE_PARALLELISM));
        let mut set = tokio::task::JoinSet::new();
        for (index, url) in jobs {
            let gate = gate.clone();
            let executable = executable.clone();
            set.spawn(async move {
                let _permit = gate.acquire_owned().await;
                let mut command = tokio::process::Command::new(&executable);
                command.args(["run", "-config", "stdin:"]);
                let delay = subscription::measure_delay_with_config(
                    |port| probe_config(&url, port, as_tunnel),
                    command,
                    subscription::DELAY_PROBE_URL,
                    subscription::DELAY_PROBE_TIMEOUT,
                )
                .await;
                (index, delay)
            });
        }
        let mut done = Vec::new();
        while let Some(Ok(result)) = set.join_next().await {
            done.push(result);
        }
        done
    })?;
    let probes = rank(
        results
            .into_iter()
            .map(|(index, result)| Probe {
                number: index + 1,
                name: rows[index].name.clone(),
                delay_ms: result.as_ref().ok().copied(),
                error: result.err(),
            })
            .collect(),
    );
    Ok(render_probes(&probes, all, top))
}

pub fn render_probes(probes: &[Probe], all: bool, top: usize) -> Output {
    let value = Value::Array(
        probes
            .iter()
            .map(|probe| {
                json!({"number": probe.number, "name": probe.name,
                "delayMs": probe.delay_ms, "error": probe.error})
            })
            .collect(),
    );
    let answered = probes.iter().filter(|p| p.delay_ms.is_some()).count();
    let shown: Vec<&Probe> = if all {
        probes.iter().collect()
    } else {
        probes.iter().take(top).collect()
    };
    let mut text = crate::render::table(
        &["NO", "SERVER", "DELAY"],
        &shown
            .iter()
            .map(|probe| {
                vec![
                    probe.number.to_string(),
                    probe.name.clone(),
                    probe
                        .delay_ms
                        .map(|ms| format!("{ms} ms"))
                        .unwrap_or_else(|| {
                            probe.error.clone().unwrap_or_else(|| "no answer".into())
                        }),
                ]
            })
            .collect::<Vec<_>>(),
    );
    text.push_str(&format!(
        "\n{answered} of {} answered. `netorch switch <profile> <NO>` picks one.",
        probes.len()
    ));
    (value, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample() -> Vec<Row> {
        [
            "  🇩🇪 ⚡ Германия",
            "🇳🇱 ⚡ Нидерланды",
            "🇩🇪 Hysteria 2 | Германия",
            "🇵🇱 Польша",
        ]
        .iter()
        .enumerate()
        .map(|(i, name)| Row {
            number: i + 1,
            name: clean(name),
            protocol: "VLESS".into(),
            active: i == 1,
        })
        .collect()
    }

    #[test]
    fn display_names_lose_their_stray_spaces() {
        assert_eq!(clean("  🇩🇪 ⚡  Германия "), "🇩🇪 ⚡ Германия");
    }

    #[test]
    fn a_number_or_a_unique_part_of_a_name_picks_a_server() {
        let rows = sample();
        assert_eq!(pick(&rows, "2"), Ok(1));
        assert_eq!(pick(&rows, "польш"), Ok(3));
        assert_eq!(pick(&rows, "НИДЕР"), Ok(1));
        assert!(pick(&rows, "9").is_err());
        assert!(pick(&rows, "").is_err());
    }

    #[test]
    fn an_ambiguous_name_lists_the_candidates_instead_of_guessing() {
        let error = pick(&sample(), "герман").unwrap_err();
        assert!(error.contains("matches 2 servers"), "{error}");
        assert!(error.contains("Hysteria"), "{error}");
    }

    #[test]
    fn an_exact_name_wins_over_longer_names_containing_it() {
        let rows = vec![
            Row {
                number: 1,
                name: "Poland".into(),
                protocol: String::new(),
                active: false,
            },
            Row {
                number: 2,
                name: "Poland 2".into(),
                protocol: String::new(),
                active: false,
            },
        ];
        assert_eq!(pick(&rows, "poland"), Ok(0));
    }

    #[test]
    fn the_picker_takes_a_number_a_single_match_or_keeps_the_current_server() {
        let rows = sample();
        let mut out = Vec::new();
        assert_eq!(choose(&rows, &mut Cursor::new("3\n"), &mut out), Ok(2));
        assert_eq!(choose(&rows, &mut Cursor::new("польша\n"), &mut out), Ok(3));
        assert_eq!(choose(&rows, &mut Cursor::new("\n"), &mut out), Ok(1));
        let shown = String::from_utf8(out).unwrap();
        assert!(shown.contains("*   2  🇳🇱 ⚡ Нидерланды"), "{shown}");
    }

    #[test]
    fn the_picker_narrows_by_text_then_picks_and_can_be_cancelled() {
        let rows = sample();
        let mut out = Vec::new();
        assert_eq!(
            choose(&rows, &mut Cursor::new("герман\n3\n"), &mut out),
            Ok(2)
        );
        assert!(choose(&rows, &mut Cursor::new("q\n"), &mut out).is_err());
        assert!(choose(&rows, &mut Cursor::new(""), &mut out).is_err());
        assert!(choose(&rows, &mut Cursor::new("99\nq\n"), &mut out).is_err());
    }

    #[test]
    fn the_ranking_puts_fast_servers_first_and_silent_ones_last() {
        let probe = |number, delay_ms| Probe {
            number,
            name: format!("s{number}"),
            delay_ms,
            error: None,
        };
        let ranked = rank(vec![
            probe(1, None),
            probe(2, Some(300)),
            probe(3, Some(80)),
            probe(4, None),
        ]);
        let order: Vec<usize> = ranked.iter().map(|p| p.number).collect();
        assert_eq!(order, [3, 2, 1, 4]);
        let (value, text) = render_probes(&ranked, false, 2);
        assert_eq!(value.as_array().unwrap().len(), 4);
        assert!(text.contains("80 ms") && !text.contains("no answer"));
        assert!(text.contains("2 of 4 answered"));
    }

    #[test]
    fn test_filters_servers_by_text_and_rejects_no_match() {
        let rows = sample();
        assert_eq!(select_for_test(&rows, None), Ok(vec![0, 1, 2, 3]));
        assert_eq!(select_for_test(&rows, Some("герман")), Ok(vec![0, 2]));
        assert!(select_for_test(&rows, Some("zzz")).is_err());
    }
}
