//! Bounded JSON C ABI for the native SwiftUI client. No privileged mutations.
use net_manager_core::{
    analysis, cidr_bulk, config_vault::ConfigVault, explorer, models::*, profiles::ProfileStore,
    route_plan,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::ffi::{c_char, CString};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod runtime;
// The proxy runtime needs the managed Xray package, pinned for Apple
// Silicon; on other targets the bridge still builds so subscription,
// profile and inventory commands can be exercised off-macOS.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod runtime {
    use net_manager_core::profiles::ProfileStore;
    use serde_json::Value;
    use std::path::{Path, PathBuf};

    pub(crate) fn managed_executable(_root: &Path) -> Option<PathBuf> {
        None
    }

    pub(crate) fn restart_around(
        _root: &Path,
        _store: &ProfileStore,
        _id: &str,
        change: impl FnOnce() -> Result<Value, String>,
    ) -> Result<Value, String> {
        change()
    }

    pub(crate) fn handle(
        _root: &Path,
        _store: &ProfileStore,
        _method: &str,
        _args: &Value,
    ) -> Option<Result<Value, String>> {
        None
    }
}

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
static TRANSACTION: Mutex<()> = Mutex::new(());
static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, std::io::Error>> = OnceLock::new();

#[derive(Deserialize)]
struct Request {
    root: PathBuf,
    method: String,
    #[serde(default)]
    args: Value,
}

fn runtime_executor() -> Result<&'static tokio::runtime::Runtime, String> {
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|_| "Network reader could not start".into())
}
fn text_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "A required field is empty".into())
}
fn store_error(_: std::io::Error) -> String {
    "The profile operation could not be completed. Check the input and file permissions.".into()
}
fn local_port_available(port: u16) -> bool {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok()
}
fn subscription_error(error: std::io::Error) -> String {
    if matches!(
        error.kind(),
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Other
    ) {
        error.to_string()
    } else {
        store_error(error)
    }
}
static DELAY_RUNTIME: OnceLock<Result<tokio::runtime::Runtime, std::io::Error>> = OnceLock::new();
const DELAY_CONCURRENCY: usize = 8;

/// Share links of a subscription profile, in endpoint order.
fn subscription_uris(root: &Path, id: &str) -> Result<Vec<String>, String> {
    let store = ProfileStore::new(root.join("profiles.json"));
    let vault = ConfigVault::new(root.join("configs"));
    let profile = store
        .load()
        .map_err(store_error)?
        .profiles
        .into_iter()
        .find(|p| p.id == id)
        .ok_or("Profile not found")?;
    if profile.subscription.is_none() {
        return Err("Delay checks are available for subscriptions".into());
    }
    Ok(vault
        .read_subscription_endpoints(id)
        .map_err(store_error)?
        .into_iter()
        .map(|endpoint| endpoint.url)
        .collect())
}

fn delay_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    DELAY_RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|_| "Delay checks could not start".to_string())
}

const DELAY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fetch outside the store lock (it can take seconds), then apply the body
/// under the lock; a failed attempt is recorded so auto-refresh backs off.
fn refresh_subscription(root: &Path, args: &Value) -> Result<Value, String> {
    let id = text_arg(args, "id")?;
    let store = ProfileStore::new(root.join("profiles.json"));
    let meta = store
        .load()
        .map_err(store_error)?
        .profiles
        .into_iter()
        .find(|p| p.id == id)
        .and_then(|p| p.subscription)
        .ok_or("Profile is not a subscription")?;
    let record_failure = |message: String| {
        let _lock = TRANSACTION.lock();
        let _ = net_manager_core::subscription::record_refresh_failure(&store, id, unix_now());
        message
    };
    let client = net_manager_core::subscription::http_client().map_err(subscription_error)?;
    let fetched = runtime_executor()?
        .block_on(net_manager_core::subscription::fetch(
            &client, &meta.url, &meta.hwid,
        ))
        .map_err(|error| record_failure(subscription_error(error)))?;
    let summary = format!(
        "{} headers: {}",
        net_manager_core::subscription::summarize_subscription_body(
            &fetched.body,
            fetched.content_type.as_deref(),
        ),
        fetched.header_names.join(",")
    );
    let _lock = TRANSACTION
        .lock()
        .map_err(|_| "Profile service is unavailable".to_string())?;
    let vault = ConfigVault::new(root.join("configs"));
    let result = runtime::restart_around(root, &store, id, || {
        let outcome = net_manager_core::subscription::refresh_body(
            &vault,
            &store,
            id,
            &fetched.body,
            fetched.meta.clone(),
            local_port_available,
        );
        log_subscription_import(
            root,
            &summary,
            !meta.hwid.is_empty(),
            outcome.as_ref().err().map(|e| e.to_string()),
        );
        encode(outcome.map_err(subscription_error)?)
    });
    if result.is_err() {
        let _ = net_manager_core::subscription::record_refresh_failure(&store, id, unix_now());
    }
    result
}

/// Exit IP as seen by IP-echo services, directly or through a running
/// connection's SOCKS port; never holds the store lock.
fn check_exit_ip(root: &Path, args: &Value) -> Result<Value, String> {
    let via = args["via"].as_str().unwrap_or("direct");
    let socks = if via == "direct" {
        None
    } else {
        let store = ProfileStore::new(root.join("profiles.json"));
        let profile = store
            .load()
            .map_err(store_error)?
            .profiles
            .into_iter()
            .find(|p| p.id == via)
            .ok_or("Profile not found")?;
        if !runtime::is_running(root, &profile)? {
            return Err("Start the connection first".into());
        }
        Some(
            profile
                .xray_socks_port
                .ok_or("This connection has no local proxy port")?,
        )
    };
    let client = net_manager_core::exit_ip::client(socks)
        .map_err(|_| "Exit IP check could not start".to_string())?;
    let entries = delay_runtime()?.block_on(net_manager_core::exit_ip::check_all(client));
    encode(entries)
}

/// One endpoint, so the UI can show each result as soon as it lands.
fn measure_delay(root: &Path, args: &Value) -> Result<Value, String> {
    let id = text_arg(args, "id")?;
    let index = text_arg(args, "index")?
        .parse::<usize>()
        .map_err(|_| "Invalid endpoint index".to_string())?;
    let uri = subscription_uris(root, id)?
        .into_iter()
        .nth(index)
        .ok_or("Invalid endpoint index")?;
    let executable =
        runtime::managed_executable(root).ok_or("Install Xray to start this connection")?;
    let result = delay_runtime()?.block_on(net_manager_core::subscription::measure_endpoint_delay(
        &executable,
        &uri,
        DELAY_TIMEOUT,
    ));
    Ok(json!({"index": index, "delayMs": result.ok()}))
}

/// Every endpoint of a subscription, eight at a time.
fn measure_delays(root: &Path, args: &Value) -> Result<Value, String> {
    let id = text_arg(args, "id")?;
    let uris = subscription_uris(root, id)?;
    let executable =
        runtime::managed_executable(root).ok_or("Install Xray to start this connection")?;
    let results = delay_runtime()?.block_on(async move {
        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(DELAY_CONCURRENCY));
        let mut tasks = tokio::task::JoinSet::new();
        for (index, uri) in uris.into_iter().enumerate() {
            let permits = permits.clone();
            let executable = executable.clone();
            tasks.spawn(async move {
                let _permit = permits.acquire_owned().await;
                let result = net_manager_core::subscription::measure_endpoint_delay(
                    &executable,
                    &uri,
                    DELAY_TIMEOUT,
                )
                .await;
                (index, result)
            });
        }
        let mut results = Vec::new();
        while let Some(Ok((index, result))) = tasks.join_next().await {
            results.push(json!({"index": index, "delayMs": result.ok()}));
        }
        results.sort_by_key(|value| value["index"].as_u64());
        results
    });
    Ok(json!(results))
}

/// Appends a secret-free import record (format, schemes, outcome) to
/// `runtime/logs/subscription-import.log`; never the URL, HWID or body.
fn log_subscription_import(root: &Path, summary: &str, with_hwid: bool, error: Option<String>) {
    let dir = root.join("runtime").join("logs");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("subscription-import.log");
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!(
        "{seconds} hwid={} {summary} result={}\n",
        if with_hwid { "sent" } else { "none" },
        error.as_deref().unwrap_or("ok")
    );
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = std::io::Write::write_all(&mut file, line.as_bytes());
        let _ = net_manager_core::config_security::protect_path(&path);
    }
}
/// Hardware UUID of this Mac, or a random ID kept in the app data directory
/// when IOKit does not report one. Only ever used as an HWID seed.
fn machine_seed(root: &Path) -> Result<String, String> {
    if let Ok(output) = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        if let Some(uuid) = text
            .lines()
            .find(|line| line.contains("\"IOPlatformUUID\""))
            .and_then(|line| line.rsplit('"').nth(1))
            .filter(|uuid| !uuid.is_empty())
        {
            return Ok(uuid.to_string());
        }
    }
    let path = root.join("device-id");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        if !existing.trim().is_empty() {
            return Ok(existing.trim().to_string());
        }
    }
    let mut bytes = [0u8; 16];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").map_err(|_| "Device ID unavailable")?,
        &mut bytes,
    )
    .map_err(|_| "Device ID unavailable")?;
    let seed: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::create_dir_all(root).map_err(store_error)?;
    let temp = root.join("device-id.tmp");
    std::fs::write(&temp, &seed).map_err(store_error)?;
    net_manager_core::config_security::protect_path(&temp).map_err(store_error)?;
    std::fs::rename(&temp, &path).map_err(store_error)?;
    Ok(seed)
}
fn encode(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|_| "Could not encode the result".into())
}
fn dispatch(root: &Path, method: &str, args: &Value) -> Result<Value, String> {
    if !root.is_absolute() {
        return Err("App data location must be absolute".into());
    }
    // Delay probes take seconds; they only read the store, so they run
    // outside the transaction lock and never stall other calls.
    match method {
        "refresh_subscription" => return refresh_subscription(root, args),
        "measure_delays" => return measure_delays(root, args),
        "measure_delay" => return measure_delay(root, args),
        "check_exit_ip" => return check_exit_ip(root, args),
        _ => {}
    }
    let _lock = TRANSACTION
        .lock()
        .map_err(|_| "Profile service is unavailable".to_string())?;
    let store = ProfileStore::new(root.join("profiles.json"));
    let vault = ConfigVault::new(root.join("configs"));
    if let Some(result) = runtime::handle(root, &store, method, args) {
        return result;
    }
    match method {
        "capabilities" => Ok(json!({"os":"macos", "minimumOS":"27.0", "nativeUI":true,
            "profiles":true,"networkInventory":true,"networkMutations":false,
            "proxyConnections":cfg!(all(target_os = "macos", target_arch = "aarch64")),
            "systemVPN":"providerSetupRequired", "version":env!("CARGO_PKG_VERSION")})),
        "generate_hwid" => Ok(json!(net_manager_core::subscription::derive_hwid(
            &machine_seed(root)?
        ))),
        "profiles" => encode(net_manager_core::subscription::public_profiles(
            store.load().map_err(store_error)?.profiles,
        )),
        "snapshot" => {
            let profiles = net_manager_core::subscription::public_profiles(
                store.load().map_err(store_error)?.profiles,
            );
            let interfaces = explorer::list_interfaces();
            let routes = runtime_executor()?.block_on(explorer::list_routes());
            let network_error = (interfaces.is_err() || routes.is_err())
                .then_some("Some network information could not be read. Try refreshing.");
            let interfaces = interfaces.unwrap_or_default();
            let routes = routes.unwrap_or_default();
            let planned = profiles
                .iter()
                .cloned()
                .map(|p| (p, false))
                .collect::<Vec<_>>();
            let map = route_plan::build_route_map(&planned, &routes);
            Ok(
                json!({"profiles":profiles,"interfaces":interfaces,"routes":routes,"routeMap":map,"networkError":network_error}),
            )
        }
        "lookup" => {
            let ip = text_arg(args, "destination")?
                .parse()
                .map_err(|_| "Enter an IPv4 or IPv6 address".to_string())?;
            encode(
                runtime_executor()?
                    .block_on(explorer::lookup_route(ip))
                    .map_err(|_| "No route could be read for this address".to_string())?,
            )
        }
        "create_static" => {
            let id = text_arg(args, "id")?;
            net_manager_core::config_vault::sanitize_profile_id(id).map_err(store_error)?;
            if store
                .load()
                .map_err(store_error)?
                .profiles
                .iter()
                .any(|p| p.id == id)
            {
                return Err("A profile with this identifier already exists".into());
            }
            let routes = cidr_bulk::parse_bulk_cidrs(text_arg(args, "cidrs")?)
                .map_err(|_| "Enter valid IPv4 or IPv6 CIDRs".to_string())?;
            if routes.is_empty() {
                return Err("Add at least one route".into());
            }
            let profile = Profile {
                id: id.into(),
                name: text_arg(args, "name")?.trim().into(),
                interface_name: text_arg(args, "interfaceName")?.trim().into(),
                routes: routes
                    .into_iter()
                    .map(|destination| PolicyRoute {
                        destination,
                        metric: 5,
                        via: None,
                    })
                    .collect(),
                ..Profile::default()
            };
            encode(net_manager_core::subscription::public_profiles(
                store.upsert(profile).map_err(store_error)?.profiles,
            ))
        }
        "rename" => {
            let mut p = store
                .load()
                .map_err(store_error)?
                .profiles
                .into_iter()
                .find(|p| Some(p.id.as_str()) == args["id"].as_str())
                .ok_or("Profile not found")?;
            p.name = text_arg(args, "name")?.trim().into();
            encode(net_manager_core::subscription::public_profiles(
                store.upsert(p).map_err(store_error)?.profiles,
            ))
        }
        "delete" => {
            let id = text_arg(args, "id")?;
            // Persist the removal before cleanup: a cleanup error must not leave a stored dangling path.
            let profiles = store.delete(id).map_err(store_error)?.profiles;
            vault.remove_profile(id).map_err(store_error)?;
            encode(net_manager_core::subscription::public_profiles(profiles))
        }
        "import_subscription" => {
            let id = text_arg(args, "id")?;
            let url = text_arg(args, "url")?;
            let hwid = args["hwid"].as_str().unwrap_or("");
            let name = args["name"].as_str().unwrap_or("");
            let client =
                net_manager_core::subscription::http_client().map_err(subscription_error)?;
            let fetched = runtime_executor()?
                .block_on(net_manager_core::subscription::fetch(&client, url, hwid))
                .map_err(subscription_error)?;
            let request = net_manager_core::subscription::SubscriptionImport {
                id,
                url,
                hwid,
                name,
                refresh_interval_minutes: None,
            };
            let summary = format!(
                "{} headers: {}",
                net_manager_core::subscription::summarize_subscription_body(
                    &fetched.body,
                    fetched.content_type.as_deref(),
                ),
                fetched.header_names.join(",")
            );
            let imported = net_manager_core::subscription::import_body(
                &vault,
                &store,
                &request,
                &fetched.body,
                fetched.meta.clone(),
                local_port_available,
            );
            log_subscription_import(
                root,
                &summary,
                !hwid.is_empty(),
                imported.as_ref().err().map(|e| e.to_string()),
            );
            let imported = imported.map_err(|error| {
                let message = subscription_error(error);
                if message == "Subscription contained no supported share links" {
                    format!("{message} ({summary})")
                } else {
                    message
                }
            })?;
            let skipped_count = imported
                .errors
                .iter()
                .map(|error| {
                    if error.path == "Subscription" {
                        error
                            .error
                            .split_whitespace()
                            .next()
                            .and_then(|n| n.parse::<usize>().ok())
                            .unwrap_or(0)
                    } else {
                        1
                    }
                })
                .sum::<usize>();
            Ok(
                json!({"profiles":net_manager_core::subscription::public_profiles(imported.profiles),"skippedCount":skipped_count}),
            )
        }
        "subscription_endpoints" => {
            let id = text_arg(args, "id")?;
            let profile = store
                .load()
                .map_err(store_error)?
                .profiles
                .into_iter()
                .find(|p| p.id == id)
                .ok_or("Profile not found")?;
            let active = profile
                .subscription
                .ok_or("Profile is not a subscription")?
                .active_index;
            let endpoints = vault.read_subscription_endpoints(id).map_err(store_error)?;
            encode(
                endpoints
                    .into_iter()
                    .enumerate()
                    .map(|(index, endpoint)| SubscriptionEndpointInfo {
                        protocol: net_manager_core::xray::endpoint_protocol(&endpoint.url),
                        name: endpoint.name,
                        active: index == active,
                    })
                    .collect::<Vec<_>>(),
            )
        }
        "switch_subscription_endpoint" => {
            let id = text_arg(args, "id")?;
            let index = text_arg(args, "index")?
                .parse::<usize>()
                .map_err(|_| "Invalid endpoint index".to_string())?;
            runtime::restart_around(root, &store, id, || {
                let document = net_manager_core::subscription::switch_endpoint(
                    &vault,
                    &store,
                    id,
                    index,
                    local_port_available,
                )
                .map_err(subscription_error)?;
                encode(net_manager_core::subscription::public_profiles(
                    document.profiles,
                ))
            })
        }
        "external_vpns" => encode(
            net_manager_core::macos_vpn::list(&mut net_manager_core::macos_vpn::SystemScutil)
                .map_err(|_| "VPN services could not be listed".to_string())?,
        ),
        "set_external_vpn" => {
            let id = args["id"].as_str().unwrap_or_default();
            let connect = args["connect"].as_str() == Some("true");
            net_manager_core::macos_vpn::nc_command(id, connect)
                .map_err(|_| "Unknown VPN service".to_string())?;
            net_manager_core::macos_vpn::set_connected(
                &mut net_manager_core::macos_vpn::SystemScutil,
                id,
                connect,
            )
            .map_err(|_| "The VPN service could not be switched".to_string())?;
            encode(
                net_manager_core::macos_vpn::list(&mut net_manager_core::macos_vpn::SystemScutil)
                    .map_err(|_| "VPN services could not be listed".to_string())?,
            )
        }
        "reorder" => {
            let backend: TunnelBackend = serde_json::from_value(args["backend"].clone())
                .map_err(|_| "Unknown connection type".to_string())?;
            let ids: Vec<String> = text_arg(args, "ids")?
                .split(',')
                .map(str::to_string)
                .collect();
            let document = store
                .reorder(backend, &ids)
                .map_err(|_| "The order could not be saved".to_string())?;
            encode(net_manager_core::subscription::public_profiles(
                document.profiles,
            ))
        }
        "import_log" => {
            let text = std::fs::read_to_string(root.join("runtime/logs/subscription-import.log"))
                .unwrap_or_default();
            let lines: Vec<&str> = text.lines().collect();
            Ok(json!(lines[lines.len().saturating_sub(64)..].join("\n")))
        }
        "set_routing_rules" => {
            let id = text_arg(args, "id")?;
            let mut profile = store
                .load()
                .map_err(store_error)?
                .profiles
                .into_iter()
                .find(|p| p.id == id)
                .ok_or("Profile not found")?;
            if profile.backend != TunnelBackend::Xray {
                return Err("Routing rules are available for Xray connections".into());
            }
            // Xray matches the first rule, so blocks win over proxy over direct.
            let mut policies = Vec::new();
            for (key, target) in [
                ("block", DomainRouteTarget::Block),
                ("proxy", DomainRouteTarget::Proxy),
                ("direct", DomainRouteTarget::Direct),
            ] {
                let domains: Vec<String> = args[key]
                    .as_str()
                    .unwrap_or_default()
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(str::to_string)
                    .collect();
                for line in &domains {
                    let single = [DomainPolicy {
                        domains: vec![line.clone()],
                        target,
                    }];
                    net_manager_core::xray::validate_routing_policy_selectors(&single)
                        .map_err(|_| format!("Invalid routing rule ({line})"))?;
                }
                if !domains.is_empty() {
                    policies.push(DomainPolicy { domains, target });
                }
            }
            profile.domain_policies = policies;
            profile.private_lan_direct = args["privateLanDirect"].as_str() == Some("true");
            runtime::restart_around(root, &store, id, || {
                let document = store.upsert(profile).map_err(store_error)?;
                encode(net_manager_core::subscription::public_profiles(
                    document.profiles,
                ))
            })
        }
        "set_refresh_interval" => {
            let id = text_arg(args, "id")?;
            let minutes = match args["minutes"].as_str().unwrap_or_default() {
                "" => None,
                value => Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| "unsupported subscription refresh interval".to_string())?,
                ),
            };
            let document = net_manager_core::subscription::set_refresh_interval(
                &store,
                id,
                minutes,
                unix_now(),
            )
            .map_err(subscription_error)?;
            encode(net_manager_core::subscription::public_profiles(
                document.profiles,
            ))
        }
        "import_share_link" => {
            let id = text_arg(args, "id")?;
            let link = text_arg(args, "link")?;
            let name = args["name"].as_str().unwrap_or("");
            let document = net_manager_core::profile_import::import_share_link(
                &vault,
                &store,
                id,
                name,
                link,
                |port| std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok(),
            )
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::InvalidInput => {
                    "Invalid or unsupported share link. Use vless://, hysteria2:// or hy2://."
                        .to_string()
                }
                std::io::ErrorKind::AlreadyExists => {
                    "A profile with this identifier already exists".to_string()
                }
                _ => store_error(error),
            })?;
            encode(net_manager_core::subscription::public_profiles(
                document.profiles,
            ))
        }
        "import" => {
            let id = text_arg(args, "id")?;
            let name = text_arg(args, "name")?.trim();
            let path = text_arg(args, "path")?;
            if store
                .load()
                .map_err(store_error)?
                .profiles
                .iter()
                .any(|p| p.id == id)
            {
                return Err("A profile with this identifier already exists".into());
            }
            let backend: TunnelBackend = serde_json::from_value(args["backend"].clone())
                .map_err(|_| "Choose a valid VPN type".to_string())?;
            let imported = vault.import(id, backend, Path::new(path)).map_err(|err| {
                let message = err.to_string();
                if matches!(
                    message.as_str(),
                    "unsupported OpenVPN route directive" | "OpenVPN referenced asset is missing"
                ) {
                    message
                } else {
                    store_error(err)
                }
            })?;
            let p = Profile {
                id: id.into(),
                name: name.into(),
                backend,
                config_path: imported.config_path.clone(),
                routes: imported.routes,
                ..Profile::default()
            };
            let result = analysis::analyze_profile(&p)
                .map_err(|_| "The configuration could not be analyzed".to_string())
                .and_then(|_| store.upsert(p).map_err(store_error));
            match result {
                Ok(doc) => encode(net_manager_core::subscription::public_profiles(
                    doc.profiles,
                )),
                Err(err) => {
                    let _ = vault.remove_revision_for_config(&imported.config_path);
                    Err(err)
                }
            }
        }
        "inspect" => {
            let p = store
                .load()
                .map_err(store_error)?
                .profiles
                .into_iter()
                .find(|p| Some(p.id.as_str()) == args["id"].as_str())
                .ok_or("Profile not found")?;
            encode(
                analysis::analyze_profile(&p)
                    .map_err(|_| "The configuration could not be analyzed".to_string())?,
            )
        }
        _ => Err(
            "This action needs the macOS VPN provider. Network changes are disabled in this build."
                .into(),
        ),
    }
}
fn response(bytes: &[u8]) -> Value {
    let result = serde_json::from_slice::<Request>(bytes)
        .map_err(|_| "Invalid bridge request".to_string())
        .and_then(|r| dispatch(&r.root, &r.method, &r.args));
    match result {
        Ok(data) => json!({"ok":true,"data":data}),
        Err(error) => json!({"ok":false,"error":error}),
    }
}
/// # Safety
/// `bytes` must point to `length` readable bytes for the duration of the call.
/// Release the returned owned string exactly once with `netorch_free`.
#[no_mangle]
pub unsafe extern "C" fn netorch_call(bytes: *const u8, length: usize) -> *mut c_char {
    let value = if bytes.is_null() || length > MAX_REQUEST_BYTES {
        json!({"ok":false,"error":"Invalid bridge request"})
    } else {
        std::panic::catch_unwind(|| response(unsafe { std::slice::from_raw_parts(bytes, length) }))
            .unwrap_or_else(|_| json!({"ok":false,"error":"Native core request failed"}))
    };
    CString::new(value.to_string())
        .expect("JSON encodes null characters")
        .into_raw()
}
/// # Safety
/// `value` must be null or a still-owned pointer returned by `netorch_call`.
#[no_mangle]
pub unsafe extern "C" fn netorch_free(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reorder_changes_the_order_within_a_backend_group() {
        let dir = tempfile::tempdir().unwrap();
        import_link(dir.path(), "a");
        import_link(dir.path(), "b");
        let profiles = dispatch(
            dir.path(),
            "reorder",
            &json!({"backend": "xray", "ids": "b,a"}),
        )
        .unwrap();
        assert_eq!(profiles[0]["id"], "b");
        assert_eq!(profiles[1]["id"], "a");
        assert!(dispatch(
            dir.path(),
            "reorder",
            &json!({"backend": "xray", "ids": "b"})
        )
        .is_err());
    }

    #[test]
    fn external_vpn_toggle_rejects_malformed_service_ids() {
        let dir = tempfile::tempdir().unwrap();
        let error = dispatch(
            dir.path(),
            "set_external_vpn",
            &json!({"id": "incy; rm -rf /", "connect": "true"}),
        )
        .unwrap_err();
        assert_eq!(error, "Unknown VPN service");
    }

    #[test]
    fn refresh_interval_is_validated_and_failures_are_recorded() {
        let (url, server) =
            serve_bodies(vec!["vless://synthetic@nl.test:443?security=tls#NL".into()]);
        let dir = tempfile::tempdir().unwrap();
        dispatch(
            dir.path(),
            "import_subscription",
            &json!({"id":"sub", "url":url, "hwid":"", "name":""}),
        )
        .unwrap();
        server.join().unwrap();
        let profiles = dispatch(
            dir.path(),
            "set_refresh_interval",
            &json!({"id":"sub", "minutes":"60"}),
        )
        .unwrap();
        assert_eq!(profiles[0]["subscription"]["refreshIntervalMinutes"], 60);
        assert!(dispatch(
            dir.path(),
            "set_refresh_interval",
            &json!({"id":"sub", "minutes":"5"}),
        )
        .is_err());
        let off = dispatch(
            dir.path(),
            "set_refresh_interval",
            &json!({"id":"sub", "minutes":""}),
        )
        .unwrap();
        assert!(off[0]["subscription"]["refreshIntervalMinutes"].is_null());
        // The serving thread is gone, so the refresh fetch fails and is recorded.
        assert!(dispatch(dir.path(), "refresh_subscription", &json!({"id":"sub"})).is_err());
        let profiles = dispatch(dir.path(), "profiles", &json!({})).unwrap();
        assert_eq!(
            profiles[0]["subscription"]["lastRefreshError"],
            "Refresh failed"
        );
    }

    #[test]
    fn exit_ip_through_a_connection_requires_it_to_run() {
        let dir = tempfile::tempdir().unwrap();
        import_link(dir.path(), "rt");
        let error = dispatch(dir.path(), "check_exit_ip", &json!({"via":"rt"})).unwrap_err();
        assert_eq!(error, "Start the connection first");
        let error = dispatch(dir.path(), "check_exit_ip", &json!({"via":"missing"})).unwrap_err();
        assert_eq!(error, "Profile not found");
    }

    #[test]
    fn routing_rules_are_validated_ordered_and_stored() {
        let dir = tempfile::tempdir().unwrap();
        import_link(dir.path(), "rt");
        let profiles = dispatch(
            dir.path(),
            "set_routing_rules",
            &json!({
                "id": "rt",
                "proxy": "domain:youtube.com\ngeosite:google\n# comment",
                "direct": "geoip:ru\n10.0.0.0/8",
                "block": "geosite:category-ads-all",
                "privateLanDirect": "true",
            }),
        )
        .unwrap();
        let policies = &profiles[0]["domainPolicies"];
        assert_eq!(policies[0]["target"], "block");
        assert_eq!(policies[1]["target"], "proxy");
        assert_eq!(policies[1]["domains"][2], "# comment");
        assert_eq!(policies[2]["target"], "direct");
        assert_eq!(profiles[0]["privateLanDirect"], true);
        let error = dispatch(
            dir.path(),
            "set_routing_rules",
            &json!({"id": "rt", "proxy": "geosite:bad category!", "direct": "", "block": ""}),
        )
        .unwrap_err();
        assert!(error.starts_with("Invalid routing rule"), "{error}");
        dispatch(
            dir.path(),
            "create_static",
            &json!({"id":"st", "name":"Static", "interfaceName":"en0", "cidrs":"192.0.2.0/24"}),
        )
        .unwrap();
        assert!(dispatch(
            dir.path(),
            "set_routing_rules",
            &json!({"id": "st", "proxy": "domain:a.test", "direct": "", "block": ""}),
        )
        .is_err());
    }

    #[test]
    fn subscription_panel_title_and_announce_are_stored_and_logged_by_name_only() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).unwrap();
            let body = "vless://synthetic@nl.test:443?security=tls#NL";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nprofile-title: Synthetic Panel\r\nannounce: base64:U2VjcmV0LWZyZWUgbmV3cw==\r\nsupport-url: https://support.example.test/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        dispatch(
            dir.path(),
            "import_subscription",
            &json!({"id":"sub", "url":url, "hwid":"", "name":"Mine"}),
        )
        .unwrap();
        server.join().unwrap();
        let profiles = dispatch(dir.path(), "profiles", &json!({})).unwrap();
        let subscription = &profiles[0]["subscription"];
        assert_eq!(subscription["providerTitle"], "Synthetic Panel");
        assert_eq!(subscription["announce"], "Secret-free news");
        assert_eq!(subscription["supportUrl"], "https://support.example.test/");
        assert_eq!(profiles[0]["name"], "Mine");
        let log = std::fs::read_to_string(dir.path().join("runtime/logs/subscription-import.log"))
            .unwrap();
        assert!(log.contains("announce") && log.contains("profile-title"));
        assert!(!log.contains("Synthetic Panel") && !log.contains("news"));
    }

    #[test]
    fn single_delay_probe_validates_index_and_requires_xray() {
        let first = "vless://synthetic@nl.test:443?security=tls#NL".to_string();
        let (url, server) = serve_bodies(vec![first]);
        let dir = tempfile::tempdir().unwrap();
        dispatch(
            dir.path(),
            "import_subscription",
            &json!({"id":"sub", "url":url, "hwid":"", "name":""}),
        )
        .unwrap();
        server.join().unwrap();
        let error = dispatch(
            dir.path(),
            "measure_delay",
            &json!({"id":"sub", "index":"0"}),
        )
        .unwrap_err();
        assert_eq!(error, "Install Xray to start this connection");
        let error = dispatch(
            dir.path(),
            "measure_delay",
            &json!({"id":"sub", "index":"7"}),
        )
        .unwrap_err();
        assert_eq!(error, "Invalid endpoint index");
    }

    /// Opt-in: NETORCH_XRAY_ARCHIVE=/path/Xray-macos-arm64-v8a.zip. Measures a
    /// loopback VLESS server and an unreachable one through real Xray.
    #[test]
    fn live_delay_probe_measures_reachable_and_unreachable_servers() {
        let Ok(archive) = std::env::var("NETORCH_XRAY_ARCHIVE") else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        dispatch(root, "install_xray", &json!({"archivePath": archive})).unwrap();
        let server_binary = root.join("xray-server");
        std::fs::copy(root.join("backends/xray/v26.7.28/xray"), &server_binary).unwrap();
        let uuid = "6f1d1b8e-3c2a-4d5e-9f00-112233445566";
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        std::fs::write(
            root.join("server.json"),
            format!(
                r#"{{"inbounds":[{{"listen":"127.0.0.1","port":{port},"protocol":"vless","settings":{{"clients":[{{"id":"{uuid}"}}],"decryption":"none"}},"streamSettings":{{"network":"tcp","security":"none"}}}}],"dns":{{"servers":["https://1.1.1.1/dns-query"]}},"outbounds":[{{"protocol":"freedom","settings":{{"domainStrategy":"UseIPv4"}}}}]}}"#
            ),
        )
        .unwrap();
        let mut server = std::process::Command::new(&server_binary)
            .args(["run", "-c"])
            .arg(root.join("server.json"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let body = format!(
            "vless://{uuid}@127.0.0.1:{port}?security=none&type=tcp#Loopback\nvless://{uuid}@127.0.0.1:1?security=none&type=tcp#Closed"
        );
        let (url, http) = serve_bodies(vec![body]);
        dispatch(
            root,
            "import_subscription",
            &json!({"id":"sub", "url":url, "hwid":"", "name":""}),
        )
        .unwrap();
        http.join().unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let results = dispatch(root, "measure_delays", &json!({"id":"sub"})).unwrap();
        server.kill().unwrap();
        server.wait().unwrap();
        eprintln!("delays: {results}");
        assert!(results[0]["delayMs"].as_u64().is_some());
        assert!(results[1]["delayMs"].is_null());
    }

    /// Serves each body once on a fresh loopback port and records request heads.
    fn serve_bodies(bodies: Vec<String>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut heads = Vec::new();
            for body in bodies {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let size = stream.read(&mut request).unwrap();
                heads.push(String::from_utf8_lossy(&request[..size]).to_ascii_lowercase());
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
            heads
        });
        (url, handle)
    }

    #[test]
    fn refresh_subscription_refetches_with_the_stored_hwid() {
        let first = "vless://synthetic@nl.test:443?security=tls#NL".to_string();
        let second = "vless://synthetic@nl.test:443?security=tls#NL\nvless://synthetic@de.test:443?security=tls#DE".to_string();
        let (url, server) = serve_bodies(vec![first, second]);
        let dir = tempfile::tempdir().unwrap();
        dispatch(
            dir.path(),
            "import_subscription",
            &json!({"id":"sub", "url":url, "hwid":"stable-hwid", "name":"Mine"}),
        )
        .unwrap();
        let outcome = dispatch(dir.path(), "refresh_subscription", &json!({"id":"sub"})).unwrap();
        assert_eq!(outcome["endpointCount"], 2);
        assert_eq!(outcome["activeIndex"], 0);
        let heads = server.join().unwrap();
        assert!(heads
            .iter()
            .all(|head| head.contains("x-hwid: stable-hwid")));
        let names = dispatch(dir.path(), "subscription_endpoints", &json!({"id":"sub"})).unwrap();
        assert_eq!(names[1]["name"], "DE");
        let profiles = dispatch(dir.path(), "profiles", &json!({})).unwrap();
        assert_eq!(profiles[0]["name"], "Mine");
    }

    #[test]
    fn measuring_delays_requires_a_subscription() {
        let dir = tempfile::tempdir().unwrap();
        dispatch(
            dir.path(),
            "import_share_link",
            &json!({"id":"one", "name":"", "link":"vless://00000000-0000-4000-8000-000000000000@nl.test:443?security=tls#NL"}),
        )
        .unwrap();
        let error = dispatch(dir.path(), "measure_delays", &json!({"id":"one"})).unwrap_err();
        assert_eq!(error, "Delay checks are available for subscriptions");
    }

    #[test]
    fn generated_hwid_is_stable_for_the_same_data_directory() {
        let dir = tempfile::tempdir().unwrap();
        let first = dispatch(dir.path(), "generate_hwid", &json!({})).unwrap();
        let second = dispatch(dir.path(), "generate_hwid", &json!({})).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.as_str().unwrap().len(), 36);
    }

    use super::*;
    use net_manager_core::profiles::ProfileStore;

    #[test]
    fn subscription_url_import_fetches_synthetic_body_and_redacts_all_responses() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/private-subscription-token",
            listener.local_addr().unwrap()
        );
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            let size = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..size])
                .to_ascii_lowercase()
                .contains("x-hwid: synthetic-private-hwid"));
            let body = "vless://synthetic-private-id@one.test:443?security=tls#First\nhy2://synthetic-private-password@two.test:443#Second\ntrojan://unsupported@three.test:443";
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSubscription-Userinfo: upload=100; download=200; total=1000\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let imported = dispatch(
            dir.path(),
            "import_subscription",
            &json!({"id":"sub", "url":url, "hwid":"synthetic-private-hwid", "name":""}),
        )
        .unwrap();
        server.join().unwrap();
        let log = std::fs::read_to_string(dir.path().join("runtime/logs/subscription-import.log"))
            .unwrap();
        assert!(log.contains("hwid=sent") && log.contains("vless×1") && log.contains("result=ok"));
        for secret in [
            "private-subscription-token",
            "synthetic-private",
            "one.test",
            "First",
        ] {
            assert!(!log.contains(secret), "log leaked {secret}");
        }
        assert_eq!(imported["profiles"][0]["subscription"]["endpointCount"], 2);
        assert_eq!(imported["skippedCount"], 1);
        for result in [
            imported,
            dispatch(dir.path(), "profiles", &json!({})).unwrap(),
            dispatch(dir.path(), "rename", &json!({"id":"sub", "name":"Renamed"})).unwrap(),
        ] {
            let output = result.to_string();
            for secret in [
                "private-subscription-token",
                "synthetic-private-hwid",
                "synthetic-private-id",
                "synthetic-private-password",
            ] {
                assert!(!output.contains(secret));
            }
        }
        let endpoints =
            dispatch(dir.path(), "subscription_endpoints", &json!({"id":"sub"})).unwrap();
        assert_eq!(endpoints[1]["name"], "Second");
        let switched = dispatch(
            dir.path(),
            "switch_subscription_endpoint",
            &json!({"id":"sub", "index":"1"}),
        )
        .unwrap();
        assert_eq!(switched[0]["subscription"]["activeIndex"], 1);
        assert!(!switched.to_string().contains("synthetic-private-password"));
    }

    #[test]
    fn share_links_create_managed_profiles_without_returning_credentials() {
        let dir = tempfile::tempdir().unwrap();
        for (id, link, expected_name) in [
            (
                "vless-node",
                "vless://synthetic-private-id@node.test:443?security=tls#Lab%20Node",
                "Lab Node",
            ),
            (
                "hy2-node",
                "hy2://synthetic-private-password@node.test:443#Second",
                "Second",
            ),
        ] {
            let result = dispatch(
                dir.path(),
                "import_share_link",
                &json!({"id":id,"name":"","link":link}),
            )
            .unwrap();
            assert!(!result.to_string().contains("synthetic-private"));
            let profiles = ProfileStore::new(dir.path().join("profiles.json"))
                .load()
                .unwrap()
                .profiles;
            let profile = profiles.iter().find(|p| p.id == id).unwrap();
            assert_eq!(profile.name, expected_name);
            assert_eq!(profile.backend, TunnelBackend::Xray);
            assert!(!profile.auto_connect);
            assert!(!profile.use_system_proxy);
            assert!(profile.routes.is_empty());
            assert!(ConfigVault::new(dir.path().join("configs"))
                .is_managed_profile_path(id, &profile.config_path));
            let inspection = analysis::analyze_profile(profile).unwrap();
            assert_eq!(inspection.listeners.len(), 2);
            assert!(inspection
                .listeners
                .iter()
                .all(|l| l.address == "127.0.0.1"));
        }
        let profiles = ProfileStore::new(dir.path().join("profiles.json"))
            .load()
            .unwrap()
            .profiles;
        let ports = profiles
            .iter()
            .flat_map(|p| [p.xray_socks_port.unwrap(), p.xray_http_port.unwrap()])
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ports.len(), 4);
    }

    #[test]
    fn rejected_share_links_do_not_leak_secrets_or_write_profiles() {
        let dir = tempfile::tempdir().unwrap();
        for link in [
            "https://node.test/private-token",
            "vless://private-token@:443",
            "trojan://private-token@node.test:443",
            "hy2://private-token@node.test?obfs=invalid",
        ] {
            let error = dispatch(
                dir.path(),
                "import_share_link",
                &json!({"id":"bad","name":"","link":link}),
            )
            .unwrap_err();
            assert!(!error.contains("private-token"));
            assert!(!dir.path().join("profiles.json").exists());
            assert!(!dir.path().join("configs").exists());
        }
    }

    #[test]
    fn supported_native_capabilities_do_not_advertise_privileged_operations() {
        let dir = tempfile::tempdir().unwrap();
        let result = dispatch(dir.path(), "capabilities", &json!({})).unwrap();
        assert_eq!(result["os"], "macos");
        assert_eq!(result["minimumOS"], "27.0");
        assert_eq!(result["nativeUI"], true);
        assert_eq!(result["networkMutations"], false);
    }

    #[test]
    fn static_profile_creation_uses_core_validation_and_can_be_renamed() {
        let dir = tempfile::tempdir().unwrap();
        let args = json!({"id":"test-profile", "name":"Lab routes", "interfaceName":"en0", "cidrs":"10.77.0.0/25, 10.77.0.128/25"});
        dispatch(dir.path(), "create_static", &args).unwrap();
        dispatch(
            dir.path(),
            "rename",
            &json!({"id":"test-profile", "name":"Renamed"}),
        )
        .unwrap();
        let doc = ProfileStore::new(dir.path().join("profiles.json"))
            .load()
            .unwrap();
        assert_eq!(doc.profiles[0].name, "Renamed");
        assert_eq!(doc.profiles[0].routes.len(), 1);
        assert_eq!(
            doc.profiles[0].routes[0].destination.to_string(),
            "10.77.0.0/24"
        );
    }

    #[test]
    fn invalid_static_routes_do_not_write_a_document() {
        let dir = tempfile::tempdir().unwrap();
        assert!(dispatch(
            dir.path(),
            "create_static",
            &json!({"id":"bad", "name":"Lab", "interfaceName":"en0", "cidrs":"not-a-route"})
        )
        .is_err());
        assert!(!dir.path().join("profiles.json").exists());
    }

    #[test]
    fn imports_are_vault_managed_and_never_return_config_text() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.json");
        let secret = "synthetic-private-value";
        std::fs::write(&source, json!({"inbounds":[],"outbounds":[{"protocol":"freedom","settings":{"password":secret}}]}).to_string()).unwrap();
        let result = dispatch(
            dir.path(),
            "import",
            &json!({"id":"imported", "name":"Lab", "backend":"xray", "path":source}),
        )
        .unwrap();
        assert!(!result.to_string().contains(secret));
        let doc = ProfileStore::new(dir.path().join("profiles.json"))
            .load()
            .unwrap();
        assert!(doc.profiles[0]
            .config_path
            .starts_with(dir.path().join("configs")));
    }

    #[test]
    fn openvpn_import_preserves_static_routes() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("client.ovpn");
        std::fs::write(
            &source,
            "client\nremote vpn.example\nroute 10.20.0.0 255.255.0.0\n",
        )
        .unwrap();
        let result = dispatch(
            dir.path(),
            "import",
            &json!({"id":"ovpn", "name":"Lab", "backend":"openVpn", "path":source}),
        )
        .unwrap();
        assert_eq!(result[0]["routes"][0]["destination"], "10.20.0.0/16");
    }

    #[test]
    fn openvpn_import_reports_unsupported_routes_and_missing_assets() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("client.ovpn");
        let request = json!({"id":"ovpn", "name":"Lab", "backend":"openVpn", "path":source});
        std::fs::write(
            &source,
            "client\nremote vpn.example\nroute 10.0.0.0 255.0.0.0 net_gateway\n",
        )
        .unwrap();
        assert_eq!(
            dispatch(dir.path(), "import", &request).unwrap_err(),
            "unsupported OpenVPN route directive"
        );
        std::fs::write(
            &source,
            "client\nremote vpn.example\npkcs12 missing-secret.p12\n",
        )
        .unwrap();
        assert_eq!(
            dispatch(dir.path(), "import", &request).unwrap_err(),
            "OpenVPN referenced asset is missing"
        );
    }

    #[test]
    fn rejected_import_does_not_leave_a_vault_revision() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.json");
        std::fs::write(&source, r#"{"inbounds":[],"outbounds":[]}"#).unwrap();
        assert!(dispatch(
            dir.path(),
            "import",
            &json!({"id":"incomplete", "name":"", "backend":"xray", "path":source})
        )
        .is_err());
        assert!(!dir.path().join("configs/incomplete").exists());
        assert!(!dir.path().join("profiles.json").exists());
    }

    #[test]
    fn c_abi_rejects_invalid_buffers_and_returns_owned_json() {
        // Invalid length is rejected before dereferencing the input pointer.
        for (input, length) in [
            (std::ptr::null(), 1),
            (b"x".as_ptr(), MAX_REQUEST_BYTES + 1),
            (b"{".as_ptr(), 1),
        ] {
            let owned = unsafe { netorch_call(input, length) };
            let result: Value =
                serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(owned) }.to_bytes())
                    .unwrap();
            assert_eq!(result["ok"], false);
            unsafe { netorch_free(owned) };
        }
        let dir = tempfile::tempdir().unwrap();
        let request = json!({"root":dir.path(), "method":"capabilities"}).to_string();
        let owned = unsafe { netorch_call(request.as_ptr(), request.len()) };
        let result: Value =
            serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(owned) }.to_bytes()).unwrap();
        assert_eq!(result["data"]["minimumOS"], "27.0");
        unsafe {
            netorch_free(owned);
            netorch_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn unavailable_mutations_fail_without_writing_or_starting_a_process() {
        let dir = tempfile::tempdir().unwrap();
        for method in [
            "connect",
            "set_interface_state",
            "set_dns",
            "set_system_proxy",
        ] {
            assert!(dispatch(dir.path(), method, &json!({})).is_err());
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// Privileged methods belong to the daemon protocol and, on macOS, to the
    /// planned launchd helper — never to this in-process bridge
    /// (docs/plans/2026-09-30-14-macos-privileged-helper.md).
    #[test]
    fn daemon_protocol_methods_are_never_served_by_the_bridge() {
        use net_manager_core::daemon_protocol::method;
        let dir = tempfile::tempdir().unwrap();
        for name in method::CAPABILITIES.iter().chain(&[method::HELLO]) {
            assert!(
                dispatch(dir.path(), name, &json!({})).is_err(),
                "bridge must not implement daemon method {name}"
            );
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn import_link(root: &Path, id: &str) {
        dispatch(
            root,
            "import_share_link",
            &json!({"id":id, "name":"Runtime", "link":"vless://00000000-0000-4000-8000-000000000000@one.test:443?security=tls#One"}),
        )
        .unwrap();
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn runtime_reports_stopped_profiles_and_missing_xray() {
        let dir = tempfile::tempdir().unwrap();
        import_link(dir.path(), "rt");
        let runtime = dispatch(dir.path(), "runtime", &json!({})).unwrap();
        assert_eq!(runtime["xrayInstalled"], false);
        assert_eq!(runtime["systemProxyOwner"], Value::Null);
        assert_eq!(runtime["statuses"][0]["profileId"], "rt");
        assert_eq!(runtime["statuses"][0]["state"], "stopped");
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn connect_requires_managed_xray_and_refuses_privileged_backends() {
        let dir = tempfile::tempdir().unwrap();
        import_link(dir.path(), "rt");
        let error = dispatch(dir.path(), "connect", &json!({"id":"rt"})).unwrap_err();
        assert_eq!(error, "Install Xray to start this connection");
        dispatch(
            dir.path(),
            "create_static",
            &json!({"id":"st", "name":"Static", "interfaceName":"en0", "cidrs":"192.0.2.0/24"}),
        )
        .unwrap();
        let error = dispatch(dir.path(), "connect", &json!({"id":"st"})).unwrap_err();
        assert!(error.contains("privileged helper"), "{error}");
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn system_proxy_and_disconnect_require_a_running_connection() {
        let dir = tempfile::tempdir().unwrap();
        import_link(dir.path(), "rt");
        let error = dispatch(
            dir.path(),
            "set_system_proxy",
            &json!({"id":"rt", "enabled":"true"}),
        )
        .unwrap_err();
        assert_eq!(error, "Start the connection first");
        assert!(dispatch(dir.path(), "disconnect", &json!({"id":"rt"})).is_err());
        // Shutdown with nothing running is a no-op and never touches the system proxy.
        dispatch(dir.path(), "shutdown", &json!({})).unwrap();
    }
}
