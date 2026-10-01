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

fn runtime() -> Result<&'static tokio::runtime::Runtime, String> {
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
fn encode(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|_| "Could not encode the result".into())
}
fn dispatch(root: &Path, method: &str, args: &Value) -> Result<Value, String> {
    if !root.is_absolute() {
        return Err("App data location must be absolute".into());
    }
    let _lock = TRANSACTION
        .lock()
        .map_err(|_| "Profile service is unavailable".to_string())?;
    let store = ProfileStore::new(root.join("profiles.json"));
    let vault = ConfigVault::new(root.join("configs"));
    match method {
        "capabilities" => Ok(json!({"os":"macos", "minimumOS":"27.0", "nativeUI":true,
            "profiles":true,"networkInventory":true,"networkMutations":false,
            "systemVPN":"providerSetupRequired", "version":env!("CARGO_PKG_VERSION")})),
        "profiles" => encode(net_manager_core::subscription::public_profiles(
            store.load().map_err(store_error)?.profiles,
        )),
        "snapshot" => {
            let profiles = net_manager_core::subscription::public_profiles(
                store.load().map_err(store_error)?.profiles,
            );
            let interfaces = explorer::list_interfaces();
            let routes = runtime()?.block_on(explorer::list_routes());
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
                runtime()?
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
            let fetched = runtime()?
                .block_on(net_manager_core::subscription::fetch(&client, url, hwid))
                .map_err(subscription_error)?;
            let request = net_manager_core::subscription::SubscriptionImport {
                id,
                url,
                hwid,
                name,
                refresh_interval_minutes: None,
            };
            let imported = net_manager_core::subscription::import_body(
                &vault,
                &store,
                &request,
                &fetched.body,
                fetched.user_info,
                local_port_available,
            )
            .map_err(subscription_error)?;
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
            let imported = vault
                .import(id, backend, Path::new(path))
                .map_err(store_error)?;
            let p = Profile {
                id: id.into(),
                name: name.into(),
                backend,
                config_path: imported.config_path.clone(),
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
}
