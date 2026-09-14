use crate::state::{existing_profile_for_update, find_profile, AppState};
use net_manager_core::analysis;
use net_manager_core::config_security;
use net_manager_core::config_vault::{ConfigImport, ConfigVault};
use net_manager_core::models::*;
use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;

const AUTO_SOCKS_PORT_START: u16 = 10808;
const AUTO_SOCKS_PORT_END: u16 = 10999;

pub(crate) fn select_available_socks_port(
    used: &HashSet<u16>,
    available: impl Fn(u16) -> bool,
) -> Result<u16, String> {
    (AUTO_SOCKS_PORT_START..=AUTO_SOCKS_PORT_END)
        .find(|port| !used.contains(port) && available(*port))
        .ok_or_else(|| {
            format!(
                "no available SOCKS5 port in automatic range {AUTO_SOCKS_PORT_START}-{AUTO_SOCKS_PORT_END}"
            )
        })
}

pub(crate) fn profile_listener_ports(profiles: &[Profile], exclude_id: &str) -> HashSet<u16> {
    let mut ports = HashSet::new();
    for profile in profiles {
        if profile.id == exclude_id {
            continue;
        }
        if let Some(port) = profile.xray_socks_port {
            ports.insert(port);
        }
        if let Ok(analysis) = analysis::analyze_profile(profile) {
            for listener in &analysis.listeners {
                if matches!(
                    listener.address.as_str(),
                    "127.0.0.1" | "0.0.0.0" | "::" | ""
                ) {
                    ports.insert(listener.port);
                }
            }
        }
    }
    ports
}

pub(crate) fn loopback_port_available(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

pub(crate) fn store_generated_xray(
    vault: &ConfigVault,
    profile_id: &str,
    plaintext_json: &[u8],
) -> std::io::Result<ConfigImport> {
    #[cfg(windows)]
    {
        let encrypted = config_security::protect_user_data(
            plaintext_json,
            &config_security::xray_context(profile_id),
        )?;
        vault.store_protected_xray_config(profile_id, &encrypted)
    }
    #[cfg(not(windows))]
    {
        vault.store_xray_config(profile_id, plaintext_json)
    }
}

pub(crate) fn rewrite_generated_socks_port(
    vault: &ConfigVault,
    profile: &mut Profile,
    new_port: u16,
) -> Result<PathBuf, String> {
    if profile.backend != TunnelBackend::Xray
        || profile.xray_socks_port.is_none()
        || !vault.is_managed_profile_path(&profile.id, &profile.config_path)
    {
        return Err("profile does not use a managed generated Xray config".into());
    }
    let bytes = config_security::read_xray_config(&profile.config_path, &profile.id)
        .map_err(|e| e.to_string())?;
    let mut doc: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let inbounds = doc
        .get_mut("inbounds")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "generated config has no inbounds array".to_string())?;
    let inbound = inbounds
        .iter_mut()
        .find(|i| i.get("tag").and_then(|t| t.as_str()) == Some("socks-in"))
        .ok_or_else(|| "generated config has no 'socks-in' inbound".to_string())?;
    inbound["port"] = serde_json::json!(new_port);
    let body = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
    let import = store_generated_xray(vault, &profile.id, &body).map_err(|e| e.to_string())?;
    profile.config_path = import.config_path.clone();
    profile.xray_socks_port = Some(new_port);
    Ok(import.config_path)
}

pub(crate) fn remove_managed_revision(
    vault: &ConfigVault,
    profile_id: &str,
    path: &Path,
    action: &str,
) -> Result<(), String> {
    if !vault.is_managed_profile_path(profile_id, path) {
        return Ok(());
    }
    vault.remove_revision_for_config(path).map_err(|err| {
        format!(
            "{action}, but managed config cleanup failed for '{}': {err}",
            path.display()
        )
    })
}

fn validate_managed_save_path(
    vault: &ConfigVault,
    stored: Option<&Profile>,
    profile: &Profile,
) -> Result<(), String> {
    if !vault.is_managed_path(&profile.config_path) {
        return Ok(());
    }
    if !vault.is_managed_profile_path(&profile.id, &profile.config_path) {
        return Err(format!(
            "config path '{}' is managed by a different profile",
            profile.config_path.display()
        ));
    }
    if let Some(existing) = stored {
        if existing.config_path == profile.config_path && existing.backend != profile.backend {
            return Err(
                "changing backend requires selecting or importing a new source config".into(),
            );
        }
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn get_profiles(state: State<'_, AppState>) -> Result<Vec<Profile>, String> {
    state
        .profiles
        .load()
        .map(|doc| doc.profiles)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn save_profile(
    mut profile: Profile,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let document = state.profiles.load().map_err(|e| e.to_string())?;
    let stored = existing_profile_for_update(&document, &profile.id).cloned();
    if let Some(existing) = &stored {
        let mut runtime = state.runtime.lock().await;
        if runtime.tunnels.status(existing).state == TunnelState::Running {
            return Err(format!(
                "profile '{}' is running; disconnect before editing",
                profile.id
            ));
        }
    }
    validate_managed_save_path(&state.config_vault, stored.as_ref(), &profile)?;
    let imported = if profile.backend == TunnelBackend::None
        || state.config_vault.is_managed_path(&profile.config_path)
    {
        None
    } else {
        let import = state
            .config_vault
            .import(&profile.id, profile.backend, &profile.config_path)
            .map_err(|e| e.to_string())?;
        profile.config_path = import.config_path.clone();
        Some(import.config_path)
    };
    let new_path = profile.config_path.clone();
    let doc = match state.profiles.upsert(profile) {
        Ok(doc) => doc,
        Err(err) => {
            if let Some(path) = imported {
                let _ = state.config_vault.remove_revision_for_config(&path);
            }
            return Err(err.to_string());
        }
    };
    if let Some(existing) = stored {
        if existing.config_path != new_path {
            remove_managed_revision(
                &state.config_vault,
                &existing.id,
                &existing.config_path,
                "profile saved",
            )?;
        }
    }
    Ok(doc.profiles)
}

#[tauri::command]
pub(crate) async fn delete_profile(
    id: String,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    let profile = find_profile(&state.profiles, &id)?;
    {
        let mut runtime = state.runtime.lock().await;
        if runtime.tunnels.status(&profile).state == TunnelState::Running {
            return Err(format!(
                "profile '{id}' is running; disconnect before deleting"
            ));
        }
        if runtime.policies.has_applied_profile(&id) {
            return Err(format!(
                "profile '{id}' has applied routes; disconnect before deleting"
            ));
        }
    }
    let doc = state.profiles.delete(&id).map_err(|e| e.to_string())?;
    state
        .config_vault
        .remove_profile(&id)
        .map_err(|err| format!("profile deleted, but managed config cleanup failed: {err}"))?;
    Ok(doc.profiles)
}

#[tauri::command]
pub(crate) async fn save_vless_profile(
    mut profile: Profile,
    vless_url: String,
    state: State<'_, AppState>,
) -> Result<Vec<Profile>, String> {
    if profile.backend != TunnelBackend::Xray {
        return Err("vless import requires an Xray profile".into());
    }
    let document = state.profiles.load().map_err(|e| e.to_string())?;
    let socks_port = match profile.xray_socks_port {
        Some(port) if port != 0 => port,
        _ => {
            let used = profile_listener_ports(&document.profiles, &profile.id);
            select_available_socks_port(&used, loopback_port_available)?
        }
    };
    profile.xray_socks_port = Some(socks_port);
    let stored = existing_profile_for_update(&document, &profile.id).cloned();
    if let Some(existing) = &stored {
        let mut runtime = state.runtime.lock().await;
        if runtime.tunnels.status(existing).state == TunnelState::Running {
            return Err(format!(
                "profile '{}' is running; disconnect before editing",
                profile.id
            ));
        }
    }
    let config = net_manager_core::xray::generate_vless_config(vless_url.trim(), socks_port)
        .map_err(|e| format!("invalid VLESS URL: {e}"))?;
    let body = serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?;
    let import =
        store_generated_xray(&state.config_vault, &profile.id, &body).map_err(|e| e.to_string())?;
    profile.config_path = import.config_path.clone();
    let doc = match state.profiles.upsert(profile) {
        Ok(doc) => doc,
        Err(err) => {
            let _ = state
                .config_vault
                .remove_revision_for_config(&import.config_path);
            return Err(err.to_string());
        }
    };
    if let Some(existing) = stored {
        if existing.config_path != import.config_path {
            remove_managed_revision(
                &state.config_vault,
                &existing.id,
                &existing.config_path,
                "profile saved",
            )?;
        }
    }
    Ok(doc.profiles)
}

/// Detect a tunnel backend for `path` by extension, with a small content sniff
/// for the ambiguous `.conf` case (WireGuard and OpenVPN both use it).
/// Returns `None` when the extension is unrecognized and no `default` hint is
/// given.
pub(crate) fn detect_backend(path: &Path, default: Option<TunnelBackend>) -> Option<TunnelBackend> {
    let lower = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    if lower.ends_with(".ovpn") {
        return Some(TunnelBackend::OpenVpn);
    }
    if lower.ends_with(".json") {
        return Some(TunnelBackend::Xray);
    }
    if lower.ends_with(".conf.dpapi") {
        return Some(TunnelBackend::WireGuard);
    }
    if lower.ends_with(".conf") {
        if let Ok(bytes) = fs::read(path) {
            let head = String::from_utf8_lossy(&bytes[..bytes.len().min(2048)]);
            if head.contains("[Interface]") {
                return Some(TunnelBackend::WireGuard);
            }
            for line in head.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("dev ")
                    || trimmed.starts_with("proto ")
                    || trimmed == "client"
                    || trimmed.starts_with("remote ")
                {
                    return Some(TunnelBackend::OpenVpn);
                }
            }
        }
        return default;
    }
    default
}

fn backend_label(backend: TunnelBackend) -> &'static str {
    match backend {
        TunnelBackend::None => "Static routes",
        TunnelBackend::WireGuard => "WireGuard",
        TunnelBackend::OpenVpn => "OpenVPN",
        TunnelBackend::Xray => "Xray",
    }
}

fn generate_import_id(index: usize) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("import-{nanos:x}-{index}")
}

/// Pure, testable core of `import_configs_batch`: imports each path into the
/// vault and upserts a profile, collecting per-file errors instead of aborting.
pub(crate) fn import_configs_into(
    vault: &ConfigVault,
    store: &net_manager_core::profiles::ProfileStore,
    paths: &[String],
    default_backend: Option<TunnelBackend>,
) -> std::io::Result<BatchImportResult> {
    let mut errors: Vec<BatchImportError> = Vec::new();
    for (index, raw) in paths.iter().enumerate() {
        let path = PathBuf::from(raw);
        let backend = match detect_backend(&path, default_backend) {
            Some(b) => b,
            None => {
                errors.push(BatchImportError {
                    path: raw.clone(),
                    error: "could not determine backend from extension; set a default backend"
                        .into(),
                });
                continue;
            }
        };
        let id = generate_import_id(index);
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{} {}", backend_label(backend), index + 1));
        let import = match vault.import(&id, backend, &path) {
            Ok(import) => import,
            Err(err) => {
                errors.push(BatchImportError {
                    path: raw.clone(),
                    error: err.to_string(),
                });
                continue;
            }
        };
        let config_path = import.config_path.clone();
        let profile = Profile {
            id: id.clone(),
            name,
            backend,
            config_path,
            interface_name: String::new(),
            routes: vec![],
            auto_connect: false,
            domain_policies: vec![],
            xray_socks_port: None,
            use_system_proxy: false,
            proxy_bypass: vec![],
        };
        if let Err(err) = store.upsert(profile) {
            let _ = vault.remove_revision_for_config(&import.config_path);
            errors.push(BatchImportError {
                path: raw.clone(),
                error: err.to_string(),
            });
        }
    }
    let profiles = store.load()?.profiles;
    Ok(BatchImportResult { profiles, errors })
}

#[tauri::command]
pub(crate) async fn import_configs_batch(
    paths: Vec<String>,
    default_backend: Option<TunnelBackend>,
    state: State<'_, AppState>,
) -> Result<BatchImportResult, String> {
    import_configs_into(
        &state.config_vault,
        &state.profiles,
        &paths,
        default_backend,
    )
    .map_err(|e| e.to_string())
}

/// Decode a v2ray-style subscription body (base64) into a list of proxy URLs.
/// Non-base64 input is treated as plain text (one URL per line). Only
/// `vless://` lines are returned; others are silently skipped.
pub(crate) fn parse_subscription_body(body: &str) -> Vec<String> {
    let decoded = base64_decode(body.trim()).unwrap_or_else(|| body.to_string());
    decoded
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("vless://"))
        .map(str::to_string)
        .collect()
}

/// Best-effort standard base64 decoder that tolerates missing padding and
/// whitespace. Returns `None` if the input is not valid base64.
fn base64_decode(input: &str) -> Option<String> {
    use base64::Engine;
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let decoded = engine.decode(&cleaned).ok()?;
    String::from_utf8(decoded).ok()
}

/// Pure, testable core of `import_subscription`: fetches the subscription
/// URL with the given HWID, decodes the body, and creates one Xray/VLESS
/// profile per `vless://` entry. Per-entry errors are collected instead of
/// aborting the batch.
pub(crate) async fn import_subscription_into(
    vault: &ConfigVault,
    store: &net_manager_core::profiles::ProfileStore,
    client: &reqwest::Client,
    url: &str,
    hwid: &str,
) -> Result<BatchImportResult, String> {
    let response = client
        .get(url)
        .header("X-HWID", hwid)
        .send()
        .await
        .map_err(|e| format!("subscription fetch failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "subscription fetch returned HTTP {}",
            response.status()
        ));
    }
    let body = response
        .text()
        .await
        .map_err(|e| format!("failed to read subscription body: {e}"))?;
    let urls = parse_subscription_body(&body);
    if urls.is_empty() {
        return Err("subscription contained no vless:// entries".into());
    }

    let document = store.load().map_err(|e| e.to_string())?;
    let mut used_ports = profile_listener_ports(&document.profiles, "");
    let mut errors: Vec<BatchImportError> = Vec::new();

    for (index, vless_url) in urls.iter().enumerate() {
        let id = generate_import_id(index);
        let socks_port = match select_available_socks_port(&used_ports, loopback_port_available) {
            Ok(port) => port,
            Err(err) => {
                errors.push(BatchImportError {
                    path: vless_url.clone(),
                    error: err,
                });
                continue;
            }
        };
        used_ports.insert(socks_port);

        let config =
            match net_manager_core::xray::generate_vless_config(vless_url.trim(), socks_port) {
                Ok(config) => config,
                Err(err) => {
                    errors.push(BatchImportError {
                        path: vless_url.clone(),
                        error: format!("invalid VLESS URL: {err}"),
                    });
                    continue;
                }
            };
        let body = match serde_json::to_vec_pretty(&config) {
            Ok(bytes) => bytes,
            Err(err) => {
                errors.push(BatchImportError {
                    path: vless_url.clone(),
                    error: err.to_string(),
                });
                continue;
            }
        };
        let import = match store_generated_xray(vault, &id, &body) {
            Ok(import) => import,
            Err(err) => {
                errors.push(BatchImportError {
                    path: vless_url.clone(),
                    error: err.to_string(),
                });
                continue;
            }
        };
        let name = net_manager_core::xray::parse_vless_url(vless_url.trim())
            .ok()
            .and_then(|p| p.name)
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| format!("VLESS {}", index + 1));
        let profile = Profile {
            id: id.clone(),
            name,
            backend: TunnelBackend::Xray,
            config_path: import.config_path.clone(),
            interface_name: String::new(),
            routes: vec![],
            auto_connect: false,
            domain_policies: vec![],
            xray_socks_port: Some(socks_port),
            use_system_proxy: false,
            proxy_bypass: vec![],
        };
        if let Err(err) = store.upsert(profile) {
            let _ = vault.remove_revision_for_config(&import.config_path);
            errors.push(BatchImportError {
                path: vless_url.clone(),
                error: err.to_string(),
            });
        }
    }

    let profiles = store.load().map_err(|e| e.to_string())?.profiles;
    Ok(BatchImportResult { profiles, errors })
}

#[tauri::command]
pub(crate) async fn import_subscription(
    url: String,
    hwid: String,
    state: State<'_, AppState>,
) -> Result<BatchImportResult, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("v2rayng/1.0")
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    import_subscription_into(&state.config_vault, &state.profiles, &client, &url, &hwid).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use base64::Engine;
    use std::fs;

    #[test]
    fn validate_managed_save_path_rejects_foreign_and_backend_swap() {
        let dir = unique_dir("managed-save");
        let vault = ConfigVault::new(dir.join("configs"));
        let source = dir.join("src.conf");
        fs::write(&source, b"[Interface]\n").unwrap();
        let import = vault
            .import("owner", TunnelBackend::WireGuard, &source)
            .unwrap();

        let mut incoming = profile("wg");
        incoming.id = "owner".into();
        incoming.config_path = import.config_path.clone();
        let stored = incoming.clone();

        assert!(
            validate_managed_save_path(&vault, Some(&stored), &incoming).is_ok(),
            "same profile, same backend, own managed path"
        );

        let mut foreign = incoming.clone();
        foreign.id = "other".into();
        let err = validate_managed_save_path(&vault, None, &foreign).unwrap_err();
        assert!(err.contains("different profile"), "{err}");

        let mut swapped = incoming.clone();
        swapped.backend = TunnelBackend::OpenVpn;
        let err = validate_managed_save_path(&vault, Some(&stored), &swapped).unwrap_err();
        assert!(err.contains("new source config"), "{err}");

        let mut external = profile("ext");
        external.config_path = dir.join("external.conf");
        assert!(validate_managed_save_path(&vault, None, &external).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn store_generated_xray_writes_platform_appropriate_revision() {
        let dir = unique_dir("gen-xray");
        let vault = ConfigVault::new(dir.join("configs"));
        let body = br#"{"inbounds":[]}"#.to_vec();
        let import = store_generated_xray(&vault, "node-auto", &body).unwrap();
        #[cfg(windows)]
        {
            assert_eq!(import.config_path.file_name().unwrap(), "config.json.dpapi");
            let plain = net_manager_core::config_security::read_xray_config(
                &import.config_path,
                "node-auto",
            )
            .unwrap();
            assert_eq!(plain, body);
            assert_ne!(fs::read(&import.config_path).unwrap(), body);
        }
        #[cfg(not(windows))]
        {
            assert_eq!(import.config_path.file_name().unwrap(), "config.json");
            assert_eq!(fs::read(&import.config_path).unwrap(), body);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn vless_generation_errors_do_not_leak_uri() {
        let sentinel = "SENTINEL-UUID-7777";
        let err = net_manager_core::xray::generate_vless_config(
            &format!("vless://{sentinel}@:443?security=tls&sni=x"),
            10808,
        )
        .unwrap_err();
        assert!(!err.to_string().contains(sentinel));
        assert!(net_manager_core::xray::generate_vless_config(
            "vless://id@node.test:443?security=tls&sni=x",
            0,
        )
        .is_err());
    }

    #[test]
    fn select_available_socks_port_skips_used_and_unavailable() {
        let used: HashSet<u16> = [10808, 10809].into_iter().collect();
        let port = select_available_socks_port(&used, |p| p != 10810).unwrap();
        assert_eq!(port, 10811);
        assert_eq!(
            select_available_socks_port(&HashSet::new(), |_| true).unwrap(),
            AUTO_SOCKS_PORT_START
        );
    }

    #[test]
    fn select_available_socks_port_errors_when_exhausted() {
        let err = select_available_socks_port(&HashSet::new(), |_| false).unwrap_err();
        assert!(err.contains("10808"), "{err}");
    }

    #[test]
    fn profile_listener_ports_collects_metadata_and_loopback_listeners() {
        let dir = unique_dir("listener-ports");
        let cfg = dir.join("other.json");
        fs::write(
            &cfg,
            r#"{"inbounds":[
                {"tag":"a","listen":"0.0.0.0","port":2080,"protocol":"socks"},
                {"tag":"b","listen":"192.168.1.5","port":2090,"protocol":"socks"}
            ]}"#,
        )
        .unwrap();
        let mut other = profile("x-other");
        other.id = "other".into();
        other.backend = TunnelBackend::Xray;
        other.config_path = cfg;
        other.xray_socks_port = Some(10809);
        let mut me = profile("x-me");
        me.id = "me".into();
        me.xray_socks_port = Some(10810);

        let used = profile_listener_ports(&[other, me], "me");
        assert!(used.contains(&10809));
        assert!(used.contains(&2080));
        assert!(!used.contains(&2090));
        assert!(!used.contains(&10810));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rewrite_generated_socks_port_creates_revision_and_rejects_ineligible() {
        let dir = unique_dir("rewrite-socks");
        let vault = ConfigVault::new(dir.join("configs"));
        let mut p = profile("x-gen");
        p.id = "gen".into();
        p.backend = TunnelBackend::Xray;
        p.xray_socks_port = Some(10808);
        let body = br#"{"inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":10808,"protocol":"socks"}]}"#;
        let import = vault.store_xray_config("gen", body).unwrap();
        p.config_path = import.config_path.clone();

        let new_path = rewrite_generated_socks_port(&vault, &mut p, 10950).unwrap();
        assert_ne!(new_path, import.config_path);
        assert_eq!(p.config_path, new_path);
        assert_eq!(p.xray_socks_port, Some(10950));
        assert!(import.config_path.exists());
        let raw = config_security::read_xray_config(&new_path, "gen").unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(doc["inbounds"][0]["port"], 10950);
        assert_eq!(doc["inbounds"][0]["tag"], "socks-in");

        let mut bad = p.clone();
        #[cfg(windows)]
        let broken =
            config_security::protect_user_data(b"{oops", &config_security::xray_context("gen"))
                .unwrap();
        #[cfg(not(windows))]
        let broken = b"{oops".to_vec();
        fs::write(&new_path, &broken).unwrap();
        assert!(rewrite_generated_socks_port(&vault, &mut bad, 10960).is_err());
        assert_eq!(bad.config_path, new_path);
        assert_eq!(bad.xray_socks_port, Some(10950));

        let mut ext = profile("x-ext");
        ext.backend = TunnelBackend::Xray;
        ext.xray_socks_port = Some(10808);
        let before = ext.config_path.clone();
        assert!(rewrite_generated_socks_port(&vault, &mut ext, 10960).is_err());
        assert_eq!(ext.config_path, before);
        assert_eq!(ext.xray_socks_port, Some(10808));

        let mut no_port = ext.clone();
        no_port.xray_socks_port = None;
        assert!(rewrite_generated_socks_port(&vault, &mut no_port, 10960).is_err());
        assert!(no_port.xray_socks_port.is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detect_backend_uses_extension_for_unambiguous_cases() {
        let dir = unique_dir("detect-ext");
        let wg = dir.join("t.conf");
        fs::write(&wg, b"[Interface]\nPrivateKey=x\n").unwrap();
        let ovpn = dir.join("c.ovpn");
        fs::write(&ovpn, b"client\ndev tun\n").unwrap();
        let xray = dir.join("n.json");
        fs::write(&xray, b"{}").unwrap();
        let dpapi = dir.join("t.conf.dpapi");
        fs::write(&dpapi, b"bytes").unwrap();

        assert_eq!(detect_backend(&wg, None), Some(TunnelBackend::WireGuard));
        assert_eq!(detect_backend(&ovpn, None), Some(TunnelBackend::OpenVpn));
        assert_eq!(detect_backend(&xray, None), Some(TunnelBackend::Xray));
        assert_eq!(detect_backend(&dpapi, None), Some(TunnelBackend::WireGuard));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detect_backend_sniffs_conf_content_to_distinguish_wireguard_and_openvpn() {
        let dir = unique_dir("detect-sniff");
        let wg = dir.join("wg.conf");
        fs::write(
            &wg,
            b"[Interface]\nPrivateKey=AAAA\n[Peer]\nPublicKey=BBBB\n",
        )
        .unwrap();
        let ovpn = dir.join("client.conf");
        fs::write(&ovpn, b"client\ndev tun\nproto udp\nremote host 443\n").unwrap();
        let ovpn_remote = dir.join("r.conf");
        fs::write(&ovpn_remote, b"remote example.com 1194\n").unwrap();

        assert_eq!(detect_backend(&wg, None), Some(TunnelBackend::WireGuard));
        assert_eq!(detect_backend(&ovpn, None), Some(TunnelBackend::OpenVpn));
        assert_eq!(
            detect_backend(&ovpn_remote, None),
            Some(TunnelBackend::OpenVpn)
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detect_backend_falls_back_to_default_for_ambiguous_conf() {
        let dir = unique_dir("detect-fallback");
        let unknown = dir.join("x.conf");
        fs::write(&unknown, b"# no recognizable directives\n").unwrap();

        assert_eq!(detect_backend(&unknown, None), None);
        assert_eq!(
            detect_backend(&unknown, Some(TunnelBackend::OpenVpn)),
            Some(TunnelBackend::OpenVpn)
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detect_backend_returns_none_for_unrecognized_extension_without_default() {
        let dir = unique_dir("detect-none");
        let txt = dir.join("notes.txt");
        fs::write(&txt, b"hello").unwrap();
        assert_eq!(detect_backend(&txt, None), None);
        assert_eq!(
            detect_backend(&txt, Some(TunnelBackend::WireGuard)),
            Some(TunnelBackend::WireGuard)
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_configs_into_creates_profiles_and_collects_errors() {
        let dir = unique_dir("batch-import");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));

        let wg = dir.join("work.conf");
        fs::write(
            &wg,
            b"[Interface]\nPrivateKey=AAAA\n[Peer]\nPublicKey=BBBB\n",
        )
        .unwrap();
        let ovpn = dir.join("client.ovpn");
        fs::write(&ovpn, b"client\ndev tun\nproto udp\nremote host 443\n").unwrap();
        let xray = dir.join("node.json");
        fs::write(&xray, br#"{"outbounds":[]}"#).unwrap();
        let bad = dir.join("missing.conf");

        let paths = vec![
            wg.to_string_lossy().to_string(),
            ovpn.to_string_lossy().to_string(),
            xray.to_string_lossy().to_string(),
            bad.to_string_lossy().to_string(),
        ];
        let result = import_configs_into(&vault, &store, &paths, None).unwrap();

        assert_eq!(result.profiles.len(), 3);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].path, bad.to_string_lossy());
        let backends: Vec<_> = result
            .profiles
            .iter()
            .map(|p| (p.name.as_str(), p.backend))
            .collect();
        assert!(backends.contains(&("work", TunnelBackend::WireGuard)));
        assert!(backends.contains(&("client", TunnelBackend::OpenVpn)));
        assert!(backends.contains(&("node", TunnelBackend::Xray)));
        for p in &result.profiles {
            assert!(p.id.starts_with("import-"));
            assert!(p.config_path.starts_with(vault.root()));
            assert!(p.routes.is_empty());
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_configs_into_reports_unknown_extension_without_default() {
        let dir = unique_dir("batch-unknown");
        let vault = ConfigVault::new(dir.join("configs"));
        let store = net_manager_core::profiles::ProfileStore::new(dir.join("profiles.json"));
        let txt = dir.join("readme.txt");
        fs::write(&txt, b"hello").unwrap();

        let result =
            import_configs_into(&vault, &store, &[txt.to_string_lossy().to_string()], None)
                .unwrap();
        assert!(result.profiles.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].error.contains("default backend"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parse_subscription_body_decodes_base64_vless_urls() {
        let raw = "vless://uuid@host:443?encryption=none\ntrojan://other@host2:443\nvless://uuid2@host3:8443?encryption=none";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let urls = parse_subscription_body(&encoded);
        assert_eq!(urls.len(), 2);
        assert!(urls[0].starts_with("vless://uuid@host"));
        assert!(urls[1].starts_with("vless://uuid2@host3"));
    }

    #[test]
    fn parse_subscription_body_accepts_plain_text() {
        let raw = "vless://uuid@host:443?encryption=none\nnot-a-url\nvless://uuid2@host2:443";
        let urls = parse_subscription_body(raw);
        assert_eq!(urls.len(), 2);
        assert!(urls[0].starts_with("vless://uuid@host"));
        assert!(urls[1].starts_with("vless://uuid2@host2"));
    }

    #[test]
    fn parse_subscription_body_returns_empty_for_no_vless() {
        let raw = "trojan://other@host:443\nss://something@host:443";
        let urls = parse_subscription_body(raw);
        assert!(urls.is_empty());
    }

    #[test]
    fn parse_subscription_body_handles_whitespace_and_padding() {
        let raw = "vless://uuid@host:443?encryption=none";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let with_whitespace = format!("  \n{}\n  ", encoded);
        let urls = parse_subscription_body(&with_whitespace);
        assert_eq!(urls.len(), 1);
        assert!(urls[0].starts_with("vless://uuid@host"));
    }

    #[test]
    fn base64_decode_returns_none_for_invalid_input() {
        assert!(base64_decode("!!!not-base64!!!").is_none());
        assert!(base64_decode("").is_none());
    }
}
