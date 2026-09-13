use crate::state::{existing_profile_for_update, find_profile, AppState};
use net_manager_core::analysis;
use net_manager_core::config_security;
use net_manager_core::config_vault::{ConfigImport, ConfigVault};
use net_manager_core::models::*;
use std::collections::HashSet;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
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
    let imported = if state.config_vault.is_managed_path(&profile.config_path) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
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
}
