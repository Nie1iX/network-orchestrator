//! Shared, local-only share-link import. Never starts a VPN or changes networking.
use crate::{
    analysis,
    config_vault::ConfigVault,
    models::*,
    profiles::{ProfileDocument, ProfileStore},
    xray,
};
use std::{collections::HashSet, io};

const AUTO_SOCKS_PORT_START: u16 = 10808;
const AUTO_SOCKS_PORT_END: u16 = 10999;

pub fn select_available_socks_port(
    used: &HashSet<u16>,
    available: impl Fn(u16) -> bool,
) -> io::Result<u16> {
    (AUTO_SOCKS_PORT_START..=AUTO_SOCKS_PORT_END)
        .find(|port| !used.contains(port) && available(*port))
        .ok_or_else(|| {
            io::Error::other(format!(
                "no available SOCKS5 port in automatic range {AUTO_SOCKS_PORT_START}-{AUTO_SOCKS_PORT_END}"
            ))
        })
}

pub fn select_generated_ports(
    preferred_socks: Option<u16>,
    preferred_http: Option<u16>,
    used: &HashSet<u16>,
    available: impl Fn(u16) -> bool,
) -> io::Result<(u16, u16)> {
    let socks = match preferred_socks {
        Some(port) if port != 0 && !used.contains(&port) && available(port) => port,
        Some(_) => return Err(io::Error::other("SOCKS5 port is unavailable")),
        None => select_available_socks_port(used, &available)?,
    };
    let mut reserved = used.clone();
    reserved.insert(socks);
    let http = match preferred_http {
        Some(port) if port != 0 && !reserved.contains(&port) && available(port) => port,
        _ => select_available_socks_port(&reserved, &available)?,
    };
    Ok((socks, http))
}

pub fn profile_listener_ports(profiles: &[Profile], exclude_id: &str) -> HashSet<u16> {
    let mut ports = HashSet::new();
    for profile in profiles {
        if profile.id == exclude_id {
            continue;
        }
        if let Some(port) = profile.xray_socks_port {
            ports.insert(port);
        }
        if let Some(port) = profile.xray_http_port {
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

/// Create a new managed Xray profile, deriving an optional name from the URL fragment.
/// `available` checks listener ports without starting a tunnel; tests inject a fake check.
pub fn import_share_link(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
    name: &str,
    link: &str,
    available: impl Fn(u16) -> bool,
) -> io::Result<ProfileDocument> {
    crate::config_vault::sanitize_profile_id(id)?;
    let link = link.trim();
    if link.is_empty() || link.len() > 65536 || link.contains(['\r', '\n']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Paste one supported share link",
        ));
    }
    let document = store.load()?;
    if document.profiles.iter().any(|p| p.id == id) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "A profile with this identifier already exists",
        ));
    }
    let used = profile_listener_ports(&document.profiles, id);
    let (socks, http) = select_generated_ports(None, None, &used, available)?;
    let config = xray::generate_share_link_config_with_http(link, socks, http).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid or unsupported share link. Use vless://, hysteria2:// or hy2://.",
        )
    })?;
    let body = serde_json::to_vec_pretty(&config)?;
    let imported = vault.store_generated_xray(id, &body)?;
    let profile = Profile {
        id: id.into(),
        name: if name.trim().is_empty() {
            xray::share_link_name(link).unwrap_or_else(|| "Imported connection".into())
        } else {
            name.trim().into()
        },
        backend: TunnelBackend::Xray,
        config_path: imported.config_path.clone(),
        xray_socks_port: Some(socks),
        xray_http_port: Some(http),
        xray_mode: XrayMode::platform_default(),
        ..Profile::default()
    };
    let result = analysis::analyze_profile(&profile).and_then(|_| store.upsert(profile));
    if result.is_err() {
        let _ = vault.remove_revision_for_config(&imported.config_path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    const LINK: &str = "vless://synthetic-id@node.test:443?security=tls#Lab%20Node";

    #[test]
    fn share_link_import_names_ports_and_duplicate_ids_are_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let doc = import_share_link(&vault, &store, "one", "  Custom name  ", LINK, |p| {
            p != 10808
        })
        .unwrap();
        assert_eq!(doc.profiles[0].name, "Custom name");
        assert_eq!(doc.profiles[0].xray_socks_port, Some(10809));
        assert_eq!(doc.profiles[0].xray_http_port, Some(10810));
        assert_eq!(doc.profiles[0].xray_mode, XrayMode::platform_default());
        let path = doc.profiles[0].config_path.clone();
        assert_eq!(
            import_share_link(&vault, &store, "one", "Replacement", LINK, |_| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(store.load().unwrap(), doc);
        assert!(path.exists());
        let doc = import_share_link(
            &vault,
            &store,
            "two",
            "",
            "hy2://synthetic-password@node.test:443",
            |_| true,
        )
        .unwrap();
        assert_eq!(doc.profiles[1].name, "Imported connection");
        assert_ne!(
            doc.profiles[1].xray_socks_port,
            doc.profiles[0].xray_socks_port
        );
        assert_ne!(
            doc.profiles[1].xray_http_port,
            doc.profiles[0].xray_http_port
        );
    }

    #[test]
    fn failed_profile_save_removes_the_generated_revision() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        // The document is absent but its staging path cannot be written.
        std::fs::create_dir(dir.path().join("profiles.json.tmp")).unwrap();
        assert!(import_share_link(&vault, &store, "failed", "Lab", LINK, |_| true).is_err());
        assert!(!dir.path().join("profiles.json").exists());
        assert_eq!(
            std::fs::read_dir(vault.root().join("failed"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn imported_file_listeners_are_reserved_even_without_port_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let config = vault.store_generated_xray("file", br#"{"inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks"}],"outbounds":[{"protocol":"freedom"}]}"#).unwrap();
        store
            .upsert(Profile {
                id: "file".into(),
                name: "File".into(),
                backend: TunnelBackend::Xray,
                config_path: config.config_path,
                ..Profile::default()
            })
            .unwrap();
        let doc = import_share_link(&vault, &store, "link", "Lab", LINK, |_| true).unwrap();
        assert_eq!(doc.profiles[1].xray_socks_port, Some(10809));
        assert_eq!(doc.profiles[1].xray_http_port, Some(10810));
    }

    #[test]
    fn unavailable_ports_and_multiline_links_write_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        assert!(import_share_link(&vault, &store, "none", "", LINK, |_| false).is_err());
        assert!(import_share_link(
            &vault,
            &store,
            "many",
            "",
            &format!("{LINK}\n{LINK}"),
            |_| true
        )
        .is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
