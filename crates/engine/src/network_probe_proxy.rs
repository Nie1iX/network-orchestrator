use crate::linux_engine::LinuxEngine;
use net_manager_core::{
    models::{TunnelBackend, TunnelState},
    system_proxy::ProxySnapshot,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn user_proxy_state_root() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        return Ok(path.join("netorch"));
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|home| home.join(".local/state/netorch"))
        .ok_or_else(|| "Cannot locate current user proxy ownership.".into())
}

fn proxy_snapshot_active(snapshot: &ProxySnapshot) -> bool {
    snapshot
        .gnome
        .as_ref()
        .is_some_and(|g| !g.mode.eq_ignore_ascii_case("none"))
        || snapshot
            .kde
            .as_ref()
            .is_some_and(|k| k.proxy_type.as_deref().is_some_and(|v| v != "0"))
}

fn proxy_matches_profile(
    snapshot: &ProxySnapshot,
    http_port: Option<u16>,
    socks_port: u16,
) -> bool {
    let local = |host: &str, port: u16, expected: u16| host == "127.0.0.1" && port == expected;
    if let Some(gnome) = &snapshot.gnome {
        return gnome.mode == "manual"
            && gnome.socks.host == "127.0.0.1"
            && gnome.socks.port == socks_port
            && match http_port {
                Some(port) => {
                    local(&gnome.http.host, gnome.http.port, port)
                        && local(&gnome.https.host, gnome.https.port, port)
                }
                None => gnome.http == Default::default() && gnome.https == Default::default(),
            };
    }
    if let Some(kde) = &snapshot.kde {
        let value_matches = |value: &Option<String>, scheme: &str, port: u16| {
            value.as_deref() == Some(format!("{scheme}://127.0.0.1 {port}").as_str())
        };
        return kde.proxy_type.as_deref() == Some("1")
            && value_matches(&kde.socks_proxy, "socks", socks_port)
            && match http_port {
                Some(port) => {
                    value_matches(&kde.http_proxy, "http", port)
                        && value_matches(&kde.https_proxy, "http", port)
                }
                None => kde.http_proxy.is_none() && kde.https_proxy.is_none(),
            };
    }
    false
}

/// Inspect the current desktop proxy without changing it. Run on a blocking worker
/// with a caller deadline: desktop adapters invoke the user's settings tools.
pub fn current_user_proxy(engine: &LinuxEngine, root: &Path) -> Result<Option<String>, String> {
    let mut adapter = net_manager_core::system_proxy::linux::system_adapter()
        .ok_or_else(|| "Cannot inspect current user proxy settings.".to_string())?;
    let snapshot = adapter
        .snapshot()
        .map_err(|_| "Cannot inspect current user proxy settings.".to_string())?;
    let marker = match std::fs::read_to_string(user_proxy_state_root()?.join("system-proxy.owner"))
    {
        Ok(owner) => Some(owner),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("Cannot inspect current user proxy ownership.".into()),
    };
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let root_hash = format!(
        "{:x}",
        Sha256::digest(canonical_root.as_os_str().as_encoded_bytes())
    );
    if marker.as_deref().is_some_and(|owner| owner != root_hash) && proxy_snapshot_active(&snapshot)
    {
        return Err(
            "A different connection owns the active user system proxy; refusing to probe directly."
                .into(),
        );
    }
    let ownership = if marker.as_deref() == Some(root_hash.as_str()) {
        net_manager_core::system_proxy::load_ownership(&root.join("proxy-state.json"))
            .map_err(|_| "Cannot read current user proxy ownership".to_string())?
    } else {
        None
    };
    let Some(owner) = ownership else {
        if proxy_snapshot_active(&snapshot) {
            return Err("A user system proxy is active but is not owned by this connection; refusing to probe directly.".into());
        }
        return Ok(None);
    };
    let profile = net_manager_core::profiles::ProfileStore::new(root.join("profiles.json"))
        .load()
        .map_err(|_| "Cannot read profiles".to_string())?
        .profiles
        .into_iter()
        .find(|profile| profile.id == owner.profile_id)
        .ok_or_else(|| "Active system proxy owner profile is unavailable.".to_string())?;
    let (http_port, socks_port) = match profile.backend {
        TunnelBackend::Xray => (profile.xray_http_port, profile.xray_socks_port),
        TunnelBackend::Mihomo => {
            let port = profile
                .mihomo
                .as_ref()
                .and_then(|options| options.mixed_port);
            (port, port)
        }
        _ => (None, None),
    };
    let socks_port = socks_port
        .filter(|port| *port != 0)
        .ok_or_else(|| "Active system proxy listener is unavailable.".to_string())?;
    if !proxy_snapshot_active(&snapshot) || !proxy_matches_profile(&snapshot, http_port, socks_port)
    {
        return Err("Current user proxy settings no longer match recorded ownership.".into());
    }
    if engine
        .status(&profile)
        .map_err(|_| "Unable to verify active system proxy status".to_string())?
        .state
        != TunnelState::Running
    {
        return Err(
            "System proxy ownership is stale; the owning connection is not running.".into(),
        );
    }
    Ok(Some(
        if let Some(port) = http_port.filter(|port| *port != 0) {
            format!("http://127.0.0.1:{port}")
        } else {
            format!("socks5h://127.0.0.1:{socks_port}")
        },
    ))
}
