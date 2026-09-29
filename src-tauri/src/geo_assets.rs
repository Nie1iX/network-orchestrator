//! Per-profile `geoip.dat`/`geosite.dat` overrides.
//!
//! The app downloads the files over HTTPS into a bounded per-profile cache
//! (`<data>/geoassets/<profile>/`); on connect their bytes are sent inline in
//! the daemon request (the sandboxed unit cannot read `/home`), decoded into
//! the root-owned xray runtime directory, and `XRAY_LOCATION_ASSET` points
//! there — the privileged process never consumes user-writable paths. A
//! stale cache is preferred over a failed refresh — a dat file is data, not
//! an executable.

use crate::state::AppState;
use net_manager_core::models::Profile;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

const MAX_GEO_ASSET_BYTES: usize = 64 * 1024 * 1024;
const REFRESH_AFTER_SECS: u64 = 24 * 60 * 60;
const META_FILE: &str = "meta.json";

pub(crate) type Fetch =
    dyn Fn(&str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>> + Send + Sync;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeoAssetMeta {
    geoip_url: Option<String>,
    geosite_url: Option<String>,
    fetched_at_unix: Option<u64>,
}

pub(crate) fn validate_geo_asset_url(url: &str) -> Result<(), String> {
    let url = url.trim();
    if url.is_empty() || url.len() > 2048 || url.chars().any(char::is_control) {
        return Err("geo asset URL is invalid".into());
    }
    if !url.starts_with("https://") {
        return Err("geo asset URL must use https".into());
    }
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn normalized_url(value: Option<&str>) -> Option<&str> {
    match value.map(str::trim) {
        Some("") | None => None,
        Some(url) => Some(url),
    }
}

fn profile_asset_dir(root: &Path, profile_id: &str) -> PathBuf {
    let safe: String = profile_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    root.join(if safe.is_empty() { "profile" } else { &safe })
}

fn load_meta(dir: &Path) -> GeoAssetMeta {
    std::fs::read_to_string(dir.join(META_FILE))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn write_meta(dir: &Path, meta: &GeoAssetMeta) -> Result<(), String> {
    let tmp = dir.join(format!("{META_FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec(meta).map_err(|e| e.to_string())?)
        .map_err(|_| "geo asset metadata write failed".to_string())?;
    std::fs::rename(&tmp, dir.join(META_FILE))
        .map_err(|_| "geo asset metadata write failed".to_string())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|_| "geo asset write failed".to_string())?;
    std::fs::rename(&tmp, path).map_err(|_| "geo asset write failed".to_string())
}

/// Whether the cached `file` still matches `url` and is fresh enough.
fn cache_is_fresh(dir: &Path, file: &str, url: &str, meta: &GeoAssetMeta) -> bool {
    let known_url = match file {
        "geoip.dat" => meta.geoip_url.as_deref(),
        _ => meta.geosite_url.as_deref(),
    };
    known_url == Some(url)
        && dir.join(file).is_file()
        && meta
            .fetched_at_unix
            .is_some_and(|ts| now_unix().saturating_sub(ts) < REFRESH_AFTER_SECS)
}

async fn ensure_with_fetch(
    state: Option<&AppState>,
    root: &Path,
    profile: &Profile,
    fetch: &Fetch,
) -> Result<Option<PathBuf>, String> {
    let geoip_url = normalized_url(profile.xray_geoip_url.as_deref());
    let geosite_url = normalized_url(profile.xray_geosite_url.as_deref());
    if geoip_url.is_none() && geosite_url.is_none() {
        // Cleared URLs must not leave stale overrides in the cache.
        let _ = std::fs::remove_dir_all(profile_asset_dir(root, &profile.id));
        return Ok(None);
    }
    for url in [geoip_url, geosite_url].into_iter().flatten() {
        validate_geo_asset_url(url)?;
    }
    let dir = profile_asset_dir(root, &profile.id);
    std::fs::create_dir_all(&dir).map_err(|_| "geo asset directory is unavailable".to_string())?;
    let mut meta = load_meta(&dir);

    for (file, url, key) in [
        ("geoip.dat", geoip_url, "geoip"),
        ("geosite.dat", geosite_url, "geosite"),
    ] {
        let target = dir.join(file);
        match url {
            None => {
                // Cleared URL must not keep staging a stale override.
                let _ = std::fs::remove_file(&target);
                match key {
                    "geoip" => meta.geoip_url = None,
                    _ => meta.geosite_url = None,
                }
            }
            Some(url) => {
                if cache_is_fresh(&dir, file, url, &meta) {
                    continue;
                }
                match fetch(url).await {
                    Ok(bytes) => {
                        write_atomic(&target, &bytes)?;
                        match key {
                            "geoip" => meta.geoip_url = Some(url.to_string()),
                            _ => meta.geosite_url = Some(url.to_string()),
                        }
                        meta.fetched_at_unix = Some(now_unix());
                    }
                    Err(err) if target.is_file() => {
                        if let Some(state) = state {
                            crate::commands::logs::record_log(
                                state,
                                crate::commands::logs::LogLevel::Warn,
                                format!(
                                    "geo asset refresh failed for '{}', using cached copy: {err}",
                                    profile.name
                                ),
                            );
                        }
                    }
                    Err(err) => return Err(err),
                }
            }
        }
    }
    write_meta(&dir, &meta)?;
    let has_any = ["geoip.dat", "geosite.dat"]
        .iter()
        .any(|name| dir.join(name).is_file());
    if has_any {
        Ok(Some(dir))
    } else {
        Err("geo asset download failed".into())
    }
}

/// Encodes the cached dat files for inline daemon transport: each present
/// file becomes a base64 field, absent files stay `None` so the daemon falls
/// back to its managed copy for that file.
pub(crate) fn protocol_geo_assets(
    dir: &Path,
) -> Result<net_manager_core::daemon_protocol::XrayGeoAssets, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let encode_file = |name: &str| -> Result<Option<String>, String> {
        let path = dir.join(name);
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|_| "geo asset is unreadable".to_string())?;
        if bytes.is_empty() || bytes.len() > MAX_GEO_ASSET_BYTES {
            return Err("geo asset is invalid".into());
        }
        Ok(Some(engine.encode(bytes)))
    };
    Ok(net_manager_core::daemon_protocol::XrayGeoAssets {
        geoip_dat_b64: encode_file("geoip.dat")?,
        geosite_dat_b64: encode_file("geosite.dat")?,
    })
}

/// Downloads configured overrides into the per-profile cache and returns the
/// directory holding them for inline transport, or `None` when the profile
/// uses the managed geo data.
pub(crate) async fn ensure_geo_assets(
    state: &AppState,
    profile: &Profile,
) -> Result<Option<PathBuf>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|_| "geo asset client is unavailable".to_string())?;
    let fetch = move |url: &str| {
        let url = url.to_string();
        let client = client.clone();
        Box::pin(async move {
            let mut response = client
                .get(&url)
                .send()
                .await
                .map_err(|_| "geo asset download failed".to_string())?;
            if !response.status().is_success() {
                return Err(format!(
                    "geo asset download returned HTTP {}",
                    response.status()
                ));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| "geo asset download failed".to_string())?
            {
                if bytes.len() + chunk.len() > MAX_GEO_ASSET_BYTES {
                    return Err("geo asset exceeds size limit".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            if bytes.is_empty() {
                return Err("geo asset is empty".into());
            }
            Ok(bytes)
        }) as Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>>
    };
    ensure_with_fetch(Some(state), &state.geo_assets_root, profile, &fetch).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::unique_dir;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn profile_with_urls(geoip: Option<&str>, geosite: Option<&str>) -> Profile {
        Profile {
            id: "prof-1".into(),
            xray_geoip_url: geoip.map(str::to_string),
            xray_geosite_url: geosite.map(str::to_string),
            ..Profile::default()
        }
    }

    fn fetcher(
        map: HashMap<String, Result<Vec<u8>, String>>,
    ) -> (Box<Fetch>, std::sync::Arc<Mutex<Vec<String>>>) {
        let calls = std::sync::Arc::new(Mutex::new(Vec::new()));
        let calls2 = calls.clone();
        (
            Box::new(move |url: &str| {
                calls2.lock().unwrap().push(url.to_string());
                let result = map
                    .get(url)
                    .cloned()
                    .unwrap_or_else(|| Err("unexpected url".into()));
                Box::pin(async move { result })
            }),
            calls,
        )
    }

    #[test]
    fn url_validation_requires_https() {
        assert!(validate_geo_asset_url("https://cdn.example/geosite.dat").is_ok());
        assert!(validate_geo_asset_url("http://cdn.example/x.dat").is_err());
        assert!(validate_geo_asset_url("").is_err());
        assert!(validate_geo_asset_url("ftp://x/y").is_err());
    }

    #[test]
    fn protocol_geo_assets_encodes_present_files_only() {
        use base64::Engine;
        let dir = unique_dir("geo-proto");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("geoip.dat"), b"ip-bytes").unwrap();
        let assets = protocol_geo_assets(&dir).unwrap();
        let decode = base64::engine::general_purpose::STANDARD;
        assert_eq!(
            decode.decode(assets.geoip_dat_b64.unwrap()).unwrap(),
            b"ip-bytes"
        );
        assert!(assets.geosite_dat_b64.is_none());
        std::fs::write(dir.join("geoip.dat"), b"").unwrap();
        assert!(protocol_geo_assets(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn no_urls_means_managed_assets() {
        let dir = unique_dir("geo-none");
        let (fetch, calls) = fetcher(HashMap::new());
        let result = ensure_with_fetch(None, &dir, &profile_with_urls(None, None), &fetch)
            .await
            .unwrap();
        assert!(result.is_none());
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn downloads_both_files_and_caches_meta() {
        let dir = unique_dir("geo-dl");
        let mut map = HashMap::new();
        map.insert("https://a/geoip.dat".to_string(), Ok(b"ip".to_vec()));
        map.insert("https://a/geosite.dat".to_string(), Ok(b"site".to_vec()));
        let (fetch, calls) = fetcher(map);
        let profile = profile_with_urls(Some("https://a/geoip.dat"), Some("https://a/geosite.dat"));
        let result = ensure_with_fetch(None, &dir, &profile, &fetch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read(result.join("geoip.dat")).unwrap(), b"ip");
        assert_eq!(std::fs::read(result.join("geosite.dat")).unwrap(), b"site");
        assert_eq!(calls.lock().unwrap().len(), 2);

        // Second call with fresh cache must not refetch.
        let result2 = ensure_with_fetch(None, &dir, &profile, &fetch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result2, result);
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn url_change_triggers_redownload_and_failed_download_keeps_cache() {
        let dir = unique_dir("geo-stale");
        let mut map = HashMap::new();
        map.insert("https://a/geoip.dat".to_string(), Ok(b"v1".to_vec()));
        map.insert(
            "https://b/geoip.dat".to_string(),
            Err("fetch failed".to_string()),
        );
        let (fetch, _) = fetcher(map);
        let profile = profile_with_urls(Some("https://a/geoip.dat"), None);
        ensure_with_fetch(None, &dir, &profile, &fetch)
            .await
            .unwrap();
        let asset_dir = profile_asset_dir(&dir, "prof-1");
        assert_eq!(std::fs::read(asset_dir.join("geoip.dat")).unwrap(), b"v1");

        // Force staleness by clearing meta freshness.
        let meta_path = asset_dir.join(META_FILE);
        std::fs::write(
            &meta_path,
            serde_json::to_vec(&GeoAssetMeta {
                geoip_url: Some("https://b/geoip.dat".into()),
                geosite_url: None,
                fetched_at_unix: Some(0),
            })
            .unwrap(),
        )
        .unwrap();
        let profile = profile_with_urls(Some("https://b/geoip.dat"), None);
        let result = ensure_with_fetch(None, &dir, &profile, &fetch)
            .await
            .unwrap();
        assert!(result.is_some());
        // Failed refresh keeps the previous bytes.
        assert_eq!(std::fs::read(asset_dir.join("geoip.dat")).unwrap(), b"v1");
    }

    #[tokio::test]
    async fn failed_download_without_cache_errors() {
        let dir = unique_dir("geo-fail");
        let (fetch, _) = fetcher(HashMap::new());
        let profile = profile_with_urls(Some("https://a/geoip.dat"), None);
        assert!(ensure_with_fetch(None, &dir, &profile, &fetch)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cleared_url_removes_stale_file() {
        let dir = unique_dir("geo-clear");
        let mut map = HashMap::new();
        map.insert("https://a/geoip.dat".to_string(), Ok(b"v1".to_vec()));
        let (fetch, _) = fetcher(map);
        let profile = profile_with_urls(Some("https://a/geoip.dat"), None);
        ensure_with_fetch(None, &dir, &profile, &fetch)
            .await
            .unwrap();
        let asset_dir = profile_asset_dir(&dir, "prof-1");
        assert!(asset_dir.join("geoip.dat").is_file());

        let cleared = profile_with_urls(None, None);
        assert!(ensure_with_fetch(None, &dir, &cleared, &fetch)
            .await
            .unwrap()
            .is_none());
        assert!(!asset_dir.join("geoip.dat").exists());
    }

    #[test]
    fn profile_dir_sanitizes_id() {
        let dir = profile_asset_dir(Path::new("/tmp/x"), "../evil/../id");
        assert!(dir.starts_with("/tmp/x"));
        assert!(!dir.to_string_lossy().contains(".."));
    }
}
