//! Custom `geoip.dat`/`geosite.dat` for a connection: downloaded and cached
//! as the user (`core::geo_assets`), then laid over the managed Xray's own
//! files. The merged copy is what a loopback Xray and its validation run
//! with; a tunnel gets the cached files inline and the helper stages them.
use net_manager_core::daemon_protocol::XrayGeoAssets;
use net_manager_core::geo_assets::{
    ensure_with_fetch, http_fetch, overlay_dir, protocol_geo_assets, wants_overrides, Fetch,
};
use net_manager_core::models::Profile;
use std::path::{Path, PathBuf};

pub(crate) struct GeoData {
    /// Merged managed + custom files, for a process running as the user.
    pub dir: PathBuf,
    /// The custom files themselves, for the helper.
    pub inline: XrayGeoAssets,
}

/// `None` when the profile uses the managed geo data.
pub(crate) fn prepare(
    root: &Path,
    executable: &Path,
    profile: &Profile,
) -> Result<Option<GeoData>, String> {
    if !wants_overrides(profile) {
        return Ok(None);
    }
    prepare_with(root, executable, profile, &*http_fetch()?)
}

pub(crate) fn prepare_with(
    root: &Path,
    executable: &Path,
    profile: &Profile,
    fetch: &Fetch,
) -> Result<Option<GeoData>, String> {
    if !wants_overrides(profile) {
        return Ok(None);
    }
    let mut notes = Vec::new();
    let cache = crate::runtime::download_runtime()?.block_on(ensure_with_fetch(
        &mut notes,
        &root.join("geoassets"),
        profile,
        fetch,
    ))?;
    let Some(cache) = cache else {
        return Ok(None);
    };
    let name: String = profile
        .id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let dir = root.join("geo-run").join(name);
    let managed = executable.parent().unwrap_or(Path::new("/"));
    overlay_dir(&cache, managed, &dir)?;
    Ok(Some(GeoData {
        dir,
        inline: protocol_geo_assets(&cache)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;

    fn fetcher(files: HashMap<String, Vec<u8>>) -> Box<Fetch> {
        Box::new(move |url: &str| {
            let found = files.get(url).cloned();
            Box::pin(async move { found.ok_or_else(|| "geo asset download failed".to_string()) })
                as Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>>
        })
    }

    fn profile(geoip: Option<&str>) -> Profile {
        Profile {
            id: "p1".into(),
            xray_geoip_url: geoip.map(Into::into),
            ..Default::default()
        }
    }

    fn installed(dir: &Path) -> PathBuf {
        let version = dir.join("xray/v1");
        std::fs::create_dir_all(&version).unwrap();
        std::fs::write(version.join("geoip.dat"), b"stock-ip").unwrap();
        std::fs::write(version.join("geosite.dat"), b"stock-site").unwrap();
        version.join("xray")
    }

    #[test]
    fn no_urls_means_the_managed_files_and_no_download() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = installed(tmp.path());
        assert!(prepare(tmp.path(), &exe, &profile(None)).unwrap().is_none());
        assert!(!tmp.path().join("geoassets").exists());
    }

    #[test]
    fn a_custom_file_is_merged_over_the_managed_one_and_sent_inline() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = installed(tmp.path());
        let fetch = fetcher(HashMap::from([(
            "https://cdn.example/geoip.dat".to_string(),
            b"custom-ip".to_vec(),
        )]));
        let data = prepare_with(
            tmp.path(),
            &exe,
            &profile(Some("https://cdn.example/geoip.dat")),
            &fetch,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            std::fs::read(data.dir.join("geoip.dat")).unwrap(),
            b"custom-ip"
        );
        assert_eq!(
            std::fs::read(data.dir.join("geosite.dat")).unwrap(),
            b"stock-site"
        );
        assert!(data.inline.geoip_dat_b64.is_some());
        assert!(data.inline.geosite_dat_b64.is_none());
    }

    #[test]
    fn a_download_that_fails_without_a_cache_stops_the_connection() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = installed(tmp.path());
        let error = prepare_with(
            tmp.path(),
            &exe,
            &profile(Some("https://cdn.example/geoip.dat")),
            &fetcher(HashMap::new()),
        )
        .err()
        .expect("error");
        assert!(!error.contains("cdn.example"), "{error}");
    }

    #[test]
    fn a_plain_http_url_is_refused_before_anything_is_fetched() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = installed(tmp.path());
        let error = prepare_with(
            tmp.path(),
            &exe,
            &profile(Some("http://cdn.example/geoip.dat")),
            &fetcher(HashMap::new()),
        )
        .err()
        .expect("error");
        assert!(error.contains("https"), "{error}");
    }
}
