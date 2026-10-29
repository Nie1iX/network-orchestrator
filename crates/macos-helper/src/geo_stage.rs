//! Geo data for a tunnel Xray. The app sends `geoip.dat`/`geosite.dat`
//! overrides inline; the helper lays them over the user's managed copies into
//! a root-owned directory the unprivileged Xray reads (`XRAY_LOCATION_ASSET`),
//! so the process never consumes a path the user can swap after the check.
use base64::Engine;
use net_manager_core::daemon_protocol::XrayGeoAssets;
use net_manager_core::geo_list::merge_geo_list;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// A dat file is data parsed by Xray; the cap keeps a corrupt file from
/// exhausting memory.
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const FILES: [&str; 2] = ["geoip.dat", "geosite.dat"];

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "geo data is invalid")
}

/// The user's own copy, read only when it is a regular file owned by `uid`
/// (a symlink or someone else's file is ignored, so root is never tricked
/// into copying a file the user could not read).
fn read_user_file(path: &Path, uid: u32) -> Option<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || std::os::unix::fs::MetadataExt::uid(&metadata) != uid {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
    (!bytes.is_empty() && bytes.len() as u64 <= MAX_BYTES).then_some(bytes)
}

fn write_public(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temp, path)
}

/// Rebuilds `target` with both files: an override is merged over the user's
/// managed copy in `managed_dir` (providers ship minimal overlays), and a
/// file with no override is the managed copy as it is.
pub fn stage(
    assets: &XrayGeoAssets,
    managed_dir: &Path,
    uid: u32,
    target: &Path,
) -> io::Result<()> {
    clear(target);
    fs::create_dir_all(target)?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o755))?;
    for (name, encoded) in [
        (FILES[0], assets.geoip_dat_b64.as_deref()),
        (FILES[1], assets.geosite_dat_b64.as_deref()),
    ] {
        let stock = read_user_file(&managed_dir.join(name), uid);
        let bytes = match encoded {
            Some(text) => {
                let overlay = base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .map_err(|_| invalid())?;
                if overlay.is_empty() || overlay.len() as u64 > MAX_BYTES {
                    return Err(invalid());
                }
                match stock.as_deref() {
                    Some(stock) => merge_geo_list(stock, &overlay).unwrap_or(overlay),
                    None => overlay,
                }
            }
            None => stock.ok_or_else(|| io::Error::other("a geo data file is unreadable"))?,
        };
        write_public(&target.join(name), &bytes)?;
    }
    Ok(())
}

/// Removes the staged files (the directory is rebuilt on the next stage).
pub fn clear(target: &Path) {
    let _ = fs::remove_dir_all(target);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn managed(dir: &Path) {
        fs::write(dir.join("geoip.dat"), b"stock-ip").unwrap();
        fs::write(dir.join("geosite.dat"), b"stock-site").unwrap();
    }

    #[test]
    fn a_missing_override_is_the_managed_copy_and_the_files_are_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let (stock, out) = (tmp.path().join("stock"), tmp.path().join("out"));
        fs::create_dir(&stock).unwrap();
        managed(&stock);
        // Not parseable as a geo list, so the override replaces the stock file.
        let assets = XrayGeoAssets {
            geoip_dat_b64: Some(b64(b"custom-ip")),
            geosite_dat_b64: None,
        };
        stage(&assets, &stock, me(), &out).unwrap();
        assert_eq!(fs::read(out.join("geoip.dat")).unwrap(), b"custom-ip");
        assert_eq!(fs::read(out.join("geosite.dat")).unwrap(), b"stock-site");
        for name in FILES {
            let mode = fs::metadata(out.join(name)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o644, "{name}");
        }
        assert_eq!(
            fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn staging_again_replaces_what_was_there() {
        let tmp = tempfile::tempdir().unwrap();
        let (stock, out) = (tmp.path().join("stock"), tmp.path().join("out"));
        fs::create_dir(&stock).unwrap();
        managed(&stock);
        fs::create_dir(&out).unwrap();
        fs::write(out.join("extra.dat"), b"old").unwrap();
        stage(&XrayGeoAssets::default(), &stock, me(), &out).unwrap();
        assert!(!out.join("extra.dat").exists());
        clear(&out);
        assert!(!out.exists());
    }

    #[test]
    fn a_bad_override_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (stock, out) = (tmp.path().join("stock"), tmp.path().join("out"));
        fs::create_dir(&stock).unwrap();
        managed(&stock);
        for bad in ["not base64!!", ""] {
            let assets = XrayGeoAssets {
                geoip_dat_b64: Some(bad.into()),
                geosite_dat_b64: None,
            };
            assert!(stage(&assets, &stock, me(), &out).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_symlinked_or_foreign_managed_file_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let (stock, out) = (tmp.path().join("stock"), tmp.path().join("out"));
        fs::create_dir(&stock).unwrap();
        let secret = tmp.path().join("secret");
        fs::write(&secret, b"root-only").unwrap();
        std::os::unix::fs::symlink(&secret, stock.join("geoip.dat")).unwrap();
        fs::write(stock.join("geosite.dat"), b"stock-site").unwrap();
        // Without an override the symlinked file is simply unavailable.
        assert!(stage(&XrayGeoAssets::default(), &stock, me(), &out).is_err());
        // With one, only the override is used and the target is never read.
        let assets = XrayGeoAssets {
            geoip_dat_b64: Some(b64(b"custom-ip")),
            geosite_dat_b64: None,
        };
        stage(&assets, &stock, me(), &out).unwrap();
        assert_eq!(fs::read(out.join("geoip.dat")).unwrap(), b"custom-ip");
        // A file owned by another user is ignored too.
        assert!(read_user_file(&stock.join("geosite.dat"), me()).is_some());
        assert!(read_user_file(&stock.join("geosite.dat"), me().wrapping_add(1)).is_none());
    }
}
