//! Shared state of one `netorch` invocation on Linux.
use crate::target::{self, Lookup};
use net_manager_core::config_vault::ConfigVault;
use net_manager_core::models::Profile;
use net_manager_core::profiles::ProfileStore;
use net_manager_engine::linux_engine::LinuxEngine;
use std::path::PathBuf;

/// Directory name the Tauri app uses under `$XDG_DATA_HOME`.
const APP_DIR: &str = "com.netmanager.app";

pub struct Ctx {
    pub root: PathBuf,
    pub engine: LinuxEngine,
    /// Whether this process is root; tests set it directly.
    pub root_user: bool,
}

pub fn is_root() -> bool {
    // SAFETY: geteuid never fails.
    unsafe { libc::geteuid() == 0 }
}

/// The app's data directory from the environment, so profiles are shared
/// with the GUI. Relative `XDG_DATA_HOME` values are ignored, as the XDG
/// specification says.
pub fn data_root(xdg: Option<PathBuf>, home: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(dir) = xdg.filter(|dir| dir.is_absolute()) {
        return Ok(dir.join(APP_DIR));
    }
    home.filter(|dir| dir.is_absolute())
        .map(|home| home.join(".local").join("share").join(APP_DIR))
        .ok_or_else(|| "The home directory could not be found".to_string())
}

/// Home of the user who ran `sudo`: where their app data is, even though
/// `$HOME` is root's.
fn sudo_user_home() -> Option<PathBuf> {
    let uid: libc::uid_t = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    // SAFETY: getpwuid returns null or a pointer valid until the next call;
    // the directory is copied out immediately.
    unsafe {
        let entry = libc::getpwuid(uid);
        if entry.is_null() {
            return None;
        }
        let dir = std::ffi::CStr::from_ptr((*entry).pw_dir).to_str().ok()?;
        Some(PathBuf::from(dir))
    }
}

pub fn default_root() -> Result<PathBuf, String> {
    if is_root() {
        // Root needs no polkit prompt, so `sudo netorch up` works; it only
        // reads the invoking user's data (writing would leave root-owned files).
        return data_root(None, sudo_user_home()).map_err(|_| {
            "Run netorch as your own user, or with sudo from your account. \
             Use --data-dir to point root at a data directory."
                .to_string()
        });
    }
    data_root(
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

impl Ctx {
    pub fn new(root: PathBuf, engine: LinuxEngine) -> Result<Self, String> {
        if !root.is_absolute() {
            return Err("The data directory must be an absolute path".into());
        }
        Ok(Self {
            root,
            engine,
            root_user: is_root(),
        })
    }

    pub fn store(&self) -> ProfileStore {
        ProfileStore::new(self.root.join("profiles.json"))
    }

    pub fn vault(&self) -> ConfigVault {
        ConfigVault::new(self.root.join("configs"))
    }

    /// Profiles as stored, for running them. Never printed as they are.
    pub fn profiles(&self) -> Result<Vec<Profile>, String> {
        self.store()
            .load()
            .map(|document| document.profiles)
            .map_err(|_| "Profiles could not be loaded".to_string())
    }

    pub fn find(&self, query: &str) -> Result<Profile, String> {
        let profiles = self.profiles()?;
        match target::resolve(&profiles, query) {
            Lookup::Found(profile) => Ok(profile.clone()),
            Lookup::Missing => Err(format!(
                "No saved profile matches \"{query}\". `netorch ls` lists them."
            )),
            Lookup::Ambiguous(found) => Err(format!(
                "\"{query}\" matches several profiles: {}",
                found
                    .iter()
                    .map(|profile| profile.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdg_data_home_wins_over_home() {
        let root = data_root(Some("/x/data".into()), Some("/home/u".into())).unwrap();
        assert_eq!(root, PathBuf::from("/x/data/com.netmanager.app"));
    }

    #[test]
    fn home_is_the_fallback_and_relative_values_are_ignored() {
        let root = data_root(Some("rel".into()), Some("/home/u".into())).unwrap();
        assert_eq!(
            root,
            PathBuf::from("/home/u/.local/share/com.netmanager.app")
        );
        assert!(data_root(None, Some("rel".into())).is_err());
        assert!(data_root(None, None).is_err());
    }
}
