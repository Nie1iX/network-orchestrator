//! Administrator-chosen daemon settings, persisted next to the journal.

use crate::journal::write_atomic;
use net_manager_core::daemon_protocol::VpnAuthMode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

pub const SETTINGS_FILE: &str = "settings.json";
const SETTINGS_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DaemonSettings {
    pub vpn_auth_mode: VpnAuthMode,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsDocument {
    version: u32,
    #[serde(flatten)]
    settings: DaemonSettings,
}

pub struct SettingsStore {
    path: PathBuf,
}

impl SettingsStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Missing or unreadable file → defaults. Settings only tune prompts, so
    /// a broken file must not keep the daemon from starting.
    pub fn load(&self) -> DaemonSettings {
        let raw = match fs::read(&self.path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return DaemonSettings::default(),
            Err(err) => {
                eprintln!(
                    "network-orchestrator-daemon: cannot read settings, using defaults: {err}"
                );
                return DaemonSettings::default();
            }
        };
        match serde_json::from_slice::<SettingsDocument>(&raw) {
            Ok(doc) if doc.version == SETTINGS_VERSION => doc.settings,
            _ => {
                eprintln!("network-orchestrator-daemon: settings file is invalid, using defaults");
                DaemonSettings::default()
            }
        }
    }

    pub fn save(&self, settings: DaemonSettings) -> io::Result<()> {
        let doc = SettingsDocument {
            version: SETTINGS_VERSION,
            settings,
        };
        let json = serde_json::to_vec_pretty(&doc)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        write_atomic(&self.path, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn store(name: &str) -> (SettingsStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "netorch-settings-{}-{name}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        (SettingsStore::new(dir.join(SETTINGS_FILE)), dir)
    }

    #[test]
    fn missing_file_uses_full_tunnel_only_default() {
        let (store, dir) = store("missing");
        assert_eq!(store.load().vpn_auth_mode, VpnAuthMode::FullTunnelOnly);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn save_roundtrips_with_private_mode() {
        let (store, dir) = store("roundtrip");
        store
            .save(DaemonSettings {
                vpn_auth_mode: VpnAuthMode::Always,
            })
            .unwrap();
        assert_eq!(store.load().vpn_auth_mode, VpnAuthMode::Always);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(SETTINGS_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_file_falls_back_to_defaults() {
        let (store, dir) = store("invalid");
        for body in [
            &b"{ not json"[..],
            br#"{"version":9,"vpnAuthMode":"noPrompt"}"#,
        ] {
            fs::write(dir.join(SETTINGS_FILE), body).unwrap();
            assert_eq!(store.load(), DaemonSettings::default());
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
