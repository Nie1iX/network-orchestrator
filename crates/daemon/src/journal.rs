//! Ownership journal: what the daemon created, for whom. Written ahead of
//! every netlink mutation so a crash never leaks unowned routes.

use net_manager_core::daemon_protocol::{OwnedResource, OwnedState};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const JOURNAL_VERSION: u32 = 5;
pub const JOURNAL_FILE: &str = "state.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JournalDocument {
    pub version: u32,
    /// Insertion order; teardown walks it in reverse.
    pub entries: Vec<JournalEntry>,
}

impl Default for JournalDocument {
    fn default() -> Self {
        Self {
            version: JOURNAL_VERSION,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JournalEntry {
    pub uid: u32,
    pub owner: String,
    pub state: OwnedState,
    pub resources: Vec<OwnedResource>,
}

pub struct JournalStore {
    path: PathBuf,
}

impl JournalStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Missing file → empty journal. A malformed or unknown-version file
    /// prevents startup so previously owned network resources are not lost.
    pub fn load(&self) -> io::Result<JournalDocument> {
        let raw = match fs::read(&self.path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(JournalDocument::default());
            }
            Err(err) => return Err(err),
        };
        match serde_json::from_slice::<JournalDocument>(&raw) {
            Ok(mut doc) if (1..=JOURNAL_VERSION).contains(&doc.version) => {
                doc.version = JOURNAL_VERSION;
                Ok(doc)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ownership journal is unreadable or has an unsupported version",
            )),
        }
    }

    /// Atomic replace: 0600 temp file, `sync_all`, rename, fsync directory.
    pub fn save(&self, doc: &JournalDocument) -> io::Result<()> {
        let parent = self.path.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let json = serde_json::to_vec_pretty(doc)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let mut temp_name = self.path.clone().into_os_string();
        temp_name.push(".tmp");
        let temp_path = PathBuf::from(temp_name);
        // A leftover temp file may carry other permissions; `mode` only
        // applies on creation.
        let _ = fs::remove_file(&temp_path);
        let result =
            write_synced(&temp_path, &json).and_then(|()| fs::rename(&temp_path, &self.path));
        if let Err(err) = result {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }
        sync_dir(parent)
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{OwnedResource, OwnedState};
    use net_manager_core::models::AppliedRoute;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-daemon-journal-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample() -> JournalDocument {
        JournalDocument {
            version: JOURNAL_VERSION,
            entries: vec![JournalEntry {
                uid: 1000,
                owner: "static-office".into(),
                state: OwnedState::Applied,
                resources: vec![OwnedResource::Route(AppliedRoute::on_link(
                    "203.0.113.0/24".parse().unwrap(),
                    2,
                    5,
                ))],
            }],
        }
    }

    fn file_names(dir: &PathBuf) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn missing_journal_is_empty() {
        let dir = unique_dir("missing");
        let doc = JournalStore::new(dir.join(JOURNAL_FILE)).load().unwrap();
        assert_eq!(doc, JournalDocument::default());
        assert!(doc.entries.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn roundtrip() {
        let dir = unique_dir("roundtrip");
        let store = JournalStore::new(dir.join("nested").join(JOURNAL_FILE));
        store.save(&sample()).unwrap();
        assert_eq!(store.load().unwrap(), sample());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("mode");
        let path = dir.join(JOURNAL_FILE);
        JournalStore::new(&path).save(&sample()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_leaves_no_temp_file() {
        let dir = unique_dir("temp");
        let store = JournalStore::new(dir.join(JOURNAL_FILE));
        store.save(&sample()).unwrap();
        store.save(&JournalDocument::default()).unwrap();
        assert_eq!(file_names(&dir), vec![JOURNAL_FILE.to_string()]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unsupported_version_blocks_start_and_preserves_journal() {
        let dir = unique_dir("version");
        let path = dir.join(JOURNAL_FILE);
        let original = r#"{"version":99,"entries":[]}"#;
        fs::write(&path, original).unwrap();
        let store = JournalStore::new(&path);
        assert_eq!(store.load().unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(store.load().unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn malformed_blocks_start_and_preserves_journal() {
        let dir = unique_dir("malformed");
        let path = dir.join(JOURNAL_FILE);
        fs::write(&path, "{not json").unwrap();
        let store = JournalStore::new(&path);
        assert_eq!(store.load().unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(store.load().unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read_to_string(&path).unwrap(), "{not json");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn version_one_route_journal_remains_readable_for_recovery() {
        let dir = unique_dir("v1-route");
        let path = dir.join(JOURNAL_FILE);
        fs::write(&path, r#"{"version":1,"entries":[{"uid":1000,"owner":"static-office","state":"applied","resources":[{"kind":"route","destination":"203.0.113.0/24","interfaceIndex":2,"metric":5}]}]}"#).unwrap();
        let loaded = JournalStore::new(&path).load().unwrap();
        assert_eq!(loaded.version, JOURNAL_VERSION);
        assert_eq!(loaded.entries.len(), 1);
        assert!(matches!(
            loaded.entries[0].resources[0],
            OwnedResource::Route(_)
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn version_two_wireguard_link_remains_readable_for_recovery() {
        let dir = unique_dir("v2-wireguard");
        let path = dir.join(JOURNAL_FILE);
        fs::write(&path, r#"{"version":2,"entries":[{"uid":1000,"owner":"wg:home","state":"applied","resources":[{"kind":"wireGuardLink","name":"wg-ab12","index":42,"ownerMarker":"network-orchestrator:1000:wg:home"}]}]}"#).unwrap();
        let loaded = JournalStore::new(&path).load().unwrap();
        assert_eq!(loaded.version, JOURNAL_VERSION);
        assert!(matches!(
            loaded.entries[0].resources[0],
            OwnedResource::WireGuardLink(_)
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn version_three_openvpn_process_upgrades_without_inventing_full_ownership() {
        let dir = unique_dir("v3-openvpn");
        let path = dir.join(JOURNAL_FILE);
        fs::write(&path, r#"{"version":3,"entries":[{"uid":1000,"owner":"ovpn:home","state":"applied","resources":[{"kind":"openVpnProcess","name":"ovpn-ab12","ownerMarker":"network-orchestrator:1000:ovpn:home"}]}]}"#).unwrap();
        let store = JournalStore::new(&path);
        let loaded = store.load().unwrap();
        assert_eq!(loaded.version, JOURNAL_VERSION);
        assert!(
            matches!(&loaded.entries[0].resources[0], OwnedResource::OpenVpnProcess(process) if process.transport_mark.is_none() && process.full.is_none())
        );
        store.save(&loaded).unwrap();
        assert_eq!(store.load().unwrap(), loaded);
        fs::remove_dir_all(dir).unwrap();
    }
}
