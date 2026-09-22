//! Ownership journal: what the daemon created, for whom. Written ahead of
//! every netlink mutation so a crash never leaks unowned routes.

use net_manager_core::daemon_protocol::{OwnedResource, OwnedState};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const JOURNAL_VERSION: u32 = 1;
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

    /// Missing file → empty journal. A malformed or unknown-version file is
    /// renamed to `state.json.corrupt-<ts>` and the daemon starts empty:
    /// refusing to start would leave the user with no daemon at all.
    pub fn load(&self) -> io::Result<JournalDocument> {
        let raw = match fs::read(&self.path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(JournalDocument::default());
            }
            Err(err) => return Err(err),
        };
        match serde_json::from_slice::<JournalDocument>(&raw) {
            Ok(doc) if doc.version == JOURNAL_VERSION => Ok(doc),
            _ => {
                let quarantine = self.quarantine_path();
                fs::rename(&self.path, &quarantine)?;
                eprintln!(
                    "network-orchestrator-daemon: unreadable journal moved to {}",
                    quarantine.display()
                );
                Ok(JournalDocument::default())
            }
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

    fn quarantine_path(&self) -> PathBuf {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".corrupt-{millis}"));
        PathBuf::from(name)
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
    fn unsupported_version_is_quarantined() {
        let dir = unique_dir("version");
        let path = dir.join(JOURNAL_FILE);
        fs::write(&path, r#"{"version":99,"entries":[]}"#).unwrap();
        let doc = JournalStore::new(&path).load().unwrap();
        assert_eq!(doc, JournalDocument::default());
        let names = file_names(&dir);
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(names[0].starts_with("state.json.corrupt-"), "{names:?}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn malformed_is_quarantined() {
        let dir = unique_dir("malformed");
        let path = dir.join(JOURNAL_FILE);
        fs::write(&path, "{not json").unwrap();
        let doc = JournalStore::new(&path).load().unwrap();
        assert!(doc.entries.is_empty());
        let names = file_names(&dir);
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(names[0].starts_with("state.json.corrupt-"), "{names:?}");
        fs::remove_dir_all(&dir).unwrap();
    }
}
