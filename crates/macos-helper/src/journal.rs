//! Crash-safe ownership record for the one TUN the helper may own. Written
//! before anything is mutated and removed only after teardown, so a restart
//! can undo exactly what a dead helper left behind.

use crate::dns::Snapshot;
use crate::routes::RouteOp;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub profile_id: String,
    pub interface: String,
    /// Xray's pid once it exists; 0 while the record is write-ahead.
    pub pid: u32,
    pub routes: Vec<RouteOp>,
    pub dns: Option<Snapshot>,
    /// Split-DNS suffixes this tunnel wrote to `/etc/resolver`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolver_domains: Vec<String>,
}

pub struct Journal {
    path: PathBuf,
}

impl Journal {
    /// The Xray TUN record.
    pub fn new(dir: &Path) -> Self {
        Self::named(dir, "xray-tun.json")
    }

    /// One record per tunnel kind, side by side in the state directory.
    pub fn named(dir: &Path, file: &str) -> Self {
        Self {
            path: dir.join(file),
        }
    }

    /// Atomic replace (temp + rename), root-only.
    pub fn save(&self, record: &Record) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&serde_json::to_vec(record).map_err(io::Error::other)?)?;
        file.sync_all()?;
        fs::rename(&tmp, &self.path)
    }

    pub fn load(&self) -> io::Result<Option<Record>> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "corrupt tun journal")),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub fn clear(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            profile_id: "p".into(),
            interface: "utun10".into(),
            pid: 7,
            routes: vec![],
            dns: Some(Snapshot {
                service: "Wi-Fi".into(),
                servers: vec![],
            }),
            resolver_domains: Vec::new(),
        }
    }

    #[test]
    fn record_round_trips_privately_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(&dir.path().join("state"));
        assert_eq!(journal.load().unwrap(), None);
        journal.save(&record()).unwrap();
        assert_eq!(journal.load().unwrap(), Some(record()));
        let mode = fs::metadata(&journal.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        journal.clear().unwrap();
        journal.clear().unwrap();
        assert_eq!(journal.load().unwrap(), None);
    }

    #[test]
    fn corrupt_journal_is_reported_not_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::new(dir.path());
        fs::write(&journal.path, b"{").unwrap();
        assert_eq!(
            journal.load().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
