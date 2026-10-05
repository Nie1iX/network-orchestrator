//! Routing intents: persisted per-user "send these destinations via this
//! path" policies. The durable record lives here; the journal only tracks
//! the kernel artifacts an intent currently owns, so intents survive
//! session cleanup, daemon shutdown and restarts — startup replay re-arms
//! them and reconcile keeps enforcing them.

use crate::always_on::{check_private_dir, current_uid};
use net_manager_core::daemon_protocol::NetIntentSetParams;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

const VERSION: u32 = 1;
const FILE: &str = "intents.json";
const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
const MAX_INTENTS: usize = 64;
const MAX_DESTINATIONS: usize = 512;

/// Persisted per-uid intent list.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IntentDocument {
    pub version: u32,
    #[serde(default)]
    pub intents: Vec<NetIntentSetParams>,
}

/// Per-user intent store under `<state>/intents/<uid>/intents.json`, with
/// the same ACL/atomicity rules as the conditional-rules store.
#[derive(Clone)]
pub struct IntentStore {
    root: PathBuf,
}

impl IntentStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn uid_dir(&self, uid: u32) -> PathBuf {
        self.root.join(uid.to_string())
    }

    fn path(&self, uid: u32) -> PathBuf {
        self.uid_dir(uid).join(FILE)
    }

    pub fn load_uid(&self, uid: u32) -> io::Result<IntentDocument> {
        if !check_private_dir(&self.root, false)? || !check_private_dir(&self.uid_dir(uid), false)?
        {
            return Ok(IntentDocument::default());
        }
        let path = self.path(uid);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(IntentDocument::default());
            }
            Err(err) => return Err(err),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != current_uid()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > MAX_DOCUMENT_BYTES as u64
        {
            return Err(invalid_data());
        }
        let bytes = fs::read(path)?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(invalid_data());
        }
        let document: IntentDocument =
            serde_json::from_slice(&bytes).map_err(|_| invalid_data())?;
        if document.version != VERSION
            || document.intents.len() > MAX_INTENTS
            || document
                .intents
                .iter()
                .any(|intent| intent.destinations.len() > MAX_DESTINATIONS)
        {
            return Err(invalid_data());
        }
        Ok(document)
    }

    /// Every uid document, loaded independently so one broken store does
    /// not hide the others. Non-directory entries are ignored.
    pub fn load_all(&self) -> io::Result<Vec<(u32, IntentDocument)>> {
        if !check_private_dir(&self.root, false)? {
            return Ok(Vec::new());
        }
        let mut uids = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if let Some(uid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            {
                uids.push(uid);
            }
        }
        uids.sort_unstable();
        Ok(uids
            .into_iter()
            .map(|uid| match self.load_uid(uid) {
                Ok(document) => (uid, document),
                Err(_) => {
                    eprintln!(
                        "network-orchestrator-daemon: intent store of uid {uid} is unreadable"
                    );
                    (uid, IntentDocument::default())
                }
            })
            .collect())
    }

    /// Insert or replace the intent with the same id.
    pub fn upsert(&self, uid: u32, intent: NetIntentSetParams) -> io::Result<()> {
        let mut document = self.load_uid(uid)?;
        if let Some(existing) = document
            .intents
            .iter_mut()
            .find(|item| item.id == intent.id)
        {
            *existing = intent;
        } else {
            if document.intents.len() >= MAX_INTENTS {
                return Err(invalid_data());
            }
            document.intents.push(intent);
        }
        self.save(uid, &document)
    }

    pub fn remove(&self, uid: u32, id: &str) -> io::Result<bool> {
        let mut document = self.load_uid(uid)?;
        let before = document.intents.len();
        document.intents.retain(|intent| intent.id != id);
        if document.intents.len() == before {
            return Ok(false);
        }
        self.save(uid, &document)?;
        Ok(true)
    }

    fn save(&self, uid: u32, document: &IntentDocument) -> io::Result<()> {
        check_private_dir(&self.root, true)?;
        let dir = self.uid_dir(uid);
        check_private_dir(&dir, true)?;
        let mut document = document.clone();
        document.version = VERSION;
        let bytes = serde_json::to_vec(&document).map_err(|_| invalid_data())?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(invalid_data());
        }
        let path = self.path(uid);
        let temp = dir.join("intents.json.tmp");
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        fs::File::open(dir)?.sync_all()
    }
}

fn invalid_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "intent store is not safe to load",
    )
}
