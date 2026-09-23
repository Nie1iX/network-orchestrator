use crate::core::DaemonCore;
use crate::validate::{validate_apply, validate_iface_name, validate_owner};
use crate::wireguard::parse_wireguard_config;
use net_manager_core::daemon_protocol::{AlwaysOnDefinition, MAX_FRAME_BYTES};
use net_manager_core::models::AppliedRoute;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const VERSION: u32 = 1;
const FILE: &str = "definitions.json";
const MAX_DOCUMENT_BYTES: usize = 8 * MAX_FRAME_BYTES;
const MAX_ENTRIES: usize = 32;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoredEntry {
    pub enabled: bool,
    pub definition: AlwaysOnDefinition,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AlwaysOnDocument {
    version: u32,
    pub paused: bool,
    pub entries: Vec<StoredEntry>,
}

impl Default for AlwaysOnDocument {
    fn default() -> Self {
        Self {
            version: VERSION,
            paused: false,
            entries: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct AlwaysOnStore {
    root: PathBuf,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayReport {
    pub started: usize,
    pub already_active: usize,
    pub blocked: usize,
    pub failed: usize,
}

pub fn validate_definition(definition: &AlwaysOnDefinition) -> io::Result<()> {
    let owner = definition.owner();
    validate_owner(&owner).map_err(|_| invalid_data())?;
    match definition {
        AlwaysOnDefinition::WireGuard(profile) => {
            parse_wireguard_config(&profile.config, &profile.routes).map_err(|_| invalid_data())?;
        }
        AlwaysOnDefinition::StaticRoutes(profile) => {
            if owner.starts_with("wg:") || owner.starts_with("ovpn:") || owner.starts_with("xray:")
            {
                return Err(invalid_data());
            }
            validate_iface_name(&profile.interface_name).map_err(|_| invalid_data())?;
            if profile.routes.is_empty() {
                return Err(invalid_data());
            }
            let routes: Vec<_> = profile
                .routes
                .iter()
                .map(|route| AppliedRoute {
                    destination: route.destination,
                    interface_index: 1,
                    metric: route.metric,
                    gateway: route.via,
                    table: None,
                })
                .collect();
            validate_apply(&routes).map_err(|_| invalid_data())?;
        }
    }
    Ok(())
}

pub fn apply_definition(
    core: &mut DaemonCore,
    uid: u32,
    definition: &AlwaysOnDefinition,
) -> io::Result<bool> {
    validate_definition(definition)?;
    let owner = definition.owner();
    if let Some(existing) = core
        .owned(uid)
        .into_iter()
        .find(|entry| entry.owner == owner)
    {
        return if existing.state == net_manager_core::daemon_protocol::OwnedState::Applied {
            Ok(false)
        } else {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "existing owner needs recovery before replay",
            ))
        };
    }
    match definition {
        AlwaysOnDefinition::WireGuard(profile) => {
            let plan = parse_wireguard_config(&profile.config, &profile.routes)
                .map_err(|_| invalid_data())?;
            core.connect_wireguard(uid, &profile.profile_id, plan)?;
        }
        AlwaysOnDefinition::StaticRoutes(profile) => {
            let name = CString::new(profile.interface_name.as_str()).map_err(|_| invalid_data())?;
            // SAFETY: if_nametoindex reads the live link index and does not mutate the network.
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "interface is unavailable",
                ));
            }
            let routes = profile
                .routes
                .iter()
                .map(|route| AppliedRoute {
                    destination: route.destination,
                    interface_index: index,
                    metric: route.metric,
                    gateway: route.via,
                    table: None,
                })
                .collect();
            core.apply_routes(uid, &profile.profile_id, routes)?;
        }
    }
    Ok(true)
}

pub fn replay(core: &mut DaemonCore, store: &AlwaysOnStore) -> io::Result<ReplayReport> {
    let mut report = ReplayReport::default();
    for (uid, document) in store.load_all()? {
        if document.paused {
            continue;
        }
        for entry in document.entries.into_iter().filter(|entry| entry.enabled) {
            if let Some(existing) = core
                .owned(uid)
                .into_iter()
                .find(|owner| owner.owner == entry.definition.owner())
            {
                if existing.state == net_manager_core::daemon_protocol::OwnedState::Applied {
                    report.already_active += 1;
                } else {
                    report.blocked += 1;
                }
                continue;
            }
            match apply_definition(core, uid, &entry.definition) {
                Ok(true) => report.started += 1,
                Ok(false) => report.already_active += 1,
                Err(_) => report.failed += 1,
            }
        }
    }
    Ok(report)
}

impl AlwaysOnStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn uid_dir(&self, uid: u32) -> PathBuf {
        self.root.join(uid.to_string())
    }

    fn path(&self, uid: u32) -> PathBuf {
        self.uid_dir(uid).join(FILE)
    }

    pub fn load_uid(&self, uid: u32) -> io::Result<AlwaysOnDocument> {
        if !check_private_dir(&self.root, false)? || !check_private_dir(&self.uid_dir(uid), false)?
        {
            return Ok(AlwaysOnDocument::default());
        }
        let path = self.path(uid);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(AlwaysOnDocument::default());
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
        let document: AlwaysOnDocument =
            serde_json::from_slice(&bytes).map_err(|_| invalid_data())?;
        if document.version != VERSION || document.entries.len() > MAX_ENTRIES {
            return Err(invalid_data());
        }
        Ok(document)
    }

    pub fn load_all(&self) -> io::Result<Vec<(u32, AlwaysOnDocument)>> {
        if !check_private_dir(&self.root, false)? {
            return Ok(Vec::new());
        }
        let mut uids = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let uid = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
                .ok_or_else(invalid_data)?;
            uids.push(uid);
        }
        uids.sort_unstable();
        uids.into_iter()
            .map(|uid| Ok((uid, self.load_uid(uid)?)))
            .collect()
    }

    pub fn insert(&self, uid: u32, definition: AlwaysOnDefinition) -> io::Result<bool> {
        let mut document = self.load_uid(uid)?;
        if let Some(entry) = document
            .entries
            .iter_mut()
            .find(|entry| entry.definition.owner() == definition.owner())
        {
            if entry.definition != definition {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "definition differs",
                ));
            }
            if entry.enabled {
                return Ok(false);
            }
            entry.enabled = true;
        } else {
            if document.entries.len() >= MAX_ENTRIES {
                return Err(invalid_data());
            }
            document.entries.push(StoredEntry {
                enabled: true,
                definition,
            });
        }
        self.save(uid, &document)?;
        Ok(true)
    }

    pub fn disable(&self, uid: u32, owner: &str) -> io::Result<bool> {
        let mut document = self.load_uid(uid)?;
        let Some(entry) = document
            .entries
            .iter_mut()
            .find(|entry| entry.definition.owner() == owner)
        else {
            return Ok(false);
        };
        entry.enabled = false;
        self.save(uid, &document)?;
        Ok(true)
    }

    pub fn remove(&self, uid: u32, owner: &str) -> io::Result<bool> {
        let mut document = self.load_uid(uid)?;
        let before = document.entries.len();
        document
            .entries
            .retain(|entry| entry.definition.owner() != owner);
        if document.entries.len() == before {
            return Ok(false);
        }
        self.save(uid, &document)?;
        Ok(true)
    }

    pub fn pause(&self, uid: u32) -> io::Result<()> {
        let mut document = self.load_uid(uid)?;
        document.paused = true;
        self.save(uid, &document)
    }

    pub fn resume(&self, uid: u32) -> io::Result<()> {
        let mut document = self.load_uid(uid)?;
        document.paused = false;
        self.save(uid, &document)
    }

    fn save(&self, uid: u32, document: &AlwaysOnDocument) -> io::Result<()> {
        check_private_dir(&self.root, true)?;
        let dir = self.uid_dir(uid);
        check_private_dir(&dir, true)?;
        let bytes = serde_json::to_vec(document).map_err(|_| invalid_data())?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(invalid_data());
        }
        let path = self.path(uid);
        let temp = dir.join("definitions.json.tmp");
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

fn check_private_dir(path: &Path, create: bool) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound && create => {
            fs::DirBuilder::new().mode(0o700).create(path)?;
            fs::symlink_metadata(path)?
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid_data());
    }
    Ok(true)
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no failure mode.
    unsafe { libc::geteuid() }
}

fn invalid_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "always-on definitions are not safe to load",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{AlwaysOnDefinition, WireGuardConnectParams};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    fn test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netorch-always-on-{}-{label}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn wireguard(id: &str) -> AlwaysOnDefinition {
        AlwaysOnDefinition::WireGuard(WireGuardConnectParams {
            profile_id: id.into(),
            config: "PrivateKey = secret-marker".into(),
            routes: Vec::new(),
        })
    }

    #[test]
    fn private_per_uid_store_preserves_definitions_and_pause() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("roundtrip");
        let store = AlwaysOnStore::new(dir.join("profiles"));
        assert!(store.insert(1000, wireguard("home")).unwrap());
        assert!(!store.insert(1000, wireguard("home")).unwrap());
        store.pause(1000).unwrap();

        let reopened = AlwaysOnStore::new(dir.join("profiles"));
        assert!(reopened.load_uid(1000).unwrap().paused);
        assert_eq!(reopened.load_uid(1000).unwrap().entries.len(), 1);
        assert!(reopened.load_uid(1001).unwrap().entries.is_empty());
        assert_eq!(
            fs::metadata(dir.join("profiles/1000/definitions.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(dir.join("profiles/1000"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        reopened.resume(1000).unwrap();
        assert!(!reopened.load_uid(1000).unwrap().paused);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn disable_tombstone_survives_restart_and_remove_clears_it() {
        let dir = test_dir("disable");
        let store = AlwaysOnStore::new(dir.join("profiles"));
        store.insert(1000, wireguard("home")).unwrap();
        assert!(store.disable(1000, "wg:home").unwrap());
        let reopened = AlwaysOnStore::new(dir.join("profiles"));
        assert!(!reopened.load_uid(1000).unwrap().entries[0].enabled);
        assert!(reopened.remove(1000, "wg:home").unwrap());
        assert!(reopened.load_uid(1000).unwrap().entries.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn symlinked_uid_directory_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("symlink");
        let target = dir.join("outside");
        fs::create_dir(&target).unwrap();
        let root = dir.join("profiles");
        fs::create_dir(&root).unwrap();
        symlink(&target, root.join("1000")).unwrap();
        let store = AlwaysOnStore::new(root);
        assert!(store.insert(1000, wireguard("home")).is_err());
        assert!(fs::read_dir(&target).unwrap().next().is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_owned_static_route_is_reconciled_without_touching_foreign_route() {
        use crate::core::testing::{FakeLinks, FakeRoutes, Op, Recorder};
        use crate::core::DaemonCore;
        use crate::journal::{JournalStore, JOURNAL_FILE};
        use net_manager_core::models::AppliedRoute;

        let dir = test_dir("flap");
        let recorder = Recorder::default();
        let mut core = DaemonCore::open(
            JournalStore::new(dir.join(JOURNAL_FILE)),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
        )
        .unwrap();
        let owned = AppliedRoute::on_link("198.18.88.0/24".parse().unwrap(), 2, 5);
        core.apply_routes(1000, "office", vec![owned.clone()])
            .unwrap();
        assert_eq!(
            core.reconcile_static_routes(std::slice::from_ref(&owned))
                .unwrap(),
            0
        );
        let foreign = AppliedRoute::on_link("198.18.88.0/24".parse().unwrap(), 2, 99);
        assert_eq!(core.reconcile_static_routes(&[foreign]).unwrap(), 1);
        assert!(core.owned(1000).is_empty());
        assert_eq!(
            recorder.ops().last(),
            Some(&Op::Remove(owned.destination.to_string()))
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
