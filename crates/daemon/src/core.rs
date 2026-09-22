//! `DaemonCore`: owner bookkeeping on top of the journal and the executors.
//! Synchronous by design; the server calls it from `spawn_blocking`.

use crate::journal::{JournalDocument, JournalEntry, JournalStore};
use crate::validate::{validate_apply, validate_iface_name, validate_owner};
use net_manager_core::daemon_protocol::{CleanupResult, OwnedEntry, OwnedResource, OwnedState};
use net_manager_core::models::AppliedRoute;
use net_manager_core::policy::{
    apply_routes_transactional, remove_routes_best_effort, RouteExecutor,
};
use std::io;

pub trait LinkExecutor: Send {
    fn set_link_state(&mut self, name: &str, up: bool) -> io::Result<()>;
}

pub struct DaemonCore {
    store: JournalStore,
    journal: JournalDocument,
    routes: Box<dyn RouteExecutor>,
    links: Box<dyn LinkExecutor>,
}

impl DaemonCore {
    /// Load the journal and tear down everything it lists: whatever a
    /// previous run left behind is no longer backed by a live client.
    pub fn open(
        store: JournalStore,
        routes: Box<dyn RouteExecutor>,
        links: Box<dyn LinkExecutor>,
    ) -> io::Result<Self> {
        let journal = store.load()?;
        let mut core = Self {
            store,
            journal,
            routes,
            links,
        };
        if !core.journal.entries.is_empty() {
            let result = core.teardown(|_| true)?;
            eprintln!(
                "network-orchestrator-daemon: startup recovery removed {} owner(s), {} stale",
                result.removed_owners.len(),
                result.failed.len()
            );
        }
        Ok(core)
    }

    /// Apply `routes` for `(uid, owner)` all-or-nothing. The journal entry is
    /// persisted as `applying` before the first kernel change.
    pub fn apply_routes(
        &mut self,
        uid: u32,
        owner: &str,
        routes: Vec<AppliedRoute>,
    ) -> io::Result<usize> {
        validate_owner(owner).map_err(invalid_input)?;
        validate_apply(&routes).map_err(invalid_input)?;
        if self.position(uid, owner).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "owner already has routes applied; remove them first",
            ));
        }
        self.journal.entries.push(JournalEntry {
            uid,
            owner: owner.to_string(),
            state: OwnedState::Applying,
            resources: routes.iter().cloned().map(OwnedResource::Route).collect(),
        });
        if let Err(err) = self.store.save(&self.journal) {
            self.journal.entries.pop();
            return Err(err);
        }
        let index = self.journal.entries.len() - 1;
        match apply_routes_transactional(self.routes.as_mut(), &routes) {
            Ok(()) => {
                self.journal.entries[index].state = OwnedState::Applied;
                self.persist();
                Ok(routes.len())
            }
            Err(err) => {
                self.journal.entries.remove(index);
                self.persist();
                Err(err)
            }
        }
    }

    /// Remove everything `(uid, owner)` owns. Routes already gone count as
    /// removed; routes that fail stay in the journal as `stale`.
    pub fn remove_owner(&mut self, uid: u32, owner: &str) -> io::Result<usize> {
        validate_owner(owner).map_err(invalid_input)?;
        let index = self
            .position(uid, owner)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "owner has nothing applied"))?;
        let count = self.journal.entries[index].resources.len();
        let result = self.teardown_entry(index);
        self.persist();
        result.map(|()| count)
    }

    pub fn owned(&self, uid: u32) -> Vec<OwnedEntry> {
        self.journal
            .entries
            .iter()
            .filter(|entry| entry.uid == uid)
            .map(|entry| OwnedEntry {
                owner: entry.owner.clone(),
                state: entry.state,
                resources: entry.resources.clone(),
            })
            .collect()
    }

    pub fn cleanup_uid(&mut self, uid: u32) -> io::Result<CleanupResult> {
        self.teardown(|entry| entry.uid == uid)
    }

    /// Tear down every owner of every uid, newest first (SIGTERM path).
    pub fn shutdown(&mut self) -> io::Result<CleanupResult> {
        self.teardown(|_| true)
    }

    pub fn set_link_state(&mut self, name: &str, up: bool) -> io::Result<()> {
        validate_iface_name(name).map_err(invalid_input)?;
        self.links.set_link_state(name, up)
    }

    fn position(&self, uid: u32, owner: &str) -> Option<usize> {
        self.journal
            .entries
            .iter()
            .position(|entry| entry.uid == uid && entry.owner == owner)
    }

    fn teardown(&mut self, matches: impl Fn(&JournalEntry) -> bool) -> io::Result<CleanupResult> {
        let mut result = CleanupResult::default();
        for index in (0..self.journal.entries.len()).rev() {
            if !matches(&self.journal.entries[index]) {
                continue;
            }
            let owner = self.journal.entries[index].owner.clone();
            match self.teardown_entry(index) {
                Ok(()) => result.removed_owners.push(owner),
                Err(_) => result.failed.push(owner),
            }
        }
        self.store.save(&self.journal)?;
        Ok(result)
    }

    /// Remove the entry's resources. On success the entry is dropped; on
    /// failure it keeps only what could not be removed and becomes `stale`.
    /// The caller persists the journal.
    fn teardown_entry(&mut self, index: usize) -> io::Result<()> {
        let routes: Vec<AppliedRoute> = self.journal.entries[index]
            .resources
            .iter()
            .map(|resource| match resource {
                OwnedResource::Route(route) => route.clone(),
            })
            .collect();
        match remove_routes_best_effort(&mut IgnoreMissing(self.routes.as_mut()), &routes) {
            Ok(()) => {
                self.journal.entries.remove(index);
                Ok(())
            }
            Err((failed, message)) => {
                let entry = &mut self.journal.entries[index];
                entry.state = OwnedState::Stale;
                // `remove_routes_best_effort` reports failures newest first.
                entry.resources = failed.into_iter().rev().map(OwnedResource::Route).collect();
                Err(io::Error::other(message))
            }
        }
    }

    /// Save after a kernel change already happened. The in-memory journal
    /// stays authoritative; a stale file only causes harmless `NotFound`
    /// removals on the next start, so the failure is logged, not returned.
    fn persist(&mut self) {
        if let Err(err) = self.store.save(&self.journal) {
            eprintln!("network-orchestrator-daemon: failed to save journal: {err}");
        }
    }
}

/// Removing a route that is already gone is success: the goal state holds.
struct IgnoreMissing<'a>(&'a mut dyn RouteExecutor);

impl RouteExecutor for IgnoreMissing<'_> {
    fn add_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
        self.0.add_route(route)
    }

    fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
        match self.0.remove_route(route) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
pub(crate) mod testing {
    use super::LinkExecutor;
    use net_manager_core::models::AppliedRoute;
    use net_manager_core::policy::RouteExecutor;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Op {
        Add(String),
        Remove(String),
        Link(String, bool),
    }

    /// Shared recorder for fake executors; failure knobs by destination.
    #[derive(Clone, Default)]
    pub struct Recorder {
        pub ops: Arc<Mutex<Vec<Op>>>,
        pub fail_add: Arc<Mutex<Vec<String>>>,
        pub fail_remove: Arc<Mutex<Vec<String>>>,
        pub missing_on_remove: Arc<Mutex<Vec<String>>>,
    }

    impl Recorder {
        pub fn ops(&self) -> Vec<Op> {
            self.ops.lock().unwrap().clone()
        }
    }

    pub struct FakeRoutes {
        pub recorder: Recorder,
        /// Called before each add, e.g. to inspect the journal on disk.
        pub before_add: Option<Box<dyn FnMut() + Send>>,
    }

    impl FakeRoutes {
        pub fn new(recorder: &Recorder) -> Self {
            Self {
                recorder: recorder.clone(),
                before_add: None,
            }
        }
    }

    impl RouteExecutor for FakeRoutes {
        fn add_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
            if let Some(hook) = self.before_add.as_mut() {
                hook();
            }
            let dest = route.destination.to_string();
            self.recorder
                .ops
                .lock()
                .unwrap()
                .push(Op::Add(dest.clone()));
            if self.recorder.fail_add.lock().unwrap().contains(&dest) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "file exists"));
            }
            Ok(())
        }

        fn remove_route(&mut self, route: &AppliedRoute) -> io::Result<()> {
            let dest = route.destination.to_string();
            self.recorder
                .ops
                .lock()
                .unwrap()
                .push(Op::Remove(dest.clone()));
            if self.recorder.fail_remove.lock().unwrap().contains(&dest) {
                return Err(io::Error::other("device busy"));
            }
            if self
                .recorder
                .missing_on_remove
                .lock()
                .unwrap()
                .contains(&dest)
            {
                return Err(io::Error::new(io::ErrorKind::NotFound, "no such route"));
            }
            Ok(())
        }
    }

    pub struct FakeLinks(pub Recorder);

    impl LinkExecutor for FakeLinks {
        fn set_link_state(&mut self, name: &str, up: bool) -> io::Result<()> {
            self.0.ops.lock().unwrap().push(Op::Link(name.into(), up));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{FakeLinks, FakeRoutes, Op, Recorder};
    use super::*;
    use crate::journal::{JournalDocument, JournalEntry, JournalStore, JOURNAL_FILE};
    use net_manager_core::daemon_protocol::{OwnedResource, OwnedState};
    use net_manager_core::models::AppliedRoute;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-daemon-core-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn route(dest: &str) -> AppliedRoute {
        AppliedRoute::on_link(dest.parse().unwrap(), 2, 5)
    }

    fn open_core(dir: &Path, recorder: &Recorder) -> DaemonCore {
        DaemonCore::open(
            JournalStore::new(dir.join(JOURNAL_FILE)),
            Box::new(FakeRoutes::new(recorder)),
            Box::new(FakeLinks(recorder.clone())),
        )
        .unwrap()
    }

    fn journal_on_disk(dir: &Path) -> JournalDocument {
        JournalStore::new(dir.join(JOURNAL_FILE)).load().unwrap()
    }

    fn add(dest: &str) -> Op {
        Op::Add(dest.into())
    }

    fn remove(dest: &str) -> Op {
        Op::Remove(dest.into())
    }

    #[test]
    fn apply_writes_journal_before_first_add() {
        let dir = unique_dir("wal");
        let recorder = Recorder::default();
        let seen: Arc<Mutex<Vec<Option<OwnedState>>>> = Arc::default();
        let mut routes = FakeRoutes::new(&recorder);
        let (seen_in_hook, journal_path) = (seen.clone(), dir.join(JOURNAL_FILE));
        routes.before_add = Some(Box::new(move || {
            let doc = JournalStore::new(&journal_path).load().unwrap();
            seen_in_hook
                .lock()
                .unwrap()
                .push(doc.entries.first().map(|entry| entry.state));
        }));
        let mut core = DaemonCore::open(
            JournalStore::new(dir.join(JOURNAL_FILE)),
            Box::new(routes),
            Box::new(FakeLinks(recorder.clone())),
        )
        .unwrap();

        core.apply_routes(1000, "office", vec![route("10.1.0.0/16")])
            .unwrap();

        assert_eq!(*seen.lock().unwrap(), vec![Some(OwnedState::Applying)]);
        assert_eq!(journal_on_disk(&dir).entries[0].state, OwnedState::Applied);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_failure_rolls_back_and_drops_entry() {
        let dir = unique_dir("rollback");
        let recorder = Recorder::default();
        recorder.fail_add.lock().unwrap().push("10.2.0.0/16".into());
        let mut core = open_core(&dir, &recorder);

        let err = core
            .apply_routes(
                1000,
                "office",
                vec![route("10.1.0.0/16"), route("10.2.0.0/16")],
            )
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            recorder.ops(),
            vec![
                add("10.1.0.0/16"),
                add("10.2.0.0/16"),
                remove("10.1.0.0/16")
            ]
        );
        assert!(core.owned(1000).is_empty());
        assert!(journal_on_disk(&dir).entries.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_rejects_invalid_input_before_executor() {
        let dir = unique_dir("invalid");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        let err = core
            .apply_routes(1000, "", vec![route("10.1.0.0/16")])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = core
            .apply_routes(1000, "office", vec![route("10.1.0.1/16")])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(recorder.ops().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn same_owner_same_uid_conflicts() {
        let dir = unique_dir("conflict");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "office", vec![route("10.1.0.0/16")])
            .unwrap();
        let err = core
            .apply_routes(1000, "office", vec![route("10.2.0.0/16")])
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(recorder.ops(), vec![add("10.1.0.0/16")]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn same_owner_different_uid_is_independent() {
        let dir = unique_dir("uids");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "office", vec![route("10.1.0.0/16")])
            .unwrap();
        core.apply_routes(1001, "office", vec![route("10.2.0.0/16")])
            .unwrap();
        assert_eq!(core.owned(1000).len(), 1);
        assert_eq!(core.owned(1001).len(), 1);
        assert_eq!(core.remove_owner(1001, "office").unwrap(), 1);
        assert_eq!(core.owned(1000).len(), 1);
        assert!(core.owned(1001).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_foreign_uid_owner_is_not_found() {
        let dir = unique_dir("foreign");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "office", vec![route("10.1.0.0/16")])
            .unwrap();
        let err = core.remove_owner(1001, "office").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(recorder.ops(), vec![add("10.1.0.0/16")]);
        assert_eq!(core.owned(1000).len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_treats_missing_route_as_removed() {
        let dir = unique_dir("missing");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "office", vec![route("10.1.0.0/16")])
            .unwrap();
        recorder
            .missing_on_remove
            .lock()
            .unwrap()
            .push("10.1.0.0/16".into());
        assert_eq!(core.remove_owner(1000, "office").unwrap(), 1);
        assert!(core.owned(1000).is_empty());
        assert!(journal_on_disk(&dir).entries.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn partial_remove_retains_failed_routes() {
        let dir = unique_dir("partial");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(
            1000,
            "office",
            vec![route("10.1.0.0/16"), route("10.2.0.0/16")],
        )
        .unwrap();
        recorder
            .fail_remove
            .lock()
            .unwrap()
            .push("10.1.0.0/16".into());

        assert!(core.remove_owner(1000, "office").is_err());

        let owned = core.owned(1000);
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].state, OwnedState::Stale);
        assert_eq!(
            owned[0].resources,
            vec![OwnedResource::Route(route("10.1.0.0/16"))]
        );
        assert_eq!(journal_on_disk(&dir).entries[0].resources.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    fn leftover(uid: u32, owner: &str, dests: &[&str]) -> JournalEntry {
        JournalEntry {
            uid,
            owner: owner.into(),
            state: OwnedState::Applying,
            resources: dests
                .iter()
                .map(|dest| OwnedResource::Route(route(dest)))
                .collect(),
        }
    }

    #[test]
    fn open_tears_down_leftovers_and_empties_journal() {
        let dir = unique_dir("leftovers");
        JournalStore::new(dir.join(JOURNAL_FILE))
            .save(&JournalDocument {
                entries: vec![
                    leftover(1000, "a", &["10.1.0.0/16", "10.2.0.0/16"]),
                    leftover(1001, "b", &["10.3.0.0/16"]),
                ],
                ..JournalDocument::default()
            })
            .unwrap();
        let recorder = Recorder::default();
        let core = open_core(&dir, &recorder);

        assert_eq!(
            recorder.ops(),
            vec![
                remove("10.3.0.0/16"),
                remove("10.2.0.0/16"),
                remove("10.1.0.0/16")
            ]
        );
        assert!(core.owned(1000).is_empty() && core.owned(1001).is_empty());
        assert!(journal_on_disk(&dir).entries.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_marks_failed_teardown_as_stale() {
        let dir = unique_dir("stale");
        JournalStore::new(dir.join(JOURNAL_FILE))
            .save(&JournalDocument {
                entries: vec![leftover(1000, "a", &["10.1.0.0/16", "10.2.0.0/16"])],
                ..JournalDocument::default()
            })
            .unwrap();
        let recorder = Recorder::default();
        recorder
            .fail_remove
            .lock()
            .unwrap()
            .push("10.2.0.0/16".into());
        let core = open_core(&dir, &recorder);

        let owned = core.owned(1000);
        assert_eq!(owned[0].state, OwnedState::Stale);
        assert_eq!(
            owned[0].resources,
            vec![OwnedResource::Route(route("10.2.0.0/16"))]
        );
        assert_eq!(journal_on_disk(&dir).entries[0].state, OwnedState::Stale);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cleanup_uid_only_touches_that_uid() {
        let dir = unique_dir("cleanup");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "a", vec![route("10.1.0.0/16")])
            .unwrap();
        core.apply_routes(1001, "b", vec![route("10.2.0.0/16")])
            .unwrap();
        let result = core.cleanup_uid(1000).unwrap();
        assert_eq!(result.removed_owners, vec!["a".to_string()]);
        assert!(result.failed.is_empty());
        assert!(core.owned(1000).is_empty());
        assert_eq!(core.owned(1001).len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shutdown_removes_all_uids_in_reverse_order() {
        let dir = unique_dir("shutdown");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        core.apply_routes(1000, "a", vec![route("10.1.0.0/16")])
            .unwrap();
        core.apply_routes(1001, "b", vec![route("10.2.0.0/16")])
            .unwrap();
        core.apply_routes(1000, "c", vec![route("10.3.0.0/16")])
            .unwrap();
        recorder.ops.lock().unwrap().clear();

        core.shutdown().unwrap();

        assert_eq!(
            recorder.ops(),
            vec![
                remove("10.3.0.0/16"),
                remove("10.2.0.0/16"),
                remove("10.1.0.0/16")
            ]
        );
        assert!(journal_on_disk(&dir).entries.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn link_state_validates_name_before_executor() {
        let dir = unique_dir("link");
        let recorder = Recorder::default();
        let mut core = open_core(&dir, &recorder);
        let err = core.set_link_state("wg0; reboot", false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(recorder.ops().is_empty());
        core.set_link_state("enp0s3", false).unwrap();
        assert_eq!(recorder.ops(), vec![Op::Link("enp0s3".into(), false)]);
        fs::remove_dir_all(&dir).unwrap();
    }
}
