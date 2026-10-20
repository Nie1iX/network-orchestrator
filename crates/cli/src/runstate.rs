//! A foreground `netorch up` owns loopback Xray and the per-app proxy, which
//! no other process can see. It leaves a small state file so `status` and
//! `down` from another terminal can find it; a dead pid makes the file stale.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RunState {
    pub profile_id: String,
    pub pid: u32,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub system_proxy: bool,
}

/// Where a `sudo netorch up` leaves its state: root-owned, never in the
/// user's data directory (root-owned files there would lock the app out).
const SYSTEM_DIR: &str = "/var/run/network-orchestrator/netorch";

fn is_root() -> bool {
    // SAFETY: geteuid never fails.
    unsafe { libc::geteuid() == 0 }
}

fn user_directory(root: &Path) -> PathBuf {
    root.join("runtime").join("netorch-up")
}

fn directory(root: &Path) -> PathBuf {
    if is_root() {
        PathBuf::from(SYSTEM_DIR)
    } else {
        user_directory(root)
    }
}

fn file(root: &Path, profile_id: &str) -> PathBuf {
    directory(root).join(format!("{profile_id}.json"))
}

/// Both places a run can have left its state.
fn candidates(root: &Path, profile_id: &str) -> [PathBuf; 2] {
    [
        PathBuf::from(SYSTEM_DIR).join(format!("{profile_id}.json")),
        user_directory(root).join(format!("{profile_id}.json")),
    ]
}

pub fn pid_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub fn write(root: &Path, state: &RunState) -> std::io::Result<()> {
    let directory = directory(root);
    std::fs::create_dir_all(&directory)?;
    let path = file(root, &state.profile_id);
    let temp = path.with_extension("tmp");
    std::fs::write(
        &temp,
        serde_json::to_vec(state).map_err(std::io::Error::other)?,
    )?;
    net_manager_core::config_security::protect_path(&temp)?;
    std::fs::rename(temp, path)
}

pub fn remove(root: &Path, profile_id: &str) {
    for path in candidates(root, profile_id) {
        let _ = std::fs::remove_file(path);
    }
}

/// The live run of this profile; a stale file is removed on the way.
pub fn read(root: &Path, profile_id: &str) -> Option<RunState> {
    let state: RunState =
        serde_json::from_slice(&std::fs::read(file(root, profile_id)).ok()?).ok()?;
    if pid_alive(state.pid) {
        Some(state)
    } else {
        remove(root, profile_id);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(pid: u32) -> RunState {
        RunState {
            profile_id: "p1".into(),
            pid,
            socks_port: Some(10808),
            http_port: None,
            system_proxy: false,
        }
    }

    #[test]
    fn a_live_run_is_found_and_a_dead_one_is_swept() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &state(std::process::id())).unwrap();
        assert_eq!(read(dir.path(), "p1"), Some(state(std::process::id())));
        // pid 2^22 is above the macOS pid limit, so it never exists.
        write(dir.path(), &state(4_194_304)).unwrap();
        assert_eq!(read(dir.path(), "p1"), None);
        assert!(!file(dir.path(), "p1").exists());
    }

    #[test]
    fn removing_a_missing_state_is_harmless() {
        let dir = tempfile::tempdir().unwrap();
        remove(dir.path(), "nothing");
        assert_eq!(read(dir.path(), "nothing"), None);
    }
}
