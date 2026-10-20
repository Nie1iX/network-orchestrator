//! The data directory has one runtime owner at a time: the app or one
//! `netorch` that runs Xray locally. The app takes the same lock
//! (`.instance.lock`), because starting a runtime stops stale Xray children
//! and gives back a leftover system proxy, which would hit the other owner.
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
}

pub fn acquire(root: &Path) -> Result<InstanceLock, String> {
    std::fs::create_dir_all(root)
        .map_err(|_| "The data directory could not be created".to_string())?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join(".instance.lock"))
        .map_err(|_| "The data directory is not writable".to_string())?;
    // SAFETY: flock on a descriptor we own for the lifetime of `file`.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(
            "Network Orchestrator or another netorch is running a connection here. \
             Quit it (or run `netorch down`) first."
                .into(),
        );
    }
    Ok(InstanceLock { _file: file })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_owner_is_refused_until_the_first_lets_go() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire(dir.path()).unwrap();
        assert!(acquire(dir.path()).unwrap_err().contains("is running"));
        drop(first);
        assert!(acquire(dir.path()).is_ok());
    }
}
