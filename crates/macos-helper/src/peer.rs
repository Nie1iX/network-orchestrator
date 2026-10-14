//! Who is on the other end of the socket. The kernel reports the peer's uid
//! and pid (`LOCAL_PEERCRED`/`LOCAL_PEERPID`); the helper then requires the
//! console user running the app's own executable.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub pid: u32,
}

/// Decides whether a connected process may talk to the helper at all.
pub trait ClientPolicy: Send + Sync + 'static {
    fn check(&self, peer: &Peer) -> Result<(), String>;
}

pub fn identify(stream: &UnixStream) -> io::Result<Peer> {
    let cred = stream.peer_cred()?;
    let pid = cred
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "peer pid is unknown"))?;
    Ok(Peer {
        uid: cred.uid(),
        pid,
    })
}

/// Owner of `/dev/console`: the user at the physical or screen-shared login
/// session. `None` (root) means the login window is showing.
pub fn console_uid() -> Option<u32> {
    std::fs::metadata("/dev/console")
        .ok()
        .map(|meta| meta.uid())
        .filter(|uid| *uid != 0)
}

/// Path of a running process as the kernel reports it.
#[cfg(target_os = "macos")]
pub fn process_path(pid: u32) -> io::Result<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    // PROC_PIDPATHINFO_MAXSIZE is 4 * MAXPATHLEN.
    let mut buffer = vec![0u8; 4096];
    // SAFETY: the buffer is valid for `buffer.len()` bytes.
    let length = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(OsStr::from_bytes(&buffer[..length as usize])))
}

#[cfg(not(target_os = "macos"))]
pub fn process_path(pid: u32) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

/// The console user, running the app executable the helper was installed with.
pub struct AppClientPolicy {
    client: PathBuf,
    console_uid: Box<dyn Fn() -> Option<u32> + Send + Sync>,
    process_path: Box<dyn Fn(u32) -> io::Result<PathBuf> + Send + Sync>,
}

impl AppClientPolicy {
    pub fn new(client: PathBuf) -> Self {
        Self {
            client,
            console_uid: Box::new(console_uid),
            process_path: Box::new(process_path),
        }
    }

    #[cfg(test)]
    fn with(
        client: PathBuf,
        console_uid: impl Fn() -> Option<u32> + Send + Sync + 'static,
        process_path: impl Fn(u32) -> io::Result<PathBuf> + Send + Sync + 'static,
    ) -> Self {
        Self {
            client,
            console_uid: Box::new(console_uid),
            process_path: Box::new(process_path),
        }
    }
}

impl ClientPolicy for AppClientPolicy {
    fn check(&self, peer: &Peer) -> Result<(), String> {
        if (self.console_uid)() != Some(peer.uid) {
            return Err("only the signed-in console user may use the helper".into());
        }
        let path = (self.process_path)(peer.pid)
            .map_err(|_| "the calling process could not be identified".to_string())?;
        if path != self.client {
            return Err("the calling process is not the Network Orchestrator app".into());
        }
        Ok(())
    }
}

/// The app executable that sits next to the helper inside the same bundle.
pub fn sibling_client(helper: &Path) -> Option<PathBuf> {
    Some(helper.parent()?.join("NetworkOrchestrator"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(console: Option<u32>, path: &'static str) -> AppClientPolicy {
        AppClientPolicy::with(
            PathBuf::from(
                "/Applications/Network Orchestrator.app/Contents/MacOS/NetworkOrchestrator",
            ),
            move || console,
            move |_| Ok(PathBuf::from(path)),
        )
    }
    const APP: &str = "/Applications/Network Orchestrator.app/Contents/MacOS/NetworkOrchestrator";

    #[test]
    fn console_user_running_the_app_is_accepted() {
        let peer = Peer { uid: 501, pid: 42 };
        assert!(policy(Some(501), APP).check(&peer).is_ok());
    }

    #[test]
    fn other_users_login_window_and_other_programs_are_rejected() {
        let peer = Peer { uid: 501, pid: 42 };
        assert!(policy(Some(502), APP).check(&peer).is_err());
        assert!(policy(None, APP).check(&peer).is_err());
        assert!(policy(Some(501), "/usr/bin/curl").check(&peer).is_err());
        let root = Peer { uid: 0, pid: 42 };
        assert!(policy(Some(501), APP).check(&root).is_err());
    }

    #[test]
    fn unreadable_process_is_rejected() {
        let policy = AppClientPolicy::with(
            PathBuf::from(APP),
            || Some(501),
            |_| Err(io::Error::other("gone")),
        );
        assert!(policy.check(&Peer { uid: 501, pid: 1 }).is_err());
    }

    #[test]
    fn client_is_resolved_next_to_the_helper() {
        let helper = Path::new("/A.app/Contents/MacOS/network-orchestrator-helper");
        assert_eq!(
            sibling_client(helper).unwrap(),
            Path::new("/A.app/Contents/MacOS/NetworkOrchestrator")
        );
    }

    #[tokio::test]
    async fn identify_reports_own_process() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let peer = identify(&ours).unwrap();
        // SAFETY: getuid never fails.
        assert_eq!(peer.uid, unsafe { libc::getuid() });
        assert_eq!(peer.pid, std::process::id());
    }
}
