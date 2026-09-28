//! Peer identity from a connected unix socket: `SO_PEERCRED` for uid/pid,
//! `SO_PEERPIDFD` for a race-free process handle, `/proc/<pid>/stat` for the
//! start time used by the polkit fallback subject.

use crate::auth::{parse_proc_stat_start_time, PeerIdentity, Pidfd};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use tokio::net::UnixStream;

pub fn identify(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let cred = stream.peer_cred()?;
    let pid = cred
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "peer pid is unknown"))?;
    // Kernels before 6.5 lack SO_PEERPIDFD; polkit then gets pid+start-time.
    let pidfd = peer_pidfd(stream.as_raw_fd())
        .ok()
        .map(|fd| Pidfd(Arc::new(fd)));
    let start_time = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| parse_proc_stat_start_time(&stat));
    Ok(PeerIdentity {
        uid: cred.uid(),
        pid,
        start_time,
        pidfd,
    })
}

fn peer_pidfd(socket: RawFd) -> io::Result<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd`/`len` are valid for writes of the sizes passed.
    let rc = unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut fd as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if fd < 0 {
        return Err(io::Error::other("kernel returned no pidfd"));
    }
    // SAFETY: the kernel handed us a fresh fd that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn identify_reports_own_process() {
        let (ours, _theirs) = tokio::net::UnixStream::pair().unwrap();
        let peer = identify(&ours).unwrap();
        // SAFETY: getuid never fails.
        assert_eq!(peer.uid, unsafe { libc::getuid() });
        assert_eq!(peer.pid, std::process::id());
        assert!(peer.start_time.is_some());
    }
}
