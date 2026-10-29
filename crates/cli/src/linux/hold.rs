//! Keeping a connection up. The daemon ties a tunnel to the client processes
//! of the user and removes it 30 s after the last one is gone, so a CLI that
//! connects and exits would lose the tunnel at once. `netorch up` therefore
//! leaves a small background process per connection (the keeper) that stays
//! connected to the daemon; `netorch up --foreground` is the keeper itself,
//! until Ctrl+C. `netorch down` stops the keeper.
use super::auth;
use super::ctx::Ctx;
use net_manager_core::models::{Profile, TunnelState};
use net_manager_engine::linux_engine::LinuxEngine;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How often a keeper looks at the tunnel.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(10);
/// Consecutive "not running" readings before a keeper gives up: three polls,
/// about the daemon's own 30 s grace, so a `switch` that reconnects in between
/// does not end it.
const MISSES_BEFORE_EXIT: u32 = 3;
/// How long `up` waits for a new keeper to report in.
const KEEPER_START_WAIT: Duration = Duration::from_secs(3);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Ctrl+C and `kill` end the wait; a closing terminal does not end a keeper.
pub fn install_signal_handlers(ignore_hangup: bool) {
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        if ignore_hangup {
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
        }
    }
}

/// Where keepers record their pid: the user's runtime directory, or
/// `/run/netorch` for root.
pub fn keeper_dir(root_user: bool) -> Result<PathBuf, String> {
    if root_user {
        return Ok(PathBuf::from("/run/netorch"));
    }
    // Non-interactive SSH commands may lack XDG_RUNTIME_DIR although the
    // user's runtime directory exists.
    // SAFETY: getuid never fails.
    let uid = unsafe { libc::getuid() };
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .or_else(|| Some(PathBuf::from(format!("/run/user/{uid}"))).filter(|dir| dir.is_dir()))
        .map(|dir| dir.join("netorch"))
        .ok_or_else(|| {
            "No runtime directory for the background process; use --foreground and keep \
             the command running"
                .to_string()
        })
}

fn pid_path(dir: &Path, profile_id: &str) -> PathBuf {
    dir.join(format!("{profile_id}.pid"))
}

fn write_pid(dir: &Path, profile_id: &str, pid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let path = pid_path(dir, profile_id);
    let temp = path.with_extension("tmp");
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut file| std::io::Write::write_all(&mut file, pid.to_string().as_bytes()))?;
    std::fs::rename(temp, path)
}

fn read_pid(dir: &Path, profile_id: &str) -> Option<u32> {
    std::fs::read_to_string(pid_path(dir, profile_id))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Whether `pid` is a live netorch keeper (not a recycled pid of something else).
fn is_keeper(pid: u32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    alive
        && std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|bytes| {
                let text = String::from_utf8_lossy(&bytes).replace('\0', " ");
                text.contains("netorch") && text.split_whitespace().any(|word| word == "hold")
            })
            .unwrap_or(false)
}

/// The keeper holding `profile_id`, if one is running.
pub fn running_keeper(dir: &Path, profile_id: &str) -> Option<u32> {
    read_pid(dir, profile_id).filter(|&pid| is_keeper(pid))
}

/// Starts a keeper for the profile unless one is already running; returns its
/// pid. The keeper is a new session of this same program, so closing the
/// terminal or the SSH connection does not end it.
pub fn ensure_keeper(ctx: &Ctx, profile: &Profile) -> Result<u32, String> {
    use std::os::unix::process::CommandExt;
    let dir = keeper_dir(ctx.root_user)?;
    if let Some(pid) = running_keeper(&dir, &profile.id) {
        return Ok(pid);
    }
    let exe = std::env::current_exe().map_err(|_| "Cannot find the netorch executable")?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("--data-dir")
        .arg(&ctx.root)
        .args(["hold", &profile.id])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: setsid is async-signal-safe and runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|_| "The background process could not be started".to_string())?;
    let started = Instant::now();
    while started.elapsed() < KEEPER_START_WAIT {
        if let Some(pid) = running_keeper(&dir, &profile.id) {
            return Ok(pid);
        }
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err("The background process did not start".into())
}

/// Stops the keeper of the profile, if any. It leaves the tunnel to whoever
/// calls this (`down` has already disconnected it).
pub fn stop_keeper(ctx: &Ctx, profile_id: &str) {
    let Ok(dir) = keeper_dir(ctx.root_user) else {
        return;
    };
    if let Some(pid) = running_keeper(&dir, profile_id) {
        // SAFETY: a plain SIGTERM to a process verified to be our keeper.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    }
    let _ = std::fs::remove_file(pid_path(&dir, profile_id));
}

/// Why a watch ended.
#[derive(Debug, PartialEq, Eq)]
pub enum WatchEnd {
    /// Asked to stop (signal).
    Signal,
    /// The tunnel is no longer running.
    TunnelGone,
}

/// Waits until `stop` is set or the tunnel has not been running for
/// `misses` readings in a row. Every reading is a short connection to the
/// daemon, which keeps this process registered as a client.
pub fn watch(
    engine: &LinuxEngine,
    profile: &Profile,
    stop: &AtomicBool,
    interval: Duration,
    misses: u32,
) -> WatchEnd {
    let mut missed = 0;
    let mut last = Instant::now() - interval;
    loop {
        if stop.load(Ordering::SeqCst) {
            return WatchEnd::Signal;
        }
        if last.elapsed() >= interval {
            last = Instant::now();
            match engine.status(profile) {
                Ok(status) if status.state == TunnelState::Running => missed = 0,
                Ok(_) => missed += 1,
                // The daemon being unreachable is not evidence the tunnel is gone.
                Err(_) => {}
            }
            if missed >= misses {
                return WatchEnd::TunnelGone;
            }
        }
        std::thread::sleep(Duration::from_millis(100).min(interval));
    }
}

/// `netorch hold <profile>`: the background keeper.
pub fn run_keeper(ctx: &Ctx, profile: &Profile) -> Result<(), String> {
    let dir = keeper_dir(ctx.root_user)?;
    install_signal_handlers(true);
    write_pid(&dir, &profile.id, std::process::id())
        .map_err(|_| "The keeper could not record itself".to_string())?;
    let end = watch(
        &ctx.engine,
        profile,
        &STOP,
        WATCH_INTERVAL,
        MISSES_BEFORE_EXIT,
    );
    // Only remove our own record: a newer keeper may have replaced it.
    if read_pid(&dir, &profile.id) == Some(std::process::id()) {
        let _ = std::fs::remove_file(pid_path(&dir, &profile.id));
    }
    let _ = end;
    Ok(())
}

/// `netorch up --foreground`: holds the connection in this terminal and
/// disconnects on Ctrl+C.
pub fn run_foreground(ctx: &Ctx, profile: &Profile) -> Result<String, String> {
    install_signal_handlers(false);
    eprintln!("Press Ctrl+C to disconnect.");
    let end = watch(
        &ctx.engine,
        profile,
        &STOP,
        WATCH_INTERVAL,
        MISSES_BEFORE_EXIT,
    );
    match end {
        WatchEnd::Signal => {
            auth::run(ctx.root_user, || ctx.engine.disconnect(profile))?;
            Ok(format!("Disconnected \"{}\"", profile.name))
        }
        WatchEnd::TunnelGone => Err(format!("\"{}\" is no longer connected", profile.name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_records_round_trip_and_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("netorch");
        write_pid(&run, "wg1", 4242).unwrap();
        assert_eq!(read_pid(&run, "wg1"), Some(4242));
        assert_eq!(read_pid(&run, "other"), None);
        let mode = std::fs::metadata(pid_path(&run, "wg1"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(&run).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn a_dead_or_foreign_pid_is_not_a_keeper() {
        // This test process is alive but is not a `netorch … hold`.
        assert!(!is_keeper(std::process::id()));
        assert!(!is_keeper(u32::MAX - 1));
        let dir = tempfile::tempdir().unwrap();
        write_pid(dir.path(), "wg1", std::process::id()).unwrap();
        assert_eq!(running_keeper(dir.path(), "wg1"), None);
    }

    #[test]
    fn root_keeps_its_records_in_run_and_users_in_their_runtime_dir() {
        assert_eq!(keeper_dir(true).unwrap(), PathBuf::from("/run/netorch"));
    }
}
