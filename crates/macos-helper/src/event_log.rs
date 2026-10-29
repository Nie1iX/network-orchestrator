//! A small text log the helper keeps for an executor that has no child
//! process writing one (WireGuard runs in-process). The app reads it from the
//! same directory as `xray-tun.log` and `openvpn.log`.
//!
//! Lines carry the same `[Info]`/`[Warning]`/`[Error]` tags Xray writes, so
//! the client colours and filters them alike. Callers log what happened, never
//! keys, endpoints or addresses.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// The file is cut to its newest half past this size.
const MAX_BYTES: u64 = 64 * 1024;

#[derive(Default, Debug)]
pub struct EventLog {
    path: Option<PathBuf>,
}

impl EventLog {
    pub fn at(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub fn info(&self, message: &str) {
        self.write("Info", message);
    }

    pub fn warning(&self, message: &str) {
        self.write("Warning", message);
    }

    pub fn error(&self, message: &str) {
        self.write("Error", message);
    }

    /// Makes the log the connecting user's own, as the other tunnel logs are:
    /// created if needed, `0600`, owned by `uid`. Best effort like writing.
    pub fn hand_to(&self, uid: u32) {
        let Some(path) = &self.path else { return };
        let Ok(file) = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
        else {
            return;
        };
        // SAFETY: `fchown` on a descriptor we just opened; -1 keeps the group.
        unsafe {
            libc::fchown(std::os::fd::AsRawFd::as_raw_fd(&file), uid, u32::MAX);
        }
    }

    /// Best effort: a log that cannot be written never fails a connection.
    fn write(&self, level: &str, message: &str) {
        let Some(path) = &self.path else { return };
        // One event, one line: a message cannot forge another entry.
        let message = message.replace(['\n', '\r'], " ");
        self.trim(path);
        let line = format!("{} [{level}] {message}\n", local_time());
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }

    fn trim(&self, path: &PathBuf) {
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        if meta.len() <= MAX_BYTES {
            return;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let mut cut = text.len() / 2;
        while !text.is_char_boundary(cut) {
            cut += 1;
        }
        // Start at a whole line.
        let keep = text[cut..].split_once('\n').map_or("", |(_, rest)| rest);
        let _ = std::fs::write(path, keep);
    }
}

/// `2026/10/23 12:00:00` in local time, like Xray's own lines.
fn local_time() -> String {
    // SAFETY: `localtime_r` writes only into the zeroed `tm` we own.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&now, &mut tm);
        format!(
            "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_appended_as_tagged_timestamped_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.log");
        let log = EventLog::at(path.clone());
        log.info("up");
        log.warning("careful");
        log.error("down");
        let text = std::fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for (line, tail) in lines
            .iter()
            .zip(["[Info] up", "[Warning] careful", "[Error] down"])
        {
            assert!(line.ends_with(tail), "{line}");
            // `2026/10/23 12:00:00 [`
            assert_eq!(line.as_bytes()[4], b'/', "{line}");
            assert_eq!(line.as_bytes()[13], b':', "{line}");
        }
    }

    #[test]
    fn a_message_cannot_forge_a_second_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.log");
        EventLog::at(path.clone()).info("one\n2026/01/01 00:00:00 [Error] fake");
        assert_eq!(std::fs::read_to_string(path).unwrap().lines().count(), 1);
    }

    #[test]
    fn a_log_without_a_path_writes_nothing_and_does_not_fail() {
        EventLog::default().error("ignored");
    }

    #[test]
    fn an_unwritable_location_is_ignored() {
        EventLog::at(PathBuf::from("/nonexistent-dir/e.log")).info("ignored");
    }

    #[test]
    fn a_long_log_keeps_its_newest_whole_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.log");
        let log = EventLog::at(path.clone());
        for index in 0..3_000 {
            log.info(&format!("event number {index:05}"));
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.len() as u64 <= MAX_BYTES + 200);
        assert!(text.lines().all(|l| l.contains("[Info] event number ")));
        assert!(text.lines().last().unwrap().ends_with("02999"));
        assert!(!text.contains("00000"));
    }

    #[test]
    fn the_log_is_private_and_handed_to_the_connecting_user() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.log");
        let log = EventLog::at(path.clone());
        // SAFETY: plain getter.
        let me = unsafe { libc::getuid() };
        log.hand_to(me);
        log.info("x");
        let meta = std::fs::metadata(path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(meta.uid(), me);
    }
}
