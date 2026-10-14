//! Split DNS for secondary tunnels: macOS sends queries for a domain to the
//! nameservers in `/etc/resolver/<domain>` instead of the system's, without
//! touching the primary tunnel's service DNS. Only files this helper wrote
//! (they carry a marker line) are ever replaced or removed.

use crate::sysexec::{Runner, DSCACHEUTIL, KILLALL};
use net_manager_core::models::valid_dns_suffix;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const DIR: &str = "/etc/resolver";
const MARKER: &str = "# Managed by Network Orchestrator";
const MAX_SERVERS: usize = 3;

fn ours(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|text| text.starts_with(MARKER))
}

fn flush(runner: &dyn Runner) {
    // Cached answers for these names would outlive the change.
    let _ = runner.run(DSCACHEUTIL, &["-flushcache".into()]);
    let _ = runner.run(KILLALL, &["-HUP".into(), "mDNSResponder".into()]);
}

/// Writes a resolver file per suffix; returns the suffixes now owned. A suffix
/// whose file already exists and is not ours is left alone and not returned.
pub fn apply(
    runner: &dyn Runner,
    dir: &Path,
    domains: &[String],
    servers: &[IpAddr],
) -> io::Result<Vec<String>> {
    let servers: Vec<&IpAddr> = servers.iter().take(MAX_SERVERS).collect();
    if domains.is_empty() || servers.is_empty() {
        return Ok(Vec::new());
    }
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
    }
    let mut body = format!("{MARKER}\n");
    for server in &servers {
        body.push_str(&format!("nameserver {server}\n"));
    }
    let mut written = Vec::new();
    for domain in domains {
        let domain = domain.to_ascii_lowercase();
        if !valid_dns_suffix(&domain) {
            continue;
        }
        let path = dir.join(&domain);
        if path.exists() && !ours(&path) {
            continue;
        }
        let temp = dir.join(format!(".{domain}.tmp"));
        let _ = fs::remove_file(&temp);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temp)?;
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, &path)?;
        written.push(domain);
    }
    if !written.is_empty() {
        flush(runner);
    }
    Ok(written)
}

/// Removes the files for `domains`, but only those still carrying our marker.
pub fn remove(runner: &dyn Runner, dir: &Path, domains: &[String]) {
    let mut removed = false;
    for domain in domains {
        if !valid_dns_suffix(domain) {
            continue;
        }
        let path = dir.join(domain);
        if ours(&path) && fs::remove_file(&path).is_ok() {
            removed = true;
        }
    }
    if removed {
        flush(runner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysexec::fake::FakeRunner;

    fn servers() -> Vec<IpAddr> {
        vec!["10.10.0.53".parse().unwrap(), "10.10.0.54".parse().unwrap()]
    }

    #[test]
    fn a_resolver_file_is_written_with_the_nameservers_and_removed_again() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::default();
        let domains = vec!["Corp.Example".to_string(), "lab.local".to_string()];
        let written = apply(&runner, dir.path(), &domains, &servers()).unwrap();
        assert_eq!(written, ["corp.example", "lab.local"]);
        let text = fs::read_to_string(dir.path().join("corp.example")).unwrap();
        assert!(text.starts_with(MARKER));
        assert!(text.contains("nameserver 10.10.0.53\nnameserver 10.10.0.54\n"));
        assert_eq!(
            fs::metadata(dir.path().join("lab.local"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert!(runner
            .calls()
            .iter()
            .any(|c| c == "dscacheutil -flushcache"));

        remove(&runner, dir.path(), &written);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn files_that_are_not_ours_are_never_replaced_or_deleted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("corp.example"), "nameserver 1.2.3.4\n").unwrap();
        let runner = FakeRunner::default();
        let written = apply(
            &runner,
            dir.path(),
            &["corp.example".to_string(), "other.example".to_string()],
            &servers(),
        )
        .unwrap();
        assert_eq!(written, ["other.example"]);
        assert_eq!(
            fs::read_to_string(dir.path().join("corp.example")).unwrap(),
            "nameserver 1.2.3.4\n"
        );
        remove(
            &runner,
            dir.path(),
            &["corp.example".to_string(), "other.example".to_string()],
        );
        assert!(dir.path().join("corp.example").exists());
        assert!(!dir.path().join("other.example").exists());
    }

    #[test]
    fn unsafe_names_and_missing_servers_write_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::default();
        let bad = vec![
            "../etc/hosts".to_string(),
            "a/b".to_string(),
            ".x".to_string(),
        ];
        assert!(apply(&runner, dir.path(), &bad, &servers())
            .unwrap()
            .is_empty());
        assert!(apply(&runner, dir.path(), &["ok.example".into()], &[])
            .unwrap()
            .is_empty());
        assert!(apply(&runner, dir.path(), &[], &servers())
            .unwrap()
            .is_empty());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        assert!(runner.calls().is_empty());
        remove(&runner, dir.path(), &bad);
    }

    #[test]
    fn at_most_three_nameservers_are_written() {
        let dir = tempfile::tempdir().unwrap();
        let many: Vec<IpAddr> = (1..=6)
            .map(|n| format!("10.0.0.{n}").parse().unwrap())
            .collect();
        apply(
            &FakeRunner::default(),
            dir.path(),
            &["a.example".into()],
            &many,
        )
        .unwrap();
        let text = fs::read_to_string(dir.path().join("a.example")).unwrap();
        assert_eq!(text.matches("nameserver").count(), 3);
    }
}
