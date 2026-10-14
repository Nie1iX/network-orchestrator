//! Root never runs a file a user can rewrite. A tunnel backend shipped inside
//! the app bundle (`openvpn`, `wireguard-go`) is read once, checked against a
//! SHA-256 pinned in the (signed) helper, and copied into a root-owned stage
//! directory; only that copy is executed. Hashing and copying the same bytes
//! closes the check-then-exec race on the bundle copy. Backends must be
//! self-contained: a dylib outside the bundle would be a user-writable load
//! path the pin cannot cover.

use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Backends are a few MB; anything larger is not what the build pinned.
pub const MAX_BACKEND_BYTES: u64 = 64 * 1024 * 1024;

fn denied(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The stage directory must belong to `owner` and be closed to everyone else.
fn check_stage_dir(dir: &Path, owner: u32) -> io::Result<()> {
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != owner || meta.mode() & 0o022 != 0 {
        return Err(denied("the backend stage directory is not private"));
    }
    Ok(())
}

fn read_bounded(source: &Path) -> io::Result<Vec<u8>> {
    // O_NOFOLLOW: a symlink swapped in for the bundle file is refused.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > MAX_BACKEND_BYTES {
        return Err(denied("the backend is not a regular file of bounded size"));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_BACKEND_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BACKEND_BYTES {
        return Err(denied("the backend grew past its size bound"));
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn staged_matches(path: &Path, expected: &str, owner: u32) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    meta.is_file()
        && meta.uid() == owner
        && meta.mode() & 0o7022 == 0
        && read_bounded(path).is_ok_and(|bytes| sha256_hex(&bytes) == expected)
}

/// Verifies `source` against `expected_sha256` and returns the path of its
/// private staged copy `stage_dir/<hash>`. Re-uses an existing copy only
/// after hashing it again.
pub fn stage_backend(
    source: &Path,
    expected_sha256: &str,
    stage_dir: &Path,
    owner: u32,
) -> io::Result<PathBuf> {
    let expected = expected_sha256.to_ascii_lowercase();
    if !is_sha256_hex(&expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the pinned hash is not SHA-256",
        ));
    }
    check_stage_dir(stage_dir, owner)?;
    let target = stage_dir.join(&expected);
    if staged_matches(&target, &expected, owner) {
        return Ok(target);
    }
    let bytes = read_bounded(source)?;
    if sha256_hex(&bytes) != expected {
        return Err(denied("the backend does not match its pinned hash"));
    }
    let temp = stage_dir.join(format!(".{expected}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temp);
    let written = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        // `mode` above is filtered by the umask; make 0755 exact.
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o755))?;
        fs::rename(&temp, &target)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    fn me() -> u32 {
        // SAFETY: getuid never fails.
        unsafe { libc::getuid() }
    }

    fn private_dir(parent: &Path, name: &str) -> PathBuf {
        let dir = parent.join(name);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    fn fixture(content: &[u8]) -> (TempDir, PathBuf, PathBuf, String) {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("openvpn");
        fs::write(&source, content).unwrap();
        let stage = private_dir(tmp.path(), "stage");
        (tmp, source, stage, sha256_hex(content))
    }

    #[test]
    fn matching_backend_is_staged_executable_and_private() {
        let (_tmp, source, stage, hash) = fixture(b"#!backend");
        let staged = stage_backend(&source, &hash, &stage, me()).unwrap();
        assert_eq!(staged, stage.join(&hash));
        assert_eq!(fs::read(&staged).unwrap(), b"#!backend");
        assert_eq!(fs::metadata(&staged).unwrap().mode() & 0o7777, 0o755);
    }

    #[test]
    fn hash_mismatch_is_refused_and_nothing_is_staged() {
        let (_tmp, source, stage, _) = fixture(b"tampered");
        let wrong = sha256_hex(b"original");
        let err = stage_backend(&source, &wrong, &stage, me()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read_dir(&stage).unwrap().count(), 0);
    }

    #[test]
    fn staged_copy_edited_afterwards_is_replaced_from_the_source() {
        let (_tmp, source, stage, hash) = fixture(b"good");
        let staged = stage_backend(&source, &hash, &stage, me()).unwrap();
        fs::write(&staged, b"evil").unwrap();
        let again = stage_backend(&source, &hash, &stage, me()).unwrap();
        assert_eq!(fs::read(again).unwrap(), b"good");
    }

    #[test]
    fn staged_copy_is_not_trusted_when_the_source_no_longer_matches() {
        let (_tmp, source, stage, hash) = fixture(b"good");
        let staged = stage_backend(&source, &hash, &stage, me()).unwrap();
        fs::write(&staged, b"evil").unwrap();
        fs::write(&source, b"evil").unwrap();
        assert!(stage_backend(&source, &hash, &stage, me()).is_err());
    }

    #[test]
    fn symlinked_source_is_refused() {
        let (tmp, source, stage, hash) = fixture(b"good");
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert!(stage_backend(&link, &hash, &stage, me()).is_err());
    }

    #[test]
    fn writable_foreign_or_missing_stage_dir_is_refused() {
        let (tmp, source, stage, hash) = fixture(b"good");
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(stage_backend(&source, &hash, &stage, me()).is_err());
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(stage_backend(&source, &hash, &stage, me() + 1).is_err());
        assert!(stage_backend(&source, &hash, &tmp.path().join("none"), me()).is_err());
    }

    #[test]
    fn malformed_pin_is_refused() {
        let (_tmp, source, stage, _) = fixture(b"good");
        for pin in ["", "abc", &"z".repeat(64)] {
            let err = stage_backend(&source, pin, &stage, me()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn oversized_source_is_refused() {
        let tmp = TempDir::new().unwrap();
        let stage = private_dir(tmp.path(), "stage");
        let source = tmp.path().join("big");
        let file = File::create(&source).unwrap();
        file.set_len(MAX_BACKEND_BYTES + 1).unwrap();
        let err = stage_backend(&source, &sha256_hex(b"x"), &stage, me()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
