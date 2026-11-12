#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const LINUX_MIHOMO_VERSION: &str = "v1.19.34";
pub const LINUX_MIHOMO_URL: &str = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-linux-amd64-v1-v1.19.34.gz";
pub const LINUX_MIHOMO_PACKAGE_ROOT: &str = "/usr/lib/network-orchestrator/mihomo";

pub const LINUX_MIHOMO_SHA256: &str =
    "0c07340a01408d033dda4088ea2a4c1e4d82aeed7b2f84f7c046e93b6ff3290c";
pub const LINUX_MIHOMO_EXECUTABLE_SHA256: &str =
    "e1140de751b2848973350edcf0ba32d37a1a8ea5833019d8eb6af67151ed4f7a";
pub const MAX_MIHOMO_ARCHIVE_BYTES: usize = 22_766_449;
const ARCHIVE_SIZE: usize = MAX_MIHOMO_ARCHIVE_BYTES;
const EXECUTABLE_SIZE: usize = 61_948_030;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedMihomoInstallation {
    pub version: String,
    pub executable: PathBuf,
    pub created: bool,
}

pub fn linux_managed_version_dir(root: &Path) -> PathBuf {
    root.join(LINUX_MIHOMO_VERSION)
}

pub fn install_verified_linux_archive(
    root: &Path,
    archive: &[u8],
) -> io::Result<ManagedMihomoInstallation> {
    install_archive(
        root,
        archive,
        LINUX_MIHOMO_SHA256,
        LINUX_MIHOMO_EXECUTABLE_SHA256,
        ARCHIVE_SIZE,
        EXECUTABLE_SIZE,
        ensure_root,
    )
}

fn install_archive(
    root: &Path,
    archive: &[u8],
    archive_sha256: &str,
    executable_sha256: &str,
    archive_size: usize,
    executable_size: usize,
    prepare_root: fn(&Path) -> io::Result<()>,
) -> io::Result<ManagedMihomoInstallation> {
    if archive.len() != archive_size {
        return Err(invalid_data(
            "managed Mihomo archive has an unexpected size",
        ));
    }
    if hash(archive) != archive_sha256 {
        return Err(invalid_data(
            "managed Mihomo archive failed integrity verification",
        ));
    }
    prepare_root(root)?;
    let mut decoder = GzDecoder::new(archive);
    let mut executable = Vec::new();
    decoder
        .by_ref()
        .take(executable_size as u64 + 1)
        .read_to_end(&mut executable)?;
    if executable.len() != executable_size {
        return Err(invalid_data(
            "managed Mihomo executable has an unexpected size",
        ));
    }
    if hash(&executable) != executable_sha256 {
        return Err(invalid_data(
            "managed Mihomo executable failed integrity verification",
        ));
    }

    let destination_dir = linux_managed_version_dir(root);
    if let Ok(metadata) = fs::symlink_metadata(&destination_dir) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(invalid_data("managed Mihomo installation path is unsafe"));
        }
        let destination = destination_dir.join("mihomo");
        if verify_managed_linux_executable(root, &destination).is_ok() {
            return Ok(ManagedMihomoInstallation {
                version: LINUX_MIHOMO_VERSION.to_owned(),
                executable: destination,
                created: false,
            });
        }
        return Err(invalid_data(
            "managed Mihomo installation already exists but is unverified",
        ));
    }

    let staging = root.join(format!(".mihomo-install-{}", std::process::id()));
    fs::create_dir(&staging)?;
    let result = (|| {
        let path = staging.join("mihomo");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(&executable)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o755))?;
            fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
        }
        fs::rename(&staging, &destination_dir)?;
        Ok(ManagedMihomoInstallation {
            version: LINUX_MIHOMO_VERSION.to_owned(),
            executable: destination_dir.join("mihomo"),
            created: true,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

pub fn verify_managed_linux_executable(root: &Path, executable: &Path) -> io::Result<()> {
    validate_ancestors(root, false)?;
    let root = root.canonicalize()?;
    let expected_dir = linux_managed_version_dir(&root);
    let expected = expected_dir.join("mihomo");
    if executable.canonicalize()? != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable is outside the managed Mihomo installation",
        ));
    }
    validate_ancestors(&expected, false)?;
    reject_symlink(&expected_dir)?;
    reject_symlink(&expected)?;
    let metadata = fs::symlink_metadata(&expected)?;
    if !metadata.is_file() || metadata.len() != EXECUTABLE_SIZE as u64 {
        return Err(invalid_data(
            "managed Mihomo executable has an unexpected size",
        ));
    }
    let mut hasher = Sha256::new();
    let mut file = File::open(&expected)?;
    let mut buffer = [0; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    if format!("{:x}", hasher.finalize()) != LINUX_MIHOMO_EXECUTABLE_SHA256 {
        return Err(invalid_data(
            "managed Mihomo executable failed integrity verification",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o755 {
            return Err(invalid_data(
                "managed Mihomo executable has unsafe permissions",
            ));
        }
    }
    Ok(())
}

pub fn remove_managed_linux_installation(root: &Path) -> io::Result<bool> {
    validate_ancestors(root, true)?;
    let path = linux_managed_version_dir(root);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            fs::remove_file(path)?;
        }
        Ok(_) => fs::remove_dir_all(path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    Ok(true)
}

fn reject_symlink(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(invalid_data(
            "managed Mihomo installation contains a symlink",
        ));
    }
    Ok(())
}

fn validate_ancestors(path: &Path, allow_missing: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for component in path.ancestors() {
            match fs::symlink_metadata(component) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(invalid_data(
                            "managed Mihomo package path contains a symlink",
                        ));
                    }
                    let mode = metadata.mode();
                    if metadata.uid() != 0 || (mode & 0o022 != 0 && mode & 0o1000 == 0) {
                        return Err(invalid_data(
                            "managed Mihomo package path is not root-owned and immutable",
                        ));
                    }
                }
                Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (path, allow_missing);
    Ok(())
}

fn ensure_root(root: &Path) -> io::Result<()> {
    validate_ancestors(root, true)?;
    fs::create_dir_all(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    }
    validate_ancestors(root, false)
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::fs;
    use tempfile::tempdir;

    fn synthetic_root(root: &Path) -> io::Result<()> {
        fs::create_dir_all(root)?;
        Ok(())
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn synthetic_archive_is_atomically_installed() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("install");
        let bytes = b"synthetic mihomo executable";
        let archive = gzip(bytes);
        let installed = install_archive(
            &root,
            &archive,
            &hash(&archive),
            &hash(bytes),
            archive.len(),
            bytes.len(),
            synthetic_root,
        )
        .unwrap();

        assert!(installed.created);
        assert_eq!(fs::read(&installed.executable).unwrap(), bytes);
        assert!(!root
            .join(format!(".mihomo-install-{}", std::process::id()))
            .exists());
    }

    #[test]
    fn synthetic_archive_decompression_is_bounded() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("install");
        let archive = gzip(&vec![b'x'; 1024 * 1024]);

        let error = install_archive(
            &root,
            &archive,
            &hash(&archive),
            &hash(b"x"),
            archive.len(),
            1,
            synthetic_root,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!linux_managed_version_dir(&root).exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_install_root() {
        use std::os::unix::fs::symlink;
        let temp = tempdir().unwrap();
        let victim = temp.path().join("victim");
        fs::create_dir(&victim).unwrap();
        fs::create_dir(victim.join(LINUX_MIHOMO_VERSION)).unwrap();
        let root = temp.path().join("install");
        symlink(&victim, &root).unwrap();

        let error = remove_managed_linux_installation(&root).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(linux_managed_version_dir(&victim).is_dir());
    }
}
