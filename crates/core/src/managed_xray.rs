use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub const MANAGED_XRAY_VERSION: &str = "v26.7.28";
pub const MANAGED_XRAY_URL: &str =
    "https://github.com/XTLS/Xray-core/releases/download/v26.7.28/Xray-windows-64.zip";
pub const MANAGED_XRAY_SHA256: &str =
    "c7172078fca4711bcd92a4774dcd1822544579c58816197575c47533317fd8d1";
pub const MAX_XRAY_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

const MAX_XRAY_ENTRY_BYTES: u64 = 48 * 1024 * 1024;
const MAX_XRAY_TOTAL_BYTES: u64 = 96 * 1024 * 1024;
const ALLOWLIST: [&str; 5] = [
    "xray.exe",
    "geoip.dat",
    "geosite.dat",
    "LICENSE",
    "README.md",
];
const REQUIRED: [&str; 3] = ["xray.exe", "geoip.dat", "geosite.dat"];
const REQUIRED_SHA256: [(&str, &str); 3] = [
    (
        "xray.exe",
        "1d9674327972a21afd4c906a7a72bb0856935aa9e0227c87f34f03d11a88bddf",
    ),
    (
        "geoip.dat",
        "cdf411fce977a1f48adb6a3b224e3e2bd7eccfcd4d6e2e30c6dc443f1a0e8e52",
    ),
    (
        "geosite.dat",
        "ea8d817c4782a84db4104ba416329bb14024f69568c666f5cca6c4303ef1942e",
    ),
];

#[derive(Clone, Copy)]
struct ArchiveLayout {
    version: &'static str,
    executable_name: &'static str,
    allowlist: &'static [&'static str],
    required_names: &'static [&'static str],
}

const WINDOWS_LAYOUT: ArchiveLayout = ArchiveLayout {
    version: MANAGED_XRAY_VERSION,
    executable_name: "xray.exe",
    allowlist: &ALLOWLIST,
    required_names: &REQUIRED,
};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const LINUX_XRAY_VERSION: &str = "v26.3.27";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const LINUX_XRAY_PACKAGE_ROOT: &str = "/usr/lib/network-orchestrator/xray";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const LINUX_XRAY_URL: &str =
    "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip";
// Official XTLS release asset Xray-linux-64.zip.dgst, SHA2-256.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const LINUX_XRAY_SHA256: &str =
    "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const LINUX_ALLOWLIST: [&str; 5] = ["xray", "geoip.dat", "geosite.dat", "LICENSE", "README.md"];
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const LINUX_REQUIRED: [&str; 3] = ["xray", "geoip.dat", "geosite.dat"];
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const LINUX_LAYOUT: ArchiveLayout = ArchiveLayout {
    version: LINUX_XRAY_VERSION,
    executable_name: "xray",
    allowlist: &LINUX_ALLOWLIST,
    required_names: &LINUX_REQUIRED,
};
// SHA-256 of required files extracted from the archive above.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const LINUX_REQUIRED_SHA256: [(&str, &str); 3] = [
    (
        "xray",
        "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed",
    ),
    (
        "geoip.dat",
        "744c97b74c52bae2ac8664fef6ac481d7765cb8432a0df54f0368a88b9b4a354",
    ),
    (
        "geosite.dat",
        "adf92de0cfc70e458b399f04c5f912bf42d115ed7e37281b30e2f1c68605e4e9",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedXrayInstallation {
    pub executable: PathBuf,
    pub version_dir: PathBuf,
    pub created: bool,
}

pub fn managed_version_dir(root: &Path) -> PathBuf {
    root.join(MANAGED_XRAY_VERSION)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn linux_managed_version_dir(root: &Path) -> PathBuf {
    root.join(LINUX_XRAY_VERSION)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn verify_managed_linux_executable(root: &Path, executable: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(invalid_data("managed xray installation contains a symlink"));
    }
    let root = root.canonicalize()?;
    let expected_dir = linux_managed_version_dir(&root);
    if executable.canonicalize()? != expected_dir.join("xray") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable is outside the managed xray installation",
        ));
    }
    for name in LINUX_REQUIRED {
        if fs::symlink_metadata(expected_dir.join(name))?
            .file_type()
            .is_symlink()
        {
            return Err(invalid_data("managed xray installation contains a symlink"));
        }
    }
    verify_required_hashes(&expected_dir, &LINUX_REQUIRED_SHA256)?;
    let executable_metadata = fs::symlink_metadata(expected_dir.join("xray"))?;
    let mode = executable_metadata.permissions().mode() & 0o777;
    if mode == 0o700 {
        return Ok(());
    }
    if !package_executable_mode_allowed(mode, executable_metadata.uid()) {
        return Err(invalid_data(
            "managed xray executable has unsafe permissions",
        ));
    }
    for name in LINUX_REQUIRED {
        verify_root_owned_readonly_path(&expected_dir.join(name))?;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn package_executable_mode_allowed(mode: u32, uid: u32) -> bool {
    mode == 0o755 && uid == 0
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn verify_root_owned_readonly_path(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for component in path.ancestors() {
        let metadata = fs::symlink_metadata(component)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(invalid_data(
                "managed xray package path is not root-owned and read-only",
            ));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn install_verified_linux_archive(
    root: &Path,
    archive: &[u8],
) -> io::Result<ManagedXrayInstallation> {
    install_archive_for_platform(
        root,
        archive,
        LINUX_XRAY_SHA256,
        &LINUX_REQUIRED_SHA256,
        LINUX_LAYOUT,
    )
}

pub fn is_managed_executable(root: &Path, executable: &Path) -> io::Result<bool> {
    let root = root.canonicalize()?;
    let executable = executable.canonicalize()?;
    Ok(executable == managed_version_dir(&root).join("xray.exe"))
}

pub fn is_managed_executable_location(root: &Path, executable: &Path) -> io::Result<bool> {
    let root = root.canonicalize()?;
    let version = managed_version_dir(&root).canonicalize()?;
    if executable.file_name() != Some(std::ffi::OsStr::new("xray.exe")) {
        return Ok(false);
    }
    let Some(parent) = executable.parent() else {
        return Ok(false);
    };
    Ok(parent.canonicalize()? == version)
}

pub fn verify_managed_executable(root: &Path, executable: &Path) -> io::Result<()> {
    let root = root.canonicalize()?;
    let executable = executable.canonicalize()?;
    let expected_dir = managed_version_dir(&root);
    if executable != expected_dir.join("xray.exe") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "executable is outside the managed xray installation",
        ));
    }
    verify_required_hashes(&expected_dir, &REQUIRED_SHA256)
}

pub fn install_verified_archive(
    root: &Path,
    archive: &[u8],
) -> io::Result<ManagedXrayInstallation> {
    install_archive_with_expected_hash(root, archive, MANAGED_XRAY_SHA256, &REQUIRED_SHA256)
}

fn install_archive_with_expected_hash(
    root: &Path,
    archive: &[u8],
    expected_hash: &str,
    expected_required: &[(&str, &str)],
) -> io::Result<ManagedXrayInstallation> {
    install_archive_for_platform(
        root,
        archive,
        expected_hash,
        expected_required,
        WINDOWS_LAYOUT,
    )
}

fn install_archive_for_platform(
    root: &Path,
    archive: &[u8],
    expected_hash: &str,
    expected_required: &[(&str, &str)],
    layout: ArchiveLayout,
) -> io::Result<ManagedXrayInstallation> {
    let ArchiveLayout {
        version,
        executable_name,
        allowlist,
        required_names,
    } = layout;
    if archive.len() > MAX_XRAY_ARCHIVE_BYTES {
        return Err(invalid_input(format!(
            "archive exceeds the {} byte download limit",
            MAX_XRAY_ARCHIVE_BYTES
        )));
    }
    let actual = format!("{:x}", Sha256::digest(archive));
    if actual != expected_hash {
        return Err(invalid_data(
            "archive sha-256 does not match the pinned digest",
        ));
    }
    let final_dir = root.join(version);
    let executable = final_dir.join(executable_name);
    if final_dir.is_dir() {
        if version_verified(&final_dir, expected_required) {
            protect_version_tree(root, &final_dir, required_names, executable_name)?;
            return Ok(ManagedXrayInstallation {
                executable,
                version_dir: final_dir,
                created: false,
            });
        }
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "managed xray directory '{}' exists but is incomplete; remove it explicitly before reinstalling",
                version
            ),
        ));
    }

    let mut seen_names = std::collections::HashSet::new();
    for name in allowlisted_central_names(archive, allowlist)? {
        if !seen_names.insert(name.clone()) {
            return Err(invalid_data(format!(
                "archive contains a duplicate entry '{name}'"
            )));
        }
    }

    let mut archive_reader =
        zip::ZipArchive::new(std::io::Cursor::new(archive)).map_err(invalid_data)?;
    let mut selected: HashMap<String, usize> = HashMap::new();
    let mut total: u64 = 0;
    for index in 0..archive_reader.len() {
        let entry = archive_reader.by_index(index).map_err(invalid_data)?;
        if !entry.is_file() || !allowlist.contains(&entry.name()) {
            continue;
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(invalid_data("archive contains a symlink"));
        }
        if selected.insert(entry.name().to_string(), index).is_some() {
            return Err(invalid_data(format!(
                "archive contains a duplicate entry '{}'",
                entry.name()
            )));
        }
        if entry.size() > MAX_XRAY_ENTRY_BYTES {
            return Err(invalid_data(format!(
                "archive entry '{}' exceeds the {} byte limit",
                entry.name(),
                MAX_XRAY_ENTRY_BYTES
            )));
        }
        total = total.saturating_add(entry.size());
        if total > MAX_XRAY_TOTAL_BYTES {
            return Err(invalid_data(format!(
                "archive entries exceed the {} byte total limit",
                MAX_XRAY_TOTAL_BYTES
            )));
        }
    }
    for required in required_names {
        if !selected.contains_key(*required) {
            return Err(invalid_data(format!(
                "archive is missing required entry '{required}'"
            )));
        }
    }

    fs::create_dir_all(root)?;
    crate::config_security::protect_path(root)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let staging = root.join(format!("{version}.tmp-{}-{nanos}", std::process::id()));
    let outcome = (|| {
        fs::create_dir(&staging)?;
        crate::config_security::protect_path(&staging)?;
        for (name, index) in &selected {
            let mut entry = archive_reader.by_index(*index).map_err(invalid_data)?;
            let declared_size = entry.size();
            let target = staging.join(name);
            let mut limited = (&mut entry).take(MAX_XRAY_ENTRY_BYTES + 1);
            let mut output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&target)?;
            let written = io::copy(&mut limited, &mut output)?;
            drop(output);
            if written != declared_size {
                return Err(invalid_data(format!(
                    "archive entry '{name}' did not match its declared size"
                )));
            }
            crate::config_security::protect_path(&target)?;
        }
        verify_required_hashes(&staging, expected_required)?;
        protect_version_tree(root, &staging, required_names, executable_name)?;
        match fs::rename(&staging, &final_dir) {
            Ok(()) => Ok(ManagedXrayInstallation {
                executable,
                version_dir: final_dir,
                created: true,
            }),
            Err(err) => {
                if version_verified(&final_dir, expected_required) {
                    protect_version_tree(root, &final_dir, required_names, executable_name)?;
                    Ok(ManagedXrayInstallation {
                        executable,
                        version_dir: final_dir,
                        created: false,
                    })
                } else {
                    Err(err)
                }
            }
        }
    })();
    if outcome.is_err() || staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    outcome
}

fn allowlisted_central_names(archive: &[u8], allowlist: &[&str]) -> io::Result<Vec<String>> {
    let scan_from = archive.len().saturating_sub(22 + 65_535);
    let mut eocd = None;
    for pos in (scan_from..archive.len().saturating_sub(21)).rev() {
        if archive[pos..pos + 4] == [0x50, 0x4b, 0x05, 0x06] {
            let comment_len =
                u16::from_le_bytes(archive[pos + 20..pos + 22].try_into().unwrap()) as usize;
            if pos + 22 + comment_len == archive.len() {
                eocd = Some(pos);
                break;
            }
        }
    }
    let eocd = eocd.ok_or_else(|| invalid_data("archive end-of-central-directory not found"))?;
    let records = u16::from_le_bytes(archive[eocd + 10..eocd + 12].try_into().unwrap()) as usize;
    let mut pos = u32::from_le_bytes(archive[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let mut names = Vec::new();
    for _ in 0..records {
        if pos + 46 > archive.len() || archive[pos..pos + 4] != [0x50, 0x4b, 0x01, 0x02] {
            return Err(invalid_data("archive central directory is malformed"));
        }
        let name_len = u16::from_le_bytes(archive[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(archive[pos + 30..pos + 32].try_into().unwrap()) as usize;
        let comment_len =
            u16::from_le_bytes(archive[pos + 32..pos + 34].try_into().unwrap()) as usize;
        let name_end = pos + 46 + name_len;
        if name_end > archive.len() {
            return Err(invalid_data("archive central directory is truncated"));
        }
        let name = std::str::from_utf8(&archive[pos + 46..name_end])
            .map_err(|_| invalid_data("archive entry name is not UTF-8"))?;
        if allowlist.contains(&name) {
            names.push(name.to_string());
        }
        pos = name_end + extra_len + comment_len;
    }
    Ok(names)
}

fn version_verified(version_dir: &Path, expected_required: &[(&str, &str)]) -> bool {
    expected_required.iter().all(|(name, expected_hash)| {
        let path = version_dir.join(name);
        fs::symlink_metadata(&path)
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
            && fs::read(&path)
                .map(|data| sha256_hex(&data) == *expected_hash)
                .unwrap_or(false)
    })
}

fn verify_required_hashes(
    version_dir: &Path,
    expected_required: &[(&str, &str)],
) -> io::Result<()> {
    for (name, expected_hash) in expected_required {
        let path = version_dir.join(name);
        let data = fs::read(&path)?;
        if sha256_hex(&data) != *expected_hash {
            return Err(invalid_data(format!(
                "managed xray file '{name}' failed integrity verification"
            )));
        }
    }
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn protect_version_tree(
    root: &Path,
    version_dir: &Path,
    required_names: &[&str],
    executable_name: &str,
) -> io::Result<()> {
    crate::config_security::protect_path(root)?;
    crate::config_security::protect_path(version_dir)?;
    for name in required_names {
        crate::config_security::protect_path(&version_dir.join(name))?;
    }
    #[cfg(unix)]
    if executable_name == "xray" {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            version_dir.join(executable_name),
            fs::Permissions::from_mode(0o700),
        )?;
    }
    #[cfg(not(unix))]
    let _ = executable_name;
    Ok(())
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-mgxray-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn build_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn required_entries() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("xray.exe", b"MZ fake xray".to_vec()),
            ("geoip.dat", b"geoip".to_vec()),
            ("geosite.dat", b"geosite".to_vec()),
        ]
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn linux_required_entries() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("xray", b"ELF fake xray".to_vec()),
            ("geoip.dat", b"geoip".to_vec()),
            ("geosite.dat", b"geosite".to_vec()),
        ]
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn install_linux_synthetic(root: &Path, archive: &[u8]) -> io::Result<ManagedXrayInstallation> {
        let file_hashes: Vec<(String, String)> = linux_required_entries()
            .iter()
            .map(|(name, data)| (name.to_string(), sha256_hex(data)))
            .collect();
        let refs: Vec<(&str, &str)> = file_hashes
            .iter()
            .map(|(n, h)| (n.as_str(), h.as_str()))
            .collect();
        install_archive_for_platform(root, archive, &sha256_hex(archive), &refs, LINUX_LAYOUT)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_manifest_installs_executable_and_assets_atomically() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("linux-valid");
        let root = dir.join("xray");
        let owned = linux_required_entries();
        let archive = build_archive(&slices(&owned));
        let installed = install_linux_synthetic(&root, &archive).unwrap();
        assert!(installed.created);
        assert_eq!(installed.version_dir, root.join("v26.3.27"));
        assert_eq!(installed.executable, installed.version_dir.join("xray"));
        assert_eq!(
            fs::metadata(&installed.executable)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(installed.version_dir.join("geoip.dat"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!install_linux_synthetic(&root, &archive).unwrap().created);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_manifest_rejects_wrong_archive_and_tampered_assets() {
        let dir = unique_dir("linux-integrity");
        let root = dir.join("xray");
        let owned = linux_required_entries();
        let archive = build_archive(&slices(&owned));
        assert_eq!(
            install_verified_linux_archive(&root, &archive)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!root.join(LINUX_XRAY_VERSION).exists());
        let installed = install_linux_synthetic(&root, &archive).unwrap();
        fs::write(installed.version_dir.join("geoip.dat"), b"tampered").unwrap();
        assert!(install_linux_synthetic(&root, &archive).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_manifest_rejects_missing_binary_without_publishing_version() {
        let dir = unique_dir("linux-missing");
        let root = dir.join("xray");
        let archive = build_archive(&[("geoip.dat", b"geoip"), ("geosite.dat", b"geosite")]);
        assert_eq!(
            install_linux_synthetic(&root, &archive).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!linux_managed_version_dir(&root).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_manifest_rejects_wrong_file_hash_before_atomic_publish() {
        let dir = unique_dir("linux-wrong-file-hash");
        let root = dir.join("xray");
        let archive = build_archive(&[
            ("xray", b"ELF fake xray"),
            ("geoip.dat", b"tampered"),
            ("geosite.dat", b"geosite"),
        ]);
        assert_eq!(
            install_linux_synthetic(&root, &archive).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!linux_managed_version_dir(&root).exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn package_mode_policy_requires_root_owner_and_no_group_write() {
        assert!(package_executable_mode_allowed(0o755, 0));
        assert!(!package_executable_mode_allowed(0o775, 0));
        assert!(!package_executable_mode_allowed(0o757, 0));
        assert!(!package_executable_mode_allowed(0o755, 1000));
        assert!(!package_executable_mode_allowed(0o644, 0));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_manifest_rejects_symlinked_existing_asset() {
        let dir = unique_dir("linux-symlink");
        let root = dir.join("xray");
        let owned = linux_required_entries();
        let archive = build_archive(&slices(&owned));
        let installed = install_linux_synthetic(&root, &archive).unwrap();
        let external = dir.join("external-geoip.dat");
        fs::write(&external, b"geoip").unwrap();
        fs::remove_file(installed.version_dir.join("geoip.dat")).unwrap();
        std::os::unix::fs::symlink(&external, installed.version_dir.join("geoip.dat")).unwrap();
        assert_eq!(
            install_linux_synthetic(&root, &archive).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn official_linux_archive_verifies_when_supplied_outside_normal_tests() {
        use std::os::unix::fs::PermissionsExt;
        let Ok(path) = std::env::var("XRAY_LINUX_ARCHIVE") else {
            return;
        };
        let archive = fs::read(path).unwrap();
        assert_eq!(sha256_hex(&archive), LINUX_XRAY_SHA256);
        let dir = unique_dir("linux-official");
        let root = dir.join("xray");
        let installed = install_verified_linux_archive(&root, &archive).unwrap();
        verify_managed_linux_executable(&root, &installed.executable).unwrap();
        let version = std::process::Command::new(&installed.executable)
            .arg("version")
            .output()
            .unwrap();
        assert!(version.status.success());
        assert!(String::from_utf8_lossy(&version.stdout).contains("26.3.27"));
        fs::set_permissions(&installed.executable, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_managed_linux_executable(&root, &installed.executable).is_err());
        fs::set_permissions(&installed.executable, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(installed.version_dir.join("geosite.dat"), b"tampered").unwrap();
        assert_eq!(
            verify_managed_linux_executable(&root, &installed.executable)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    fn slices<'a>(entries: &'a [(&'a str, Vec<u8>)]) -> Vec<(&'a str, &'a [u8])> {
        entries.iter().map(|(n, d)| (*n, d.as_slice())).collect()
    }

    fn sha256_hex(data: &[u8]) -> String {
        format!("{:x}", Sha256::digest(data))
    }

    fn install_synthetic(root: &Path, archive: &[u8]) -> io::Result<ManagedXrayInstallation> {
        let file_hashes: Vec<(String, String)> = required_entries()
            .iter()
            .map(|(name, data)| (name.to_string(), sha256_hex(data)))
            .collect();
        let refs: Vec<(&str, &str)> = file_hashes
            .iter()
            .map(|(n, h)| (n.as_str(), h.as_str()))
            .collect();
        install_archive_with_expected_hash(root, archive, &sha256_hex(archive), &refs)
    }

    fn version_dir(root: &Path) -> PathBuf {
        managed_version_dir(root)
    }

    #[test]
    fn valid_archive_installs_allowlisted_files() {
        let dir = unique_dir("valid");
        let root = dir.join("backends").join("xray");
        let owned = required_entries();
        let mut entries: Vec<(&str, &[u8])> = slices(&owned);
        entries.push(("LICENSE", b"license text"));
        entries.push(("README.md", b"readme"));
        let archive = build_archive(&entries);

        let result = install_synthetic(&root, &archive).unwrap();

        assert!(result.created);
        assert_eq!(result.version_dir, version_dir(&root));
        assert_eq!(result.executable, version_dir(&root).join("xray.exe"));
        for (name, data) in &entries {
            assert_eq!(fs::read(version_dir(&root).join(name)).unwrap(), *data);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wrong_hash_leaves_no_version_directory() {
        let dir = unique_dir("wronghash");
        let root = dir.join("xray");
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);

        let err = install_verified_archive(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!version_dir(&root).exists());
        assert!(!root.exists() || fs::read_dir(&root).unwrap().next().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn oversized_archive_is_rejected_before_open() {
        let dir = unique_dir("oversized");
        let root = dir.join("xray");
        let archive = vec![0u8; MAX_XRAY_ARCHIVE_BYTES + 1];

        let err = install_verified_archive(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!version_dir(&root).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unknown_and_traversal_entries_are_not_written() {
        let dir = unique_dir("traversal");
        let root = dir.join("xray");
        let owned = required_entries();
        let mut entries: Vec<(&str, &[u8])> = slices(&owned);
        entries.push(("sub/xray.exe", b"nested"));
        entries.push(("evil.dll", b"evil"));
        let archive = build_archive(&entries);

        let result = install_synthetic(&root, &archive).unwrap();

        assert!(result.created);
        let written: Vec<_> = fs::read_dir(&result.version_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(written.len(), 3);
        assert!(!result.version_dir.join("sub").exists());
        assert!(!result.version_dir.join("evil.dll").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_required_entry_fails_without_version() {
        let dir = unique_dir("missingreq");
        let root = dir.join("xray");
        let archive = build_archive(&[
            ("xray.exe", b"MZ".as_slice()),
            ("geoip.dat", b"geoip".as_slice()),
        ]);

        let err = install_synthetic(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!version_dir(&root).exists());
        let staging_left: Vec<_> = fs::read_dir(&root)
            .map(|rd| rd.filter_map(|e| e.ok()).collect())
            .unwrap_or_default();
        assert!(staging_left.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn duplicate_allowlisted_entry_fails_without_version() {
        let dir = unique_dir("dup");
        let root = dir.join("xray");
        let owned = required_entries();
        let mut entries: Vec<(&str, &[u8])> = slices(&owned);
        entries.push(("xray2exe", b"MZ second"));
        let mut archive = build_archive(&entries);
        let mut cursor = 0;
        while let Some(pos) = archive[cursor..]
            .windows(b"xray2exe".len())
            .position(|w| w == b"xray2exe")
        {
            archive[cursor + pos..cursor + pos + 8].copy_from_slice(b"xray.exe");
            cursor += pos + 8;
        }

        let err = install_synthetic(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!version_dir(&root).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn oversized_entry_metadata_fails_without_version() {
        let dir = unique_dir("bigentry");
        let root = dir.join("xray");
        let big = vec![0u8; usize::try_from(MAX_XRAY_ENTRY_BYTES + 1).unwrap()];
        let archive = build_archive(&[
            ("xray.exe", b"MZ".as_slice()),
            ("geoip.dat", b"geoip".as_slice()),
            ("geosite.dat", big.as_slice()),
        ]);

        let err = install_synthetic(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!version_dir(&root).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn complete_existing_version_is_idempotent() {
        let dir = unique_dir("idempotent");
        let root = dir.join("xray");
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);

        let first = install_synthetic(&root, &archive).unwrap();
        assert!(first.created);
        let second = install_synthetic(&root, &archive).unwrap();

        assert!(!second.created);
        assert_eq!(second.executable, first.executable);
        assert_eq!(
            fs::read(version_dir(&root).join("xray.exe")).unwrap(),
            b"MZ fake xray"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn incomplete_existing_version_is_preserved() {
        let dir = unique_dir("incomplete");
        let root = dir.join("xray");
        let final_dir = version_dir(&root);
        fs::create_dir_all(&final_dir).unwrap();
        fs::write(final_dir.join("xray.exe"), b"original").unwrap();
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);

        let err = install_synthetic(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(final_dir.join("xray.exe")).unwrap(), b"original");
        assert!(!final_dir.join("geoip.dat").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tampered_existing_version_is_preserved_and_rejected() {
        let dir = unique_dir("tampered");
        let root = dir.join("xray");
        let final_dir = version_dir(&root);
        fs::create_dir_all(&final_dir).unwrap();
        for name in ["xray.exe", "geoip.dat", "geosite.dat"] {
            fs::write(final_dir.join(name), b"tampered").unwrap();
        }
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);

        let err = install_synthetic(&root, &archive).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        for name in ["xray.exe", "geoip.dat", "geosite.dat"] {
            assert_eq!(fs::read(final_dir.join(name)).unwrap(), b"tampered");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verify_managed_executable_rejects_tampered_runtime_file() {
        let dir = unique_dir("verify-tampered");
        let root = dir.join("xray");
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);
        let installed = install_synthetic(&root, &archive).unwrap();

        fs::write(installed.version_dir.join("geosite.dat"), b"tampered").unwrap();

        let err = verify_managed_executable(&root, &installed.executable).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verify_managed_executable_rejects_noncanonical_sibling() {
        let dir = unique_dir("verify-sibling");
        let root = dir.join("xray");
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);
        install_synthetic(&root, &archive).unwrap();
        let sibling = dir.join("other").join("xray.exe");
        fs::create_dir_all(sibling.parent().unwrap()).unwrap();
        fs::write(&sibling, b"MZ").unwrap();

        let err = verify_managed_executable(&root, &sibling).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn managed_executable_requires_exact_canonical_path() {
        let dir = unique_dir("canonical");
        let root = dir.join("xray");
        let owned = required_entries();
        let entries: Vec<(&str, &[u8])> = slices(&owned);
        let archive = build_archive(&entries);
        let installed = install_synthetic(&root, &archive).unwrap();

        assert!(is_managed_executable(&root, &installed.executable).unwrap());
        let sibling = dir.join("other").join("xray.exe");
        fs::create_dir_all(sibling.parent().unwrap()).unwrap();
        fs::write(&sibling, b"MZ").unwrap();
        assert!(!is_managed_executable(&root, &sibling).unwrap());
        let nested = version_dir(&root).join("sub").join("xray.exe");
        fs::create_dir_all(nested.parent().unwrap()).unwrap();
        fs::write(&nested, b"MZ").unwrap();
        assert!(!is_managed_executable(&root, &nested).unwrap());
        assert!(is_managed_executable(&root, &dir.join("missing.exe")).is_err());
        assert!(is_managed_executable(&dir.join("noroot"), &installed.executable).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn managed_location_allows_missing_executable_but_rejects_escape() {
        let dir = unique_dir("location");
        let root = dir.join("xray");
        let version = version_dir(&root);
        fs::create_dir_all(&version).unwrap();

        let missing_exe = version.join("xray.exe");
        assert!(is_managed_executable_location(&root, &missing_exe).unwrap());

        assert!(!is_managed_executable_location(&root, &version.join("xray2.exe")).unwrap());

        let sibling_dir = root.join("other");
        fs::create_dir_all(&sibling_dir).unwrap();
        assert!(!is_managed_executable_location(&root, &sibling_dir.join("xray.exe")).unwrap());

        let nested_dir = version.join("sub");
        fs::create_dir_all(&nested_dir).unwrap();
        assert!(!is_managed_executable_location(&root, &nested_dir.join("xray.exe")).unwrap());

        let escaped = version.join("..").join("other").join("xray.exe");
        assert!(!is_managed_executable_location(&root, &escaped).unwrap());

        assert!(is_managed_executable_location(&dir.join("noroot"), &missing_exe).is_err());
        let missing_parent = version.join("nosuchdir").join("xray.exe");
        assert!(is_managed_executable_location(&root, &missing_parent).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
