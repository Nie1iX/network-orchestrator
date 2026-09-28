use std::io;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathProtection {
    pub protected_dacl: bool,
    pub current_user: bool,
    pub system: bool,
    pub administrators: bool,
}

pub fn xray_context(profile_id: &str) -> Vec<u8> {
    format!("network-orchestrator:xray:{profile_id}").into_bytes()
}

pub fn read_xray_config(path: &Path, profile_id: &str) -> io::Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    let protected = path
        .file_name()
        .map(|name| {
            name.to_string_lossy()
                .to_lowercase()
                .ends_with(".json.dpapi")
        })
        .unwrap_or(false);
    if protected {
        unprotect_user_data(&bytes, &xray_context(profile_id))
    } else {
        Ok(bytes)
    }
}

#[cfg(windows)]
mod imp {
    use super::PathProtection;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    use windows::Win32::Security::{
        GetFileSecurityW, GetSecurityDescriptorControl, GetTokenInformation, SetFileSecurityW,
        TokenUser, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const GENERIC_READ: u32 = 0x8000_0000;

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Read a file bypassing its DACL by opening it with
    /// `FILE_FLAG_BACKUP_SEMANTICS`. Requires `SeBackupPrivilege` to be
    /// enabled on the process token (see `enable_backup_privilege`).
    /// Used to import ACL-protected files such as WireGuard `.conf.dpapi`
    /// configs that are owned by SYSTEM and deny access to administrators.
    pub fn read_with_backup_semantics(path: &Path) -> io::Result<Vec<u8>> {
        let name = wide(path);
        let handle = unsafe {
            CreateFileW(
                PCWSTR::from_raw(name.as_ptr()),
                GENERIC_READ,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        }
        .map_err(|err| {
            let raw = err.code().0;
            if raw < 0 && (raw & 0x1FFF_0000) == (0x0007 << 16) {
                io::Error::from_raw_os_error(raw & 0xFFFF)
            } else {
                io::Error::other(err.to_string())
            }
        })?;
        let handle = OwnedHandle(handle);
        let mut out = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            let mut read = 0u32;
            let ok =
                unsafe { ReadFile(handle.0, Some(&mut buf), Some(&mut read as *mut u32), None) };
            match ok {
                Ok(()) => {
                    if read == 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..read as usize]);
                }
                Err(err) => return Err(io::Error::other(err.to_string())),
            }
        }
        Ok(out)
    }

    unsafe fn read_wide_string(ptr: *const u16) -> io::Result<String> {
        if ptr.is_null() {
            return Err(io::Error::other("win32 returned a null string"));
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16(core::slice::from_raw_parts(ptr, len))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
    }

    fn current_user_sid() -> io::Result<String> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
                .map_err(|_| io::Error::last_os_error())?;
            let token = OwnedHandle(token);
            let mut needed = 0u32;
            let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut needed);
            if needed == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut buffer = vec![0u8; needed as usize];
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(buffer.as_mut_ptr() as *mut _),
                needed,
                &mut needed,
            )
            .map_err(|_| io::Error::last_os_error())?;
            let user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let mut sid_string = windows::core::PWSTR::null();
            ConvertSidToStringSidW(user.User.Sid, &mut sid_string)
                .map_err(|_| io::Error::last_os_error())?;
            let text = read_wide_string(sid_string.0);
            let _ = LocalFree(HLOCAL(sid_string.0 as *mut _));
            text
        }
    }

    pub fn protect_path(path: &Path) -> io::Result<()> {
        let meta = std::fs::metadata(path)?;
        let sid = current_user_sid()?;
        let inheritance = if meta.is_dir() { "OICI" } else { "" };
        let sddl = format!(
            "D:P(A;{inheritance};FA;;;{sid})(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)"
        );
        let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR::from_raw(sddl_wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
            .map_err(|_| io::Error::last_os_error())?;
            let name = wide(path);
            let applied = SetFileSecurityW(
                PCWSTR::from_raw(name.as_ptr()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            );
            let _ = LocalFree(HLOCAL(descriptor.0));
            if applied.as_bool() {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    fn data_blob(data: &[u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
        if data.len() > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "data too large for DPAPI",
            ));
        }
        Ok(CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        })
    }

    unsafe fn take_blob(blob: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let bytes = core::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(blob.pbData as *mut _));
        bytes
    }

    pub fn protect_user_data(data: &[u8], context: &[u8]) -> io::Result<Vec<u8>> {
        if context.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "protection context must not be empty",
            ));
        }
        let input = data_blob(data)?;
        let entropy = data_blob(context)?;
        let description: Vec<u16> = "Network Orchestrator Xray config"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let mut output = CRYPT_INTEGER_BLOB::default();
            CryptProtectData(
                &input,
                PCWSTR::from_raw(description.as_ptr()),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
            .map_err(|_| io::Error::last_os_error())?;
            Ok(take_blob(output))
        }
    }

    pub fn unprotect_user_data(data: &[u8], context: &[u8]) -> io::Result<Vec<u8>> {
        if context.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "protection context must not be empty",
            ));
        }
        let input = data_blob(data)?;
        let entropy = data_blob(context)?;
        unsafe {
            let mut output = CRYPT_INTEGER_BLOB::default();
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
            .map_err(|_| io::Error::last_os_error())?;
            Ok(take_blob(output))
        }
    }

    /// Decrypt data that was protected with machine-scope DPAPI and no entropy
    /// (e.g. WireGuard's `.conf.dpapi` files encrypted by the tunnel service).
    /// Any process on the machine can decrypt machine-scope blobs.
    pub fn unprotect_machine_data(data: &[u8]) -> io::Result<Vec<u8>> {
        let input = data_blob(data)?;
        unsafe {
            let mut output = CRYPT_INTEGER_BLOB::default();
            CryptUnprotectData(
                &input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
            .map_err(|_| io::Error::last_os_error())?;
            Ok(take_blob(output))
        }
    }

    /// Encrypt data with machine-scope DPAPI and no entropy. Test-only
    /// helper to create blobs compatible with WireGuard's `.conf.dpapi`.
    #[cfg(test)]
    pub fn protect_machine_data(data: &[u8]) -> io::Result<Vec<u8>> {
        use windows::Win32::Security::Cryptography::CRYPTPROTECT_LOCAL_MACHINE;
        let input = data_blob(data)?;
        unsafe {
            let mut output = CRYPT_INTEGER_BLOB::default();
            CryptProtectData(
                &input,
                PCWSTR::null(),
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            )
            .map_err(|_| io::Error::last_os_error())?;
            Ok(take_blob(output))
        }
    }

    pub fn inspect_path_protection(path: &Path) -> io::Result<PathProtection> {
        let name = wide(path);
        unsafe {
            let mut needed = 0u32;
            let _ = GetFileSecurityW(
                PCWSTR::from_raw(name.as_ptr()),
                DACL_SECURITY_INFORMATION.0,
                PSECURITY_DESCRIPTOR(std::ptr::null_mut()),
                0,
                &mut needed,
            );
            if needed == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut buffer = vec![0u8; needed as usize];
            let descriptor = PSECURITY_DESCRIPTOR(buffer.as_mut_ptr() as *mut _);
            let fetched = GetFileSecurityW(
                PCWSTR::from_raw(name.as_ptr()),
                DACL_SECURITY_INFORMATION.0,
                descriptor,
                needed,
                &mut needed,
            );
            if !fetched.as_bool() {
                return Err(io::Error::last_os_error());
            }
            let mut control = 0u16;
            let mut revision = 0u32;
            GetSecurityDescriptorControl(descriptor, &mut control, &mut revision)
                .map_err(|_| io::Error::last_os_error())?;
            let mut sddl = windows::core::PWSTR::null();
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl,
                None,
            )
            .map_err(|_| io::Error::last_os_error())?;
            let text = read_wide_string(sddl.0);
            let _ = LocalFree(HLOCAL(sddl.0 as *mut _));
            let text = text?;
            let sid = current_user_sid()?;
            Ok(PathProtection {
                protected_dacl: control & SE_DACL_PROTECTED.0 != 0,
                current_user: text.contains(&format!("FA;;;{sid})")),
                system: text.contains("FA;;;SY)"),
                administrators: text.contains("FA;;;BA)"),
            })
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::PathProtection;
    use std::io;
    use std::path::Path;

    /// Restrict a file to `0600` and a directory to `0700` (owner read/write/
    /// execute only). This is the Unix analogue of the Windows protected
    /// DACL: no group or other access at all.
    pub fn protect_path(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let mode = if metadata.is_dir() { 0o700 } else { 0o600 };
        let mut permissions = metadata.permissions();
        permissions.set_mode(mode);
        std::fs::set_permissions(path, permissions)
    }

    /// Report whether `path` currently has exactly the owner-only mode
    /// `protect_path` sets. There is no Unix equivalent of separate
    /// "system"/"administrators" principals, so all four fields collapse to
    /// the same owner-only check.
    pub fn inspect_path_protection(path: &Path) -> io::Result<PathProtection> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let expected_mode = if metadata.is_dir() { 0o700 } else { 0o600 };
        let protected = metadata.permissions().mode() & 0o777 == expected_mode;
        Ok(PathProtection {
            protected_dacl: protected,
            current_user: protected,
            system: protected,
            administrators: protected,
        })
    }

    pub fn protect_user_data(_data: &[u8], _context: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DPAPI protection is only available on Windows",
        ))
    }

    pub fn unprotect_user_data(_data: &[u8], _context: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DPAPI protection is only available on Windows",
        ))
    }

    pub fn unprotect_machine_data(_data: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DPAPI protection is only available on Windows",
        ))
    }

    pub fn read_with_backup_semantics(path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    /// Test-only: there is no Unix equivalent of machine-scope DPAPI, so any
    /// test that needs this must stay `#[cfg(windows)]`-gated itself.
    #[cfg(test)]
    pub fn protect_machine_data(_data: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DPAPI protection is only available on Windows",
        ))
    }
}

pub use imp::{
    inspect_path_protection, protect_path, protect_user_data, read_with_backup_semantics,
    unprotect_machine_data, unprotect_user_data,
};

#[cfg(test)]
pub use imp::protect_machine_data;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-acl-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn protect_and_inspect_directory_and_file() {
        let dir = unique_dir("protect");
        let file = dir.join("secret.conf");
        fs::write(&file, b"PrivateKey=AAAA").unwrap();

        protect_path(&dir).unwrap();
        protect_path(&file).unwrap();

        let dir_protection = inspect_path_protection(&dir).unwrap();
        let file_protection = inspect_path_protection(&file).unwrap();
        assert_eq!(
            dir_protection,
            PathProtection {
                protected_dacl: true,
                current_user: true,
                system: true,
                administrators: true,
            }
        );
        assert_eq!(file_protection, dir_protection);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn protect_missing_path_returns_not_found() {
        let dir = unique_dir("protect-missing");
        let missing = dir.join("absent.conf");
        let err = protect_path(&missing).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xray_context_uses_profile_id() {
        assert_eq!(xray_context("node-1"), b"network-orchestrator:xray:node-1");
    }

    #[test]
    fn read_xray_config_returns_plain_json_bytes() {
        let dir = unique_dir("xray-read");
        let path = dir.join("node.json");
        fs::write(&path, b"{\"a\":1}").unwrap();
        assert_eq!(read_xray_config(&path, "node-1").unwrap(), b"{\"a\":1}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn protect_and_unprotect_user_data_roundtrip() {
        let context = xray_context("node-1");
        let plaintext = b"{\"secret\":\"UUID-777\"}";
        let ciphertext = protect_user_data(plaintext, &context).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(!ciphertext.windows(8).any(|window| window == b"UUID-777"));
        assert_eq!(
            unprotect_user_data(&ciphertext, &context).unwrap(),
            plaintext
        );
        assert!(unprotect_user_data(&ciphertext, &xray_context("other")).is_err());
        let mut corrupt = ciphertext.clone();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0xFF;
        assert!(unprotect_user_data(&corrupt, &context).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn protect_user_data_rejects_empty_context() {
        assert_eq!(
            protect_user_data(b"data", b"").unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            unprotect_user_data(b"data", b"").unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[cfg(windows)]
    #[test]
    fn read_xray_config_decrypts_dpapi_suffix() {
        let dir = unique_dir("xray-dpapi");
        let path = dir.join("config.json.DPAPI");
        let bytes = protect_user_data(b"{\"a\":1}", &xray_context("node-1")).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert_eq!(read_xray_config(&path, "node-1").unwrap(), b"{\"a\":1}");
        assert!(read_xray_config(&path, "other").is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn protect_user_data_is_unsupported() {
        assert_eq!(
            protect_user_data(b"data", b"ctx").unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(
            unprotect_user_data(b"data", b"ctx").unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn read_xray_config_dpapi_suffix_is_unsupported() {
        let dir = unique_dir("xray-dpapi");
        let path = dir.join("config.json.dpapi");
        fs::write(&path, b"opaque").unwrap();
        assert_eq!(
            read_xray_config(&path, "node-1").unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn protect_and_unprotect_machine_data_roundtrip() {
        let plaintext = b"[Interface]\nPrivateKey = test\n\n[Peer]\nAllowedIPs = 10.0.0.0/24\n";
        let ciphertext = protect_machine_data(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(!ciphertext.windows(8).any(|w| w == b"PrivateKey"));
        assert_eq!(unprotect_machine_data(&ciphertext).unwrap(), plaintext);
    }

    #[cfg(windows)]
    #[test]
    fn unprotect_machine_data_rejects_corrupt_input() {
        let ciphertext = protect_machine_data(b"test data").unwrap();
        let mut corrupt = ciphertext.clone();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0xFF;
        assert!(unprotect_machine_data(&corrupt).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn unprotect_machine_data_is_unsupported() {
        assert_eq!(
            unprotect_machine_data(b"data").unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
    }
}
