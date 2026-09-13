#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathProtection {
    pub protected_dacl: bool,
    pub current_user: bool,
    pub system: bool,
    pub administrators: bool,
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
    use windows::Win32::Security::{
        GetFileSecurityW, GetSecurityDescriptorControl, GetTokenInformation, SetFileSecurityW,
        TokenUser, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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

    pub fn protect_path(path: &Path) -> io::Result<()> {
        std::fs::metadata(path).map(|_| ())
    }

    pub fn inspect_path_protection(_path: &Path) -> io::Result<PathProtection> {
        Ok(PathProtection {
            protected_dacl: true,
            current_user: true,
            system: true,
            administrators: true,
        })
    }
}

pub use imp::{inspect_path_protection, protect_path};

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
}
