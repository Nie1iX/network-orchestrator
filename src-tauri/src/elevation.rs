#[cfg(windows)]
mod imp {
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    struct TokenHandle(HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn to_io_error(err: windows::core::Error) -> io::Error {
        let hresult = err.code().0;
        if hresult < 0 && (hresult & 0x1FFF_0000) == (0x0007 << 16) {
            io::Error::from_raw_os_error(hresult & 0xFFFF)
        } else {
            io::Error::other(err.to_string())
        }
    }

    pub fn is_elevated() -> io::Result<bool> {
        unsafe {
            let mut raw = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw).map_err(to_io_error)?;
            let token = TokenHandle(raw);
            let mut elevation = TOKEN_ELEVATION::default();
            let mut size = 0u32;
            GetTokenInformation(
                token.0,
                TokenElevation,
                Some(&mut elevation as *mut TOKEN_ELEVATION as *mut core::ffi::c_void),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            )
            .map_err(to_io_error)?;
            Ok(elevation.TokenIsElevated != 0)
        }
    }

    pub fn restart_elevated() -> io::Result<()> {
        let exe = std::env::current_exe()?;
        let file: Vec<u16> = exe
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let verb: Vec<u16> = OsStr::new("runas")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let result = unsafe {
            ShellExecuteW(
                HWND::default(),
                PCWSTR::from_raw(verb.as_ptr()),
                PCWSTR::from_raw(file.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        if result.0 as usize <= 32 {
            return Err(io::Error::other(format!(
                "ShellExecuteW runas failed with code {}",
                result.0 as usize
            )));
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use imp::{is_elevated, restart_elevated};

#[cfg(not(windows))]
pub fn is_elevated() -> std::io::Result<bool> {
    Ok(true)
}

#[cfg(not(windows))]
pub fn restart_elevated() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "elevation relaunch is only supported on Windows",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_elevated_returns_ok() {
        assert!(is_elevated().is_ok());
    }
}
