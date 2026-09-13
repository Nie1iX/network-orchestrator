use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const PROXY_STATE_DOCUMENT_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxySnapshot {
    pub proxy_enable: Option<u32>,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyOwnership {
    pub profile_id: String,
    pub snapshot: ProxySnapshot,
    pub applied_server: String,
    pub applied_override: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStateDocument {
    pub version: u32,
    pub ownership: Option<ProxyOwnership>,
}

pub trait ProxyAdapter: Send {
    fn snapshot(&mut self) -> io::Result<ProxySnapshot>;
    fn apply(&mut self, server: &str, bypass: &str) -> io::Result<()>;
    fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()>;
}

pub struct SystemProxyManager {
    path: PathBuf,
    adapter: Box<dyn ProxyAdapter>,
    ownership: Option<ProxyOwnership>,
}

impl std::fmt::Debug for SystemProxyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemProxyManager")
            .field("path", &self.path)
            .field("ownership", &self.ownership)
            .finish_non_exhaustive()
    }
}

impl SystemProxyManager {
    #[cfg(windows)]
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        Self::with_adapter(path, Box::new(WindowsProxyAdapter))
    }

    #[cfg(not(windows))]
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        Self::with_adapter(path, Box::new(UnsupportedProxyAdapter))
    }

    pub fn with_adapter(
        path: impl Into<PathBuf>,
        adapter: Box<dyn ProxyAdapter>,
    ) -> io::Result<Self> {
        let path = path.into();
        if path.exists() {
            crate::config_security::protect_path(&path)?;
        }
        let document = load_document(&path)?;
        if path.exists() {
            crate::config_security::protect_path(&path)?;
        }
        Ok(Self {
            path,
            adapter,
            ownership: document.ownership,
        })
    }

    pub fn ownership(&self) -> Option<&ProxyOwnership> {
        self.ownership.as_ref()
    }

    pub fn apply(&mut self, profile_id: &str, port: u16, bypass: &[String]) -> io::Result<()> {
        if self.ownership.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "system proxy is already owned by a profile",
            ));
        }
        let snapshot = self.adapter.snapshot()?;
        let server = format!("socks=127.0.0.1:{port}");
        let applied_override = bypass.join(";");
        self.ownership = Some(ProxyOwnership {
            profile_id: profile_id.to_string(),
            snapshot: snapshot.clone(),
            applied_server: server.clone(),
            applied_override: applied_override.clone(),
        });
        if let Err(err) = self.persist() {
            self.ownership = None;
            return Err(err);
        }
        if let Err(err) = self.adapter.apply(&server, &applied_override) {
            let mut message = format!("failed to apply system proxy: {err}");
            match self.adapter.restore(&snapshot) {
                Err(restore_err) => {
                    message.push_str(&format!(
                        "; snapshot restore failed: {restore_err}; ownership record kept for recovery"
                    ));
                }
                Ok(()) => {
                    self.ownership = None;
                    if let Err(persist_err) = self.persist() {
                        message
                            .push_str(&format!("; ownership record cleanup failed: {persist_err}"));
                    }
                }
            }
            return Err(io::Error::new(err.kind(), message));
        }
        Ok(())
    }

    pub fn restore(&mut self, profile_id: &str) -> io::Result<()> {
        let Some(ownership) = self.ownership.clone() else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no system proxy ownership is recorded",
            ));
        };
        if ownership.profile_id != profile_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "system proxy is owned by profile '{}', not '{profile_id}'",
                    ownership.profile_id
                ),
            ));
        }
        self.adapter.restore(&ownership.snapshot)?;
        self.ownership = None;
        self.persist()
    }

    pub fn restore_any(&mut self) -> io::Result<()> {
        let Some(ownership) = self.ownership.clone() else {
            return Ok(());
        };
        self.adapter.restore(&ownership.snapshot)?;
        self.ownership = None;
        self.persist()
    }

    fn persist(&self) -> io::Result<()> {
        save_document(
            &self.path,
            &ProxyStateDocument {
                version: PROXY_STATE_DOCUMENT_VERSION,
                ownership: self.ownership.clone(),
            },
        )
    }
}

fn load_document(path: &Path) -> io::Result<ProxyStateDocument> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(ProxyStateDocument {
                version: PROXY_STATE_DOCUMENT_VERSION,
                ownership: None,
            });
        }
        Err(err) => return Err(err),
    };
    let document: ProxyStateDocument = serde_json::from_str(&raw)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if document.version != PROXY_STATE_DOCUMENT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported proxy state document version {}",
                document.version
            ),
        ));
    }
    Ok(document)
}

fn save_document(path: &Path, document: &ProxyStateDocument) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(document)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let mut temp_name = path.as_os_str().to_os_string();
    temp_name.push(".tmp");
    let temp_path = PathBuf::from(temp_name);
    fs::write(&temp_path, json)?;
    crate::config_security::protect_path(&temp_path)?;
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    crate::config_security::protect_path(path)?;
    Ok(())
}

pub fn snapshot_matches(expected: &ProxySnapshot, actual: &ProxySnapshot) -> bool {
    expected == actual
}

#[cfg(not(windows))]
struct UnsupportedProxyAdapter;

#[cfg(not(windows))]
impl ProxyAdapter for UnsupportedProxyAdapter {
    fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
        Err(unsupported())
    }
    fn apply(&mut self, _server: &str, _bypass: &str) -> io::Result<()> {
        Err(unsupported())
    }
    fn restore(&mut self, _snapshot: &ProxySnapshot) -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(not(windows))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "system proxy is supported on Windows only",
    )
}

#[cfg(windows)]
struct WindowsProxyAdapter;

#[cfg(windows)]
mod windows_proxy {
    use super::{io, ProxySnapshot};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_SZ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };

    const SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    const PROXY_ENABLE: &str = "ProxyEnable";
    const PROXY_SERVER: &str = "ProxyServer";
    const PROXY_OVERRIDE: &str = "ProxyOverride";

    struct RegKey(HKEY);

    impl Drop for RegKey {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        OsStr::new(text)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn open_key(access: windows::Win32::System::Registry::REG_SAM_FLAGS) -> io::Result<RegKey> {
        let mut key = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(wide(SUBKEY).as_ptr()),
                0,
                access,
                &mut key,
            )
        };
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(RegKey(key))
    }

    fn get_dword(key: HKEY, name: &str) -> io::Result<Option<u32>> {
        let mut value = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let status = unsafe {
            RegGetValueW(
                key,
                PCWSTR::null(),
                PCWSTR(wide(name).as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some(&mut value as *mut u32 as *mut _),
                Some(&mut size),
            )
        };
        if status.is_err() {
            if status.0 as i32 == 2 {
                return Ok(None);
            }
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(Some(value))
    }

    fn get_string(key: HKEY, name: &str) -> io::Result<Option<String>> {
        let name_wide = wide(name);
        let mut size = 0u32;
        let status = unsafe {
            RegGetValueW(
                key,
                PCWSTR::null(),
                PCWSTR(name_wide.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                None,
                Some(&mut size),
            )
        };
        if status.is_err() {
            if status.0 as i32 == 2 {
                return Ok(None);
            }
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        let mut buffer = vec![0u16; (size as usize / 2).max(1)];
        let status = unsafe {
            RegGetValueW(
                key,
                PCWSTR::null(),
                PCWSTR(name_wide.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr() as *mut _),
                Some(&mut size),
            )
        };
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        let len = size as usize / 2;
        buffer.truncate(len.min(buffer.len()));
        while buffer.last() == Some(&0) {
            buffer.pop();
        }
        Ok(Some(String::from_utf16_lossy(&buffer)))
    }

    fn set_dword(key: HKEY, name: &str, value: u32) -> io::Result<()> {
        let status = unsafe {
            RegSetValueExW(
                key,
                PCWSTR(wide(name).as_ptr()),
                0,
                REG_DWORD,
                Some(std::slice::from_raw_parts(
                    &value as *const u32 as *const u8,
                    4,
                )),
            )
        };
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(())
    }

    fn set_string(key: HKEY, name: &str, value: &str) -> io::Result<()> {
        let data = wide(value);
        let status = unsafe {
            RegSetValueExW(
                key,
                PCWSTR(wide(name).as_ptr()),
                0,
                REG_SZ,
                Some(std::slice::from_raw_parts(
                    data.as_ptr() as *const u8,
                    data.len() * 2,
                )),
            )
        };
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(())
    }

    fn delete_value(key: HKEY, name: &str) -> io::Result<()> {
        let status = unsafe { RegDeleteValueW(key, PCWSTR(wide(name).as_ptr())) };
        if status.is_err() && status.0 as i32 != 2 {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(())
    }

    fn read_back(key: HKEY) -> io::Result<ProxySnapshot> {
        Ok(ProxySnapshot {
            proxy_enable: get_dword(key, PROXY_ENABLE)?,
            proxy_server: get_string(key, PROXY_SERVER)?,
            proxy_override: get_string(key, PROXY_OVERRIDE)?,
        })
    }

    fn broadcast_settings_change() {
        let param = wide(SUBKEY);
        unsafe {
            let mut result: usize = 0;
            let _ = SendMessageTimeoutW(
                HWND(HWND_BROADCAST.0),
                WM_SETTINGCHANGE,
                WPARAM(0),
                LPARAM(param.as_ptr() as isize),
                SMTO_ABORTIFHUNG,
                2000,
                Some(&mut result as *mut usize as *mut _),
            );
        }
    }

    pub fn snapshot() -> io::Result<ProxySnapshot> {
        let key = open_key(KEY_READ)?;
        Ok(ProxySnapshot {
            proxy_enable: get_dword(key.0, PROXY_ENABLE)?,
            proxy_server: get_string(key.0, PROXY_SERVER)?,
            proxy_override: get_string(key.0, PROXY_OVERRIDE)?,
        })
    }

    pub fn apply(server: &str, bypass: &str) -> io::Result<()> {
        let key = open_key(KEY_READ | KEY_WRITE)?;
        set_dword(key.0, PROXY_ENABLE, 1)?;
        set_string(key.0, PROXY_SERVER, server)?;
        set_string(key.0, PROXY_OVERRIDE, bypass)?;
        let expected = ProxySnapshot {
            proxy_enable: Some(1),
            proxy_server: Some(server.to_string()),
            proxy_override: Some(bypass.to_string()),
        };
        let actual = read_back(key.0)?;
        drop(key);
        if !super::snapshot_matches(&expected, &actual) {
            return Err(io::Error::other(
                "applied system proxy values do not match the registry",
            ));
        }
        broadcast_settings_change();
        Ok(())
    }

    pub fn restore(snapshot: &ProxySnapshot) -> io::Result<()> {
        let key = open_key(KEY_READ | KEY_WRITE)?;
        match snapshot.proxy_enable {
            Some(value) => set_dword(key.0, PROXY_ENABLE, value)?,
            None => delete_value(key.0, PROXY_ENABLE)?,
        }
        match &snapshot.proxy_server {
            Some(value) => set_string(key.0, PROXY_SERVER, value)?,
            None => delete_value(key.0, PROXY_SERVER)?,
        }
        match &snapshot.proxy_override {
            Some(value) => set_string(key.0, PROXY_OVERRIDE, value)?,
            None => delete_value(key.0, PROXY_OVERRIDE)?,
        }
        let actual = read_back(key.0)?;
        drop(key);
        if !super::snapshot_matches(snapshot, &actual) {
            return Err(io::Error::other(
                "restored system proxy values do not match the registry",
            ));
        }
        broadcast_settings_change();
        Ok(())
    }
}

#[cfg(windows)]
impl ProxyAdapter for WindowsProxyAdapter {
    fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
        windows_proxy::snapshot()
    }
    fn apply(&mut self, server: &str, bypass: &str) -> io::Result<()> {
        windows_proxy::apply(server, bypass)
    }
    fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()> {
        windows_proxy::restore(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use crate::system_proxy::{
        ProxyAdapter, ProxySnapshot, ProxyStateDocument, SystemProxyManager,
    };
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-proxy-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[derive(Default)]
    struct FakeAdapter {
        snapshot: ProxySnapshot,
        fail_apply: bool,
        fail_restore: bool,
        calls: Vec<String>,
        store_path: Option<PathBuf>,
        ownership_seen_during_apply: Option<bool>,
    }

    impl ProxyAdapter for FakeAdapter {
        fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
            Ok(self.snapshot.clone())
        }
        fn apply(&mut self, server: &str, bypass: &str) -> io::Result<()> {
            self.calls.push(format!("apply:{server}|{bypass}"));
            if let Some(path) = &self.store_path {
                self.ownership_seen_during_apply = Some(
                    fs::read_to_string(path)
                        .ok()
                        .map(|raw| {
                            raw.contains("\"ownership\":{") || raw.contains("\"ownership\": {")
                        })
                        .unwrap_or(false),
                );
            }
            if self.fail_apply {
                return Err(io::Error::other("adapter apply failed"));
            }
            Ok(())
        }
        fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()> {
            self.calls.push(format!(
                "restore:enable={:?}|server={:?}|override={:?}",
                snapshot.proxy_enable, snapshot.proxy_server, snapshot.proxy_override
            ));
            if self.fail_restore {
                return Err(io::Error::other("adapter restore failed"));
            }
            Ok(())
        }
    }

    fn manager(
        dir: &std::path::Path,
        adapter: FakeAdapter,
    ) -> (SystemProxyManager, Arc<Mutex<FakeAdapter>>) {
        let adapter = Arc::new(Mutex::new(adapter));
        let mgr = SystemProxyManager::with_adapter(
            dir.join("proxy-state.json"),
            Box::new(SharedAdapter(adapter.clone())),
        )
        .unwrap();
        (mgr, adapter)
    }

    struct SharedAdapter(Arc<Mutex<FakeAdapter>>);

    impl ProxyAdapter for SharedAdapter {
        fn snapshot(&mut self) -> io::Result<ProxySnapshot> {
            self.0.lock().unwrap().snapshot()
        }
        fn apply(&mut self, server: &str, bypass: &str) -> io::Result<()> {
            self.0.lock().unwrap().apply(server, bypass)
        }
        fn restore(&mut self, snapshot: &ProxySnapshot) -> io::Result<()> {
            self.0.lock().unwrap().restore(snapshot)
        }
    }

    #[test]
    fn missing_store_loads_empty_and_malformed_fails() {
        let dir = unique_dir("load");
        let mgr = SystemProxyManager::with_adapter(
            dir.join("proxy-state.json"),
            Box::new(SharedAdapter(Arc::new(Mutex::new(FakeAdapter::default())))),
        )
        .unwrap();
        assert!(mgr.ownership().is_none());

        let bad = dir.join("bad.json");
        fs::write(&bad, b"{ not json").unwrap();
        let err = SystemProxyManager::with_adapter(
            &bad,
            Box::new(SharedAdapter(Arc::new(Mutex::new(FakeAdapter::default())))),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let ver = dir.join("ver.json");
        fs::write(&ver, br#"{"version": 99, "ownership": null}"#).unwrap();
        let err = SystemProxyManager::with_adapter(
            &ver,
            Box::new(SharedAdapter(Arc::new(Mutex::new(FakeAdapter::default())))),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_persists_ownership_before_adapter_call() {
        let dir = unique_dir("apply");
        let store = dir.join("proxy-state.json");
        let adapter = FakeAdapter {
            snapshot: ProxySnapshot {
                proxy_enable: Some(0),
                proxy_server: None,
                proxy_override: Some("localhost".into()),
            },
            store_path: Some(store.clone()),
            ..Default::default()
        };
        let (mut mgr, adapter) = manager(&dir, adapter);
        mgr.apply("p1", 10808, &["<local>".into(), "10.*".into()])
            .unwrap();

        assert_eq!(
            adapter.lock().unwrap().ownership_seen_during_apply,
            Some(true)
        );
        let calls = &adapter.lock().unwrap().calls;
        assert_eq!(calls, &["apply:socks=127.0.0.1:10808|<local>;10.*"]);

        let owner = mgr.ownership().unwrap();
        assert_eq!(owner.profile_id, "p1");
        assert_eq!(owner.applied_server, "socks=127.0.0.1:10808");
        assert_eq!(owner.applied_override, "<local>;10.*");
        assert_eq!(owner.snapshot.proxy_enable, Some(0));
        assert_eq!(owner.snapshot.proxy_server, None);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_rejects_second_owner() {
        let dir = unique_dir("conflict");
        let (mut mgr, _adapter) = manager(&dir, FakeAdapter::default());
        mgr.apply("p1", 10808, &[]).unwrap();
        let err = mgr.apply("p2", 10809, &[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(mgr.ownership().unwrap().profile_id, "p1");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_failure_rolls_back_snapshot_and_clears_ownership() {
        let dir = unique_dir("rollback");
        let adapter = FakeAdapter {
            fail_apply: true,
            snapshot: ProxySnapshot {
                proxy_enable: Some(1),
                proxy_server: Some("old".into()),
                proxy_override: None,
            },
            ..Default::default()
        };
        let (mut mgr, adapter) = manager(&dir, adapter);
        let err = mgr.apply("p1", 10808, &[]).unwrap_err();
        assert!(err.to_string().contains("adapter apply failed"));

        let calls = adapter.lock().unwrap().calls.clone();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].starts_with("apply:"));
        assert_eq!(
            calls[1],
            "restore:enable=Some(1)|server=Some(\"old\")|override=None"
        );
        assert!(mgr.ownership().is_none());
        let doc: ProxyStateDocument =
            serde_json::from_str(&fs::read_to_string(dir.join("proxy-state.json")).unwrap())
                .unwrap();
        assert!(doc.ownership.is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_failure_with_restore_failure_keeps_ownership() {
        let dir = unique_dir("rollback-fail");
        let adapter = FakeAdapter {
            fail_apply: true,
            fail_restore: true,
            snapshot: ProxySnapshot {
                proxy_enable: Some(1),
                proxy_server: Some("old".into()),
                proxy_override: None,
            },
            ..Default::default()
        };
        let (mut mgr, adapter) = manager(&dir, adapter);
        let err = mgr.apply("p1", 10808, &[]).unwrap_err();
        assert!(err.to_string().contains("adapter apply failed"));
        assert!(err.to_string().contains("adapter restore failed"));

        let calls = adapter.lock().unwrap().calls.clone();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].starts_with("apply:"));
        assert!(calls[1].starts_with("restore:"));

        let owner = mgr
            .ownership()
            .expect("ownership must survive failed rollback");
        assert_eq!(owner.profile_id, "p1");
        let doc: ProxyStateDocument =
            serde_json::from_str(&fs::read_to_string(dir.join("proxy-state.json")).unwrap())
                .unwrap();
        assert_eq!(doc.ownership.unwrap().profile_id, "p1");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn restore_requires_owner_and_restores_snapshot() {
        let dir = unique_dir("restore");
        let adapter = FakeAdapter {
            snapshot: ProxySnapshot {
                proxy_enable: None,
                proxy_server: None,
                proxy_override: None,
            },
            ..Default::default()
        };
        let (mut mgr, adapter) = manager(&dir, adapter);
        mgr.apply("p1", 10808, &["<local>".into()]).unwrap();

        let err = mgr.restore("other").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(mgr.ownership().is_some());

        mgr.restore("p1").unwrap();
        let calls = &adapter.lock().unwrap().calls;
        assert_eq!(
            calls.last().unwrap(),
            "restore:enable=None|server=None|override=None"
        );
        assert!(mgr.ownership().is_none());

        let err = mgr.restore("p1").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn restore_any_clears_stale_ownership() {
        let dir = unique_dir("any");
        let (mut mgr, adapter) = manager(&dir, FakeAdapter::default());
        mgr.apply("gone", 10808, &[]).unwrap();
        mgr.restore_any().unwrap();
        assert!(mgr.ownership().is_none());
        assert!(adapter
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|c| c.starts_with("restore:")));

        let mut mgr2 = SystemProxyManager::with_adapter(
            dir.join("proxy-state.json"),
            Box::new(SharedAdapter(Arc::new(Mutex::new(FakeAdapter::default())))),
        )
        .unwrap();
        mgr2.restore_any().unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn snapshot_matches_compares_exactly() {
        use crate::system_proxy::snapshot_matches;
        let base = ProxySnapshot {
            proxy_enable: Some(1),
            proxy_server: Some("socks=127.0.0.1:10808".into()),
            proxy_override: Some("<local>".into()),
        };
        assert!(snapshot_matches(&base, &base.clone()));

        let mut different = base.clone();
        different.proxy_enable = Some(0);
        assert!(!snapshot_matches(&base, &different));

        let mut missing = base.clone();
        missing.proxy_server = None;
        assert!(!snapshot_matches(&base, &missing));

        let empty = ProxySnapshot::default();
        assert!(snapshot_matches(&empty, &ProxySnapshot::default()));
    }

    #[test]
    fn applied_state_file_is_acl_protected() {
        let dir = unique_dir("acl");
        let store = dir.join("proxy-state.json");
        let (mut mgr, _) = manager(&dir, FakeAdapter::default());
        mgr.apply("p1", 10808, &["<local>".into()]).unwrap();

        #[cfg(windows)]
        {
            let protection = crate::config_security::inspect_path_protection(&store).unwrap();
            assert!(protection.protected_dacl);
            assert!(protection.current_user);
            assert!(protection.system);
            assert!(protection.administrators);
        }
        #[cfg(not(windows))]
        {
            assert!(store.exists());
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ownership_survives_manager_reload() {
        let dir = unique_dir("reload");
        let store = dir.join("proxy-state.json");
        let (mut mgr, _) = manager(&dir, FakeAdapter::default());
        mgr.apply("p1", 10808, &["127.*".into()]).unwrap();
        drop(mgr);

        let mgr = SystemProxyManager::with_adapter(
            &store,
            Box::new(SharedAdapter(Arc::new(Mutex::new(FakeAdapter::default())))),
        )
        .unwrap();
        let owner = mgr.ownership().unwrap();
        assert_eq!(owner.profile_id, "p1");
        assert_eq!(owner.applied_server, "socks=127.0.0.1:10808");
        fs::remove_dir_all(&dir).unwrap();
    }
}
