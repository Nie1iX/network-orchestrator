use crate::models::{BackendExecutableSetting, BackendExecutableSource, TunnelBackend};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

pub const BACKEND_SETTINGS_DOCUMENT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackendSettingsDocument {
    pub version: u32,
    #[serde(default)]
    pub wire_guard: Option<BackendExecutableSetting>,
    #[serde(default)]
    pub open_vpn: Option<BackendExecutableSetting>,
    #[serde(default)]
    pub xray: Option<BackendExecutableSetting>,
}

impl Default for BackendSettingsDocument {
    fn default() -> Self {
        Self {
            version: BACKEND_SETTINGS_DOCUMENT_VERSION,
            wire_guard: None,
            open_vpn: None,
            xray: None,
        }
    }
}

pub struct BackendSettingsStore {
    path: PathBuf,
}

impl BackendSettingsStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> io::Result<BackendSettingsDocument> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(BackendSettingsDocument::default());
            }
            Err(err) => return Err(err),
        };
        let document: BackendSettingsDocument = serde_json::from_str(&raw)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if document.version != BACKEND_SETTINGS_DOCUMENT_VERSION {
            return Err(invalid_data(format!(
                "unsupported backend settings document version {}",
                document.version
            )));
        }
        for setting in [&document.wire_guard, &document.open_vpn, &document.xray]
            .into_iter()
            .flatten()
        {
            validate_setting(setting)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        }
        Ok(document)
    }

    pub fn save(&self, document: &BackendSettingsDocument) -> io::Result<()> {
        validate_document(document)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            crate::config_security::protect_path(parent)?;
        }
        let json = serde_json::to_string_pretty(document)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let mut temp_name = self.path.clone().into_os_string();
        temp_name.push(".tmp");
        let temp_path = PathBuf::from(temp_name);
        fs::write(&temp_path, json)?;
        crate::config_security::protect_path(&temp_path)?;
        if let Err(err) = fs::rename(&temp_path, &self.path) {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }
        crate::config_security::protect_path(&self.path)?;
        Ok(())
    }

    pub fn get(&self, backend: TunnelBackend) -> io::Result<Option<BackendExecutableSetting>> {
        let document = self.load()?;
        Ok(match backend {
            TunnelBackend::None => None,
            TunnelBackend::WireGuard => document.wire_guard,
            TunnelBackend::OpenVpn => document.open_vpn,
            TunnelBackend::Xray => document.xray,
        })
    }

    pub fn set(
        &self,
        backend: TunnelBackend,
        setting: Option<BackendExecutableSetting>,
    ) -> io::Result<BackendSettingsDocument> {
        if let Some(setting) = &setting {
            validate_setting(setting)?;
        }
        let mut document = self.load()?;
        match backend {
            TunnelBackend::None => {}
            TunnelBackend::WireGuard => document.wire_guard = setting,
            TunnelBackend::OpenVpn => document.open_vpn = setting,
            TunnelBackend::Xray => document.xray = setting,
        }
        self.save(&document)?;
        Ok(document)
    }
}

fn validate_document(document: &BackendSettingsDocument) -> io::Result<()> {
    if document.version != BACKEND_SETTINGS_DOCUMENT_VERSION {
        return Err(invalid_input(format!(
            "unsupported backend settings document version {}",
            document.version
        )));
    }
    for setting in [&document.wire_guard, &document.open_vpn, &document.xray]
        .into_iter()
        .flatten()
    {
        validate_setting(setting)?;
    }
    Ok(())
}

fn validate_setting(setting: &BackendExecutableSetting) -> io::Result<()> {
    if setting.path.as_os_str().to_string_lossy().trim().is_empty() {
        return Err(invalid_input("backend executable path must not be blank"));
    }
    match setting.source {
        BackendExecutableSource::AutoDetected => Err(invalid_input(
            "autoDetected is response-only and cannot be persisted",
        )),
        BackendExecutableSource::Configured => {
            if setting.version.is_some() {
                return Err(invalid_input(
                    "configured executable version must stay empty",
                ));
            }
            Ok(())
        }
        BackendExecutableSource::Managed => match setting.version.as_deref().map(str::trim) {
            Some(version) if !version.is_empty() => Ok(()),
            _ => Err(invalid_input(
                "managed executable setting requires a version",
            )),
        },
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BackendExecutableSetting, BackendExecutableSource, TunnelBackend};
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-backendsettings-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn configured(path: &str) -> BackendExecutableSetting {
        BackendExecutableSetting {
            path: PathBuf::from(path),
            source: BackendExecutableSource::Configured,
            version: None,
        }
    }

    #[test]
    fn missing_settings_document_returns_defaults() {
        let dir = unique_dir("missing");
        let store = BackendSettingsStore::new(dir.join("backend-settings.json"));

        let doc = store.load().unwrap();

        assert_eq!(doc.version, BACKEND_SETTINGS_DOCUMENT_VERSION);
        assert!(doc.wire_guard.is_none());
        assert!(doc.open_vpn.is_none());
        assert!(doc.xray.is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn settings_round_trip_all_backends() {
        let dir = unique_dir("roundtrip");
        let store = BackendSettingsStore::new(dir.join("backend-settings.json"));

        store
            .set(
                TunnelBackend::WireGuard,
                Some(configured(r"C:\tools\wireguard.exe")),
            )
            .unwrap();
        store
            .set(
                TunnelBackend::OpenVpn,
                Some(configured(r"C:\tools\openvpn.exe")),
            )
            .unwrap();
        store
            .set(
                TunnelBackend::Xray,
                Some(BackendExecutableSetting {
                    path: PathBuf::from(r"C:\app\backends\xray\v26.7.28\xray.exe"),
                    source: BackendExecutableSource::Managed,
                    version: Some("v26.7.28".into()),
                }),
            )
            .unwrap();

        let doc = store.load().unwrap();
        assert_eq!(
            doc.wire_guard.as_ref().unwrap().path,
            PathBuf::from(r"C:\tools\wireguard.exe")
        );
        assert_eq!(
            doc.open_vpn.as_ref().unwrap().path,
            PathBuf::from(r"C:\tools\openvpn.exe")
        );
        let xray = doc.xray.as_ref().unwrap();
        assert_eq!(xray.source, BackendExecutableSource::Managed);
        assert_eq!(xray.version.as_deref(), Some("v26.7.28"));
        assert_eq!(
            store.get(TunnelBackend::Xray).unwrap().unwrap().path,
            xray.path
        );

        let doc = store.set(TunnelBackend::OpenVpn, None).unwrap();
        assert!(doc.open_vpn.is_none());
        assert!(store.get(TunnelBackend::OpenVpn).unwrap().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unsupported_settings_version_is_rejected() {
        let dir = unique_dir("version");
        let path = dir.join("backend-settings.json");
        fs::write(&path, br#"{"version": 2}"#).unwrap();

        let err = BackendSettingsStore::new(&path).load().unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("unsupported backend settings document version 2"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_nullable_fields_default_to_none() {
        let dir = unique_dir("nullable");
        let path = dir.join("backend-settings.json");
        fs::write(&path, br#"{"version": 1, "xray": null}"#).unwrap();

        let doc = BackendSettingsStore::new(&path).load().unwrap();

        assert_eq!(doc.version, BACKEND_SETTINGS_DOCUMENT_VERSION);
        assert!(doc.wire_guard.is_none());
        assert!(doc.open_vpn.is_none());
        assert!(doc.xray.is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_rejects_unsupported_version_without_touching_file() {
        let dir = unique_dir("saveversion");
        let path = dir.join("backend-settings.json");
        let store = BackendSettingsStore::new(&path);
        store
            .set(
                TunnelBackend::WireGuard,
                Some(configured(r"C:\wg\wireguard.exe")),
            )
            .unwrap();
        let baseline = fs::read(&path).unwrap();

        let mut doc = store.load().unwrap();
        doc.version = 2;
        let err = store.save(&doc).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err
            .to_string()
            .contains("unsupported backend settings document version 2"));
        assert_eq!(fs::read(&path).unwrap(), baseline);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_rejects_auto_detected_source_without_touching_file() {
        let dir = unique_dir("saveautodetected");
        let path = dir.join("backend-settings.json");
        let store = BackendSettingsStore::new(&path);
        store
            .set(
                TunnelBackend::WireGuard,
                Some(configured(r"C:\wg\wireguard.exe")),
            )
            .unwrap();
        let baseline = fs::read(&path).unwrap();

        let mut doc = store.load().unwrap();
        doc.wire_guard = Some(BackendExecutableSetting {
            path: PathBuf::from(r"C:\tools\wireguard.exe"),
            source: BackendExecutableSource::AutoDetected,
            version: None,
        });
        let err = store.save(&doc).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&path).unwrap(), baseline);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn auto_detected_source_cannot_be_persisted() {
        let dir = unique_dir("autodetected");
        let store = BackendSettingsStore::new(dir.join("backend-settings.json"));

        let err = store
            .set(
                TunnelBackend::Xray,
                Some(BackendExecutableSetting {
                    path: PathBuf::from(r"C:\tools\xray.exe"),
                    source: BackendExecutableSource::AutoDetected,
                    version: None,
                }),
            )
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        fs::write(
            dir.join("backend-settings.json"),
            br#"{"version": 1, "xray": {"path": "C:\\tools\\xray.exe", "source": "autoDetected", "version": null}}"#,
        )
        .unwrap();
        let err = store.load().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn managed_setting_requires_version() {
        let dir = unique_dir("managed-version");
        let store = BackendSettingsStore::new(dir.join("backend-settings.json"));

        for version in [None, Some(String::new()), Some("   ".into())] {
            let err = store
                .set(
                    TunnelBackend::Xray,
                    Some(BackendExecutableSetting {
                        path: PathBuf::from(r"C:\app\xray.exe"),
                        source: BackendExecutableSource::Managed,
                        version,
                    }),
                )
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
        assert!(store.load().unwrap().xray.is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn configured_setting_rejects_version() {
        let dir = unique_dir("configured-version");
        let store = BackendSettingsStore::new(dir.join("backend-settings.json"));

        let err = store
            .set(
                TunnelBackend::WireGuard,
                Some(BackendExecutableSetting {
                    path: PathBuf::from(r"C:\tools\wireguard.exe"),
                    source: BackendExecutableSource::Configured,
                    version: Some("9.9".into()),
                }),
            )
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(store.load().unwrap().wire_guard.is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn settings_save_leaves_no_temp_file() {
        let dir = unique_dir("tempfile");
        let path = dir.join("backend-settings.json");
        let store = BackendSettingsStore::new(&path);

        store
            .set(
                TunnelBackend::WireGuard,
                Some(configured(r"C:\wg\wireguard.exe")),
            )
            .unwrap();

        assert!(path.is_file());
        assert!(!path.with_extension("json.tmp").exists());
        let mut temp_name = path.clone().into_os_string();
        temp_name.push(".tmp");
        assert!(!PathBuf::from(temp_name).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn blank_path_is_rejected() {
        let dir = unique_dir("blankpath");
        let store = BackendSettingsStore::new(dir.join("backend-settings.json"));

        let err = store
            .set(TunnelBackend::OpenVpn, Some(configured("   ")))
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn settings_file_is_acl_protected() {
        let dir = unique_dir("acl");
        let path = dir.join("backend-settings.json");
        let store = BackendSettingsStore::new(&path);

        store
            .set(
                TunnelBackend::WireGuard,
                Some(configured(r"C:\wg\wireguard.exe")),
            )
            .unwrap();

        let protection = crate::config_security::inspect_path_protection(&path).unwrap();
        assert!(protection.protected_dacl);
        assert!(protection.current_user);
        assert!(protection.system);
        assert!(protection.administrators);
        fs::remove_dir_all(&dir).unwrap();
    }
}
