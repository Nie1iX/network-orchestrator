use crate::models::{Profile, TunnelBackend};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

pub const PROFILE_DOCUMENT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDocument {
    pub version: u32,
    pub profiles: Vec<Profile>,
}

pub struct ProfileStore {
    path: PathBuf,
}

impl ProfileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> io::Result<ProfileDocument> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(ProfileDocument {
                    version: PROFILE_DOCUMENT_VERSION,
                    profiles: Vec::new(),
                });
            }
            Err(err) => return Err(err),
        };
        let document: ProfileDocument = serde_json::from_str(&raw)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if document.version != PROFILE_DOCUMENT_VERSION {
            return Err(invalid_data(format!(
                "unsupported profile document version {}",
                document.version
            )));
        }
        Ok(document)
    }

    pub fn save(&self, document: &ProfileDocument) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(document)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let mut temp_name = self.path.clone().into_os_string();
        temp_name.push(".tmp");
        let temp_path = PathBuf::from(temp_name);
        fs::write(&temp_path, json)?;
        if let Err(err) = fs::rename(&temp_path, &self.path) {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }
        Ok(())
    }

    pub fn upsert(&self, profile: Profile) -> io::Result<ProfileDocument> {
        validate_profile(&profile)?;
        let mut document = self.load()?;
        if let Some(existing) = document.profiles.iter_mut().find(|p| p.id == profile.id) {
            *existing = profile;
        } else {
            document.profiles.push(profile);
        }
        self.save(&document)?;
        Ok(document)
    }

    pub fn delete(&self, id: &str) -> io::Result<ProfileDocument> {
        let mut document = self.load()?;
        let len_before = document.profiles.len();
        document.profiles.retain(|p| p.id != id);
        if document.profiles.len() == len_before {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("profile '{id}' not found"),
            ));
        }
        self.save(&document)?;
        Ok(document)
    }
}

pub fn validate_profile(profile: &Profile) -> io::Result<()> {
    if profile.id.trim().is_empty() {
        return Err(invalid_data("profile id must not be blank"));
    }
    if profile.name.trim().is_empty() {
        return Err(invalid_data("profile name must not be blank"));
    }
    if profile.config_path.to_string_lossy().trim().is_empty() {
        return Err(invalid_data("profile config path must not be blank"));
    }
    if !profile.routes.is_empty() && profile.interface_name.trim().is_empty() {
        return Err(invalid_data(
            "profile interface name must not be blank when policy routes are set",
        ));
    }
    for route in &profile.routes {
        if route.metric > 9999 {
            return Err(invalid_data(format!(
                "route metric {} exceeds maximum 9999",
                route.metric
            )));
        }
    }
    if profile.backend != TunnelBackend::Xray && !profile.domain_policies.is_empty() {
        return Err(invalid_data(
            "domain policies are only supported for Xray profiles",
        ));
    }
    if profile.backend == TunnelBackend::Xray {
        for policy in &profile.domain_policies {
            if policy.domains.is_empty() {
                return Err(invalid_data("domain policy must list at least one domain"));
            }
            if policy.domains.iter().any(|domain| domain.trim().is_empty()) {
                return Err(invalid_data("domain policy must not contain blank domains"));
            }
        }
        if matches!(profile.xray_socks_port, Some(0)) {
            return Err(invalid_data("xray socks port must be nonzero"));
        }
    }
    let file_name = profile
        .config_path
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let allowed = match profile.backend {
        TunnelBackend::WireGuard => {
            file_name.ends_with(".conf") || file_name.ends_with(".conf.dpapi")
        }
        TunnelBackend::OpenVpn => file_name.ends_with(".ovpn") || file_name.ends_with(".conf"),
        TunnelBackend::Xray => file_name.ends_with(".json"),
    };
    if !allowed {
        return Err(invalid_data(format!(
            "config path '{}' has an unsupported extension for {:?}",
            profile.config_path.display(),
            profile.backend
        )));
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DomainPolicy, DomainRouteTarget, PolicyRoute, TunnelBackend};
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-profiles-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn wg_profile() -> Profile {
        Profile {
            id: "work-wg".into(),
            name: "Work WireGuard".into(),
            backend: TunnelBackend::WireGuard,
            config_path: PathBuf::from(r"C:\configs\work.conf"),
            interface_name: "wg-work".into(),
            routes: vec![PolicyRoute {
                destination: "10.7.0.0/24".parse().unwrap(),
                metric: 5,
            }],
            auto_connect: true,
            domain_policies: vec![],
            xray_socks_port: None,
        }
    }

    #[test]
    fn missing_store_returns_empty_v1_document() {
        let dir = unique_dir("missing");
        let store = ProfileStore::new(dir.join("profiles.json"));

        let doc = store.load().unwrap();

        assert_eq!(doc.version, PROFILE_DOCUMENT_VERSION);
        assert!(doc.profiles.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn round_trip_preserves_wireguard_profile() {
        let dir = unique_dir("roundtrip");
        let store = ProfileStore::new(dir.join("profiles.json"));
        let profile = wg_profile();

        let saved = store.upsert(profile.clone()).unwrap();
        assert_eq!(saved.profiles, vec![profile.clone()]);

        let loaded = store.load().unwrap();
        assert_eq!(loaded.version, PROFILE_DOCUMENT_VERSION);
        assert_eq!(loaded.profiles, vec![profile]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn upsert_replaces_same_id_instead_of_duplicating() {
        let dir = unique_dir("upsert");
        let store = ProfileStore::new(dir.join("profiles.json"));

        store.upsert(wg_profile()).unwrap();
        let mut updated = wg_profile();
        updated.name = "Renamed".into();
        updated.auto_connect = false;
        let doc = store.upsert(updated.clone()).unwrap();

        assert_eq!(doc.profiles.len(), 1);
        assert_eq!(doc.profiles[0], updated);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn validation_rejects_wrong_extension_and_blank_interface_name() {
        let mut bad_ext = wg_profile();
        bad_ext.config_path = PathBuf::from(r"C:\configs\work.txt");
        let err = validate_profile(&bad_ext).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut blank_iface = wg_profile();
        blank_iface.interface_name = "   ".into();
        let err = validate_profile(&blank_iface).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn blank_interface_allowed_only_without_routes() {
        let mut profile = wg_profile();
        profile.interface_name = "   ".into();
        profile.routes = vec![];
        assert!(validate_profile(&profile).is_ok());

        profile.routes = vec![PolicyRoute {
            destination: "10.7.0.0/24".parse().unwrap(),
            metric: 5,
        }];
        let err = validate_profile(&profile).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    fn xray_profile() -> Profile {
        Profile {
            id: "work-xray".into(),
            name: "Work Xray".into(),
            backend: TunnelBackend::Xray,
            config_path: PathBuf::from(r"C:\configs\work.json"),
            interface_name: String::new(),
            routes: vec![],
            auto_connect: false,
            domain_policies: vec![DomainPolicy {
                domains: vec!["example.com".into()],
                target: DomainRouteTarget::Proxy,
            }],
            xray_socks_port: Some(10808),
        }
    }

    #[test]
    fn xray_requires_json_extension() {
        assert!(validate_profile(&xray_profile()).is_ok());

        let mut bad = xray_profile();
        bad.config_path = PathBuf::from(r"C:\configs\work.conf");
        let err = validate_profile(&bad).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut upper = xray_profile();
        upper.config_path = PathBuf::from(r"C:\configs\WORK.JSON");
        assert!(validate_profile(&upper).is_ok());
    }

    #[test]
    fn legacy_profile_json_deserializes_without_xray_fields() {
        let json = r#"{
            "id": "legacy",
            "name": "Legacy WG",
            "backend": "wireGuard",
            "configPath": "C:\\configs\\legacy.conf",
            "interfaceName": "wg0",
            "routes": [],
            "autoConnect": false
        }"#;
        let profile: Profile = serde_json::from_str(json).unwrap();
        assert!(profile.domain_policies.is_empty());
        assert_eq!(profile.xray_socks_port, None);
        assert!(validate_profile(&profile).is_ok());
    }

    #[test]
    fn domain_policies_rejected_for_non_xray_backends() {
        let mut profile = wg_profile();
        profile.domain_policies = vec![DomainPolicy {
            domains: vec!["example.com".into()],
            target: DomainRouteTarget::Direct,
        }];
        let err = validate_profile(&profile).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn xray_domain_policies_require_nonblank_domains() {
        let mut empty_list = xray_profile();
        empty_list.domain_policies = vec![DomainPolicy {
            domains: vec![],
            target: DomainRouteTarget::Proxy,
        }];
        assert_eq!(
            validate_profile(&empty_list).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut blank = xray_profile();
        blank.domain_policies = vec![DomainPolicy {
            domains: vec!["example.com".into(), "   ".into()],
            target: DomainRouteTarget::Direct,
        }];
        assert_eq!(
            validate_profile(&blank).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn xray_socks_port_must_be_nonzero() {
        let mut zero = xray_profile();
        zero.xray_socks_port = Some(0);
        assert_eq!(
            validate_profile(&zero).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut absent = xray_profile();
        absent.xray_socks_port = None;
        assert!(validate_profile(&absent).is_ok());
    }

    #[test]
    fn load_rejects_unsupported_version() {
        let dir = unique_dir("version");
        let path = dir.join("profiles.json");
        fs::write(&path, r#"{"version":2,"profiles":[]}"#).unwrap();
        let store = ProfileStore::new(&path);

        let err = store.load().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }
}
