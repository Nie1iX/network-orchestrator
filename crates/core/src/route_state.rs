use crate::models::AppliedProfileRoutes;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

pub const APPLIED_ROUTE_DOCUMENT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppliedRouteDocument {
    pub version: u32,
    pub profiles: Vec<AppliedProfileRoutes>,
}

pub struct AppliedRouteStore {
    path: PathBuf,
}

impl AppliedRouteStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> io::Result<AppliedRouteDocument> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(AppliedRouteDocument {
                    version: APPLIED_ROUTE_DOCUMENT_VERSION,
                    profiles: Vec::new(),
                });
            }
            Err(err) => return Err(err),
        };
        let document: AppliedRouteDocument = serde_json::from_str(&raw)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if document.version != APPLIED_ROUTE_DOCUMENT_VERSION {
            return Err(invalid_data(format!(
                "unsupported applied route document version {}",
                document.version
            )));
        }
        Ok(document)
    }

    pub fn save(&self, document: &AppliedRouteDocument) -> io::Result<()> {
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
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AppliedRoute;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-routestate-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample() -> AppliedRouteDocument {
        AppliedRouteDocument {
            version: APPLIED_ROUTE_DOCUMENT_VERSION,
            profiles: vec![AppliedProfileRoutes {
                profile_id: "p1".into(),
                routes: vec![AppliedRoute {
                    destination: "10.0.0.0/24".parse().unwrap(),
                    interface_index: 7,
                    metric: 5,
                }],
            }],
        }
    }

    #[test]
    fn load_missing_returns_empty_document() {
        let dir = unique_dir("missing");
        let store = AppliedRouteStore::new(dir.join("applied-routes.json"));
        let doc = store.load().unwrap();
        assert_eq!(doc.version, APPLIED_ROUTE_DOCUMENT_VERSION);
        assert!(doc.profiles.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_load_roundtrips() {
        let dir = unique_dir("roundtrip");
        let store = AppliedRouteStore::new(dir.join("nested").join("applied-routes.json"));
        store.save(&sample()).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded, sample());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_rejects_malformed_json() {
        let dir = unique_dir("malformed");
        let path = dir.join("applied-routes.json");
        fs::write(&path, b"{ not json").unwrap();
        let err = AppliedRouteStore::new(&path).load().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_rejects_unsupported_version() {
        let dir = unique_dir("version");
        let path = dir.join("applied-routes.json");
        fs::write(&path, br#"{"version": 99, "profiles": []}"#).unwrap();
        let err = AppliedRouteStore::new(&path).load().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }
}
