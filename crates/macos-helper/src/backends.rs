//! The tunnel backends this helper may execute. The catalog is compiled into
//! the (signed) helper, so a pinned hash cannot be edited without breaking
//! the helper's code signature. An entry pins one self-contained binary that
//! ships in the app bundle under `Contents/Helpers/`.

use crate::trusted_exec::stage_backend;
use serde::Deserialize;
use std::io;
use std::path::{Path, PathBuf};

const EMBEDDED: &str = include_str!("../backends.json");

/// Bundle directory (relative to `Contents/`) the pinned binaries live in.
pub const BUNDLE_DIR: &str = "Helpers";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Backend {
    /// Stable id the protocol uses: `openvpn`, `wireguard-go`.
    pub name: String,
    pub version: String,
    /// File name inside [`BUNDLE_DIR`].
    pub file: String,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    backends: Vec<Backend>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    backends: Vec<Backend>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

impl Catalog {
    pub fn embedded() -> io::Result<Self> {
        Self::parse(EMBEDDED)
    }

    pub fn parse(json: &str) -> io::Result<Self> {
        let document: Document = serde_json::from_str(json).map_err(|e| invalid(e.to_string()))?;
        for (index, backend) in document.backends.iter().enumerate() {
            let plain_file = !backend.file.is_empty()
                && !backend.file.starts_with('.')
                && backend
                    .file
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            if !plain_file {
                return Err(invalid("a backend file must be a plain file name"));
            }
            if backend.sha256.len() != 64 || !backend.sha256.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(invalid("a backend pin must be a SHA-256 hex digest"));
            }
            if document.backends[..index]
                .iter()
                .any(|other| other.name == backend.name)
            {
                return Err(invalid("duplicate backend name"));
            }
        }
        Ok(Self {
            backends: document.backends,
        })
    }

    pub fn get(&self, name: &str) -> Option<&Backend> {
        self.backends.iter().find(|backend| backend.name == name)
    }

    /// Verifies the bundled binary and returns the private copy to execute.
    /// `contents` is the app's `Contents/` directory.
    pub fn stage(
        &self,
        name: &str,
        contents: &Path,
        stage_dir: &Path,
        owner: u32,
    ) -> io::Result<PathBuf> {
        let backend = self
            .get(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown backend"))?;
        let source = contents.join(BUNDLE_DIR).join(&backend.file);
        stage_backend(&source, &backend.sha256, stage_dir, owner)
    }
}

/// `Contents/` of the bundle the helper binary (`Contents/MacOS/…`) lives in.
pub fn bundle_contents(helper: &Path) -> Option<PathBuf> {
    Some(helper.parent()?.parent()?.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn pin(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn catalog(file: &str, hash: &str) -> String {
        format!(
            r#"{{"backends":[{{"name":"openvpn","version":"2.6.14","file":"{file}","sha256":"{hash}"}}]}}"#
        )
    }

    #[test]
    fn embedded_catalog_is_valid() {
        Catalog::embedded().unwrap();
    }

    #[test]
    fn malformed_entries_are_rejected() {
        let hash = pin(b"x");
        for json in [
            catalog("../openvpn", &hash),
            catalog("a/b", &hash),
            catalog(".hidden", &hash),
            catalog("", &hash),
            catalog("openvpn", "abc"),
            r#"{"backends":[],"extra":1}"#.to_string(),
            format!(
                r#"{{"backends":[{{"name":"a","version":"1","file":"f","sha256":"{hash}"}},{{"name":"a","version":"1","file":"g","sha256":"{hash}"}}]}}"#
            ),
        ] {
            assert!(Catalog::parse(&json).is_err(), "{json}");
        }
    }

    #[test]
    fn pinned_backend_is_staged_from_the_bundle() {
        let tmp = tempfile::TempDir::new().unwrap();
        let contents = tmp.path().join("Contents");
        fs::create_dir_all(contents.join(BUNDLE_DIR)).unwrap();
        fs::write(contents.join(BUNDLE_DIR).join("openvpn"), b"bin").unwrap();
        let stage = tmp.path().join("stage");
        fs::create_dir(&stage).unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o755)).unwrap();
        let catalog = Catalog::parse(&catalog("openvpn", &pin(b"bin"))).unwrap();
        // SAFETY: getuid never fails.
        let me = unsafe { libc::getuid() };
        let staged = catalog.stage("openvpn", &contents, &stage, me).unwrap();
        assert_eq!(fs::read(staged).unwrap(), b"bin");
        fs::write(contents.join(BUNDLE_DIR).join("openvpn"), b"evil").unwrap();
        fs::remove_dir_all(&stage).unwrap();
        fs::create_dir(&stage).unwrap();
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(catalog.stage("openvpn", &contents, &stage, me).is_err());
        let unknown = catalog.stage("wireguard-go", &contents, &stage, me);
        assert_eq!(unknown.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn contents_is_two_levels_above_the_helper() {
        let helper = Path::new("/A.app/Contents/MacOS/network-orchestrator-helper");
        assert_eq!(
            bundle_contents(helper).unwrap(),
            Path::new("/A.app/Contents")
        );
    }
}
