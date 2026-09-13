use crate::config_security::protect_path;
use crate::models::TunnelBackend;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigImport {
    pub config_path: PathBuf,
    pub warnings: Vec<String>,
}

pub struct ConfigVault {
    root: PathBuf,
}

impl ConfigVault {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ensure_root_protected(&self) -> io::Result<()> {
        fs::create_dir_all(&self.root)?;
        protect_path(&self.root)
    }

    pub fn is_managed_path(&self, path: &Path) -> bool {
        let Ok(rel) = path.strip_prefix(&self.root) else {
            return false;
        };
        let mut parts = rel.components();
        let Some(Component::Normal(id)) = parts.next() else {
            return false;
        };
        let Some(id) = id.to_str() else {
            return false;
        };
        if !is_safe_id(id) {
            return false;
        }
        let Some(Component::Normal(rev)) = parts.next() else {
            return false;
        };
        let Some(rev) = rev.to_str() else {
            return false;
        };
        if !rev.starts_with("rev-") || rev.len() <= "rev-".len() {
            return false;
        }
        let Some(Component::Normal(first)) = parts.next() else {
            return false;
        };
        match parts.next() {
            None => first.to_str().is_some_and(|name| {
                CONFIG_NAMES.contains(&name)
                    || name == format!("{id}.conf")
                    || name == format!("{id}.conf.dpapi")
            }),
            Some(Component::Normal(_)) => first == OsStr::new("assets") && parts.next().is_none(),
            _ => false,
        }
    }

    pub fn is_managed_profile_path(&self, profile_id: &str, path: &Path) -> bool {
        if !self.is_managed_path(path) {
            return false;
        }
        let Ok(safe) = sanitize_profile_id(profile_id) else {
            return false;
        };
        path.strip_prefix(&self.root)
            .ok()
            .and_then(|rel| rel.components().next())
            .and_then(|component| match component {
                Component::Normal(id) => id.to_str(),
                _ => None,
            })
            .is_some_and(|id| id == safe)
    }

    pub fn import(
        &self,
        profile_id: &str,
        backend: TunnelBackend,
        source: &Path,
    ) -> io::Result<ConfigImport> {
        let safe = sanitize_profile_id(profile_id)?;
        if !source.is_file() {
            return Err(invalid_input(format!(
                "source '{}' is not a regular file",
                source.display()
            )));
        }
        let source_name = source
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        let config_name = match backend {
            TunnelBackend::WireGuard if source_name.ends_with(".conf.dpapi") => {
                format!("{safe}.conf.dpapi")
            }
            TunnelBackend::WireGuard if source_name.ends_with(".conf") => format!("{safe}.conf"),
            TunnelBackend::OpenVpn if source_name.ends_with(".ovpn") => "client.ovpn".to_string(),
            TunnelBackend::OpenVpn if source_name.ends_with(".conf") => "client.conf".to_string(),
            TunnelBackend::Xray if source_name.ends_with(".json") => "config.json".to_string(),
            _ => {
                return Err(invalid_input(format!(
                    "unsupported {} config extension for '{}'",
                    backend_label(backend),
                    source.display()
                )))
            }
        };

        let nanos = unix_nanos()?;
        let profile_dir = self.root.join(&safe);
        let staging = profile_dir.join(format!("rev-{nanos}.tmp"));
        let revision = profile_dir.join(format!("rev-{nanos}"));
        self.ensure_root_protected()?;
        fs::create_dir_all(&profile_dir)?;
        protect_path(&profile_dir)?;

        let result = (|| -> io::Result<Vec<String>> {
            fs::create_dir(&staging)?;
            protect_path(&staging)?;
            let warnings = match backend {
                TunnelBackend::OpenVpn => stage_openvpn(source, &staging, &config_name)?,
                _ => {
                    let staged_config = staging.join(&config_name);
                    fs::copy(source, &staged_config)?;
                    protect_path(&staged_config)?;
                    Vec::new()
                }
            };
            fs::rename(&staging, &revision)?;
            if let Err(err) =
                protect_path(&revision).and_then(|_| protect_path(&revision.join(&config_name)))
            {
                let _ = fs::remove_dir_all(&revision);
                return Err(err);
            }
            Ok(warnings)
        })();

        match result {
            Ok(warnings) => Ok(ConfigImport {
                config_path: revision.join(config_name),
                warnings,
            }),
            Err(err) => {
                let _ = fs::remove_dir_all(&staging);
                Err(err)
            }
        }
    }

    pub fn store_xray_config(&self, profile_id: &str, bytes: &[u8]) -> io::Result<ConfigImport> {
        let safe = sanitize_profile_id(profile_id)?;
        let nanos = unix_nanos()?;
        let profile_dir = self.root.join(&safe);
        let staging = profile_dir.join(format!("rev-{nanos}.tmp"));
        let revision = profile_dir.join(format!("rev-{nanos}"));
        self.ensure_root_protected()?;
        fs::create_dir_all(&profile_dir)?;
        protect_path(&profile_dir)?;

        let result = (|| -> io::Result<()> {
            fs::create_dir(&staging)?;
            protect_path(&staging)?;
            let staged_config = staging.join("config.json");
            fs::write(&staged_config, bytes)?;
            protect_path(&staged_config)?;
            fs::rename(&staging, &revision)?;
            if let Err(err) =
                protect_path(&revision).and_then(|_| protect_path(&revision.join("config.json")))
            {
                let _ = fs::remove_dir_all(&revision);
                return Err(err);
            }
            Ok(())
        })();

        match result {
            Ok(()) => Ok(ConfigImport {
                config_path: revision.join("config.json"),
                warnings: Vec::new(),
            }),
            Err(err) => {
                let _ = fs::remove_dir_all(&staging);
                Err(err)
            }
        }
    }

    pub fn remove_revision_for_config(&self, config_path: &Path) -> io::Result<()> {
        if !self.is_managed_path(config_path) {
            return Err(invalid_input("path is not a managed vault config revision"));
        }
        let mut parts = config_path
            .strip_prefix(&self.root)
            .unwrap_or_else(|_| Path::new(""))
            .components();
        let profile_dir = self
            .root
            .join(parts.next().map(|c| c.as_os_str()).unwrap_or_default());
        let revision = profile_dir.join(parts.next().map(|c| c.as_os_str()).unwrap_or_default());
        reject_symlink(&profile_dir)?;
        reject_symlink(&revision)?;
        match fs::remove_dir_all(&revision) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub fn remove_profile(&self, profile_id: &str) -> io::Result<()> {
        let safe = sanitize_profile_id(profile_id)?;
        let dir = self.root.join(&safe);
        reject_symlink(&dir)?;
        match fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
}

const CONFIG_NAMES: &[&str] = &[
    "tunnel.conf",
    "tunnel.conf.dpapi",
    "client.ovpn",
    "client.conf",
    "config.json",
];

const PATH_DIRECTIVES: &[&str] = &[
    "ca",
    "cert",
    "key",
    "dh",
    "pkcs12",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "secret",
    "auth-user-pass",
    "crl-verify",
];

pub(crate) const SCRIPT_DIRECTIVES: &[&str] = &[
    "up",
    "down",
    "route-up",
    "ipchange",
    "client-connect",
    "client-disconnect",
    "learn-address",
    "auth-user-pass-verify",
    "tls-verify",
    "plugin",
];

fn stage_openvpn(source: &Path, staging: &Path, config_name: &str) -> io::Result<Vec<String>> {
    let text = fs::read_to_string(source)?;
    let source_dir = source.parent().unwrap_or_else(|| Path::new("."));
    let assets_dir = staging.join("assets");
    let mut assets_created = false;
    let mut copied: HashMap<PathBuf, String> = HashMap::new();
    let mut warned: HashSet<String> = HashSet::new();
    let mut warnings = Vec::new();
    let mut output = Vec::new();
    let mut in_block: Option<String> = None;

    for raw_line in text.lines() {
        let tokens = tokenize_line(raw_line);
        if let Some(tag) = &in_block {
            output.push(raw_line.to_string());
            if let Some((true, close)) = tokens.first().and_then(|t| inline_tag(t)) {
                if close.eq_ignore_ascii_case(tag) {
                    in_block = None;
                }
            }
            continue;
        }
        if tokens.is_empty() {
            output.push(raw_line.to_string());
            continue;
        }
        if let Some((false, open)) = inline_tag(&tokens[0]) {
            in_block = Some(open.to_lowercase());
            output.push(raw_line.to_string());
            continue;
        }
        let directive = tokens[0].trim_start_matches('-').to_lowercase();
        if directive == "config" {
            return Err(invalid_data("nested 'config' directives are not supported"));
        }
        if SCRIPT_DIRECTIVES.contains(&directive.as_str()) && warned.insert(directive.clone()) {
            warnings.push(format!(
                "directive '{directive}' references an external or executable item that requires review"
            ));
        }
        if tokens.len() >= 2
            && (PATH_DIRECTIVES.contains(&directive.as_str())
                || SCRIPT_DIRECTIVES.contains(&directive.as_str()))
        {
            let resolved = resolve_reference(source_dir, &tokens[1]);
            let meta = fs::symlink_metadata(&resolved)?;
            if !meta.is_file() {
                return Err(invalid_input(format!(
                    "referenced path '{}' is not a regular file",
                    tokens[1]
                )));
            }
            let relative = match copied.get(&resolved) {
                Some(existing) => existing.clone(),
                None => {
                    if !assets_created {
                        fs::create_dir(&assets_dir)?;
                        protect_path(&assets_dir)?;
                        assets_created = true;
                    }
                    let file_name = format!(
                        "{}-{}",
                        copied.len(),
                        sanitize_basename(resolved.file_name())
                    );
                    let staged_asset = assets_dir.join(&file_name);
                    fs::copy(&resolved, &staged_asset)?;
                    protect_path(&staged_asset)?;
                    let relative = format!("assets/{file_name}");
                    copied.insert(resolved.clone(), relative.clone());
                    relative
                }
            };
            let mut rebuilt = format!("{} \"{}\"", tokens[0], relative);
            for arg in &tokens[2..] {
                rebuilt.push(' ');
                rebuilt.push_str(&quote_token(arg));
            }
            output.push(rebuilt);
            continue;
        }
        output.push(raw_line.to_string());
    }

    if let Some(tag) = in_block {
        return Err(invalid_data(format!("unterminated inline block <{tag}>")));
    }

    let mut text_out = output.join("\n");
    text_out.push('\n');
    let staged_config = staging.join(config_name);
    fs::write(&staged_config, text_out)?;
    protect_path(&staged_config)?;
    Ok(warnings)
}

pub(crate) fn inline_tag(token: &str) -> Option<(bool, &str)> {
    let inner = token.strip_prefix('<')?.strip_suffix('>')?;
    match inner.strip_prefix('/') {
        Some(name) if !name.is_empty() => Some((true, name)),
        None if !inner.is_empty() => Some((false, inner)),
        _ => None,
    }
}

fn resolve_reference(base: &Path, reference: &str) -> PathBuf {
    let path = Path::new(reference);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

pub(crate) fn tokenize_line(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut active = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == ' ' || c == '\t' {
            if active {
                tokens.push(std::mem::take(&mut current));
                active = false;
            }
            i += 1;
            continue;
        }
        if c == '#' || c == ';' {
            break;
        }
        if c == '"' || c == '\'' {
            active = true;
            i += 1;
            while i < chars.len() && chars[i] != c {
                if c == '"' && chars[i] == '\\' && i + 1 < chars.len() {
                    current.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                current.push(chars[i]);
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == '\\' && i + 1 < chars.len() {
            active = true;
            current.push(chars[i + 1]);
            i += 2;
            continue;
        }
        active = true;
        current.push(c);
        i += 1;
    }
    if active {
        tokens.push(current);
    }
    tokens
}

fn quote_token(token: &str) -> String {
    let needs_quote = token.is_empty()
        || token
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '#' | ';' | '\\'));
    if !needs_quote {
        return token.to_string();
    }
    let mut escaped = String::with_capacity(token.len() + 2);
    for c in token.chars() {
        if c == '"' || c == '\\' {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    format!("\"{escaped}\"")
}

fn sanitize_profile_id(id: &str) -> io::Result<String> {
    let safe: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if !is_safe_id(&safe) {
        return Err(invalid_input(
            "profile id cannot be used to name a vault directory",
        ));
    }
    if safe == id {
        Ok(safe)
    } else {
        Ok(format!("{safe}-{}", fnv1a_hex(id.as_bytes())))
    }
}

fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !id.chars().all(|c| c == '_')
}

fn sanitize_basename(name: Option<&OsStr>) -> String {
    let raw = name.and_then(|n| n.to_str()).unwrap_or("");
    let safe: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() || safe.chars().all(|c| c == '_' || c == '.') {
        "asset".to_string()
    } else {
        safe
    }
}

fn reject_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(invalid_input(format!(
            "refusing to remove symlinked vault path '{}'",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn unix_nanos() -> io::Result<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .map_err(|err| invalid_input(format!("system clock before unix epoch: {err}")))
}

fn backend_label(backend: TunnelBackend) -> &'static str {
    match backend {
        TunnelBackend::WireGuard => "wireguard",
        TunnelBackend::OpenVpn => "openvpn",
        TunnelBackend::Xray => "xray",
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-core-vault-{}-{}-{}",
            std::process::id(),
            name,
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn vault(name: &str) -> (ConfigVault, PathBuf) {
        let dir = unique_dir(name);
        let root = dir.join("vault");
        (ConfigVault::new(&root), dir)
    }

    #[test]
    fn import_wireguard_copies_exact_bytes_into_managed_revision() {
        let (vault, dir) = vault("wg-import");
        let source = dir.join("work.conf");
        let bytes = b"[Interface]\nPrivateKey=AAAA\n[Peer]\nPublicKey=BBBB\n";
        fs::write(&source, bytes).unwrap();

        let import = vault
            .import("work-wg", TunnelBackend::WireGuard, &source)
            .unwrap();

        assert_eq!(import.config_path.file_name().unwrap(), "work-wg.conf");
        assert!(vault.is_managed_path(&import.config_path));
        assert_eq!(fs::read(&import.config_path).unwrap(), bytes);
        assert!(import.warnings.is_empty());
        let rel = import.config_path.strip_prefix(vault.root()).unwrap();
        let comps: Vec<_> = rel.components().collect();
        assert_eq!(comps.len(), 3);
        assert_eq!(comps[0].as_os_str(), "work-wg");
        assert!(comps[1].as_os_str().to_string_lossy().starts_with("rev-"));

        let dpapi = dir.join("site.conf.dpapi");
        fs::write(&dpapi, b"blob").unwrap();
        let import = vault
            .import("work-wg", TunnelBackend::WireGuard, &dpapi)
            .unwrap();
        assert_eq!(
            import.config_path.file_name().unwrap(),
            "work-wg.conf.dpapi"
        );
        assert_eq!(fs::read(&import.config_path).unwrap(), b"blob");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_xray_copies_exact_bytes() {
        let (vault, dir) = vault("xray-import");
        let source = dir.join("node.json");
        let bytes = br#"{"outbounds":[]}"#;
        fs::write(&source, bytes).unwrap();

        let import = vault.import("node", TunnelBackend::Xray, &source).unwrap();

        assert_eq!(import.config_path.file_name().unwrap(), "config.json");
        assert!(vault.is_managed_path(&import.config_path));
        assert_eq!(fs::read(&import.config_path).unwrap(), bytes);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_openvpn_rewrites_paths_and_preserves_args() {
        let (vault, dir) = vault("ovpn-import");
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(cfg_dir.join("ca.crt"), b"CA").unwrap();
        fs::write(cfg_dir.join("my cert.crt"), b"CERT").unwrap();
        fs::write(cfg_dir.join("client.key"), b"KEY").unwrap();
        fs::write(cfg_dir.join("ta.key"), b"TA").unwrap();
        fs::write(cfg_dir.join("dh.pem"), b"DH").unwrap();
        let source = cfg_dir.join("client.ovpn");
        fs::write(
            &source,
            "client\r\ndev tun\nca ca.crt\ncert \"my cert.crt\"\nkey client.key\n\
             tls-auth ta.key 1\n--dh dh.pem\nauth-user-pass\n<ca>\nINLINE\n</ca>\n\
             # comment\nremote example.com 443\n",
        )
        .unwrap();

        let import = vault
            .import("home", TunnelBackend::OpenVpn, &source)
            .unwrap();

        assert_eq!(import.config_path.file_name().unwrap(), "client.ovpn");
        let text = fs::read_to_string(&import.config_path).unwrap();
        assert!(text.contains("ca \"assets/0-ca.crt\""), "{text}");
        assert!(text.contains("cert \"assets/1-my_cert.crt\""), "{text}");
        assert!(text.contains("key \"assets/2-client.key\""), "{text}");
        assert!(text.contains("tls-auth \"assets/3-ta.key\" 1"), "{text}");
        assert!(text.contains("--dh \"assets/4-dh.pem\""), "{text}");
        assert!(text.contains("\nauth-user-pass\n"), "{text}");
        assert!(text.contains("<ca>\nINLINE\n</ca>"), "{text}");
        assert!(text.contains("# comment"), "{text}");
        assert!(text.contains("remote example.com 443"), "{text}");
        assert!(!text.contains("my cert.crt"), "{text}");
        assert!(import.warnings.is_empty());

        let rev = import.config_path.parent().unwrap();
        assert_eq!(
            fs::read(rev.join("assets").join("0-ca.crt")).unwrap(),
            b"CA"
        );
        assert_eq!(
            fs::read(rev.join("assets").join("1-my_cert.crt")).unwrap(),
            b"CERT"
        );
        assert!(vault.is_managed_path(&rev.join("assets").join("0-ca.crt")));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_openvpn_copies_absolute_referenced_file() {
        let (vault, dir) = vault("ovpn-abs");
        let asset_dir = unique_dir("ovpn-abs-assets");
        let ca = asset_dir.join("ca.pem");
        fs::write(&ca, b"ABS-CA").unwrap();
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        let source = cfg_dir.join("client.ovpn");
        fs::write(&source, format!("ca '{}'\n", ca.display())).unwrap();

        let import = vault
            .import("abs", TunnelBackend::OpenVpn, &source)
            .unwrap();
        let text = fs::read_to_string(&import.config_path).unwrap();
        assert!(text.contains("ca \"assets/0-ca.pem\""), "{text}");
        let rev = import.config_path.parent().unwrap();
        assert_eq!(
            fs::read(rev.join("assets").join("0-ca.pem")).unwrap(),
            b"ABS-CA"
        );
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&asset_dir).unwrap();
    }

    #[test]
    fn openvpn_auth_user_pass_without_arg_is_preserved() {
        let (vault, dir) = vault("ovpn-aup");
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        let source = cfg_dir.join("client.conf");
        fs::write(&source, "client\nauth-user-pass\n").unwrap();

        let import = vault.import("p", TunnelBackend::OpenVpn, &source).unwrap();
        assert_eq!(import.config_path.file_name().unwrap(), "client.conf");
        let text = fs::read_to_string(&import.config_path).unwrap();
        assert!(text.contains("auth-user-pass\n"), "{text}");
        assert!(!import.config_path.parent().unwrap().join("assets").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_openvpn_rejects_nested_config_and_cleans_staging() {
        let (vault, dir) = vault("ovpn-nested");
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        let source = cfg_dir.join("client.ovpn");
        fs::write(&source, "client\nconfig other.ovpn\n").unwrap();

        let err = vault
            .import("nested", TunnelBackend::OpenVpn, &source)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let profile_dir = vault.root().join("nested");
        let leftovers: Vec<_> = fs::read_dir(&profile_dir)
            .map(|d| d.filter_map(|e| e.ok()).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_openvpn_rejects_missing_asset_and_cleans_staging() {
        let (vault, dir) = vault("ovpn-missing");
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        let source = cfg_dir.join("client.ovpn");
        fs::write(&source, "client\nca missing-ca.crt\n").unwrap();

        let err = vault
            .import("miss", TunnelBackend::OpenVpn, &source)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        let profile_dir = vault.root().join("miss");
        let leftovers: Vec<_> = fs::read_dir(&profile_dir)
            .map(|d| d.filter_map(|e| e.ok()).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_openvpn_warns_once_per_script_directive() {
        let (vault, dir) = vault("ovpn-scripts");
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        for name in ["a.bat", "b.bat", "x.dll", "c.bat"] {
            fs::write(cfg_dir.join(name), name).unwrap();
        }
        let source = cfg_dir.join("client.ovpn");
        fs::write(
            &source,
            "client\nup a.bat\nup b.bat\nplugin x.dll\ndown c.bat\n",
        )
        .unwrap();

        let import = vault
            .import("scr", TunnelBackend::OpenVpn, &source)
            .unwrap();
        assert_eq!(import.warnings.len(), 3);
        assert!(import.warnings.iter().any(|w| w.contains("'up'")));
        assert!(import.warnings.iter().any(|w| w.contains("'down'")));
        assert!(import.warnings.iter().any(|w| w.contains("'plugin'")));
        let text = fs::read_to_string(&import.config_path).unwrap();
        assert!(text.contains("up \"assets/0-a.bat\""), "{text}");
        assert!(text.contains("plugin \"assets/2-x.dll\""), "{text}");
        let assets = import.config_path.parent().unwrap().join("assets");
        assert!(assets.join("0-a.bat").is_file());
        assert!(assets.join("2-x.dll").is_file());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_openvpn_script_directives_copy_args_and_preserve_rest() {
        let (vault, dir) = vault("ovpn-script-args");
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(cfg_dir.join("up.bat"), "@echo up").unwrap();
        let plug_dir = cfg_dir.join("plugin dir");
        fs::create_dir(&plug_dir).unwrap();
        fs::write(plug_dir.join("plug.dll"), "dll").unwrap();
        let source = cfg_dir.join("client.ovpn");
        fs::write(
            &source,
            "client\nup\nup up.bat extra 'arg two'\nplugin 'plugin dir/plug.dll' /mode\n",
        )
        .unwrap();

        let import = vault
            .import("scr", TunnelBackend::OpenVpn, &source)
            .unwrap();
        assert!(import.warnings.iter().any(|w| w.contains("'up'")));
        assert!(import.warnings.iter().any(|w| w.contains("'plugin'")));
        let text = fs::read_to_string(&import.config_path).unwrap();
        assert!(text.contains("\nup\n"), "{text}");
        assert!(
            text.contains("up \"assets/0-up.bat\" extra 'arg two'")
                || text.contains("up \"assets/0-up.bat\" extra \"arg two\""),
            "{text}"
        );
        assert!(
            text.contains("plugin \"assets/1-plug.dll\" /mode"),
            "{text}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_openvpn_rejects_missing_script_and_cleans_staging() {
        let (vault, dir) = vault("ovpn-missing-script");
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        let source = cfg_dir.join("client.ovpn");
        fs::write(&source, "client\nup missing.bat\n").unwrap();

        let err = vault
            .import("miss", TunnelBackend::OpenVpn, &source)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        let profile_dir = vault.root().join("miss");
        let leftovers: Vec<_> = fs::read_dir(&profile_dir)
            .map(|d| d.filter_map(|e| e.ok()).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn is_managed_path_rejects_traversal_siblings_and_root() {
        let (vault, dir) = vault("managed-check");
        let root = vault.root();
        assert!(!vault.is_managed_path(root));
        assert!(!vault.is_managed_path(&root.join("p1")));
        assert!(!vault.is_managed_path(&root.join("p1").join("rev-1")));
        for name in [
            "tunnel.conf",
            "tunnel.conf.dpapi",
            "client.ovpn",
            "client.conf",
            "config.json",
        ] {
            assert!(
                vault.is_managed_path(&root.join("p1").join("rev-1").join(name)),
                "{name} should be managed"
            );
        }
        assert!(!vault.is_managed_path(&root.join("p1").join("rev-1").join("foo.txt")));
        assert!(!vault.is_managed_path(&root.join("p1").join("rev-1").join("evil.conf.dpapi.bak")));
        assert!(vault.is_managed_path(&root.join("p1").join("rev-1").join("p1.conf")));
        assert!(vault.is_managed_path(&root.join("p1").join("rev-1").join("p1.conf.dpapi")));
        assert!(!vault.is_managed_path(&root.join("p1").join("rev-1").join("p2.conf")));
        assert!(vault.is_managed_path(
            &root
                .join("p1")
                .join("rev-1")
                .join("assets")
                .join("0-ca.crt")
        ));
        assert!(!vault.is_managed_path(&root.join("p1").join("rev-1").join("assets")));
        assert!(!vault.is_managed_path(
            &root
                .join("p1")
                .join("rev-1")
                .join("assets")
                .join("sub")
                .join("x")
        ));
        assert!(!vault.is_managed_path(&root.join("p1").join("rev-1").join("..").join("evil")));
        assert!(!vault.is_managed_path(
            &root
                .join("p1")
                .join("rev-1")
                .join("assets")
                .join("..")
                .join("x")
        ));
        assert!(!vault.is_managed_path(&root.join("p1").join("notrev").join("config.json")));
        let sibling = root.parent().unwrap().join("vault-evil");
        assert!(!vault.is_managed_path(&sibling.join("p1").join("rev-1").join("config.json")));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wireguard_imports_get_unique_profile_named_configs() {
        let (vault, dir) = vault("wg-unique");
        let source = dir.join("shared.conf");
        fs::write(&source, b"[Interface]\n").unwrap();

        let first = vault
            .import("site-a", TunnelBackend::WireGuard, &source)
            .unwrap();
        let second = vault
            .import("site-b", TunnelBackend::WireGuard, &source)
            .unwrap();
        assert_eq!(first.config_path.file_name().unwrap(), "site-a.conf");
        assert_eq!(second.config_path.file_name().unwrap(), "site-b.conf");
        assert_ne!(
            crate::vpn::wireguard_tunnel_name(&first.config_path).unwrap(),
            crate::vpn::wireguard_tunnel_name(&second.config_path).unwrap()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn is_managed_profile_path_scopes_to_owning_profile() {
        let (vault, dir) = vault("own-scope");
        let source = dir.join("a.conf");
        fs::write(&source, b"x").unwrap();
        let import = vault
            .import("owner", TunnelBackend::WireGuard, &source)
            .unwrap();
        assert!(vault.is_managed_profile_path("owner", &import.config_path));
        assert!(!vault.is_managed_profile_path("other", &import.config_path));
        assert!(!vault.is_managed_profile_path("owner", &dir.join("a.conf")));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn store_xray_config_writes_exact_bytes_into_managed_revision() {
        let (vault, dir) = vault("xray-store");
        let bytes = br#"{"inbounds":[],"outbounds":[]}"#;
        let import = vault.store_xray_config("p", bytes).unwrap();
        assert_eq!(import.config_path.file_name().unwrap(), "config.json");
        assert!(vault.is_managed_path(&import.config_path));
        assert_eq!(fs::read(&import.config_path).unwrap(), bytes);
        assert!(import.warnings.is_empty());

        assert!(vault.store_xray_config("///..", bytes).is_err());
        let leftovers: Vec<_> = fs::read_dir(vault.root().join("p"))
            .map(|d| d.filter_map(|e| e.ok()).collect())
            .unwrap_or_default();
        assert!(leftovers
            .iter()
            .all(|e| !e.file_name().to_string_lossy().ends_with(".tmp")));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_revision_scoped_to_containing_revision() {
        let (vault, dir) = vault("rm-rev");
        let source = dir.join("a.conf");
        fs::write(&source, b"one").unwrap();
        let first = vault
            .import("p", TunnelBackend::WireGuard, &source)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let second = vault
            .import("p", TunnelBackend::WireGuard, &source)
            .unwrap();

        vault
            .remove_revision_for_config(&first.config_path)
            .unwrap();
        assert!(!first.config_path.parent().unwrap().exists());
        assert!(second.config_path.exists());

        let external = dir.join("outside.conf");
        fs::write(&external, b"x").unwrap();
        assert_eq!(
            vault
                .remove_revision_for_config(&external)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(external.exists());

        let gone = vault
            .root()
            .join("p")
            .join("rev-999999")
            .join("tunnel.conf");
        assert!(vault.remove_revision_for_config(&gone).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_profile_removes_only_matching_safe_dir() {
        let (vault, dir) = vault("rm-prof");
        let source = dir.join("a.conf");
        fs::write(&source, b"one").unwrap();
        vault
            .import("keep-me", TunnelBackend::WireGuard, &source)
            .unwrap();
        let dropped = vault
            .import("drop.me", TunnelBackend::WireGuard, &source)
            .unwrap();
        let drop_dir = dropped
            .config_path
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        vault.remove_profile("nonexistent").unwrap();
        assert!(vault.root().join("keep-me").exists());
        assert!(drop_dir.exists());
        assert!(drop_dir.starts_with(vault.root()));

        vault.remove_profile("drop.me").unwrap();
        assert!(!drop_dir.exists());
        assert!(vault.root().join("keep-me").exists());

        let link = vault.root().join("linked");
        let target = vault.root().join("keep-me");
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_dir(&target, &link);
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&target, &link);
        #[cfg(any(windows, unix))]
        if linked.is_ok() {
            assert_eq!(
                vault.remove_profile("linked").unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert!(link.exists() || fs::symlink_metadata(&link).is_ok());
            #[cfg(windows)]
            fs::remove_dir(&link).unwrap();
            #[cfg(unix)]
            fs::remove_file(&link).unwrap();
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_rejects_nonfile_and_bad_extension() {
        let (vault, dir) = vault("bad-src");
        let missing = dir.join("nope.conf");
        assert!(vault
            .import("p", TunnelBackend::WireGuard, &missing)
            .is_err());
        assert!(vault.import("p", TunnelBackend::WireGuard, &dir).is_err());

        let txt = dir.join("notes.txt");
        fs::write(&txt, b"hi").unwrap();
        assert!(vault.import("p", TunnelBackend::WireGuard, &txt).is_err());
        let conf = dir.join("c.conf");
        fs::write(&conf, b"{}").unwrap();
        assert!(vault.import("p", TunnelBackend::Xray, &conf).is_err());
        let ovpn = dir.join("c.ovpn");
        fs::write(&ovpn, b"client").unwrap();
        assert!(vault.import("p", TunnelBackend::WireGuard, &ovpn).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_rejects_non_utf8_openvpn() {
        let (vault, dir) = vault("ovpn-utf8");
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        let source = cfg_dir.join("client.ovpn");
        fs::write(&source, [0x63u8, 0x6c, 0xff, 0xfe]).unwrap();
        let err = vault
            .import("u", TunnelBackend::OpenVpn, &source)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_openvpn_inline_block_copied_verbatim_without_parsing() {
        let (vault, dir) = vault("ovpn-inline");
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(cfg_dir.join("client.key"), b"KEY").unwrap();
        let source = cfg_dir.join("client.ovpn");
        fs::write(
            &source,
            "client\n  <Ca>\nconfig evil.ovpn\nkey outside.key\nup script.bat\nINLINE </ca> text\n</cA>\n\
             key client.key\n",
        )
        .unwrap();

        let import = vault
            .import("inl", TunnelBackend::OpenVpn, &source)
            .unwrap();
        let text = fs::read_to_string(&import.config_path).unwrap();
        assert!(text.contains("  <Ca>\n"), "{text}");
        assert!(text.contains("config evil.ovpn"), "{text}");
        assert!(text.contains("key outside.key"), "{text}");
        assert!(text.contains("up script.bat"), "{text}");
        assert!(text.contains("INLINE </ca> text"), "{text}");
        assert!(text.contains("</cA>"), "{text}");
        assert!(text.contains("key \"assets/0-client.key\""), "{text}");
        assert!(import.warnings.is_empty());
        let assets: Vec<_> = fs::read_dir(import.config_path.parent().unwrap().join("assets"))
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(assets.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_openvpn_rejects_unterminated_inline_block_and_cleans_staging() {
        let (vault, dir) = vault("ovpn-unterminated");
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        let source = cfg_dir.join("client.ovpn");
        fs::write(&source, "client\n<ca>\nnever closed\n").unwrap();

        let err = vault
            .import("term", TunnelBackend::OpenVpn, &source)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let profile_dir = vault.root().join("term");
        let leftovers: Vec<_> = fs::read_dir(&profile_dir)
            .map(|d| d.filter_map(|e| e.ok()).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn colliding_sanitized_ids_get_stable_distinct_dirs() {
        let (vault, dir) = vault("collide");
        let source = dir.join("a.conf");
        fs::write(&source, b"x").unwrap();

        let first = vault
            .import("a.b", TunnelBackend::WireGuard, &source)
            .unwrap();
        let second = vault
            .import("a/b", TunnelBackend::WireGuard, &source)
            .unwrap();
        let first_dir = first.config_path.parent().unwrap().parent().unwrap();
        let second_dir = second.config_path.parent().unwrap().parent().unwrap();
        assert_ne!(first_dir, second_dir);
        let first_name = first_dir.file_name().unwrap().to_str().unwrap();
        assert!(first_name.starts_with("a_b-"), "{first_name}");
        assert_eq!(first_name.len(), "a_b-".len() + 16);

        vault.remove_profile("a.b").unwrap();
        assert!(!first_dir.exists());
        assert!(second_dir.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_rejects_unusable_profile_id() {
        let (vault, dir) = vault("bad-id");
        let source = dir.join("a.conf");
        fs::write(&source, b"x").unwrap();
        assert!(vault.import("", TunnelBackend::WireGuard, &source).is_err());
        assert!(vault
            .import("///..", TunnelBackend::WireGuard, &source)
            .is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_and_store_protect_managed_paths() {
        use crate::config_security::inspect_path_protection;
        let (vault, dir) = vault("protected");
        let cfg_dir = dir.join("cfg");
        fs::create_dir_all(&cfg_dir).unwrap();
        fs::write(cfg_dir.join("ca.crt"), b"CA").unwrap();
        let source = cfg_dir.join("client.ovpn");
        fs::write(&source, "client\ndev tun\nca ca.crt\n").unwrap();
        let source_bytes = fs::read(&source).unwrap();
        #[cfg(windows)]
        let source_acl_before = inspect_path_protection(&source).unwrap();

        let import = vault
            .import("home", TunnelBackend::OpenVpn, &source)
            .unwrap();
        let revision = import.config_path.parent().unwrap();
        let profile_dir = revision.parent().unwrap();
        let asset = revision.join("assets").join("0-ca.crt");

        #[cfg(windows)]
        for path in [
            vault.root().to_path_buf(),
            profile_dir.to_path_buf(),
            revision.to_path_buf(),
            import.config_path.clone(),
            revision.join("assets"),
            asset,
        ] {
            let protection = inspect_path_protection(&path).unwrap();
            assert!(
                protection.protected_dacl
                    && protection.current_user
                    && protection.system
                    && protection.administrators,
                "{} not fully protected",
                path.display()
            );
        }

        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        #[cfg(windows)]
        assert_eq!(inspect_path_protection(&source).unwrap(), source_acl_before);

        let stored = vault
            .store_xray_config("node", br#"{"outbounds":[]}"#)
            .unwrap();
        let stored_revision = stored.config_path.parent().unwrap();
        #[cfg(windows)]
        for path in [stored_revision.to_path_buf(), stored.config_path.clone()] {
            let protection = inspect_path_protection(&path).unwrap();
            assert!(protection.protected_dacl, "{} unprotected", path.display());
        }
        assert_eq!(
            fs::read(&stored.config_path).unwrap(),
            br#"{"outbounds":[]}"#
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
