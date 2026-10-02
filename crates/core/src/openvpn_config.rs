use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path};

pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_ASSET_BYTES: usize = 512 * 1024;
const MAX_TOTAL_ASSET_BYTES: usize = 1024 * 1024;
const MAX_ASSETS: usize = 32;
/// OpenVPN reads config lines (and inline blocks) with `fgets` into a
/// 256-byte buffer. A longer line is split, and a chunk that happens to start
/// with a close tag or directive would be parsed differently from what this
/// sanitizer validated. 254 leaves room for `\n` and NUL.
const MAX_LINE_BYTES: usize = 254;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenVpnConfigError {
    InvalidConfig,
    UnsupportedDirective,
    MissingAsset,
    InvalidAsset,
    TooLarge,
}

pub struct SanitizedOpenVpnAsset {
    pub name: String,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for SanitizedOpenVpnAsset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SanitizedOpenVpnAsset")
            .field("bytes_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

pub struct SanitizedOpenVpnConfig {
    pub config: String,
    pub assets: Vec<SanitizedOpenVpnAsset>,
}

impl fmt::Debug for SanitizedOpenVpnConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SanitizedOpenVpnConfig")
            .field("assets_len", &self.assets.len())
            .finish_non_exhaustive()
    }
}

/// Validates an imported client config without opening any source path.
///
/// The caller must supply only bytes already read from ConfigVault and must create
/// `staging_dir` with root-owned 0700 permissions, then write the returned config
/// and assets there with 0600 permissions before starting OpenVPN.
pub fn sanitize_openvpn_config(
    input: &str,
    managed_assets: &BTreeMap<String, Vec<u8>>,
    staging_dir: &Path,
) -> Result<SanitizedOpenVpnConfig, OpenVpnConfigError> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(OpenVpnConfigError::TooLarge);
    }
    if !safe_staging_dir(staging_dir) {
        return Err(OpenVpnConfigError::InvalidConfig);
    }

    let mut output = String::new();
    let mut assets = Vec::new();
    let mut total_asset_bytes = 0usize;
    let mut inline: Option<String> = None;
    let mut has_client = false;
    let mut has_remote = false;
    for raw_line in input.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.len() > MAX_LINE_BYTES || line.contains('\0') || line.contains('\r') {
            return Err(OpenVpnConfigError::InvalidConfig);
        }
        if let Some(tag) = inline.as_deref() {
            if line.trim() == format!("</{tag}>") {
                output.push_str(&format!("</{tag}>\n"));
                inline = None;
            } else if line.trim_start().starts_with('<') {
                return Err(OpenVpnConfigError::InvalidConfig);
            } else {
                output.push_str(line);
                output.push('\n');
            }
            continue;
        }
        let tokens = tokenize(line)?;
        if tokens.is_empty() {
            continue;
        }
        if tokens[0].starts_with('<') {
            if tokens.len() != 1 || line.trim() != tokens[0] {
                return Err(OpenVpnConfigError::InvalidConfig);
            }
            let tag = tokens[0]
                .strip_prefix('<')
                .and_then(|s| s.strip_suffix('>'))
                .ok_or(OpenVpnConfigError::InvalidConfig)?;
            if !matches!(
                tag,
                "ca" | "cert"
                    | "key"
                    | "tls-auth"
                    | "tls-crypt"
                    | "tls-crypt-v2"
                    | "pkcs12"
                    | "auth-user-pass"
            ) {
                return Err(OpenVpnConfigError::UnsupportedDirective);
            }
            inline = Some(tag.to_owned());
            output.push_str(&format!("<{tag}>\n"));
            continue;
        }
        let directive = tokens[0].trim_start_matches('-').to_ascii_lowercase();
        let args = &tokens[1..];
        match directive.as_str() {
            "client" | "tls-client" | "nobind" | "persist-key" | "persist-tun"
            | "remote-random" | "auth-nocache" | "pull" | "float" | "route-nopull"
            | "ping-timer-rem" => require_args(args, 0, 0)?,
            "dev" if args == ["tun"] => {}
            "proto" if args.len() == 1 && is_client_proto(&args[0]) => {}
            "remote-cert-tls" if args == ["server"] => {}
            "auth-user-pass" | "askpass" => match args {
                // Bare: credentials are requested via the management interface.
                [] => {}
                // `username-only` prompts for a username without a password.
                [arg] if directive == "auth-user-pass" && arg == "username-only" => {}
                [_] => {
                    output.push_str(&staged_asset_line(
                        &directive,
                        args,
                        managed_assets,
                        staging_dir,
                        &mut assets,
                        &mut total_asset_bytes,
                    )?);
                    continue;
                }
                _ => return Err(OpenVpnConfigError::InvalidConfig),
            },
            "remote" => validate_remote(args)?,
            "resolv-retry"
                if args.len() == 1 && (args[0] == "infinite" || positive_number(&args[0])) => {}
            "connect-retry"
                if (1..=2).contains(&args.len()) && args.iter().all(|a| positive_number(a)) => {}
            "keepalive" if args.len() == 2 && args.iter().all(|a| positive_number(a)) => {}
            "inactive"
                if (1..=2).contains(&args.len()) && args.iter().all(|a| positive_number(a)) => {}
            "explicit-exit-notify"
                if args.len() <= 1 && args.iter().all(|a| positive_number(a)) => {}
            "ping" | "ping-restart" | "tun-mtu" | "verb" | "mute" | "connect-timeout"
            | "connect-retry-max" | "ping-exit" | "reneg-sec" | "reneg-bytes" | "reneg-pkts"
            | "hand-window" | "sndbuf" | "rcvbuf" | "mssfix" | "fragment" | "link-mtu"
                if args.len() == 1 && positive_number(&args[0]) => {}
            "key-direction" if args.len() == 1 && matches!(args[0].as_str(), "0" | "1") => {}
            "topology"
                if args.len() == 1 && matches!(args[0].as_str(), "subnet" | "net30" | "p2p") => {}
            "auth-retry"
                if args.len() == 1
                    && matches!(args[0].as_str(), "none" | "nointeract" | "interact") => {}
            "auth"
            | "cipher"
            | "data-ciphers"
            | "data-ciphers-fallback"
            | "ncp-ciphers"
            | "tls-version-min"
            | "tls-version-max"
            | "tls-cipher"
            | "tls-ciphersuites"
            | "peer-fingerprint"
                if args.len() == 1 && safe_option_value(&args[0]) => {}
            "verify-x509-name"
                if (1..=2).contains(&args.len()) && args.iter().all(|a| safe_option_value(a)) => {}
            "ca" | "cert" | "key" | "tls-crypt" | "tls-crypt-v2" | "pkcs12" if args.len() == 1 => {
                output.push_str(&staged_asset_line(
                    &directive,
                    args,
                    managed_assets,
                    staging_dir,
                    &mut assets,
                    &mut total_asset_bytes,
                )?);
                continue;
            }
            "tls-auth"
                if (1..=2).contains(&args.len())
                    && (args.len() == 1 || matches!(args[1].as_str(), "0" | "1")) =>
            {
                output.push_str(&staged_asset_line(
                    &directive,
                    args,
                    managed_assets,
                    staging_dir,
                    &mut assets,
                    &mut total_asset_bytes,
                )?);
                continue;
            }
            "dev"
            | "proto"
            | "remote-cert-tls"
            | "resolv-retry"
            | "connect-retry"
            | "keepalive"
            | "inactive"
            | "explicit-exit-notify"
            | "ping"
            | "ping-restart"
            | "tun-mtu"
            | "verb"
            | "mute"
            | "connect-timeout"
            | "connect-retry-max"
            | "ping-exit"
            | "reneg-sec"
            | "reneg-bytes"
            | "reneg-pkts"
            | "hand-window"
            | "sndbuf"
            | "rcvbuf"
            | "mssfix"
            | "fragment"
            | "link-mtu"
            | "key-direction"
            | "topology"
            | "auth-retry"
            | "auth"
            | "cipher"
            | "data-ciphers"
            | "data-ciphers-fallback"
            | "ncp-ciphers"
            | "tls-version-min"
            | "tls-version-max"
            | "tls-cipher"
            | "tls-ciphersuites"
            | "peer-fingerprint"
            | "verify-x509-name"
            | "ca"
            | "cert"
            | "key"
            | "tls-crypt"
            | "tls-crypt-v2"
            | "pkcs12"
            | "tls-auth" => {
                return Err(OpenVpnConfigError::InvalidConfig);
            }
            _ => return Err(OpenVpnConfigError::UnsupportedDirective),
        }
        has_client |= directive == "client";
        has_remote |= directive == "remote";
        output.push_str(&directive);
        for arg in args {
            output.push(' ');
            output.push_str(arg);
        }
        output.push('\n');
    }
    // Rewritten lines (e.g. staged asset paths) must obey the same limit.
    if output.lines().any(|line| line.len() > MAX_LINE_BYTES) {
        return Err(OpenVpnConfigError::InvalidConfig);
    }
    if inline.is_some() || !has_client || !has_remote {
        return Err(OpenVpnConfigError::InvalidConfig);
    }
    Ok(SanitizedOpenVpnConfig {
        config: output,
        assets,
    })
}

fn safe_staging_dir(path: &Path) -> bool {
    path.as_os_str().len() <= 256
        && path
            .strip_prefix("/run/network-orchestrator")
            .is_ok_and(|relative| relative.components().next().is_some())
        && path.components().all(|part| match part {
            Component::RootDir => true,
            Component::Normal(name) => name.to_str().is_some_and(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            }),
            _ => false,
        })
}

fn require_args(args: &[String], min: usize, max: usize) -> Result<(), OpenVpnConfigError> {
    if (min..=max).contains(&args.len()) {
        Ok(())
    } else {
        Err(OpenVpnConfigError::InvalidConfig)
    }
}

fn positive_number(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

fn safe_option_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:+,=@/-".contains(&b))
}

fn validate_remote(args: &[String]) -> Result<(), OpenVpnConfigError> {
    if !(1..=3).contains(&args.len()) || !safe_option_value(&args[0]) {
        return Err(OpenVpnConfigError::InvalidConfig);
    }
    if args.len() >= 2 && !positive_number(&args[1]) {
        return Err(OpenVpnConfigError::InvalidConfig);
    }
    if args.len() == 3 && !is_client_proto(&args[2]) {
        return Err(OpenVpnConfigError::InvalidConfig);
    }
    Ok(())
}

/// OpenVPN accepts `tcp`, `tcp4` and `tcp6` as client-side aliases on
/// `proto` and on `remote` lines (`tcp` resolves to `tcp4-client` when the
/// config is a client profile). Server-side `*-server` variants are never
/// valid in a client profile and stay rejected.
fn is_client_proto(proto: &str) -> bool {
    matches!(
        proto,
        "udp"
            | "udp4"
            | "udp6"
            | "tcp"
            | "tcp4"
            | "tcp6"
            | "tcp-client"
            | "tcp4-client"
            | "tcp6-client"
    )
}

fn staged_asset_line(
    directive: &str,
    args: &[String],
    managed_assets: &BTreeMap<String, Vec<u8>>,
    staging_dir: &Path,
    assets: &mut Vec<SanitizedOpenVpnAsset>,
    total_asset_bytes: &mut usize,
) -> Result<String, OpenVpnConfigError> {
    let source = &args[0];
    source
        .strip_prefix("assets/")
        .filter(|s| {
            !s.is_empty()
                && *s != "."
                && *s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
        .ok_or(OpenVpnConfigError::InvalidAsset)?;
    let bytes = managed_assets
        .get(source)
        .ok_or(OpenVpnConfigError::MissingAsset)?;
    if bytes.is_empty() {
        return Err(OpenVpnConfigError::InvalidAsset);
    }
    if bytes.len() > MAX_ASSET_BYTES
        || assets.len() >= MAX_ASSETS
        || *total_asset_bytes + bytes.len() > MAX_TOTAL_ASSET_BYTES
    {
        return Err(OpenVpnConfigError::TooLarge);
    }
    let staged_name = format!("asset-{}", assets.len());
    let path = staging_dir.join(&staged_name);
    let path = path.to_str().ok_or(OpenVpnConfigError::InvalidConfig)?;
    let mut line = format!("{directive} {path}");
    if args.len() == 2 {
        line.push(' ');
        line.push_str(&args[1]);
    }
    line.push('\n');
    *total_asset_bytes += bytes.len();
    assets.push(SanitizedOpenVpnAsset {
        name: staged_name,
        bytes: bytes.clone(),
    });
    Ok(line)
}

fn tokenize(line: &str) -> Result<Vec<String>, OpenVpnConfigError> {
    let mut chars = line.chars().peekable();
    let mut tokens = Vec::new();
    while let Some(&ch) = chars.peek() {
        if ch.is_ascii_whitespace() {
            chars.next();
            continue;
        }
        if ch == '#' || ch == ';' {
            break;
        }
        let quote_char = if ch == '"' || ch == '\'' {
            chars.next()
        } else {
            None
        };
        let mut token = String::new();
        let mut closed = quote_char.is_none();
        while let Some(&c) = chars.peek() {
            if let Some(q) = quote_char {
                if c == q {
                    chars.next();
                    closed = true;
                    break;
                }
            } else if c.is_ascii_whitespace() {
                break;
            }
            if c == '\\'
                || c == '\0'
                || c == '\r'
                || (quote_char.is_none() && (c == '"' || c == '\''))
            {
                return Err(OpenVpnConfigError::InvalidConfig);
            }
            token.push(c);
            chars.next();
        }
        if !closed
            || chars
                .peek()
                .is_some_and(|c| !c.is_ascii_whitespace() && *c != '#' && *c != ';')
        {
            return Err(OpenVpnConfigError::InvalidConfig);
        }
        tokens.push(token);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sanitize(input: &str) -> Result<SanitizedOpenVpnConfig, OpenVpnConfigError> {
        sanitize_openvpn_config(
            input,
            &BTreeMap::new(),
            Path::new("/run/network-orchestrator/test"),
        )
    }

    #[test]
    fn accepts_inline_certs_and_basic_client_options() {
        let config = sanitize("client\nremote vpn.example 1194\nproto udp\ndev tun\nremote-cert-tls server\n<ca>\nCERTIFICATE\n</ca>\n<key>\nPRIVATE SECRET\n</key>\n")
            .unwrap();
        assert!(config.config.contains("remote vpn.example 1194\n"));
        assert!(config.config.contains("<key>\nPRIVATE SECRET\n</key>\n"));
        assert!(config.assets.is_empty());
    }

    #[test]
    fn accepts_openvpn_client_protocol_aliases() {
        for proto in [
            "udp",
            "udp4",
            "udp6",
            "tcp",
            "tcp4",
            "tcp6",
            "tcp-client",
            "tcp4-client",
            "tcp6-client",
        ] {
            assert!(
                sanitize(&format!("client\nremote vpn.example 1194 {proto}\n")).is_ok(),
                "remote … {proto}"
            );
            assert!(
                sanitize(&format!("client\nremote vpn.example\nproto {proto}\n")).is_ok(),
                "proto {proto}"
            );
        }
        for proto in ["tcp-server", "tcp4-server", "tcp6-server"] {
            assert!(
                sanitize(&format!("client\nremote vpn.example 1194 {proto}\n")).is_err(),
                "remote … {proto}"
            );
            assert!(
                sanitize(&format!("client\nremote vpn.example\nproto {proto}\n")).is_err(),
                "proto {proto}"
            );
        }
    }

    #[test]
    fn accepts_common_client_options_and_still_rejects_bad_arguments() {
        for lines in [
            "verb 4\n",
            "explicit-exit-notify\n",
            "explicit-exit-notify 3\n",
            "keepalive 10 60\n",
            "mute 20\n",
            "connect-timeout 30\nconnect-retry-max 3\n",
            "ping-exit 60\nping-timer-rem\n",
            "reneg-sec 0\n",
            "sndbuf 393216\nrcvbuf 393216\n",
            "mssfix 1400\nfragment 1300\nlink-mtu 1500\n",
            "ncp-ciphers AES-256-GCM:AES-128-GCM\n",
            "tls-version-max 1.3\ntls-ciphersuites TLS_AES_256_GCM_SHA384\n",
            "peer-fingerprint AA:BB:CC\n",
            "topology subnet\n",
            "auth-retry nointeract\n",
            "pull\nfloat\nroute-nopull\n",
            "inactive 3600\ninactive 3600 1000000\n",
        ] {
            assert!(
                sanitize(&format!("client\nremote vpn.example 1194 udp\n{lines}")).is_ok(),
                "{lines:?}"
            );
        }
        for lines in [
            "verb\n",
            "verb debug\n",
            "keepalive 10\n",
            "topology p2p extra\n",
            "topology evil\n",
            "auth-retry always\n",
            "peer-fingerprint\n",
            "explicit-exit-notify 1 2\n",
        ] {
            assert!(
                sanitize(&format!("client\nremote vpn.example 1194 udp\n{lines}")).is_err(),
                "{lines:?}"
            );
        }
    }

    #[test]
    fn requires_a_client_profile_with_remote_endpoint() {
        for input in ["", "client\n", "remote vpn.example 1194\n"] {
            assert_eq!(
                sanitize(input).err(),
                Some(OpenVpnConfigError::InvalidConfig)
            );
        }
    }

    #[test]
    fn rewrites_only_managed_assets_to_private_staging_paths() {
        let mut assets = BTreeMap::new();
        assets.insert("assets/0-ca.crt".to_owned(), b"CERTIFICATE".to_vec());
        let result = sanitize_openvpn_config(
            "client\nca \"assets/0-ca.crt\"\nremote vpn.example 443\n",
            &assets,
            Path::new("/run/network-orchestrator/test"),
        )
        .unwrap();
        assert!(result
            .config
            .contains("ca /run/network-orchestrator/test/asset-0\n"));
        assert_eq!(result.assets[0].name, "asset-0");
        assert_eq!(result.assets[0].bytes, b"CERTIFICATE");
    }

    #[test]
    fn rejects_executable_and_file_output_directives() {
        for directive in [
            "up /tmp/hook",
            "down /tmp/hook",
            "route-up /tmp/hook",
            "route-pre-down /tmp/hook",
            "ipchange /tmp/hook",
            "tls-verify /tmp/hook",
            "tls-crypt-v2-verify /tmp/hook",
            "auth-user-pass-verify /tmp/hook",
            "client-connect /tmp/hook",
            "client-disconnect /tmp/hook",
            "learn-address /tmp/hook",
            "dns-updown /tmp/hook",
            "plugin /tmp/plugin.so",
            "config other.ovpn",
            "log /tmp/log",
            "log-append /tmp/log",
            "status /tmp/status",
            "writepid /tmp/pid",
            "management 127.0.0.1 1234",
            "cd /tmp",
            "chroot /tmp",
            "tmp-dir /tmp",
            "dev-node /tmp/tun",
            "daemon",
            "user nobody",
            "group nogroup",
            "script-security 3",
            "setenv PATH /tmp",
            "route 1.2.3.0 255.255.255.0",
            "up-restart",
        ] {
            assert!(
                sanitize(&format!("client\nremote vpn.example\n{directive}\n")).is_err(),
                "{directive}"
            );
        }
    }

    #[test]
    fn management_credentials_require_valueless_directives() {
        let safe = sanitize(
            "client\nremote vpn.example\nauth-user-pass\naskpass\nauth-user-pass username-only\n",
        )
        .unwrap();
        assert!(safe.config.contains("auth-user-pass\n"));
        assert!(safe.config.contains("askpass\n"));
        assert!(safe.config.contains("auth-user-pass username-only\n"));
        for directive in [
            "auth-user-pass /tmp/secret.txt",
            "askpass /tmp/key-password.txt",
            "auth-user-pass a.txt b.txt",
            "askpass username-only",
            "static-challenge OTP 1",
        ] {
            assert!(
                sanitize(&format!("client\nremote vpn.example\n{directive}\n")).is_err(),
                "{directive}"
            );
        }
    }

    #[test]
    fn credential_files_stage_as_assets_and_inline_blocks_pass_verbatim() {
        let mut managed = BTreeMap::new();
        managed.insert("assets/up.txt".to_string(), b"alice\ns3cret\n".to_vec());
        managed.insert("assets/pass.txt".to_string(), b"key-pass\n".to_vec());
        let safe = sanitize_openvpn_config(
            "client\nremote vpn.example\nauth-user-pass \"assets/up.txt\"\naskpass assets/pass.txt\n",
            &managed,
            Path::new("/run/network-orchestrator/test"),
        )
        .unwrap();
        assert!(safe
            .config
            .contains("auth-user-pass /run/network-orchestrator/test/asset-0\n"));
        assert!(safe
            .config
            .contains("askpass /run/network-orchestrator/test/asset-1\n"));
        assert_eq!(safe.assets[0].bytes, b"alice\ns3cret\n");
        assert_eq!(safe.assets[1].bytes, b"key-pass\n");
        assert!(!format!("{safe:?}").contains("s3cret"));
        // Inline <auth-user-pass> reaches the runtime config verbatim —
        // OpenVPN reads embedded credentials without a prompt.
        let safe = sanitize(
            "client\nremote vpn.example\n<auth-user-pass>\nalice\ns3cret\n</auth-user-pass>\n",
        )
        .unwrap();
        assert!(safe
            .config
            .contains("<auth-user-pass>\nalice\ns3cret\n</auth-user-pass>\n"));
    }

    #[test]
    fn rejects_unknown_and_malformed_quoted_options_without_leaking_values() {
        for line in [
            "future-option PRIVATE-SECRET",
            "remote \"unterminated PRIVATE-SECRET",
            "remote 'vpn.example' 443 extra",
            "remote vpn.example\nplugin secret.so",
            "remote vpn.example\\",
            "ca /home/user/PRIVATE-SECRET.pem",
            "ca ../PRIVATE-SECRET.pem",
            "<plugin>",
        ] {
            let err = sanitize(&format!("client\nremote vpn.example\n{line}\n"))
                .err()
                .unwrap();
            let text = format!("{err:?}");
            assert!(!text.contains("PRIVATE-SECRET"), "{text}");
            assert!(!text.contains("/home/"), "{text}");
        }
    }

    /// OpenVPN reads config and inline blocks with `fgets` into a 256-byte
    /// buffer, so a longer line is split and a chunk starting with the close
    /// tag ends the block early; later "inline data" would then be parsed as
    /// root-run directives.
    #[test]
    fn rejects_lines_openvpn_would_split() {
        let smuggle = format!(
            "client\nremote vpn.example\n<ca>\n{}</ca>\nplugin /dev/shm/x.so\n</ca>\n",
            "A".repeat(255)
        );
        assert_eq!(
            sanitize(&smuggle).err(),
            Some(OpenVpnConfigError::InvalidConfig)
        );
        let long_value = format!(
            "client\nremote vpn.example\nverify-x509-name {}\n",
            "a".repeat(260)
        );
        assert_eq!(
            sanitize(&long_value).err(),
            Some(OpenVpnConfigError::InvalidConfig)
        );
        let longest_ok = format!(
            "client\nremote vpn.example\n<ca>\n{}\n</ca>\n",
            "A".repeat(254)
        );
        assert!(sanitize(&longest_ok).is_ok());
    }

    #[test]
    fn asset_limits_fit_real_bundles_and_bound_daemon_memory() {
        // Real certificates, keys and pkcs12 bundles are kilobytes.
        assert_eq!(MAX_ASSET_BYTES, 512 * 1024);
        assert_eq!(MAX_TOTAL_ASSET_BYTES, 1024 * 1024);
        let config = "client\nremote vpn.example\nca assets/a\ncert assets/b\nkey assets/c\n";
        let mut assets = BTreeMap::new();
        assets.insert("assets/a".to_owned(), vec![b'A'; MAX_ASSET_BYTES]);
        assets.insert("assets/b".to_owned(), vec![b'B'; MAX_ASSET_BYTES]);
        assets.insert("assets/c".to_owned(), vec![b'C'; 1]);
        let staging = Path::new("/run/network-orchestrator/test");
        assert_eq!(
            sanitize_openvpn_config(config, &assets, staging).err(),
            Some(OpenVpnConfigError::TooLarge)
        );
        let config = "client\nremote vpn.example\nca assets/a\ncert assets/b\n";
        assert!(sanitize_openvpn_config(config, &assets, staging).is_ok());
    }

    #[test]
    fn rejects_limits_and_bad_inline_blocks() {
        assert_eq!(
            sanitize(&"x".repeat(MAX_CONFIG_BYTES + 1)).err(),
            Some(OpenVpnConfigError::TooLarge)
        );
        let mut assets = BTreeMap::new();
        assets.insert("assets/0-key".to_owned(), vec![b'X'; MAX_ASSET_BYTES + 1]);
        assert_eq!(
            sanitize_openvpn_config(
                "client\nremote vpn.example\nkey assets/0-key\n",
                &assets,
                Path::new("/run/network-orchestrator/test")
            )
            .err(),
            Some(OpenVpnConfigError::TooLarge),
        );
        for input in [
            "<key>\nSECRET\n",
            "<key>\nSECRET\n</ca>\n",
            "<key> extra\nSECRET\n</key>\n",
            "<key>\n</key> plugin secret.so\n",
            "<key>\n</key> plugin secret.so\n</key>\n",
        ] {
            assert!(
                sanitize(&format!("client\nremote vpn.example\n{input}")).is_err(),
                "{input}"
            );
        }
    }

    #[test]
    fn staging_directory_must_be_an_absolute_private_runtime_path() {
        for path in [
            "/tmp/user-owned",
            "/run/network-orchestrator",
            "/run/network-orchestrator/../tmp",
            "relative",
        ] {
            assert_eq!(
                sanitize_openvpn_config(
                    "client\nremote vpn.example\n",
                    &BTreeMap::new(),
                    Path::new(path)
                )
                .err(),
                Some(OpenVpnConfigError::InvalidConfig),
                "{path}",
            );
        }
    }

    #[test]
    fn debug_output_never_contains_config_or_asset_secrets() {
        let mut assets = BTreeMap::new();
        assets.insert("assets/0-key".to_owned(), b"PRIVATE-SECRET".to_vec());
        let result = sanitize_openvpn_config(
            "client\nremote vpn.example\nkey assets/0-key\n",
            &assets,
            Path::new("/run/network-orchestrator/test"),
        )
        .unwrap();
        let text = format!("{result:?} {:?}", result.assets[0]);
        assert!(!text.contains("PRIVATE-SECRET"));
        assert!(!text.contains("assets/0-key"));
    }
}
