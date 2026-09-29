use crate::validate::validate_owner;
use base64::Engine;
use net_manager_core::daemon_protocol::{OpenVpnConnectRequest, OpenVpnCredentials};
use net_manager_core::models::PolicyRoute;
use net_manager_core::openvpn_config::{sanitize_openvpn_config, SanitizedOpenVpnConfig};
use net_manager_core::openvpn_management::validate_openvpn_credentials;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::io;

pub struct OpenVpnPlan {
    pub profile_id: String,
    /// Preferred link/staging name — human-readable when a hint was supplied.
    pub name: String,
    /// Deterministic collision fallback tried when `name` is occupied.
    pub fallback_name: String,
    /// Validated config text and decoded assets. Re-sanitized against the
    /// resolved staging dir at start time so a fallback name rebinds the
    /// embedded `asset-N` paths.
    config_text: String,
    asset_bytes: BTreeMap<String, Vec<u8>>,
    pub credentials: Option<OpenVpnCredentials>,
    pub routes: Vec<PolicyRoute>,
}

impl OpenVpnPlan {
    /// Re-sanitizes the config for the staging dir belonging to `name`.
    /// Validation already ran in `prepare_openvpn`; this only rebinds paths.
    pub fn sanitized_config(
        &self,
        staging: &std::path::Path,
    ) -> io::Result<SanitizedOpenVpnConfig> {
        sanitize_openvpn_config(&self.config_text, &self.asset_bytes, staging)
            .map_err(|_| rejected())
    }
}

/// Validate everything available before polkit and before any process or file mutation.
pub fn prepare_openvpn(
    uid: u32,
    request: impl Into<OpenVpnConnectRequest>,
) -> io::Result<OpenVpnPlan> {
    let OpenVpnConnectRequest {
        profile: params,
        credentials,
    } = request.into();
    let owner = format!("ovpn:{}", params.profile_id);
    validate_owner(&owner).map_err(|_| rejected())?;
    if credentials
        .as_ref()
        .is_some_and(|value| validate_openvpn_credentials(value).is_err())
    {
        return Err(rejected());
    }
    if params.routes.len() > 64 {
        return Err(rejected());
    }
    let mut seen = HashSet::new();
    for route in &params.routes {
        if route.via.is_some()
            || route.destination.trunc() != route.destination
            || route.destination.prefix_len() == 0
            || !seen.insert(route.destination)
        {
            return Err(rejected());
        }
    }
    if seen.contains(&"0.0.0.0/1".parse().unwrap())
        && seen.contains(&"128.0.0.0/1".parse().unwrap())
    {
        return Err(rejected());
    }
    let (name, fallback_name) = crate::core::tunnel_link_names(
        "ovpn-",
        uid,
        &params.profile_id,
        params.interface_name.as_deref(),
    );
    let staging = crate::openvpn_process::stage_dir(uid, &name);
    if params.assets.len() > 32 {
        return Err(rejected());
    }
    let mut asset_bytes = BTreeMap::new();
    for (path, encoded) in params.assets {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| rejected())?;
        asset_bytes.insert(path, bytes);
    }
    let config_text = params.config;
    let config =
        sanitize_openvpn_config(&config_text, &asset_bytes, &staging).map_err(|_| rejected())?;
    let has_auth = config.config.lines().any(|line| line == "auth-user-pass");
    let has_askpass = config.config.lines().any(|line| line == "askpass");
    let has_key = config.config.lines().any(|line| {
        matches!(line, "<key>" | "<pkcs12>")
            || line.starts_with("key ")
            || line.starts_with("pkcs12 ")
    });
    let supplied_auth = credentials
        .as_ref()
        .is_some_and(|value| value.auth_user_pass.is_some());
    let supplied_key_passphrase = credentials
        .as_ref()
        .is_some_and(|value| value.private_key_passphrase.is_some());
    if has_auth != supplied_auth
        || (has_askpass && !has_key)
        || ((has_askpass || encrypted_key(config.config.as_bytes())) && !supplied_key_passphrase)
        || (supplied_key_passphrase && !has_key)
    {
        return Err(rejected());
    }
    if config
        .assets
        .iter()
        .any(|asset| encrypted_key(&asset.bytes))
        && !supplied_key_passphrase
    {
        return Err(rejected());
    }
    Ok(OpenVpnPlan {
        profile_id: params.profile_id,
        name,
        fallback_name,
        config_text,
        asset_bytes,
        credentials,
        routes: params.routes,
    })
}

fn encrypted_key(bytes: &[u8]) -> bool {
    bytes
        .windows(b"-----BEGIN ENCRYPTED PRIVATE KEY-----".len())
        .any(|w| w == b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || bytes
            .windows(b"Proc-Type: 4,ENCRYPTED".len())
            .any(|w| w == b"Proc-Type: 4,ENCRYPTED")
}

fn rejected() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "OpenVPN profile is unsupported or unsafe",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{
        OpenVpnConnectParams, OpenVpnConnectRequest, OpenVpnCredentials, OpenVpnUserPass,
    };

    fn params(config: &str) -> OpenVpnConnectParams {
        OpenVpnConnectParams {
            profile_id: "home".into(),
            config: config.into(),
            assets: BTreeMap::new(),
            routes: vec![],
            interface_name: None,
        }
    }

    #[test]
    fn prepares_safe_split_profile_with_deterministic_runtime_path() {
        let mut input = params("client\nremote vpn.example 1194\nca assets/0-ca.crt\n");
        input.assets.insert(
            "assets/0-ca.crt".into(),
            base64::engine::general_purpose::STANDARD.encode(b"CERT"),
        );
        let first = prepare_openvpn(1000, input.clone()).unwrap();
        let second = prepare_openvpn(1000, input).unwrap();
        assert_eq!(first.name, second.name);
        assert_eq!(first.fallback_name, second.fallback_name);
        assert!(first.name.starts_with("ovpn-"));
        assert!(first.name.len() <= 15);
        let staged = crate::openvpn_process::stage_dir(1000, &first.name);
        let sanitized = first.sanitized_config(&staged).unwrap();
        assert!(sanitized
            .config
            .contains(&format!("{}/asset-0", staged.display())));
        assert_eq!(sanitized.assets[0].bytes, b"CERT");
        assert_ne!(
            first.name,
            prepare_openvpn(1001, params("client\nremote vpn.example\n"))
                .unwrap()
                .name
        );
    }

    #[test]
    fn rejects_scripts_credentials_full_and_dns_before_any_runner_call() {
        for config in [
            "client\nremote vpn.example\nplugin /tmp/evil.so\n",
            "client\nremote vpn.example\nup /tmp/hook\n",
            "client\nremote vpn.example\nauth-user-pass\n",
            "client\nremote vpn.example\naskpass\n",
            "client\nremote vpn.example\npkcs12 assets/0.p12\n",
            "client\nremote vpn.example\ndhcp-option DNS 10.8.0.1\n",
            "client\nremote vpn.example\nredirect-gateway def1\n",
        ] {
            assert!(prepare_openvpn(1000, params(config)).is_err(), "{config}");
        }
        let mut input = params("client\nremote vpn.example\n");
        input.routes.push(PolicyRoute {
            destination: "0.0.0.0/0".parse().unwrap(),
            metric: 1,
            via: None,
        });
        assert!(prepare_openvpn(1000, input).is_err());
    }

    #[test]
    fn rejects_bad_asset_encoding_and_encrypted_key_without_exposing_secret() {
        let mut input = params("client\nremote vpn.example\nkey assets/0-key.pem\n");
        input
            .assets
            .insert("assets/0-key.pem".into(), "PRIVATE-SECRET!!!".into());
        let error = prepare_openvpn(1000, input).err().unwrap();
        assert!(!error.to_string().contains("PRIVATE-SECRET"));
        let mut input = params("client\nremote vpn.example\nkey assets/0-key.pem\n");
        input.assets.insert(
            "assets/0-key.pem".into(),
            base64::engine::general_purpose::STANDARD
                .encode(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nSECRET"),
        );
        assert!(prepare_openvpn(1000, input).is_err());
    }

    #[test]
    fn accepts_management_auth_and_encrypted_key_without_staging_credentials() {
        let mut request = OpenVpnConnectRequest::from(params(
            "client\nremote vpn.example\nauth-user-pass\naskpass\nkey assets/key.pem\n",
        ));
        request.profile.assets.insert(
            "assets/key.pem".into(),
            base64::engine::general_purpose::STANDARD
                .encode(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nENCRYPTED-CONTENT"),
        );
        request.credentials = Some(OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "alice".into(),
                password: "SECRET-AUTH".into(),
            }),
            private_key_passphrase: Some("SECRET-KEY".into()),
        });
        let plan = prepare_openvpn(1000, request).unwrap();
        let staged = crate::openvpn_process::stage_dir(1000, &plan.name);
        let sanitized = plan.sanitized_config(&staged).unwrap();
        assert!(sanitized.config.contains("auth-user-pass\n"));
        assert!(!sanitized.config.contains("SECRET-AUTH"));
        assert!(!sanitized.config.contains("SECRET-KEY"));
        assert_eq!(sanitized.assets.len(), 1);
        assert!(plan.credentials.is_some());
    }

    #[test]
    fn largest_valid_connect_request_fits_one_frame_with_headroom() {
        use net_manager_core::daemon_protocol::{
            encode_line, method, RequestFrame, MAX_FRAME_BYTES,
        };
        use net_manager_core::openvpn_config::{MAX_ASSET_BYTES, MAX_CONFIG_BYTES};
        let mut config = String::from("client\nremote vpn.example\nca assets/a\ncert assets/b\n");
        // Control bytes in comments are the worst case for JSON escaping (6x).
        let comment = format!("#{}\n", "\u{1}".repeat(200));
        while config.len() + comment.len() <= MAX_CONFIG_BYTES {
            config.push_str(&comment);
        }
        let mut input = params(&config);
        for name in ["assets/a", "assets/b"] {
            input.assets.insert(
                name.into(),
                base64::engine::general_purpose::STANDARD.encode(vec![7_u8; MAX_ASSET_BYTES]),
            );
        }
        for index in 0..64_u32 {
            input.routes.push(PolicyRoute {
                destination: format!("10.{index}.0.0/16").parse().unwrap(),
                metric: 5,
                via: None,
            });
        }
        let frame = RequestFrame {
            id: u64::MAX,
            method: method::OPENVPN_CONNECT.into(),
            params: serde_json::to_value(&input).unwrap(),
        };
        let encoded = encode_line(&frame).unwrap().len();
        prepare_openvpn(1000, input.clone()).expect("request is at the validation limits");
        // Credentials (bounded to a few KiB) and asset names must still fit.
        assert!(encoded + 64 * 1024 <= MAX_FRAME_BYTES, "{encoded}");
        // The frame cap is sized for `xray.connect` inline geo assets; the
        // OpenVPN worst case must stay a small fraction of that budget.
        assert!(encoded * 4 <= MAX_FRAME_BYTES, "{encoded}");
        // The asset budget is really exhausted: one more byte is rejected.
        input.assets.insert(
            "assets/b".into(),
            base64::engine::general_purpose::STANDARD.encode(vec![7_u8; MAX_ASSET_BYTES + 1]),
        );
        assert!(prepare_openvpn(1000, input).is_err());
    }

    #[test]
    fn rejects_missing_or_injected_credentials_before_authorization() {
        let mut request =
            OpenVpnConnectRequest::from(params("client\nremote vpn.example\nauth-user-pass\n"));
        request.credentials = Some(OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "alice".into(),
                password: "SECRET\ncommand".into(),
            }),
            private_key_passphrase: None,
        });
        let error = prepare_openvpn(1000, request).err().unwrap();
        assert!(!error.to_string().contains("SECRET"));
        let mut request = OpenVpnConnectRequest::from(params("client\nremote vpn.example\n"));
        request.credentials = Some(OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "alice".into(),
                password: "unused".into(),
            }),
            private_key_passphrase: None,
        });
        assert!(prepare_openvpn(1000, request).is_err());
    }
}
