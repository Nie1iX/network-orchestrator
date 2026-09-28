use net_manager_core::daemon_protocol::{
    AlwaysOnKind, AlwaysOnListResult, AlwaysOnRemoveResult, AlwaysOnResumeResult, AlwaysOnSetResult,
};
use tauri::State;

use crate::state::AppState;

#[cfg(target_os = "linux")]
use net_manager_core::daemon_protocol::{
    method, AlwaysOnDefinition, AlwaysOnRemoveParams, AlwaysOnSetParams, AlwaysOnStaticRoutes,
    WireGuardConnectParams,
};
#[cfg(target_os = "linux")]
use net_manager_core::models::{Profile, TunnelBackend};

#[cfg(target_os = "linux")]
fn build_definition(
    vault: &net_manager_core::config_vault::ConfigVault,
    profile: &Profile,
) -> Result<AlwaysOnDefinition, String> {
    match profile.backend {
        TunnelBackend::WireGuard => {
            use std::io::Read;
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

            if !vault.is_managed_profile_path(&profile.id, &profile.config_path)
                || profile.config_path.to_string_lossy().ends_with(".dpapi")
            {
                return Err("always-on WireGuard requires its own managed config".into());
            }
            let revision = profile
                .config_path
                .parent()
                .ok_or_else(|| "managed WireGuard config is invalid".to_string())?;
            let profile_dir = revision
                .parent()
                .ok_or_else(|| "managed WireGuard config is invalid".to_string())?;
            for path in [vault.root(), profile_dir, revision] {
                if !std::fs::symlink_metadata(path)
                    .is_ok_and(|metadata| metadata.file_type().is_dir())
                {
                    return Err("managed WireGuard config is invalid".into());
                }
            }
            let metadata = std::fs::symlink_metadata(&profile.config_path)
                .map_err(|_| "managed WireGuard config is unavailable".to_string())?;
            if !metadata.file_type().is_file()
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.len() > 256 * 1024
            {
                return Err("managed WireGuard config is invalid".into());
            }
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&profile.config_path)
                .map_err(|_| "managed WireGuard config is unavailable".to_string())?;
            let opened = file
                .metadata()
                .map_err(|_| "managed WireGuard config is unavailable".to_string())?;
            if !opened.file_type().is_file()
                || opened.ino() != metadata.ino()
                || opened.dev() != metadata.dev()
            {
                return Err("managed WireGuard config is invalid".into());
            }
            let mut bytes = Vec::new();
            file.take(256 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "cannot read managed WireGuard config".to_string())?;
            if bytes.len() > 256 * 1024 {
                return Err("managed WireGuard config is too large".into());
            }
            let config = String::from_utf8(bytes)
                .map_err(|_| "managed WireGuard config is not UTF-8".to_string())?;
            Ok(AlwaysOnDefinition::WireGuard(WireGuardConnectParams {
                profile_id: profile.id.clone(),
                config,
                routes: profile.routes.clone(),
            }))
        }
        TunnelBackend::None => {
            let name = profile.interface_name.as_str();
            if name.is_empty()
                || name.len() > 15
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                || profile.routes.is_empty()
            {
                return Err(
                    "always-on static routes require routes and a stable interface name".into(),
                );
            }
            Ok(AlwaysOnDefinition::StaticRoutes(AlwaysOnStaticRoutes {
                profile_id: profile.id.clone(),
                interface_name: name.to_string(),
                routes: profile.routes.clone(),
            }))
        }
        TunnelBackend::OpenVpn | TunnelBackend::Xray => {
            Err("always-on supports only WireGuard and static routes".into())
        }
    }
}

#[cfg(target_os = "linux")]
async fn list_with_client(
    client: &crate::daemon_client::DaemonClient,
) -> Result<AlwaysOnListResult, String> {
    client
        .request(method::ALWAYS_ON_LIST, serde_json::Value::Null)
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))
}

#[cfg(target_os = "linux")]
async fn set_with_client(
    vault: &net_manager_core::config_vault::ConfigVault,
    profile: &Profile,
    client: &crate::daemon_client::DaemonClient,
) -> Result<AlwaysOnSetResult, String> {
    let definition = build_definition(vault, profile)?;
    client
        .request(method::ALWAYS_ON_SET, AlwaysOnSetParams { definition })
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))
}

#[cfg(target_os = "linux")]
async fn remove_with_client(
    client: &crate::daemon_client::DaemonClient,
    kind: AlwaysOnKind,
    profile_id: &str,
) -> Result<AlwaysOnRemoveResult, String> {
    client
        .request(
            method::ALWAYS_ON_REMOVE,
            AlwaysOnRemoveParams {
                kind,
                profile_id: profile_id.to_string(),
            },
        )
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))
}

#[cfg(target_os = "linux")]
async fn resume_with_client(
    client: &crate::daemon_client::DaemonClient,
) -> Result<AlwaysOnResumeResult, String> {
    client
        .request(method::ALWAYS_ON_RESUME, serde_json::Value::Null)
        .await
        .map_err(|err| crate::daemon_client::user_message(&err))
}

#[cfg(target_os = "linux")]
pub(crate) async fn ensure_not_enrolled(
    client: &crate::daemon_client::DaemonClient,
    profile: &Profile,
) -> Result<(), String> {
    let kind = match profile.backend {
        TunnelBackend::WireGuard => AlwaysOnKind::WireGuard,
        TunnelBackend::None => AlwaysOnKind::StaticRoutes,
        TunnelBackend::OpenVpn | TunnelBackend::Xray => return Ok(()),
    };
    let list = list_with_client(client).await?;
    if list
        .profiles
        .iter()
        .any(|item| item.kind == kind && item.profile_id == profile.id)
    {
        return Err("disable always-on before editing or deleting this profile".into());
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn get_always_on_profiles() -> Result<AlwaysOnListResult, String> {
    #[cfg(target_os = "linux")]
    {
        list_with_client(&crate::daemon_client::DaemonClient::system()).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(AlwaysOnListResult {
            profiles: Vec::new(),
            paused: false,
            supported_kinds: Vec::new(),
        })
    }
}

#[tauri::command]
pub(crate) async fn set_always_on_profile(
    id: String,
    state: State<'_, AppState>,
) -> Result<AlwaysOnSetResult, String> {
    #[cfg(target_os = "linux")]
    {
        let profile = crate::state::find_profile(&state.profiles, &id)?;
        set_with_client(
            &state.config_vault,
            &profile,
            &crate::daemon_client::DaemonClient::system(),
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (id, state);
        Err("always-on is available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn remove_always_on_profile(
    kind: AlwaysOnKind,
    profile_id: String,
) -> Result<AlwaysOnRemoveResult, String> {
    #[cfg(target_os = "linux")]
    {
        remove_with_client(
            &crate::daemon_client::DaemonClient::system(),
            kind,
            &profile_id,
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (kind, profile_id);
        Err("always-on is available on Linux only".into())
    }
}

#[tauri::command]
pub(crate) async fn resume_always_on() -> Result<AlwaysOnResumeResult, String> {
    #[cfg(target_os = "linux")]
    {
        resume_with_client(&crate::daemon_client::DaemonClient::system()).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("always-on is available on Linux only".into())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::test_support::unique_dir;
    use net_manager_core::config_vault::ConfigVault;
    use net_manager_core::daemon_protocol::{method, RequestFrame, ResponseFrame};
    use net_manager_core::models::{PolicyRoute, TunnelBackend};
    use serde_json::json;
    use std::fs;
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    #[test]
    fn definition_reads_own_wireguard_vault_config_and_rejects_external_path() {
        let dir = unique_dir("always-on-wg");
        let vault = ConfigVault::new(dir.join("configs"));
        let config = b"[Interface]\nPrivateKey = test-secret\n";
        let stored = vault.store_wireguard_config("wg1", config).unwrap();
        let profile = Profile {
            id: "wg1".into(),
            backend: TunnelBackend::WireGuard,
            config_path: stored.config_path,
            ..Profile::default()
        };
        let definition = build_definition(&vault, &profile).unwrap();
        let AlwaysOnDefinition::WireGuard(params) = definition else {
            panic!("expected WireGuard definition");
        };
        assert_eq!(params.config.as_bytes(), config);
        assert!(!format!("{params:?}").contains("test-secret"));
        let external = Profile {
            config_path: dir.join("outside.conf"),
            ..profile
        };
        assert!(build_definition(&vault, &external).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn static_definition_uses_stable_interface_name_and_saved_routes() {
        let dir = unique_dir("always-on-static");
        let vault = ConfigVault::new(dir.join("configs"));
        let profile = Profile {
            id: "office".into(),
            backend: TunnelBackend::None,
            interface_name: "eth0".into(),
            routes: vec![PolicyRoute {
                destination: "203.0.113.0/24".parse().unwrap(),
                metric: 5,
                via: Some("192.0.2.1".parse().unwrap()),
            }],
            ..Profile::default()
        };
        let AlwaysOnDefinition::StaticRoutes(params) = build_definition(&vault, &profile).unwrap()
        else {
            panic!("expected static definition");
        };
        assert_eq!(params.interface_name, "eth0");
        assert_eq!(params.routes, profile.routes);
        let missing_interface = Profile {
            interface_name: String::new(),
            ..profile
        };
        assert!(build_definition(&vault, &missing_interface).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn typed_rpc_set_list_remove_resume_and_enrollment_guard() {
        let dir = unique_dir("always-on-rpc");
        let socket = dir.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            for expected in [
                method::ALWAYS_ON_SET,
                method::ALWAYS_ON_LIST,
                method::ALWAYS_ON_LIST,
                method::ALWAYS_ON_REMOVE,
                method::ALWAYS_ON_RESUME,
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let hello: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 1024)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                writer
                    .write_all(
                        &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                            hello.id,
                            json!({"protocol":1,"daemonVersion":"test","uid":1000,"capabilities":[]}),
                        ))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                let request: RequestFrame = serde_json::from_slice(
                    &net_manager_core::daemon_protocol::read_frame(&mut reader, 4096)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(request.method, expected);
                let result = match expected {
                    method::ALWAYS_ON_SET => {
                        assert_eq!(request.params["definition"]["kind"], "wireGuard");
                        assert_eq!(request.params["definition"]["profile"]["profileId"], "wg1");
                        assert!(request.params["definition"]["profile"]["config"]
                            .as_str()
                            .unwrap()
                            .contains("test-secret"));
                        assert!(request.params.to_string().find("configPath").is_none());
                        json!({"stored":true,"active":true})
                    }
                    method::ALWAYS_ON_LIST => json!({
                        "profiles":[{"kind":"wireGuard","profileId":"wg1","enabled":true}],
                        "paused":false,
                        "supportedKinds":["wireGuard","staticRoutes"]
                    }),
                    method::ALWAYS_ON_REMOVE => {
                        assert_eq!(
                            request.params,
                            json!({"kind":"wireGuard","profileId":"wg1"})
                        );
                        json!({"removed":true,"disconnected":true})
                    }
                    method::ALWAYS_ON_RESUME => json!({"resumed":true}),
                    _ => unreachable!(),
                };
                writer
                    .write_all(
                        &net_manager_core::daemon_protocol::encode_line(&ResponseFrame::ok(
                            request.id, result,
                        ))
                        .unwrap(),
                    )
                    .await
                    .unwrap();
            }
        });
        let vault = ConfigVault::new(dir.join("configs"));
        let stored = vault
            .store_wireguard_config("wg1", b"[Interface]\nPrivateKey = test-secret\n")
            .unwrap();
        let profile = Profile {
            id: "wg1".into(),
            backend: TunnelBackend::WireGuard,
            config_path: stored.config_path,
            ..Profile::default()
        };
        let client = crate::daemon_client::DaemonClient::new(socket);
        assert!(
            set_with_client(&vault, &profile, &client)
                .await
                .unwrap()
                .stored
        );
        let list = list_with_client(&client).await.unwrap();
        assert_eq!(list.profiles.len(), 1);
        assert!(!serde_json::to_string(&list)
            .unwrap()
            .contains("test-secret"));
        assert!(ensure_not_enrolled(&client, &profile).await.is_err());
        assert!(
            remove_with_client(&client, AlwaysOnKind::WireGuard, "wg1")
                .await
                .unwrap()
                .removed
        );
        assert!(resume_with_client(&client).await.unwrap().resumed);
        server.await.unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
