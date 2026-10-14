//! The helper's own methods. Executors register here as they are
//! implemented; the capability list stays honest and everything else is
//! refused as unsupported.

use crate::peer::Peer;
use crate::server::Handler;
use crate::xray::{Error, XrayExecutor};
use net_manager_core::daemon_protocol::{
    from_value, method, CleanupResult, ErrorCode, OwnedEntry, OwnedListResult, OwnedResource,
    OwnedState, RequestFrame, ResponseFrame, XrayConnectParams, XrayProcessResource,
    XrayProfileParams,
};
use serde::Serialize;
use std::sync::Arc;

pub struct HelperService {
    xray: Arc<XrayExecutor>,
}

impl HelperService {
    pub fn new(xray: Arc<XrayExecutor>) -> Self {
        Self { xray }
    }
}

fn ok<T: Serialize>(id: u64, value: &T) -> ResponseFrame {
    match serde_json::to_value(value) {
        Ok(value) => ResponseFrame::ok(id, value),
        Err(err) => ResponseFrame::error(id, ErrorCode::Internal, err.to_string()),
    }
}

fn failure(id: u64, error: Error) -> ResponseFrame {
    let code = match &error {
        Error::Invalid(_) => ErrorCode::InvalidParams,
        Error::Conflict(_) => ErrorCode::Conflict,
        Error::NotFound(_) => ErrorCode::NotFound,
        Error::Unavailable(_) => ErrorCode::Unavailable,
    };
    ResponseFrame::error(id, code, error.to_string())
}

fn owner_of(profile_id: &str) -> String {
    format!("xray:{profile_id}")
}

impl Handler for HelperService {
    fn capabilities(&self) -> Vec<String> {
        [
            method::OWNED_LIST,
            method::RECOVERY_CLEANUP,
            method::XRAY_CONNECT,
            method::XRAY_DISCONNECT,
            method::XRAY_STATUS,
        ]
        .iter()
        .map(|name| name.to_string())
        .collect()
    }

    fn handle(&self, peer: &Peer, request: RequestFrame) -> ResponseFrame {
        let id = request.id;
        match request.method.as_str() {
            method::OWNED_LIST => {
                let owners = self
                    .xray
                    .owned()
                    .map(|record| OwnedEntry {
                        owner: owner_of(&record.profile_id),
                        state: if record.pid == 0 {
                            OwnedState::Applying
                        } else {
                            OwnedState::Applied
                        },
                        resources: vec![OwnedResource::XrayProcess(XrayProcessResource {
                            name: record.interface,
                            index: 0,
                            owner_marker: record.profile_id,
                            transport_mark: 0,
                            full: None,
                        })],
                    })
                    .into_iter()
                    .collect();
                ok(id, &OwnedListResult { owners })
            }
            method::RECOVERY_CLEANUP => {
                let owner = self.xray.owned().map(|record| owner_of(&record.profile_id));
                // Only a tunnel nobody is running is "recovered"; a live one
                // is torn down by `xray.disconnect`.
                let mut result = CleanupResult::default();
                match self.xray.recover() {
                    Ok(true) => result.removed_owners.extend(owner),
                    Ok(false) => {}
                    Err(_) => result.failed.extend(owner),
                }
                ok(id, &result)
            }
            method::XRAY_CONNECT => match from_value::<XrayConnectParams>(request.params) {
                Ok(params) => match self.xray.connect(peer.uid, params) {
                    Ok(result) => ok(id, &result),
                    Err(error) => failure(id, error),
                },
                Err(_) => ResponseFrame::error(id, ErrorCode::InvalidParams, "invalid parameters"),
            },
            method::XRAY_STATUS => match from_value::<XrayProfileParams>(request.params) {
                Ok(params) => ok(id, &self.xray.status(peer.uid, &params.profile_id)),
                Err(_) => ResponseFrame::error(id, ErrorCode::InvalidParams, "invalid parameters"),
            },
            method::XRAY_DISCONNECT => match from_value::<XrayProfileParams>(request.params) {
                Ok(params) => match self.xray.disconnect(peer.uid, &params.profile_id) {
                    Ok(result) => ok(id, &result),
                    Err(error) => failure(id, error),
                },
                Err(_) => ResponseFrame::error(id, ErrorCode::InvalidParams, "invalid parameters"),
            },
            _ => ResponseFrame::error(
                id,
                ErrorCode::UnsupportedMethod,
                "this method is not available in the macOS helper yet",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Journal;
    use crate::sysexec::SystemRunner;
    use crate::xray::{Platform, Process, SpawnSpec, TunDevice};
    use serde_json::{json, Value};
    use std::io;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    /// Never reaches the machine: every device or launch attempt is refused.
    struct Denied;
    impl Platform for Denied {
        fn open_tun(&self, _: u32) -> io::Result<Box<dyn TunDevice>> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
        fn verify_xray(&self, _: u32, _: Option<&str>) -> Result<PathBuf, Error> {
            Err(Error::Unavailable(
                "Install Xray to start this connection".into(),
            ))
        }
        fn spawn(&self, _: &dyn TunDevice, _: &SpawnSpec) -> io::Result<Box<dyn Process>> {
            unreachable!()
        }
        fn resolve(&self, _: &str) -> Vec<Ipv4Addr> {
            vec![]
        }
        fn is_our_xray(&self, _: u32) -> bool {
            false
        }
        fn kill(&self, _: u32) {}
    }

    fn service() -> (HelperService, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let executor = XrayExecutor::new(
            Box::new(Denied),
            Box::new(SystemRunner),
            Journal::new(dir.path()),
            dir.path().join("xray.log"),
        );
        (HelperService::new(Arc::new(executor)), dir)
    }

    fn call(service: &HelperService, name: &str, params: Value) -> ResponseFrame {
        service.handle(
            &Peer { uid: 501, pid: 1 },
            RequestFrame {
                id: 9,
                method: name.into(),
                params,
            },
        )
    }

    #[test]
    fn owned_list_and_cleanup_are_empty_without_a_tunnel() {
        let (service, _dir) = service();
        assert_eq!(
            call(&service, method::OWNED_LIST, Value::Null)
                .outcome
                .unwrap()["owners"],
            json!([])
        );
        assert!(call(&service, method::RECOVERY_CLEANUP, Value::Null)
            .outcome
            .is_ok());
    }

    #[test]
    fn only_xray_tunnels_are_advertised_and_served() {
        let (service, _dir) = service();
        let capabilities = service.capabilities();
        for name in [
            method::XRAY_CONNECT,
            method::XRAY_DISCONNECT,
            method::XRAY_STATUS,
        ] {
            assert!(capabilities.iter().any(|c| c == name), "{name}");
        }
        assert!(!capabilities.iter().any(|name| name.starts_with("openvpn")));
        for name in [
            method::OPENVPN_CONNECT,
            method::WIREGUARD_CONNECT,
            method::ROUTES_APPLY,
            method::XRAY_INSTALL,
        ] {
            let error = call(&service, name, Value::Null).outcome.unwrap_err();
            assert_eq!(error.code, ErrorCode::UnsupportedMethod, "{name}");
        }
    }

    #[test]
    fn xray_methods_validate_params_and_map_errors() {
        let (service, _dir) = service();
        let error = call(&service, method::XRAY_CONNECT, json!({"nope": 1}))
            .outcome
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
        let error = call(
            &service,
            method::XRAY_CONNECT,
            json!({"profileId": "p", "config": "{\"outbounds\":[]}"}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(error.message, "Install Xray to start this connection");
        // Status of nothing is a stopped profile, disconnect a no-op.
        let status = call(&service, method::XRAY_STATUS, json!({"profileId": "p"}))
            .outcome
            .unwrap();
        assert_eq!(status["state"], "stopped");
        let stopped = call(&service, method::XRAY_DISCONNECT, json!({"profileId": "p"}))
            .outcome
            .unwrap();
        assert_eq!(stopped["stopped"], false);
    }
}
