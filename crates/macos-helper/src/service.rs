//! The helper's own methods. Tunnel executors register here as they are
//! implemented; until then the capability list stays honest and everything
//! else is refused as unsupported.

use crate::peer::Peer;
use crate::server::Handler;
use net_manager_core::daemon_protocol::{
    method, CleanupResult, ErrorCode, OwnedListResult, RequestFrame, ResponseFrame,
};
use serde::Serialize;

#[derive(Default)]
pub struct HelperService;

fn ok<T: Serialize>(id: u64, value: &T) -> ResponseFrame {
    match serde_json::to_value(value) {
        Ok(value) => ResponseFrame::ok(id, value),
        Err(err) => ResponseFrame::error(id, ErrorCode::Internal, err.to_string()),
    }
}

impl Handler for HelperService {
    fn capabilities(&self) -> Vec<String> {
        [method::OWNED_LIST, method::RECOVERY_CLEANUP]
            .iter()
            .map(|name| name.to_string())
            .collect()
    }

    fn handle(&self, _peer: &Peer, request: RequestFrame) -> ResponseFrame {
        match request.method.as_str() {
            // No executor owns anything yet, so there is nothing to list or clean.
            method::OWNED_LIST => ok(request.id, &OwnedListResult { owners: Vec::new() }),
            method::RECOVERY_CLEANUP => ok(request.id, &CleanupResult::default()),
            _ => ResponseFrame::error(
                request.id,
                ErrorCode::UnsupportedMethod,
                "this method is not available in the macOS helper yet",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn call(name: &str) -> ResponseFrame {
        HelperService.handle(
            &Peer { uid: 501, pid: 1 },
            RequestFrame {
                id: 9,
                method: name.into(),
                params: Value::Null,
            },
        )
    }

    #[test]
    fn owned_list_and_cleanup_are_empty() {
        assert_eq!(
            call(method::OWNED_LIST).outcome.unwrap()["owners"],
            serde_json::json!([])
        );
        assert!(call(method::RECOVERY_CLEANUP).outcome.is_ok());
    }

    #[test]
    fn tunnel_methods_are_not_advertised_or_served() {
        let capabilities = HelperService.capabilities();
        assert!(!capabilities.iter().any(|name| name.starts_with("openvpn")));
        for name in [
            method::OPENVPN_CONNECT,
            method::WIREGUARD_CONNECT,
            method::ROUTES_APPLY,
        ] {
            let error = call(name).outcome.unwrap_err();
            assert_eq!(error.code, ErrorCode::UnsupportedMethod);
        }
    }
}
