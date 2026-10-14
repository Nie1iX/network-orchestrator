//! The helper's own methods. Executors register here as they are
//! implemented; the capability list stays honest and everything else is
//! refused as unsupported.

use crate::journal::Record;
use crate::openvpn::OpenVpnExecutor;
use crate::peer::Peer;
use crate::server::Handler;
use crate::wireguard::WireGuardExecutor;
use crate::xray::{Error, XrayExecutor};
use net_manager_core::daemon_protocol::{
    from_value, method, CleanupResult, ErrorCode, OpenVpnConnectRequest, OpenVpnProcessResource,
    OpenVpnProfileParams, OwnedEntry, OwnedListResult, OwnedResource, OwnedState, RequestFrame,
    ResponseFrame, WireGuardConnectParams, WireGuardLinkResource, WireGuardProfileParams,
    XrayConnectParams, XrayProcessResource, XrayProfileParams,
};
use net_manager_core::models::TunnelRole;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

pub struct HelperService {
    xray: Arc<XrayExecutor>,
    wireguard: Arc<WireGuardExecutor>,
    openvpn: Arc<OpenVpnExecutor>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Xray,
    WireGuard,
    OpenVpn,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Xray => "Xray",
            Kind::WireGuard => "WireGuard",
            Kind::OpenVpn => "OpenVPN",
        }
    }
}

impl HelperService {
    pub fn new(
        xray: Arc<XrayExecutor>,
        wireguard: Arc<WireGuardExecutor>,
        openvpn: Arc<OpenVpnExecutor>,
    ) -> Self {
        Self {
            xray,
            wireguard,
            openvpn,
        }
    }

    /// Tunnels of different kinds run together, but only one of them may be
    /// the primary: two would fight over the default route and the system DNS.
    /// Secondary tunnels carry only their own networks and never conflict.
    fn primary_held_by_another(&self, kind: Kind, role: TunnelRole) -> Option<Kind> {
        if role != TunnelRole::Primary {
            return None;
        }
        [
            (Kind::Xray, self.xray.holds_primary()),
            (Kind::WireGuard, self.wireguard.holds_primary()),
            (Kind::OpenVpn, self.openvpn.holds_primary()),
        ]
        .into_iter()
        .find(|(other, holds)| *other != kind && *holds)
        .map(|(other, _)| other)
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

fn invalid_params(id: u64) -> ResponseFrame {
    ResponseFrame::error(id, ErrorCode::InvalidParams, "invalid parameters")
}

/// Decode params, run `action`, answer.
fn call<P: DeserializeOwned, R: Serialize>(
    request: RequestFrame,
    action: impl FnOnce(P) -> Result<R, Error>,
) -> ResponseFrame {
    let id = request.id;
    match from_value::<P>(request.params) {
        Ok(params) => match action(params) {
            Ok(result) => ok(id, &result),
            Err(error) => failure(id, error),
        },
        Err(_) => invalid_params(id),
    }
}

fn owner_of(kind: Kind, profile_id: &str) -> String {
    let prefix = match kind {
        Kind::Xray => "xray",
        Kind::WireGuard => "wireguard",
        Kind::OpenVpn => "openvpn",
    };
    format!("{prefix}:{profile_id}")
}

fn owned_entry(kind: Kind, record: Record) -> OwnedEntry {
    let owner_marker = record.profile_id.clone();
    let name = record.interface.clone();
    let resource = match kind {
        Kind::Xray => OwnedResource::XrayProcess(XrayProcessResource {
            name,
            index: 0,
            owner_marker,
            transport_mark: 0,
            full: None,
        }),
        Kind::WireGuard => OwnedResource::WireGuardLink(WireGuardLinkResource {
            name,
            index: 0,
            owner_marker,
            full: None,
            warnings: Vec::new(),
        }),
        Kind::OpenVpn => OwnedResource::OpenVpnProcess(OpenVpnProcessResource {
            name,
            owner_marker,
            transport_mark: None,
            full: None,
        }),
    };
    OwnedEntry {
        owner: owner_of(kind, &record.profile_id),
        state: if record.pid == 0 {
            OwnedState::Applying
        } else {
            OwnedState::Applied
        },
        resources: vec![resource],
    }
}

impl Handler for HelperService {
    fn capabilities(&self) -> Vec<String> {
        [
            method::OWNED_LIST,
            method::RECOVERY_CLEANUP,
            method::XRAY_CONNECT,
            method::XRAY_DISCONNECT,
            method::XRAY_STATUS,
            method::WIREGUARD_CONNECT,
            method::WIREGUARD_DISCONNECT,
            method::WIREGUARD_STATUS,
            method::OPENVPN_CONNECT,
            method::OPENVPN_DISCONNECT,
            method::OPENVPN_STATUS,
        ]
        .iter()
        .map(|name| name.to_string())
        .collect()
    }

    fn handle(&self, peer: &Peer, request: RequestFrame) -> ResponseFrame {
        let id = request.id;
        let uid = peer.uid;
        let conflict = |kind: Kind, role: TunnelRole| {
            self.primary_held_by_another(kind, role).map(|other| {
                Error::Conflict(format!(
                    "the {} connection is already the primary one; make one of them secondary or disconnect it",
                    other.label()
                ))
            })
        };
        match request.method.as_str() {
            method::OWNED_LIST => {
                let owners = [
                    (Kind::Xray, self.xray.owned()),
                    (Kind::WireGuard, self.wireguard.owned()),
                    (Kind::OpenVpn, self.openvpn.owned()),
                ]
                .into_iter()
                .filter_map(|(kind, record)| record.map(|record| owned_entry(kind, record)))
                .collect();
                ok(id, &OwnedListResult { owners })
            }
            method::RECOVERY_CLEANUP => {
                // Only a tunnel nobody is running is "recovered"; a live one
                // is torn down by its own disconnect.
                let mut result = CleanupResult::default();
                let owner = |kind: Kind, record: Option<Record>| {
                    record.map(|record| owner_of(kind, &record.profile_id))
                };
                for (kind, before, outcome) in [
                    (Kind::Xray, self.xray.owned(), self.xray.recover()),
                    (
                        Kind::WireGuard,
                        self.wireguard.owned(),
                        self.wireguard.recover(),
                    ),
                    (Kind::OpenVpn, self.openvpn.owned(), self.openvpn.recover()),
                ] {
                    match outcome {
                        Ok(true) => result.removed_owners.extend(owner(kind, before)),
                        Ok(false) => {}
                        Err(_) => result.failed.extend(owner(kind, before)),
                    }
                }
                ok(id, &result)
            }
            method::XRAY_CONNECT => call(request, |params: XrayConnectParams| {
                if let Some(error) = conflict(Kind::Xray, params.role) {
                    return Err(error);
                }
                self.xray.connect(uid, params)
            }),
            method::XRAY_STATUS => call(request, |params: XrayProfileParams| {
                Ok(self.xray.status(uid, &params.profile_id))
            }),
            method::XRAY_DISCONNECT => call(request, |params: XrayProfileParams| {
                self.xray.disconnect(uid, &params.profile_id)
            }),
            method::WIREGUARD_CONNECT => call(request, |params: WireGuardConnectParams| {
                if let Some(error) = conflict(Kind::WireGuard, params.role) {
                    return Err(error);
                }
                self.wireguard.connect(uid, params)
            }),
            method::WIREGUARD_STATUS => call(request, |params: WireGuardProfileParams| {
                Ok(self.wireguard.status(uid, &params.profile_id))
            }),
            method::WIREGUARD_DISCONNECT => call(request, |params: WireGuardProfileParams| {
                self.wireguard.disconnect(uid, &params.profile_id)
            }),
            method::OPENVPN_CONNECT => call(request, |params: OpenVpnConnectRequest| {
                if let Some(error) = conflict(Kind::OpenVpn, params.profile.role) {
                    return Err(error);
                }
                self.openvpn.connect(uid, params)
            }),
            method::OPENVPN_STATUS => call(request, |params: OpenVpnProfileParams| {
                Ok(self.openvpn.status(uid, &params.profile_id))
            }),
            method::OPENVPN_DISCONNECT => call(request, |params: OpenVpnProfileParams| {
                self.openvpn.disconnect(uid, &params.profile_id)
            }),
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
    use crate::openvpn::{OvpnPlatform, SpawnSpec as OvpnSpawn};
    use crate::sysexec::fake::FakeRunner;
    use crate::wg_engine::PacketIo;
    use crate::wireguard::WgPlatform;
    use crate::xray::{Platform, Process, SpawnSpec, TunDevice};
    use base64::Engine as _;
    use serde_json::{json, Value};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixDatagram;
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

    struct DeniedWg;
    impl WgPlatform for DeniedWg {
        fn create_tun(&self, _: u32) -> io::Result<(Box<dyn TunDevice>, Box<dyn PacketIo>)> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
        fn resolve(&self, _: &str) -> Option<SocketAddr> {
            None
        }
    }

    struct DeniedOvpn;
    impl OvpnPlatform for DeniedOvpn {
        fn stage_binary(&self) -> io::Result<PathBuf> {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
        fn free_unit(&self) -> io::Result<String> {
            Ok("utun12".into())
        }
        fn spawn(&self, _: &OvpnSpawn) -> io::Result<Box<dyn Process>> {
            unreachable!()
        }
        fn resolve(&self, _: &str) -> Vec<IpAddr> {
            vec![]
        }
        fn is_our_openvpn(&self, _: u32) -> bool {
            false
        }
        fn kill(&self, _: u32) {}
    }

    /// A WireGuard platform that works, to have a live tunnel in the way.
    struct FakeTun;
    impl TunDevice for FakeTun {
        fn name(&self) -> &str {
            "utun11"
        }
    }
    struct FakeIo(UnixDatagram);
    impl PacketIo for FakeIo {
        fn raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.recv(buf)
        }
        fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            self.0.send(packet).map(|_| ())
        }
    }
    struct WorkingWg;
    impl WgPlatform for WorkingWg {
        fn create_tun(&self, _: u32) -> io::Result<(Box<dyn TunDevice>, Box<dyn PacketIo>)> {
            let (engine_side, far) = UnixDatagram::pair()?;
            engine_side.set_nonblocking(true)?;
            std::mem::forget(far);
            Ok((Box::new(FakeTun), Box::new(FakeIo(engine_side))))
        }
        fn resolve(&self, _: &str) -> Option<SocketAddr> {
            Some("203.0.113.7:51820".parse().unwrap())
        }
    }

    fn build(wg: Box<dyn WgPlatform>, runner: FakeRunner) -> (HelperService, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let xray = XrayExecutor::new(
            Box::new(Denied),
            Box::new(FakeRunner::default()),
            Journal::new(dir.path()),
            dir.path().join("xray.log"),
        );
        let wireguard = WireGuardExecutor::new(
            wg,
            Box::new(runner),
            Journal::named(dir.path(), "wireguard.json"),
            dir.path().join("resolver"),
        );
        let openvpn = OpenVpnExecutor::new(
            Box::new(DeniedOvpn),
            Box::new(FakeRunner::default()),
            Journal::named(dir.path(), "openvpn.json"),
            dir.path().join("openvpn"),
            dir.path().join("resolver"),
        );
        (
            HelperService::new(Arc::new(xray), Arc::new(wireguard), Arc::new(openvpn)),
            dir,
        )
    }

    fn service() -> (HelperService, tempfile::TempDir) {
        build(Box::new(DeniedWg), FakeRunner::default())
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

    fn wg_config() -> String {
        let key = |b: u8| base64::engine::general_purpose::STANDARD.encode([b; 32]);
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.7.0.2/32\n[Peer]\nPublicKey = {}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.7.0.0/24\n",
            key(1),
            key(2)
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
    fn the_three_tunnel_kinds_are_advertised_and_the_rest_is_refused() {
        let (service, _dir) = service();
        let capabilities = service.capabilities();
        for name in [
            method::XRAY_CONNECT,
            method::XRAY_DISCONNECT,
            method::XRAY_STATUS,
            method::WIREGUARD_CONNECT,
            method::WIREGUARD_DISCONNECT,
            method::WIREGUARD_STATUS,
            method::OPENVPN_CONNECT,
            method::OPENVPN_DISCONNECT,
            method::OPENVPN_STATUS,
        ] {
            assert!(capabilities.iter().any(|c| c == name), "{name}");
        }
        for name in [
            method::ROUTES_APPLY,
            method::XRAY_INSTALL,
            method::OPENVPN_PROBE,
            method::OPENVPN_PLAN,
            method::TAILSCALE_UP,
        ] {
            let error = call(&service, name, Value::Null).outcome.unwrap_err();
            assert_eq!(error.code, ErrorCode::UnsupportedMethod, "{name}");
            assert!(!capabilities.iter().any(|c| c == name), "{name}");
        }
    }

    #[test]
    fn every_tunnel_method_validates_params_and_maps_errors() {
        let (service, _dir) = service();
        for name in [
            method::XRAY_CONNECT,
            method::WIREGUARD_CONNECT,
            method::OPENVPN_CONNECT,
        ] {
            let error = call(&service, name, json!({"nope": 1}))
                .outcome
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidParams, "{name}");
        }
        // Xray without an install, WireGuard without a usable config.
        let error = call(
            &service,
            method::XRAY_CONNECT,
            json!({"profileId": "p", "config": "{\"outbounds\":[]}"}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unavailable);
        let error = call(
            &service,
            method::WIREGUARD_CONNECT,
            json!({"profileId": "p", "config": "garbage"}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
        assert!(!error.message.contains("garbage"));
        // Status of nothing is a stopped profile, disconnect a no-op.
        for (status, disconnect, key) in [
            (method::XRAY_STATUS, method::XRAY_DISCONNECT, "profileId"),
            (
                method::WIREGUARD_STATUS,
                method::WIREGUARD_DISCONNECT,
                "profileId",
            ),
            (
                method::OPENVPN_STATUS,
                method::OPENVPN_DISCONNECT,
                "profileId",
            ),
        ] {
            let state = call(&service, status, json!({ key: "p" })).outcome.unwrap();
            assert_eq!(state["state"], "stopped", "{status}");
            let stopped = call(&service, disconnect, json!({ key: "p" }))
                .outcome
                .unwrap();
            assert_eq!(stopped["stopped"], false, "{disconnect}");
        }
    }

    #[test]
    fn a_running_tunnel_blocks_the_other_kinds_and_is_listed() {
        let runner = FakeRunner::default();
        runner.reply(
            "route -n get default",
            "gateway: 192.168.1.1\n interface: en0\n",
        );
        let (service, _dir) = build(Box::new(WorkingWg), runner);
        let connected = call(
            &service,
            method::WIREGUARD_CONNECT,
            json!({"profileId": "wg", "config": wg_config()}),
        );
        assert!(connected.outcome.is_ok(), "{connected:?}");

        for (name, params) in [
            (
                method::XRAY_CONNECT,
                json!({"profileId": "x", "config": "{}"}),
            ),
            (
                method::OPENVPN_CONNECT,
                json!({"profileId": "o", "config": "client\nremote a.example\n", "assets": {}}),
            ),
        ] {
            let error = call(&service, name, params).outcome.unwrap_err();
            assert_eq!(error.code, ErrorCode::Conflict, "{name}");
            assert!(error.message.contains("WireGuard"), "{}", error.message);
            assert!(error.message.contains("primary"), "{}", error.message);
        }
        let owners = call(&service, method::OWNED_LIST, Value::Null)
            .outcome
            .unwrap();
        assert_eq!(owners["owners"][0]["owner"], "wireguard:wg");
        assert_eq!(owners["owners"][0]["resources"][0]["kind"], "wireGuardLink");

        let stopped = call(
            &service,
            method::WIREGUARD_DISCONNECT,
            json!({"profileId": "wg"}),
        )
        .outcome
        .unwrap();
        assert_eq!(stopped["stopped"], true);
        // Free again: the other kind gets as far as its own validation.
        let error = call(
            &service,
            method::XRAY_CONNECT,
            json!({"profileId": "x", "config": "{}"}),
        )
        .outcome
        .unwrap_err();
        assert_ne!(error.code, ErrorCode::Conflict);
    }

    #[test]
    fn secondary_tunnels_never_conflict_and_only_one_primary_may_exist() {
        let runner = FakeRunner::default();
        runner.reply(
            "route -n get default",
            "gateway: 192.168.1.1\n interface: en0\n",
        );
        let (service, _dir) = build(Box::new(WorkingWg), runner);
        // A secondary WireGuard is up (it carries one network).
        let up = call(
            &service,
            method::WIREGUARD_CONNECT,
            json!({"profileId": "wg", "config": wg_config(), "role": "secondary",
                   "routes": [{"destination": "10.7.0.0/24", "metric": 5}]}),
        );
        assert!(up.outcome.is_ok(), "{up:?}");
        // A primary of another kind is allowed next to it: it gets as far as
        // its own checks (no Xray install / no bundled OpenVPN here).
        for (name, params) in [
            (
                method::XRAY_CONNECT,
                json!({"profileId": "x", "config": "{}"}),
            ),
            (
                method::OPENVPN_CONNECT,
                json!({"profileId": "o", "config": "client\nremote a.example\n", "assets": {}}),
            ),
        ] {
            let error = call(&service, name, params).outcome.unwrap_err();
            assert_ne!(error.code, ErrorCode::Conflict, "{name}: {}", error.message);
        }
        call(
            &service,
            method::WIREGUARD_DISCONNECT,
            json!({"profileId": "wg"}),
        );
        // Now WireGuard is the primary: another primary conflicts, a secondary does not.
        assert!(call(
            &service,
            method::WIREGUARD_CONNECT,
            json!({"profileId": "wg", "config": wg_config()})
        )
        .outcome
        .is_ok());
        let error = call(
            &service,
            method::XRAY_CONNECT,
            json!({"profileId": "x", "config": "{}"}),
        )
        .outcome
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        let error = call(
            &service,
            method::XRAY_CONNECT,
            json!({"profileId": "x", "config": "{}", "role": "secondary",
                   "routes": [{"destination": "10.9.0.0/16", "metric": 5}]}),
        )
        .outcome
        .unwrap_err();
        assert_ne!(error.code, ErrorCode::Conflict);
    }
}
