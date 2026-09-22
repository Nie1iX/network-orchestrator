//! Wire protocol between the app and `network-orchestrator-daemon`.
//!
//! Newline-delimited JSON over a unix socket. Every request is a
//! [`RequestFrame`]; the daemon answers with a [`ResponseFrame`] carrying the
//! same `id`, and pushes [`EventFrame`]s to subscribed connections. Params
//! and results are typed per method but travel as raw JSON inside the frame,
//! so an unknown method still parses and can be answered with
//! `unsupportedMethod`.

use crate::models::AppliedRoute;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_SOCKET_PATH: &str = "/run/network-orchestrator/daemon.sock";
pub const SOCKET_ENV: &str = "NETWORK_ORCHESTRATOR_SOCKET";
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_ROUTES_PER_REQUEST: usize = 8192;
pub const MAX_OWNER_BYTES: usize = 128;
pub const HELLO_TIMEOUT_SECS: u64 = 5;
pub const MAX_CONNECTIONS: usize = 64;

pub mod method {
    pub const HELLO: &str = "hello";
    pub const ROUTES_APPLY: &str = "routes.apply";
    pub const ROUTES_REMOVE: &str = "routes.remove";
    pub const LINK_SET_STATE: &str = "link.set_state";
    pub const OWNED_LIST: &str = "owned.list";
    pub const RECOVERY_CLEANUP: &str = "recovery.cleanup";
    pub const SUBSCRIBE: &str = "subscribe";

    /// Methods reported in `hello.capabilities` (everything but `hello`).
    pub const CAPABILITIES: [&str; 6] = [
        ROUTES_APPLY,
        ROUTES_REMOVE,
        LINK_SET_STATE,
        OWNED_LIST,
        RECOVERY_CLEANUP,
        SUBSCRIBE,
    ];
}

pub mod event {
    pub const OWNED_CHANGED: &str = "owned.changed";
    /// Sent when a subscriber missed events; the client must re-read state.
    pub const RESYNC: &str = "resync";
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestFrame {
    pub id: u64,
    pub method: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
}

/// `{"id","ok":true,"result"}` or `{"id","ok":false,"error"}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RawResponse", into = "RawResponse")]
pub struct ResponseFrame {
    pub id: u64,
    pub outcome: Result<Value, ErrorBody>,
}

impl ResponseFrame {
    pub fn ok(id: u64, result: Value) -> Self {
        Self {
            id,
            outcome: Ok(result),
        }
    }

    pub fn error(id: u64, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            id,
            outcome: Err(ErrorBody {
                code,
                message: message.into(),
            }),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RawResponse {
    id: u64,
    ok: bool,
    // `Some(Value::Null)` still serializes as `"result":null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<ErrorBody>,
}

impl TryFrom<RawResponse> for ResponseFrame {
    type Error = String;

    fn try_from(raw: RawResponse) -> Result<Self, String> {
        let outcome = match (raw.ok, raw.error) {
            (true, _) => Ok(raw.result.unwrap_or(Value::Null)),
            (false, Some(error)) => Err(error),
            (false, None) => return Err("error response without an error body".into()),
        };
        Ok(Self {
            id: raw.id,
            outcome,
        })
    }
}

impl From<ResponseFrame> for RawResponse {
    fn from(frame: ResponseFrame) -> Self {
        match frame.outcome {
            Ok(result) => Self {
                id: frame.id,
                ok: true,
                result: Some(result),
                error: None,
            },
            Err(error) => Self {
                id: frame.id,
                ok: false,
                result: None,
                error: Some(error),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    HandshakeRequired,
    ProtocolMismatch,
    UnsupportedMethod,
    InvalidParams,
    FrameTooLarge,
    Busy,
    NotAuthorized,
    AuthorizationDismissed,
    Conflict,
    NotFound,
    Unavailable,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventFrame {
    pub event: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

impl EventFrame {
    pub fn new(event: &str, data: Value) -> Self {
        Self {
            event: event.to_string(),
            data,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HelloParams {
    pub protocol: u32,
    pub client: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HelloResult {
    pub protocol: u32,
    pub daemon_version: String,
    pub uid: u32,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoutesApplyParams {
    pub owner: String,
    pub routes: Vec<AppliedRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoutesApplyResult {
    pub applied: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnerParams {
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RoutesRemoveResult {
    pub removed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinkSetStateParams {
    pub name: String,
    pub up: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OwnedState {
    /// Write-ahead record: netlink changes may be partially applied.
    Applying,
    Applied,
    /// Teardown failed; the listed resources may still exist.
    Stale,
}

/// One resource the daemon created for an owner. Tagged by `kind` so later
/// stages can add links, rules, DNS or processes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum OwnedResource {
    Route(AppliedRoute),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnedEntry {
    pub owner: String,
    pub state: OwnedState,
    pub resources: Vec<OwnedResource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnedListResult {
    pub owners: Vec<OwnedEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CleanupResult {
    pub removed_owners: Vec<String>,
    /// Owners whose teardown failed; they stay listed as `stale`.
    pub failed: Vec<String>,
}

/// Payload of the `owned.changed` event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnedChanged {
    pub owner: String,
}

/// Decode typed params/results; malformed input is `InvalidData`.
pub fn from_value<T: DeserializeOwned>(value: Value) -> io::Result<T> {
    serde_json::from_value(value).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// Serialize one frame as a single JSON line terminated by `\n`.
pub fn encode_line<T: Serialize>(frame: &T) -> io::Result<Vec<u8>> {
    let mut line =
        serde_json::to_vec(frame).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    line.push(b'\n');
    Ok(line)
}

/// Read one `\n`-terminated frame (without the newline).
///
/// - `Ok(None)` on a clean EOF between frames;
/// - `InvalidData` as soon as the frame grows past `max` bytes, without
///   waiting for the rest of it;
/// - `UnexpectedEof` if the peer closes mid-frame.
pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed in the middle of a frame",
                ))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let chunk = &available[..newline.unwrap_or(available.len())];
        if line.len() + chunk.len() > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame exceeds {max} bytes"),
            ));
        }
        line.extend_from_slice(chunk);
        let consumed = chunk.len() + usize::from(newline.is_some());
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AppliedRoute;
    use serde::de::DeserializeOwned;
    use serde_json::{json, Value};
    use std::time::Duration;
    use tokio::io::{AsyncWriteExt, BufReader};

    /// Parse `text` into `T`, serialize it back and require the exact same
    /// JSON value (field order aside).
    fn round_trip<T: Serialize + DeserializeOwned>(text: &str) -> T {
        let original: Value = serde_json::from_str(text).unwrap();
        let typed: T = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(serde_json::to_value(&typed).unwrap(), original, "{text}");
        typed
    }

    fn request<P: Serialize + DeserializeOwned>(text: &str) -> (RequestFrame, P) {
        let frame: RequestFrame = round_trip(text);
        let params: P = from_value(frame.params.clone()).unwrap();
        assert_eq!(serde_json::to_value(&params).unwrap(), frame.params);
        (frame, params)
    }

    fn ok_response<R: Serialize + DeserializeOwned>(text: &str) -> (u64, R) {
        let frame: ResponseFrame = round_trip(text);
        let value = frame.outcome.clone().expect("ok response");
        let result: R = from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&result).unwrap(), value);
        (frame.id, result)
    }

    fn error_response(text: &str) -> (u64, ErrorBody) {
        let frame: ResponseFrame = round_trip(text);
        (frame.id, frame.outcome.expect_err("error response"))
    }

    #[test]
    fn golden_hello() {
        let (frame, params): (_, HelloParams) = request(
            r#"{"id":1,"method":"hello","params":{"protocol":1,"client":"net-manager-app/0.1.1"}}"#,
        );
        assert_eq!(frame.method, method::HELLO);
        assert_eq!(params.protocol, PROTOCOL_VERSION);
        assert_eq!(params.client, "net-manager-app/0.1.1");

        let (id, result): (_, HelloResult) = ok_response(
            r#"{"id":1,"ok":true,"result":{"protocol":1,"daemonVersion":"0.1.1","uid":1000,
              "capabilities":["routes.apply","routes.remove","link.set_state","owned.list","recovery.cleanup","subscribe"]}}"#,
        );
        assert_eq!(id, 1);
        assert_eq!(result.uid, 1000);
        assert_eq!(result.daemon_version, "0.1.1");
        assert_eq!(result.capabilities, method::CAPABILITIES);

        let (_, error) = error_response(
            r#"{"id":1,"ok":false,"error":{"code":"protocolMismatch","message":"daemon speaks protocol 1, client 2"}}"#,
        );
        assert_eq!(error.code, ErrorCode::ProtocolMismatch);
    }

    #[test]
    fn golden_routes_apply() {
        let (frame, params): (_, RoutesApplyParams) = request(
            r#"{"id":2,"method":"routes.apply","params":{"owner":"static-office","routes":[
              {"destination":"203.0.113.0/24","interfaceIndex":2,"gateway":"192.168.1.1","metric":5},
              {"destination":"2001:db8::/32","interfaceIndex":2,"metric":5}]}}"#,
        );
        assert_eq!(frame.method, method::ROUTES_APPLY);
        assert_eq!(params.owner, "static-office");
        assert_eq!(
            params.routes[0].gateway,
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(
            params.routes[1],
            AppliedRoute::on_link("2001:db8::/32".parse().unwrap(), 2, 5)
        );

        let (_, result): (_, RoutesApplyResult) =
            ok_response(r#"{"id":2,"ok":true,"result":{"applied":2}}"#);
        assert_eq!(result.applied, 2);

        let (_, error) = error_response(
            r#"{"id":2,"ok":false,"error":{"code":"authorizationDismissed","message":"authorization dialog was dismissed; nothing was applied"}}"#,
        );
        assert_eq!(error.code, ErrorCode::AuthorizationDismissed);
    }

    #[test]
    fn golden_routes_remove() {
        let (frame, params): (_, OwnerParams) =
            request(r#"{"id":3,"method":"routes.remove","params":{"owner":"static-office"}}"#);
        assert_eq!(frame.method, method::ROUTES_REMOVE);
        assert_eq!(params.owner, "static-office");
        let (_, result): (_, RoutesRemoveResult) =
            ok_response(r#"{"id":3,"ok":true,"result":{"removed":2}}"#);
        assert_eq!(result.removed, 2);
    }

    #[test]
    fn golden_link_set_state() {
        let (frame, params): (_, LinkSetStateParams) =
            request(r#"{"id":4,"method":"link.set_state","params":{"name":"enp0s3","up":false}}"#);
        assert_eq!(frame.method, method::LINK_SET_STATE);
        assert_eq!(params.name, "enp0s3");
        assert!(!params.up);
        let (_, result): (_, Value) = ok_response(r#"{"id":4,"ok":true,"result":null}"#);
        assert_eq!(result, Value::Null);
    }

    #[test]
    fn golden_owned_list() {
        let frame: RequestFrame = round_trip(r#"{"id":5,"method":"owned.list"}"#);
        assert_eq!(frame.method, method::OWNED_LIST);
        assert_eq!(frame.params, Value::Null);

        let (_, result): (_, OwnedListResult) = ok_response(
            r#"{"id":5,"ok":true,"result":{"owners":[{"owner":"static-office","state":"applied","resources":[
              {"kind":"route","destination":"203.0.113.0/24","interfaceIndex":2,"gateway":"192.168.1.1","metric":5}]}]}}"#,
        );
        let entry = &result.owners[0];
        assert_eq!(entry.owner, "static-office");
        assert_eq!(entry.state, OwnedState::Applied);
        let OwnedResource::Route(route) = &entry.resources[0];
        assert_eq!(route.gateway, Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn golden_recovery_cleanup() {
        let frame: RequestFrame = round_trip(r#"{"id":6,"method":"recovery.cleanup"}"#);
        assert_eq!(frame.method, method::RECOVERY_CLEANUP);
        let (_, result): (_, CleanupResult) = ok_response(
            r#"{"id":6,"ok":true,"result":{"removedOwners":["static-office"],"failed":[]}}"#,
        );
        assert_eq!(result.removed_owners, vec!["static-office".to_string()]);
        assert!(result.failed.is_empty());
    }

    #[test]
    fn golden_subscribe_and_events() {
        let frame: RequestFrame = round_trip(r#"{"id":7,"method":"subscribe"}"#);
        assert_eq!(frame.method, method::SUBSCRIBE);
        let (_, result): (_, Value) = ok_response(r#"{"id":7,"ok":true,"result":null}"#);
        assert_eq!(result, Value::Null);

        let event: EventFrame =
            round_trip(r#"{"event":"owned.changed","data":{"owner":"static-office"}}"#);
        assert_eq!(event.event, event::OWNED_CHANGED);
        let data: OwnedChanged = from_value(event.data).unwrap();
        assert_eq!(data.owner, "static-office");

        let event: EventFrame = round_trip(r#"{"event":"resync"}"#);
        assert_eq!(event.event, event::RESYNC);
    }

    #[test]
    fn unknown_method_parses_as_frame() {
        let frame: RequestFrame =
            serde_json::from_str(r#"{"id":9,"method":"frobnicate","params":{"x":1}}"#).unwrap();
        assert_eq!(frame.id, 9);
        assert_eq!(frame.method, "frobnicate");
        assert_eq!(frame.params, json!({"x":1}));
    }

    #[test]
    fn owned_resource_route_is_kind_tagged() {
        let resource =
            OwnedResource::Route(AppliedRoute::on_link("10.0.0.0/8".parse().unwrap(), 3, 1));
        assert_eq!(
            serde_json::to_value(&resource).unwrap(),
            json!({"kind":"route","destination":"10.0.0.0/8","interfaceIndex":3,"metric":1})
        );
    }

    #[test]
    fn unknown_resource_kind_is_invalid_data() {
        let err =
            from_value::<OwnedResource>(json!({"kind":"dns","server":"1.1.1.1"})).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn encode_line_appends_single_newline() {
        let line = encode_line(&EventFrame::new(event::RESYNC, Value::Null)).unwrap();
        assert_eq!(line, b"{\"event\":\"resync\"}\n");
    }

    #[tokio::test]
    async fn read_frame_splits_lines() {
        let mut reader: &[u8] = b"{\"a\":1}\n{\"b\":2}\n";
        assert_eq!(
            read_frame(&mut reader, 64).await.unwrap().unwrap(),
            b"{\"a\":1}"
        );
        assert_eq!(
            read_frame(&mut reader, 64).await.unwrap().unwrap(),
            b"{\"b\":2}"
        );
        assert!(read_frame(&mut reader, 64).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_without_newline() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        writer.write_all(&[b'a'; 64]).await.unwrap();
        // The writer stays open: the limit must trip without waiting for
        // a newline or EOF.
        let mut reader = BufReader::new(reader);
        let result = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut reader, 16))
            .await
            .expect("read_frame must not wait for a newline");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        drop(writer);
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_clean_eof() {
        let mut reader: &[u8] = b"";
        assert!(read_frame(&mut reader, 16).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_frame_rejects_eof_mid_frame() {
        let mut reader: &[u8] = b"{\"a\":";
        let err = read_frame(&mut reader, 16).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
