//! Connection handling: handshake, dispatch, events. Generic over the
//! stream so tests drive it through `tokio::io::duplex`.

use crate::auth::{required_action, Action, AuthDecision, Authorizer, PeerIdentity};
use crate::core::DaemonCore;
use crate::validate::{validate_apply, validate_iface_name, validate_owner};
use net_manager_core::daemon_protocol::{
    encode_line, event, from_value, method, read_frame, ErrorCode, EventFrame, HelloParams,
    HelloResult, LinkSetStateParams, OwnedChanged, OwnedListResult, OwnerParams, RequestFrame,
    ResponseFrame, RoutesApplyParams, RoutesApplyResult, RoutesRemoveResult, HELLO_TIMEOUT_SECS,
    MAX_CONNECTIONS, MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc, Semaphore};

const EVENT_CAPACITY: usize = 256;

/// "Something `owner` of `uid` owns changed"; delivered to that uid only.
#[derive(Debug, Clone)]
pub struct OwnerEvent {
    pub uid: u32,
    pub owner: String,
}

pub struct ServerContext<A> {
    pub core: Arc<Mutex<DaemonCore>>,
    pub authorizer: A,
    pub events: broadcast::Sender<OwnerEvent>,
    pub connections: Arc<Semaphore>,
    pub hello_timeout: Duration,
}

impl<A: Authorizer> ServerContext<A> {
    pub fn new(core: DaemonCore, authorizer: A) -> Self {
        Self {
            core: Arc::new(Mutex::new(core)),
            authorizer,
            events: broadcast::channel(EVENT_CAPACITY).0,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            hello_timeout: Duration::from_secs(HELLO_TIMEOUT_SECS),
        }
    }
}

type Failure = (ErrorCode, String);

/// Entry point for an accepted connection: enforces the connection limit,
/// then serves it until either side closes.
pub async fn serve_accepted<S, A>(mut stream: S, peer: PeerIdentity, ctx: Arc<ServerContext<A>>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    A: Authorizer,
{
    let Ok(_permit) = ctx.connections.clone().try_acquire_owned() else {
        let busy = ResponseFrame::error(0, ErrorCode::Busy, "too many connections");
        let _ = write_frame(&mut stream, &busy).await;
        return;
    };
    let uid = peer.uid;
    if let Err(err) = serve_connection(stream, peer, ctx).await {
        eprintln!("network-orchestrator-daemon: connection of uid {uid} failed: {err}");
    }
}

pub async fn serve_connection<S, A>(
    stream: S,
    peer: PeerIdentity,
    ctx: Arc<ServerContext<A>>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    A: Authorizer,
{
    let (read, mut write) = tokio::io::split(stream);
    // `read_frame` is not cancel-safe, so frames are read by a dedicated task
    // and handed over through a channel that `select!` can poll safely.
    let (frames_tx, mut frames) = mpsc::channel(1);
    let _reader = AbortOnDrop(tokio::spawn(async move {
        let mut reader = BufReader::new(read);
        loop {
            let frame = read_frame(&mut reader, MAX_FRAME_BYTES).await;
            let last = !matches!(frame, Ok(Some(_)));
            if frames_tx.send(frame).await.is_err() || last {
                break;
            }
        }
    }));

    let first = match tokio::time::timeout(ctx.hello_timeout, frames.recv()).await {
        Err(_) => return Ok(()),
        Ok(frame) => match next_frame(frame, &mut write).await? {
            Some(frame) => frame,
            None => return Ok(()),
        },
    };
    let request_id = match handshake(&first) {
        Ok(id) => id,
        Err(response) => return write_frame(&mut write, &response).await,
    };
    let hello = HelloResult {
        protocol: PROTOCOL_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        uid: peer.uid,
        capabilities: method::CAPABILITIES.iter().map(|m| m.to_string()).collect(),
    };
    write_frame(&mut write, &ok(request_id, &hello)).await?;

    let mut subscription: Option<broadcast::Receiver<OwnerEvent>> = None;
    loop {
        let frame = tokio::select! {
            frame = frames.recv() => match next_frame(frame, &mut write).await? {
                Some(frame) => frame,
                None => return Ok(()),
            },
            event = next_event(&mut subscription, peer.uid) => {
                write_frame(&mut write, &event).await?;
                continue;
            }
        };
        let response = match serde_json::from_slice::<RequestFrame>(&frame) {
            Ok(request) => {
                if request.method == method::SUBSCRIBE && subscription.is_none() {
                    subscription = Some(ctx.events.subscribe());
                }
                dispatch(request, &peer, &ctx).await
            }
            Err(_) => ResponseFrame::error(0, ErrorCode::InvalidParams, "malformed request frame"),
        };
        write_frame(&mut write, &response).await?;
    }
}

/// Unwrap what the reader task delivered. Oversized frames are answered
/// with `frameTooLarge`; any read error or EOF ends the connection.
async fn next_frame<W: AsyncWrite + Unpin>(
    frame: Option<io::Result<Option<Vec<u8>>>>,
    write: &mut W,
) -> io::Result<Option<Vec<u8>>> {
    match frame {
        Some(Ok(Some(frame))) => Ok(Some(frame)),
        Some(Err(err)) if err.kind() == io::ErrorKind::InvalidData => {
            let response = ResponseFrame::error(0, ErrorCode::FrameTooLarge, err.to_string());
            write_frame(write, &response).await?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// Validate the mandatory first `hello`; returns its request id.
fn handshake(frame: &[u8]) -> Result<u64, ResponseFrame> {
    let request: RequestFrame = serde_json::from_slice(frame).map_err(|_| {
        ResponseFrame::error(0, ErrorCode::InvalidParams, "malformed request frame")
    })?;
    if request.method != method::HELLO {
        return Err(ResponseFrame::error(
            request.id,
            ErrorCode::HandshakeRequired,
            "the first request must be hello",
        ));
    }
    let params: HelloParams = from_value(request.params).map_err(|err| {
        ResponseFrame::error(request.id, ErrorCode::InvalidParams, err.to_string())
    })?;
    if params.protocol != PROTOCOL_VERSION {
        return Err(ResponseFrame::error(
            request.id,
            ErrorCode::ProtocolMismatch,
            format!(
                "daemon speaks protocol {PROTOCOL_VERSION}, client {}",
                params.protocol
            ),
        ));
    }
    Ok(request.id)
}

/// Wait for the next event for `uid`; never resolves without a subscription.
async fn next_event(
    subscription: &mut Option<broadcast::Receiver<OwnerEvent>>,
    uid: u32,
) -> EventFrame {
    let Some(receiver) = subscription.as_mut() else {
        return std::future::pending().await;
    };
    loop {
        match receiver.recv().await {
            Ok(event) if event.uid == uid => {
                let data = serde_json::to_value(OwnedChanged { owner: event.owner })
                    .unwrap_or(Value::Null);
                return EventFrame::new(event::OWNED_CHANGED, data);
            }
            Ok(_) => continue,
            Err(broadcast::error::RecvError::Lagged(_)) => {
                return EventFrame::new(event::RESYNC, Value::Null);
            }
            Err(broadcast::error::RecvError::Closed) => return std::future::pending().await,
        }
    }
}

/// parse → validate → polkit → core → event → response.
async fn dispatch<A: Authorizer>(
    request: RequestFrame,
    peer: &PeerIdentity,
    ctx: &ServerContext<A>,
) -> ResponseFrame {
    let id = request.id;
    let method_name = request.method.clone();
    let result = handle(request, peer, ctx).await;
    if let Some(action) = required_action(&method_name) {
        let outcome = match &result {
            Ok(_) => "ok".to_string(),
            Err((code, _)) => format!("{code:?}"),
        };
        eprintln!(
            "network-orchestrator-daemon: uid {} {} ({}): {outcome}",
            peer.uid,
            method_name,
            action.polkit_id()
        );
    }
    match result {
        Ok(value) => ResponseFrame::ok(id, value),
        Err((code, message)) => ResponseFrame::error(id, code, message),
    }
}

async fn handle<A: Authorizer>(
    request: RequestFrame,
    peer: &PeerIdentity,
    ctx: &ServerContext<A>,
) -> Result<Value, Failure> {
    let uid = peer.uid;
    match request.method.as_str() {
        method::HELLO => Err((
            ErrorCode::InvalidParams,
            "hello was already exchanged".into(),
        )),
        method::SUBSCRIBE => Ok(Value::Null),
        method::OWNED_LIST => {
            let owners = with_core(ctx, move |core| Ok(core.owned(uid))).await?;
            to_value(&OwnedListResult { owners })
        }
        method::ROUTES_APPLY => {
            let params: RoutesApplyParams = params(request.params)?;
            validate_owner(&params.owner).map_err(invalid)?;
            validate_apply(&params.routes).map_err(invalid)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let owner = params.owner.clone();
            let applied = with_core(ctx, move |core| {
                core.apply_routes(uid, &params.owner, params.routes)
            })
            .await?;
            notify(ctx, uid, owner);
            to_value(&RoutesApplyResult { applied })
        }
        method::ROUTES_REMOVE => {
            let params: OwnerParams = params(request.params)?;
            validate_owner(&params.owner).map_err(invalid)?;
            authorize(ctx, peer, Action::ConnectProfile).await?;
            let owner = params.owner.clone();
            let result = with_core(ctx, move |core| core.remove_owner(uid, &params.owner)).await;
            // A partial failure still changed the owner (now `stale`).
            if !matches!(
                &result,
                Err((ErrorCode::NotFound | ErrorCode::InvalidParams, _))
            ) {
                notify(ctx, uid, owner);
            }
            to_value(&RoutesRemoveResult { removed: result? })
        }
        method::LINK_SET_STATE => {
            let params: LinkSetStateParams = params(request.params)?;
            validate_iface_name(&params.name).map_err(invalid)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            with_core(ctx, move |core| {
                core.set_link_state(&params.name, params.up)
            })
            .await?;
            Ok(Value::Null)
        }
        method::RECOVERY_CLEANUP => {
            authorize(ctx, peer, Action::ConnectProfile).await?;
            let result = with_core(ctx, move |core| core.cleanup_uid(uid)).await?;
            for owner in result.removed_owners.iter().chain(&result.failed) {
                notify(ctx, uid, owner.clone());
            }
            to_value(&result)
        }
        _ => Err((
            ErrorCode::UnsupportedMethod,
            format!("unsupported method '{}'", request.method),
        )),
    }
}

async fn authorize<A: Authorizer>(
    ctx: &ServerContext<A>,
    peer: &PeerIdentity,
    action: Action,
) -> Result<(), Failure> {
    match ctx.authorizer.check(peer, action).await {
        Ok(AuthDecision::Authorized) => Ok(()),
        Ok(AuthDecision::Denied) => Err((
            ErrorCode::NotAuthorized,
            format!(
                "polkit denied {}; a polkit authentication agent must be running in your session",
                action.polkit_id()
            ),
        )),
        Ok(AuthDecision::Dismissed) => Err((
            ErrorCode::AuthorizationDismissed,
            "authorization dialog was dismissed; nothing was applied".into(),
        )),
        Err(err) => Err((ErrorCode::Unavailable, err.to_string())),
    }
}

/// Run `f` on the core off the async workers: netlink calls block.
async fn with_core<A, T, F>(ctx: &ServerContext<A>, f: F) -> Result<T, Failure>
where
    T: Send + 'static,
    F: FnOnce(&mut DaemonCore) -> io::Result<T> + Send + 'static,
{
    let core = ctx.core.clone();
    tokio::task::spawn_blocking(move || {
        let mut core = core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut core)
    })
    .await
    .map_err(|err| (ErrorCode::Internal, err.to_string()))?
    .map_err(|err| (error_code(&err), err.to_string()))
}

fn error_code(err: &io::Error) -> ErrorCode {
    match err.kind() {
        io::ErrorKind::InvalidInput => ErrorCode::InvalidParams,
        io::ErrorKind::AlreadyExists => ErrorCode::Conflict,
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe => ErrorCode::Unavailable,
        _ => ErrorCode::Internal,
    }
}

fn notify<A>(ctx: &ServerContext<A>, uid: u32, owner: String) {
    // No subscribers is not an error.
    let _ = ctx.events.send(OwnerEvent { uid, owner });
}

fn params<T: DeserializeOwned>(value: Value) -> Result<T, Failure> {
    from_value(value).map_err(|err| (ErrorCode::InvalidParams, err.to_string()))
}

fn invalid(message: String) -> Failure {
    (ErrorCode::InvalidParams, message)
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, Failure> {
    serde_json::to_value(value).map_err(|err| (ErrorCode::Internal, err.to_string()))
}

fn ok<T: Serialize>(id: u64, value: &T) -> ResponseFrame {
    match serde_json::to_value(value) {
        Ok(value) => ResponseFrame::ok(id, value),
        Err(err) => ResponseFrame::error(id, ErrorCode::Internal, err.to_string()),
    }
}

async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    write: &mut W,
    frame: &T,
) -> io::Result<()> {
    write.write_all(&encode_line(frame)?).await?;
    write.flush().await
}

#[cfg(target_os = "linux")]
pub use listener::{bind_socket, serve};

#[cfg(target_os = "linux")]
mod listener {
    use super::{serve_accepted, ServerContext};
    use crate::auth::Authorizer;
    use std::fs;
    use std::io;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UnixListener;

    /// Bind `path`, replacing a stale socket (never any other file), and make
    /// it 0666 regardless of the umask: access control is polkit's job.
    pub fn bind_socket(path: &Path) -> io::Result<UnixListener> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("refusing to replace non-socket {}", path.display()),
                ))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        Ok(listener)
    }

    /// Accept forever; each connection is identified via `SO_PEERCRED`
    /// before a single byte is read from it.
    pub async fn serve<A: Authorizer>(listener: UnixListener, ctx: Arc<ServerContext<A>>) {
        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(err) => {
                    eprintln!("network-orchestrator-daemon: accept failed: {err}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            match crate::peer::identify(&stream) {
                Ok(peer) => {
                    tokio::spawn(serve_accepted(stream, peer, ctx.clone()));
                }
                Err(err) => eprintln!("network-orchestrator-daemon: unidentified peer: {err}"),
            }
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Action, AuthDecision, Authorizer, PeerIdentity};
    use crate::core::testing::{FakeLinks, FakeRoutes, Recorder};
    use crate::core::DaemonCore;
    use crate::journal::{JournalStore, JOURNAL_FILE};
    use net_manager_core::daemon_protocol::MAX_FRAME_BYTES;
    use serde_json::{json, Value};
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct FakeAuthorizer {
        decision: AuthDecision,
        calls: AtomicUsize,
    }

    impl Authorizer for FakeAuthorizer {
        async fn check(&self, _peer: &PeerIdentity, _action: Action) -> io::Result<AuthDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision)
        }
    }

    struct Harness {
        ctx: Arc<ServerContext<FakeAuthorizer>>,
        recorder: Recorder,
        dir: PathBuf,
    }

    impl Harness {
        fn new(decision: AuthDecision) -> Self {
            Self::with(decision, |_| {})
        }

        fn with(
            decision: AuthDecision,
            tune: impl FnOnce(&mut ServerContext<FakeAuthorizer>),
        ) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "netmgr-daemon-server-{}-{}",
                std::process::id(),
                DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let recorder = Recorder::default();
            let core = DaemonCore::open(
                JournalStore::new(dir.join(JOURNAL_FILE)),
                Box::new(FakeRoutes::new(&recorder)),
                Box::new(FakeLinks(recorder.clone())),
            )
            .unwrap();
            let mut ctx = ServerContext::new(
                core,
                FakeAuthorizer {
                    decision,
                    calls: AtomicUsize::new(0),
                },
            );
            tune(&mut ctx);
            Self {
                ctx: Arc::new(ctx),
                recorder,
                dir,
            }
        }

        fn connect(&self, uid: u32) -> Client {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let peer = PeerIdentity {
                uid,
                pid: 4242,
                start_time: Some(1),
                pidfd: None,
            };
            tokio::spawn(serve_accepted(server, peer, self.ctx.clone()));
            let (read, write) = tokio::io::split(client);
            Client {
                reader: BufReader::new(read),
                writer: write,
            }
        }

        async fn hello(&self, uid: u32) -> Client {
            let mut client = self.connect(uid);
            client
                .send(json!({"id":1,"method":"hello","params":{"protocol":1,"client":"test"}}))
                .await;
            let reply = client.recv().await.unwrap();
            assert_eq!(reply["ok"], json!(true), "{reply}");
            client
        }

        fn auth_calls(&self) -> usize {
            self.ctx.authorizer.calls.load(Ordering::SeqCst)
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    struct Client {
        reader: BufReader<ReadHalf<DuplexStream>>,
        writer: WriteHalf<DuplexStream>,
    }

    impl Client {
        async fn send(&mut self, value: Value) {
            let mut line = serde_json::to_vec(&value).unwrap();
            line.push(b'\n');
            self.writer.write_all(&line).await.unwrap();
        }

        /// Next frame, or `None` once the daemon closed the connection.
        async fn recv(&mut self) -> Option<Value> {
            self.recv_within(Duration::from_secs(5))
                .await
                .expect("daemon did not answer in time")
        }

        async fn recv_within(&mut self, limit: Duration) -> Result<Option<Value>, ()> {
            let mut line = String::new();
            match tokio::time::timeout(limit, self.reader.read_line(&mut line)).await {
                Err(_) => Err(()),
                Ok(Ok(0)) | Ok(Err(_)) => Ok(None),
                Ok(Ok(_)) => Ok(Some(serde_json::from_str(&line).unwrap())),
            }
        }

        async fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
            let mut frame = json!({"id": id, "method": method});
            if !params.is_null() {
                frame["params"] = params;
            }
            self.send(frame).await;
            let reply = self.recv().await.expect("connection closed");
            assert_eq!(reply["id"], json!(id), "{reply}");
            reply
        }
    }

    fn error_code(reply: &Value) -> &str {
        reply["error"]["code"].as_str().unwrap_or("<none>")
    }

    fn apply_params(owner: &str, dest: &str) -> Value {
        json!({"owner": owner, "routes": [{"destination": dest, "interfaceIndex": 2, "metric": 5}]})
    }

    #[tokio::test]
    async fn hello_reports_uid_and_capabilities() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.connect(1000);
        let reply = client
            .call(1, "hello", json!({"protocol":1,"client":"test"}))
            .await;
        assert_eq!(reply["result"]["uid"], json!(1000));
        assert_eq!(reply["result"]["protocol"], json!(1));
        assert_eq!(
            reply["result"]["capabilities"],
            json!(net_manager_core::daemon_protocol::method::CAPABILITIES)
        );
    }

    #[tokio::test]
    async fn first_request_must_be_hello() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.connect(1000);
        let reply = client.call(3, "owned.list", Value::Null).await;
        assert_eq!(error_code(&reply), "handshakeRequired");
        assert_eq!(client.recv().await, None);
    }

    #[tokio::test]
    async fn protocol_mismatch_closes() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.connect(1000);
        let reply = client
            .call(1, "hello", json!({"protocol":2,"client":"test"}))
            .await;
        assert_eq!(error_code(&reply), "protocolMismatch");
        assert_eq!(
            reply["error"]["message"],
            json!("daemon speaks protocol 1, client 2")
        );
        assert_eq!(client.recv().await, None);
    }

    #[tokio::test]
    async fn unknown_method_keeps_connection() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        let reply = client.call(2, "frobnicate", json!({"x":1})).await;
        assert_eq!(error_code(&reply), "unsupportedMethod");
        let reply = client.call(3, "owned.list", Value::Null).await;
        assert_eq!(reply["result"], json!({"owners": []}));
    }

    #[tokio::test]
    async fn oversized_frame_closes() {
        let harness = Harness::new(AuthDecision::Authorized);
        let Client {
            mut reader,
            mut writer,
        } = harness.hello(1000).await;
        tokio::spawn(async move {
            let _ = writer.write_all(&vec![b'a'; MAX_FRAME_BYTES + 1]).await;
            // Keep the write side open: the daemon must not wait for EOF.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(error_code(&reply), "frameTooLarge");
        line.clear();
        let closed = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("connection must close");
        assert_eq!(closed.unwrap(), 0);
    }

    #[tokio::test]
    async fn invalid_params_never_reach_authorizer() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        let cases = [
            ("routes.apply", apply_params("office", "10.0.0.1/8")),
            ("routes.apply", apply_params("", "10.0.0.0/8")),
            (
                "routes.apply",
                json!({"owner":"office","routes":[{"destination":"10.0.0.0/8","interfaceIndex":2,"metric":5,"table":255}]}),
            ),
            ("routes.apply", json!({"owner":"office"})),
            ("routes.remove", json!({"owner":"a\nb"})),
            ("link.set_state", json!({"name":"wg0; reboot","up":true})),
            ("link.set_state", json!({"name":"wg0"})),
        ];
        for (id, (method, params)) in cases.into_iter().enumerate() {
            let reply = client.call(id as u64 + 10, method, params).await;
            assert_eq!(error_code(&reply), "invalidParams", "{method}: {reply}");
        }
        assert_eq!(harness.auth_calls(), 0);
        assert!(harness.recorder.ops().is_empty());
    }

    #[tokio::test]
    async fn denied_does_not_touch_executor() {
        let harness = Harness::new(AuthDecision::Denied);
        let mut client = harness.hello(1000).await;
        let reply = client
            .call(2, "routes.apply", apply_params("office", "10.0.0.0/8"))
            .await;
        assert_eq!(error_code(&reply), "notAuthorized");
        assert!(reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("polkit"));
        let reply = client
            .call(3, "link.set_state", json!({"name":"enp0s3","up":false}))
            .await;
        assert_eq!(error_code(&reply), "notAuthorized");
        assert_eq!(harness.auth_calls(), 2);
        assert!(harness.recorder.ops().is_empty());
    }

    #[tokio::test]
    async fn dismissed_maps_to_authorization_dismissed() {
        let harness = Harness::new(AuthDecision::Dismissed);
        let mut client = harness.hello(1000).await;
        let reply = client
            .call(2, "routes.apply", apply_params("office", "10.0.0.0/8"))
            .await;
        assert_eq!(error_code(&reply), "authorizationDismissed");
        assert!(harness.recorder.ops().is_empty());
    }

    #[tokio::test]
    async fn apply_list_remove_round_trip() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        let reply = client
            .call(2, "routes.apply", apply_params("office", "10.0.0.0/8"))
            .await;
        assert_eq!(reply["result"], json!({"applied": 1}));
        let reply = client
            .call(3, "routes.apply", apply_params("office", "10.9.0.0/16"))
            .await;
        assert_eq!(error_code(&reply), "conflict");
        let reply = client.call(4, "owned.list", Value::Null).await;
        assert_eq!(reply["result"]["owners"][0]["owner"], json!("office"));
        assert_eq!(reply["result"]["owners"][0]["state"], json!("applied"));
        let reply = client
            .call(5, "routes.remove", json!({"owner":"office"}))
            .await;
        assert_eq!(reply["result"], json!({"removed": 1}));
        let reply = client
            .call(6, "routes.remove", json!({"owner":"office"}))
            .await;
        assert_eq!(error_code(&reply), "notFound");
        let reply = client
            .call(7, "link.set_state", json!({"name":"enp0s3","up":true}))
            .await;
        assert_eq!(reply["result"], Value::Null);
        assert_eq!(reply["ok"], json!(true));
    }

    #[tokio::test]
    async fn recovery_cleanup_removes_only_callers_owners() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut mine = harness.hello(1000).await;
        let mut theirs = harness.hello(1001).await;
        mine.call(2, "routes.apply", apply_params("a", "10.1.0.0/16"))
            .await;
        theirs
            .call(2, "routes.apply", apply_params("b", "10.2.0.0/16"))
            .await;
        let reply = mine.call(3, "recovery.cleanup", Value::Null).await;
        assert_eq!(
            reply["result"],
            json!({"removedOwners": ["a"], "failed": []})
        );
        let reply = theirs.call(3, "owned.list", Value::Null).await;
        assert_eq!(reply["result"]["owners"][0]["owner"], json!("b"));
    }

    #[tokio::test]
    async fn apply_notifies_subscriber_of_same_uid_only() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut same = harness.hello(1000).await;
        let mut other = harness.hello(1001).await;
        assert_eq!(
            same.call(2, "subscribe", Value::Null).await["ok"],
            json!(true)
        );
        assert_eq!(
            other.call(2, "subscribe", Value::Null).await["ok"],
            json!(true)
        );

        let mut actor = harness.hello(1000).await;
        actor
            .call(2, "routes.apply", apply_params("office", "10.0.0.0/8"))
            .await;

        assert_eq!(
            same.recv().await,
            Some(json!({"event":"owned.changed","data":{"owner":"office"}}))
        );
        assert_eq!(
            other.recv_within(Duration::from_millis(300)).await,
            Err(()),
            "another uid must not see the event"
        );
    }

    #[tokio::test]
    async fn lagged_subscriber_gets_resync() {
        let harness = Harness::with(AuthDecision::Authorized, |ctx| {
            ctx.events = tokio::sync::broadcast::channel(2).0;
        });
        let mut client = harness.hello(1000).await;
        assert_eq!(
            client.call(2, "subscribe", Value::Null).await["ok"],
            json!(true)
        );
        // current_thread runtime: the connection task cannot run between
        // these sends, so the receiver is guaranteed to lag.
        for n in 0..10 {
            let _ = harness.ctx.events.send(OwnerEvent {
                uid: 1000,
                owner: format!("o{n}"),
            });
        }
        assert_eq!(client.recv().await, Some(json!({"event":"resync"})));
    }

    #[tokio::test]
    async fn connection_limit_returns_busy() {
        let harness = Harness::with(AuthDecision::Authorized, |ctx| {
            ctx.connections = Arc::new(tokio::sync::Semaphore::new(1));
        });
        let _first = harness.hello(1000).await;
        let mut second = harness.connect(1000);
        let reply = second.recv().await.unwrap();
        assert_eq!(error_code(&reply), "busy");
        assert_eq!(second.recv().await, None);
    }
}
