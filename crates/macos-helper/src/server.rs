//! Framed `daemon_protocol` server: peer policy at accept time, a mandatory
//! `hello`, then one request at a time per connection. Handlers are blocking
//! and run on the blocking pool.

use crate::peer::{identify, ClientPolicy, Peer};
use net_manager_core::daemon_protocol::method;
use net_manager_core::daemon_protocol::{
    encode_line, read_frame, ErrorCode, HelloParams, HelloResult, RequestFrame, ResponseFrame,
    HELLO_TIMEOUT_SECS, MAX_CONNECTIONS, MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;

/// What the helper does once a peer is verified.
pub trait Handler: Send + Sync + 'static {
    /// Methods this build implements, reported in `hello.capabilities`.
    fn capabilities(&self) -> Vec<String>;
    /// Whether each trusted tool can be executed right now.
    fn tools(&self) -> BTreeMap<String, bool> {
        BTreeMap::new()
    }
    /// Serve one request. Blocking; called from `spawn_blocking`.
    fn handle(&self, peer: &Peer, request: RequestFrame) -> ResponseFrame;
    /// A verified connection of `uid` ended; `remaining` of its connections
    /// are still open.
    fn connection_closed(&self, _uid: u32, _remaining: usize) {}
}

pub struct ServerContext {
    pub policy: Box<dyn ClientPolicy>,
    pub handler: Arc<dyn Handler>,
    pub version: String,
    pub hello_timeout: Duration,
    connections: Arc<Semaphore>,
    open_by_uid: std::sync::Mutex<BTreeMap<u32, usize>>,
}

impl ServerContext {
    pub fn new(policy: Box<dyn ClientPolicy>, handler: Arc<dyn Handler>, version: &str) -> Self {
        Self {
            policy,
            handler,
            version: version.to_string(),
            hello_timeout: Duration::from_secs(HELLO_TIMEOUT_SECS),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            open_by_uid: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    fn opened(&self, uid: u32) {
        *self.open_by_uid.lock().unwrap().entry(uid).or_default() += 1;
    }

    fn closed(&self, uid: u32) -> usize {
        let mut open = self.open_by_uid.lock().unwrap();
        let remaining = open.get(&uid).copied().unwrap_or(1).saturating_sub(1);
        if remaining == 0 {
            open.remove(&uid);
        } else {
            open.insert(uid, remaining);
        }
        remaining
    }
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
    let params: HelloParams = serde_json::from_value(request.params).map_err(|err| {
        ResponseFrame::error(request.id, ErrorCode::InvalidParams, err.to_string())
    })?;
    if params.protocol != PROTOCOL_VERSION {
        return Err(ResponseFrame::error(
            request.id,
            ErrorCode::ProtocolMismatch,
            format!(
                "helper speaks protocol {PROTOCOL_VERSION}, client {}",
                params.protocol
            ),
        ));
    }
    Ok(request.id)
}

/// Serve one accepted connection until either side closes it.
pub async fn serve_connection<S>(
    mut stream: S,
    peer: Peer,
    ctx: Arc<ServerContext>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    if let Err(reason) = ctx.policy.check(&peer) {
        let denied = ResponseFrame::error(0, ErrorCode::NotAuthorized, reason);
        return write_frame(&mut stream, &denied).await;
    }
    let Ok(_permit) = ctx.connections.clone().try_acquire_owned() else {
        let busy = ResponseFrame::error(0, ErrorCode::Busy, "too many connections");
        return write_frame(&mut stream, &busy).await;
    };
    ctx.opened(peer.uid);
    let result = converse(stream, peer, &ctx).await;
    let remaining = ctx.closed(peer.uid);
    let handler = ctx.handler.clone();
    let uid = peer.uid;
    let _ = tokio::task::spawn_blocking(move || handler.connection_closed(uid, remaining)).await;
    result
}

async fn converse<S>(stream: S, peer: Peer, ctx: &Arc<ServerContext>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let first =
        match tokio::time::timeout(ctx.hello_timeout, read_frame(&mut reader, MAX_FRAME_BYTES))
            .await
        {
            Err(_) | Ok(Ok(None)) => return Ok(()),
            Ok(Err(err)) => return answer_read_error(err, &mut write).await,
            Ok(Ok(Some(frame))) => frame,
        };
    let id = match handshake(&first) {
        Ok(id) => id,
        Err(response) => return write_frame(&mut write, &response).await,
    };
    let hello = HelloResult {
        protocol: PROTOCOL_VERSION,
        daemon_version: ctx.version.clone(),
        uid: peer.uid,
        capabilities: ctx.handler.capabilities(),
        tools: ctx.handler.tools(),
    };
    write_frame(&mut write, &ok(id, &hello)).await?;
    loop {
        let frame = match read_frame(&mut reader, MAX_FRAME_BYTES).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(err) => return answer_read_error(err, &mut write).await,
        };
        let response = match serde_json::from_slice::<RequestFrame>(&frame) {
            Ok(request) => {
                let handler = ctx.handler.clone();
                let id = request.id;
                tokio::task::spawn_blocking(move || handler.handle(&peer, request))
                    .await
                    .unwrap_or_else(|_| {
                        ResponseFrame::error(id, ErrorCode::Internal, "the helper request failed")
                    })
            }
            Err(_) => ResponseFrame::error(0, ErrorCode::InvalidParams, "malformed request frame"),
        };
        write_frame(&mut write, &response).await?;
    }
}

async fn answer_read_error<W: AsyncWrite + Unpin>(err: io::Error, write: &mut W) -> io::Result<()> {
    if err.kind() == io::ErrorKind::InvalidData {
        let response = ResponseFrame::error(0, ErrorCode::FrameTooLarge, err.to_string());
        write_frame(write, &response).await
    } else {
        Ok(())
    }
}

/// Bind `path`, replacing a stale socket (never any other file). The socket
/// is world-connectable: access control is the peer policy's job.
pub fn bind_socket(path: &Path) -> io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        match fs::DirBuilder::new().mode(0o755).create(dir) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }
    }
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

/// Accept forever; every connection is identified before a byte is read.
pub async fn serve(listener: UnixListener, ctx: Arc<ServerContext>) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                eprintln!("network-orchestrator-helper: accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        match identify(&stream) {
            Ok(peer) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(err) = serve_connection(stream, peer, ctx).await {
                        eprintln!(
                            "network-orchestrator-helper: connection of uid {} failed: {err}",
                            peer.uid
                        );
                    }
                });
            }
            Err(err) => eprintln!("network-orchestrator-helper: unidentified peer: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_manager_core::daemon_protocol::{read_frame, RequestFrame};
    use serde_json::{json, Value};
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    struct Allow(bool);
    impl ClientPolicy for Allow {
        fn check(&self, _: &Peer) -> Result<(), String> {
            if self.0 {
                Ok(())
            } else {
                Err("denied".into())
            }
        }
    }

    #[derive(Default)]
    struct Echo {
        closed: std::sync::Mutex<Vec<(u32, usize)>>,
    }
    impl Handler for Echo {
        fn capabilities(&self) -> Vec<String> {
            vec!["echo".into()]
        }
        fn handle(&self, peer: &Peer, request: RequestFrame) -> ResponseFrame {
            ResponseFrame::ok(
                request.id,
                json!({"uid": peer.uid, "method": request.method}),
            )
        }
        fn connection_closed(&self, uid: u32, remaining: usize) {
            self.closed.lock().unwrap().push((uid, remaining));
        }
    }

    fn context(allow: bool) -> (Arc<ServerContext>, Arc<Echo>) {
        let handler = Arc::new(Echo::default());
        let ctx = ServerContext::new(Box::new(Allow(allow)), handler.clone(), "test");
        (Arc::new(ctx), handler)
    }

    async fn exchange(
        ctx: Arc<ServerContext>,
        lines: &[Value],
    ) -> (Vec<Value>, tokio::task::JoinHandle<io::Result<()>>) {
        let (client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(serve_connection(server, Peer { uid: 501, pid: 7 }, ctx));
        let (read, mut write) = tokio::io::split(client);
        for line in lines {
            write.write_all(&encode_line(line).unwrap()).await.unwrap();
        }
        write.shutdown().await.unwrap();
        let mut reader = BufReader::new(read);
        let mut frames = Vec::new();
        while let Some(frame) = read_frame(&mut reader, MAX_FRAME_BYTES).await.unwrap() {
            frames.push(serde_json::from_slice(&frame).unwrap());
        }
        (frames, task)
    }

    fn hello() -> Value {
        json!({"id": 1, "method": "hello", "params": {"protocol": PROTOCOL_VERSION, "client": "t"}})
    }

    #[tokio::test]
    async fn hello_then_requests_are_served() {
        let (ctx, handler) = context(true);
        let (frames, task) =
            exchange(ctx, &[hello(), json!({"id": 2, "method": "echo.ping"})]).await;
        task.await.unwrap().unwrap();
        assert_eq!(frames[0]["ok"], true);
        assert_eq!(frames[0]["result"]["uid"], 501);
        assert_eq!(frames[0]["result"]["capabilities"], json!(["echo"]));
        assert_eq!(frames[1]["result"]["method"], "echo.ping");
        assert_eq!(handler.closed.lock().unwrap().as_slice(), [(501, 0)]);
    }

    #[tokio::test]
    async fn requests_before_hello_are_refused() {
        let (ctx, _) = context(true);
        let (frames, _) = exchange(ctx, &[json!({"id": 5, "method": "echo.ping"})]).await;
        assert_eq!(frames[0]["error"]["code"], "handshakeRequired");
    }

    #[tokio::test]
    async fn protocol_mismatch_is_refused() {
        let (ctx, _) = context(true);
        let bad = json!({"id": 1, "method": "hello", "params": {"protocol": 999, "client": "t"}});
        let (frames, _) = exchange(ctx, &[bad]).await;
        assert_eq!(frames[0]["error"]["code"], "protocolMismatch");
    }

    #[tokio::test]
    async fn rejected_peers_never_reach_the_handler() {
        let (ctx, handler) = context(false);
        let (frames, task) =
            exchange(ctx, &[hello(), json!({"id": 2, "method": "echo.ping"})]).await;
        task.await.unwrap().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["error"]["code"], "notAuthorized");
        assert!(handler.closed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_frames_get_an_error_and_the_connection_survives() {
        let (ctx, _) = context(true);
        let (client, server) = UnixStream::pair().unwrap();
        tokio::spawn(serve_connection(server, Peer { uid: 501, pid: 7 }, ctx));
        let (read, mut write) = tokio::io::split(client);
        write
            .write_all(&encode_line(&hello()).unwrap())
            .await
            .unwrap();
        write.write_all(b"not json\n").await.unwrap();
        write
            .write_all(&encode_line(&json!({"id": 3, "method": "echo.ping"})).unwrap())
            .await
            .unwrap();
        write.shutdown().await.unwrap();
        let mut reader = BufReader::new(read);
        let mut codes = Vec::new();
        while let Some(frame) = read_frame(&mut reader, MAX_FRAME_BYTES).await.unwrap() {
            let value: Value = serde_json::from_slice(&frame).unwrap();
            codes.push(value["ok"].as_bool().unwrap());
        }
        assert_eq!(codes, [true, false, true]);
    }

    #[test]
    fn bind_replaces_stale_sockets_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            drop(bind_socket(&path).unwrap());
            let listener = bind_socket(&path).unwrap();
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o666);
            drop(listener);
            fs::remove_file(&path).unwrap();
            fs::write(&path, b"x").unwrap();
            assert!(bind_socket(&path).is_err());
        });
    }
}
