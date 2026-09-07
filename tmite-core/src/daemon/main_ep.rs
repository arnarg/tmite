use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::daemon::state::State;
use crate::net::RejectDelay;
use crate::stream_io::{expect_frame, write_frame};
use tmite_proto::alpn::DATA_ALPN;
use tmite_proto::frame::{DataDenyReason, DataFrame, TYPE_FORWARD};
use tmite_proto::limits;

/// Data-plane protocol handler for the daemon main endpoint (§7.3).
#[derive(Debug)]
pub struct DataPlaneHandler {
    state: Arc<State>,
    reject_delay: Mutex<RejectDelay>,
    idle_timeout: Duration,
}

impl DataPlaneHandler {
    pub fn new(state: Arc<State>, idle_timeout: Duration) -> Self {
        Self {
            state,
            reject_delay: Mutex::new(RejectDelay::new()),
            idle_timeout,
        }
    }
}

impl ProtocolHandler for DataPlaneHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        let node_id = remote.to_string();

        let Some(peer) = self.state.peer_by_node(&node_id) else {
            let mut delay = self.reject_delay.lock().await;
            tracing::warn!("rejecting unknown peer {node_id}");
            tokio::time::sleep(delay.delay()).await;
            delay.escalate();
            drop(delay);
            conn.close(0u8.into(), b"unauthorized");
            return Ok(());
        };

        self.reject_delay.lock().await.reset();
        tracing::info!(peer = %peer.name, %node_id, "data-plane session established");
        self.state.touch_last_seen(&node_id);
        connection_loop(conn, peer.name, self.state.clone(), self.idle_timeout).await;
        Ok(())
    }
}

/// Per-connection stream accept loop. The loop itself never blocks on
/// application logic: each stream runs in its own task (§7.3 R1).
async fn connection_loop(
    conn: Connection,
    peer_name: String,
    state: Arc<State>,
    idle_timeout: Duration,
) {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let state = state.clone();
                let peer_name = peer_name.clone();
                tokio::spawn(async move {
                    handle_stream(send, recv, peer_name, state, idle_timeout).await;
                });
            }
            Err(e) => {
                tracing::debug!(peer = %peer_name, "connection closed: {e}");
                break;
            }
        }
    }
}

/// Per-stream handler: one FORWARD, ACL check, dial, relay.
async fn handle_stream(
    send: SendStream,
    mut recv: RecvStream,
    peer_name: String,
    state: Arc<State>,
    idle_timeout: Duration,
) {
    let target =
        match expect_frame::<DataFrame>(&mut recv, TYPE_FORWARD, limits::FIRST_FRAME_TIMEOUT).await
        {
            Ok(DataFrame::Forward { target }) => target,
            Ok(_) | Err(_) => {
                tracing::debug!(peer = %peer_name, "malformed first frame; closing stream");
                return;
            }
        };

    if !valid_target(&target) {
        deny(send, DataDenyReason::ServerError).await;
        return;
    }

    // ACL: exact byte-for-byte match against this peer's rules (§8).
    if !state.rule_allows(&peer_name, &target) {
        tracing::info!(peer = %peer_name, %target, "forward denied: no rule");
        deny(send, DataDenyReason::Unauthorized).await;
        return;
    }

    let tcp =
        match tokio::time::timeout(limits::TARGET_CONNECT_TIMEOUT, TcpStream::connect(&target))
            .await
        {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(e)) => {
                tracing::info!(peer = %peer_name, %target, "dial failed: {e}");
                deny(
                    send,
                    DataDenyReason::TargetUnreachable {
                        os_error: e.to_string(),
                    },
                )
                .await;
                return;
            }
            Err(_) => {
                tracing::info!(peer = %peer_name, %target, "dial timed out");
                deny(
                    send,
                    DataDenyReason::TargetUnreachable {
                        os_error: "connect timed out".to_string(),
                    },
                )
                .await;
                return;
            }
        };

    let mut send = send;
    if write_frame(&mut send, DataFrame::Ok {}.msg_type(), &DataFrame::Ok {})
        .await
        .is_err()
    {
        return;
    }
    tracing::debug!(peer = %peer_name, %target, "forwarding");
    relay(send, recv, tcp, idle_timeout).await;
}

async fn deny(send: SendStream, reason: DataDenyReason) {
    let frame = DataFrame::Deny { reason };
    let mut send = send;
    let _ = write_frame(&mut send, frame.msg_type(), &frame).await;
    let _ = send.finish();
}

/// Shape check: `host:port`, ≤ 256 chars, no whitespace; a single colon
/// (literal match only happens elsewhere — this is just sanity, §7.3).
pub fn valid_target(target: &str) -> bool {
    if target.is_empty() || target.len() > limits::MAX_TARGET_LEN {
        return false;
    }
    if target.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((host, port)) = target.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && !host.contains(':') && !port.is_empty() && port.parse::<u16>().is_ok()
}

/// Raw byte relay with mandatory half-close propagation (§7.5):
/// TCP FIN ⇄ iroh stream finish(), bounded buffering, backpressure via
/// blocking `write_all`. Runs both directions to completion; errors in one
/// direction surface in the other through the transports themselves.
async fn relay(send: SendStream, mut recv: RecvStream, tcp: TcpStream, idle_timeout: Duration) {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let mut send = send;

    let up = async {
        // iroh stream → target: on stream EOF propagate FIN to the socket.
        let res = pump(&mut recv, &mut tcp_write, idle_timeout).await;
        let _ = tcp_write.shutdown().await;
        res
    };
    let down = async {
        // target → iroh stream: on socket EOF propagate FIN on the stream.
        let res = pump(&mut tcp_read, &mut send, idle_timeout).await;
        let _ = send.finish();
        res
    };
    let (up_res, down_res) = tokio::join!(up, down);
    if let Err(e) = up_res {
        tracing::trace!("relay up-direction ended: {e}");
    }
    if let Err(e) = down_res {
        tracing::trace!("relay down-direction ended: {e}");
    }
}

/// Bounded, backpressured copy with an optional per-read deadline.
pub async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    idle_timeout: Duration,
) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = if idle_timeout.is_zero() {
            r.read(&mut buf).await?
        } else {
            match tokio::time::timeout(idle_timeout, r.read(&mut buf)).await {
                Ok(res) => res?,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "idle timeout",
                    ));
                }
            }
        };
        if n == 0 {
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
    }
}

/// Builds the daemon's Router with the single data-plane ALPN (§7.2).
pub async fn spawn_main_endpoint(
    state: Arc<State>,
    idle_timeout: Duration,
    net_opts: &crate::net::NetOpts,
    secret_key: iroh::SecretKey,
) -> Result<(Router, iroh::Endpoint), super::DaemonError> {
    let endpoint = crate::net::build_endpoint(
        secret_key,
        vec![DATA_ALPN.to_vec()],
        crate::net::EndpointRole::Main,
        net_opts,
    )
    .await
    .map_err(|e| super::DaemonError::Endpoint(e.to_string()))?;
    let handler = DataPlaneHandler::new(state, idle_timeout);
    let router = Router::builder(endpoint.clone())
        .accept(DATA_ALPN, handler)
        .spawn();
    Ok((router, endpoint))
}
