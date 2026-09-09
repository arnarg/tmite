use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, VarInt};
use iroh::{Endpoint, PublicKey, SecretKey};
use serde_json::json;
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use zeroize::Zeroizing;

use crate::daemon::notify::{Notification, Notifier};
use crate::daemon::state::{Peer, State};
use crate::fsio;
use crate::net::{EndpointRole, NetOpts, RejectDelay, build_endpoint};
use crate::stream_io::{expect_frame, write_frame};
use iroh::endpoint::RecvStream;
use tmite_proto::alpn::PAIRING_ALPN;
use tmite_proto::frame::{PairDenyReason, PairingFrame, TYPE_PAIR_HELLO, TYPE_VERSION};
use tmite_proto::ipc::{CodeEventData, InviteResult, PairRequestEventData, Reply};
use tmite_proto::limits;

#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    #[error("too many pending invites (max {})", limits::MAX_PENDING_INVITES)]
    Cap,
    #[error("peer \"{0}\" already exists")]
    NameTaken(String),
    #[error("invite endpoint setup failed: {0}")]
    Endpoint(String),
}

impl InviteError {
    pub fn error_code(&self) -> tmite_proto::ipc::ErrorCode {
        match self {
            InviteError::Cap => tmite_proto::ipc::ErrorCode::InviteCap,
            _ => tmite_proto::ipc::ErrorCode::Internal,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecideError {
    #[error("invite not found")]
    NotFound,
    #[error("invite already expired")]
    Expired,
}

enum InviteCmd {
    Decide(bool),
}

#[derive(Debug, Clone)]
enum Outcome {
    Paired { node_id: String },
    Rejected,
    Expired,
    Cancelled,
}

pub struct CreatedInvite {
    pub invite_id: String,
    pub code: String,
    pub ttl_secs: u64,
    pub result: oneshot::Receiver<InviteResult>,
}

type Entries = Arc<Mutex<std::collections::HashMap<String, InviteEntry>>>;

struct InviteEntry {
    shared: Arc<InviteShared>,
    cmd_tx: mpsc::UnboundedSender<InviteCmd>,
}

pub struct InviteShared {
    pub invite_id: String,
    pub name: String,
    pub deadline: tokio::time::Instant,
    pub state: Arc<State>,
    decision: Mutex<Option<bool>>,
    notify: Notify,
    cmd_rx: Mutex<mpsc::UnboundedReceiver<InviteCmd>>,
    result_tx: Mutex<Option<oneshot::Sender<InviteResult>>>,
    outcome_tx: mpsc::UnboundedSender<Outcome>,
    event_tx: mpsc::UnboundedSender<Reply>,
    notifier: Notifier,
    request_id: u64,
    delay: Mutex<RejectDelay>,
    peer_recorded: Mutex<bool>,
    /// Single pair-connection slot: only one pair connection may be in
    /// progress per invite (§5). Claimed by the accept loop before spawning
    /// the handler task; a second concurrent connection gets `PAIR_DENY
    /// { Busy }`.
    pair_busy: Mutex<bool>,
    /// The daemon's main-endpoint identity, delivered to the client in
    /// `PAIR_CONFIRM` so it can pin and dial the right node (§5, §10.3).
    server_node_id: PublicKey,
    entries: Entries,
}

impl InviteShared {
    async fn set_decision(&self, accept: bool) {
        *self.decision.lock().await = Some(accept);
        self.notify.notify_waiters();
    }

    async fn decision(&self) -> Option<bool> {
        *self.decision.lock().await
    }

    async fn claim_pair_slot(&self) -> bool {
        let mut busy = self.pair_busy.lock().await;
        if *busy {
            false
        } else {
            *busy = true;
            true
        }
    }

    async fn release_pair_slot(&self) {
        *self.pair_busy.lock().await = false;
    }

    fn emit(&self, event: &str, data: serde_json::Value) {
        let _ = self
            .event_tx
            .send(Reply::event(self.request_id, event, data));
    }

    async fn finish(&self, result: InviteResult) {
        if let Some(tx) = self.result_tx.lock().await.take() {
            let _ = tx.send(result);
        }
        self.entries.lock().await.remove(&self.invite_id);
    }
}

pub struct InviteManager {
    net_opts: NetOpts,
    state: Arc<State>,
    server_node_id: PublicKey,
    entries: Entries,
    notifier: Notifier,
}

impl InviteManager {
    pub fn new(
        net_opts: NetOpts,
        state: Arc<State>,
        server_node_id: PublicKey,
        notifier: Notifier,
    ) -> Self {
        Self {
            net_opts,
            state,
            server_node_id,
            entries: Arc::new(Mutex::new(std::collections::HashMap::new())),
            notifier,
        }
    }

    pub async fn pending_count(&self) -> usize {
        self.entries.lock().await.len()
    }

    pub async fn list(&self) -> Vec<tmite_proto::ipc::InviteInfo> {
        let entries = self.entries.lock().await;
        let mut v: Vec<_> = entries
            .values()
            .map(|e| tmite_proto::ipc::InviteInfo {
                invite_id: e.shared.invite_id.clone(),
                name: e.shared.name.clone(),
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Creates a pending invite: derives the endpoint key from a fresh code
    /// (§4.2), spawns the ephemeral invite endpoint, and wires IPC events.
    pub async fn create(
        &self,
        name: &str,
        ttl: Option<u64>,
        request_id: u64,
        event_tx: mpsc::UnboundedSender<Reply>,
    ) -> Result<CreatedInvite, InviteError> {
        if !self.state.is_name_free(name) {
            return Err(InviteError::NameTaken(name.to_string()));
        }
        if self.entries.lock().await.len() >= limits::MAX_PENDING_INVITES {
            return Err(InviteError::Cap);
        }

        let ttl_secs = ttl
            .unwrap_or(limits::DEFAULT_INVITE_TTL)
            .min(limits::MAX_INVITE_TTL);

        let entropy = Zeroizing::new(tmite_proto::pairing::generate_entropy());
        let code = tmite_proto::pairing::entropy_to_code(&entropy);
        let seed = Zeroizing::new(tmite_proto::pairing::derive_invite_seed(&entropy));
        let secret_key = SecretKey::from_bytes(&seed);
        let invite_node_id = secret_key.public();

        let mut id_bytes = [0u8; 16];
        tmite_proto::pairing::random_bytes(&mut id_bytes);
        let invite_id = fsio::hex(&id_bytes);

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (result_tx, result_rx) = oneshot::channel();
        let (outcome_tx, outcome_rx) = mpsc::unbounded_channel();

        let shared = Arc::new(InviteShared {
            invite_id: invite_id.clone(),
            name: name.to_string(),
            deadline: tokio::time::Instant::now() + Duration::from_secs(ttl_secs),
            state: self.state.clone(),
            decision: Mutex::new(None),
            notify: Notify::new(),
            cmd_rx: Mutex::new(cmd_rx),
            result_tx: Mutex::new(Some(result_tx)),
            outcome_tx,
            event_tx,
            notifier: self.notifier.clone(),
            request_id,
            delay: Mutex::new(RejectDelay::new()),
            peer_recorded: Mutex::new(false),
            pair_busy: Mutex::new(false),
            server_node_id: self.server_node_id,
            entries: self.entries.clone(),
        });

        self.entries.lock().await.insert(
            invite_id.clone(),
            InviteEntry {
                shared: shared.clone(),
                cmd_tx,
            },
        );

        let opts = self.net_opts.clone();
        let task_name = name.to_string();
        self.notifier.notify(Notification::InviteCreated {
            name: task_name.clone(),
            invite_id: invite_id.clone(),
            ttl_secs,
        });
        tokio::spawn(run_invite_endpoint(
            shared,
            secret_key,
            invite_node_id,
            task_name,
            code.clone(),
            opts,
            outcome_rx,
        ));

        Ok(CreatedInvite {
            invite_id,
            code,
            ttl_secs,
            result: result_rx,
        })
    }

    /// Applies an admin decision to a pending invite.
    pub async fn decide(&self, invite_id: &str, accept: bool) -> Result<(), DecideError> {
        let entry = self
            .entries
            .lock()
            .await
            .get(invite_id)
            .map(|e| e.cmd_tx.clone());
        match entry {
            Some(cmd_tx) => {
                if cmd_tx.send(InviteCmd::Decide(accept)).is_err() {
                    Err(DecideError::Expired)
                } else {
                    Ok(())
                }
            }
            None => Err(DecideError::NotFound),
        }
    }
}

async fn run_invite_endpoint(
    shared: Arc<InviteShared>,
    secret_key: SecretKey,
    invite_node_id: PublicKey,
    name: String,
    code: String,
    opts: NetOpts,
    outcome_rx: mpsc::UnboundedReceiver<Outcome>,
) {
    let endpoint = match build_endpoint(
        secret_key,
        vec![PAIRING_ALPN.to_vec()],
        EndpointRole::Invite,
        &opts,
    )
    .await
    {
        Ok(ep) => ep,
        Err(e) => {
            tracing::error!("invite endpoint setup failed: {e}");
            shared.finish(InviteResult::Expired).await;
            return;
        }
    };

    let ttl_secs = shared
        .deadline
        .duration_since(tokio::time::Instant::now())
        .as_secs();
    shared.emit(
        "code",
        json!(CodeEventData {
            invite_id: shared.invite_id.clone(),
            code,
            name,
            ttl_secs,
        }),
    );
    tracing::info!(
        "invite {id} up as {node} (ttl {ttl_secs}s)",
        id = shared.invite_id,
        node = invite_node_id,
        ttl_secs = ttl_secs
    );

    invite_serve(endpoint, shared, outcome_rx).await;
}

/// Runs the accept/decision loop on an already-built invite endpoint.
/// Split out of `run_invite_endpoint` so tests can drive it on an offline
/// loopback endpoint.
async fn invite_serve(
    endpoint: Endpoint,
    shared: Arc<InviteShared>,
    mut outcome_rx: mpsc::UnboundedReceiver<Outcome>,
) {
    let mut outcome: Option<Outcome> = None;
    loop {
        tokio::select! {
            biased;
            o = outcome_rx.recv() => {
                if let Some(o) = o { outcome = Some(o); }
                break;
            }
            cmd = async { shared.cmd_rx.lock().await.recv().await } => {
                match cmd {
                    Some(InviteCmd::Decide(accept)) => {
                        shared.set_decision(accept).await;
                        if !accept {
                            outcome = Some(Outcome::Rejected);
                            break;
                        }
                    }
                    None => {
                        outcome = Some(Outcome::Cancelled);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(shared.deadline) => {
                outcome = Some(Outcome::Expired);
                break;
            }
            incoming = endpoint.accept() => {
                match incoming {
                    Some(connecting) => {
                        let delay = { shared.delay.lock().await.delay() };
                        tokio::time::sleep(delay).await;
                        if tokio::time::Instant::now() >= shared.deadline {
                            outcome = Some(Outcome::Expired);
                            break;
                        }
                        match connecting.await {
                            Ok(conn) => {
                                { shared.delay.lock().await.reset(); }
                                if shared.claim_pair_slot().await {
                                    let s = shared.clone();
                                    tokio::spawn(handle_pair_conn(conn, s));
                                } else {
                                    tokio::spawn(refuse_pair_busy(conn));
                                }
                            }
                            Err(e) => {
                                tracing::debug!("invite connection failed: {e}");
                                { shared.delay.lock().await.escalate(); }
                            }
                        }
                    }
                    None => {
                        outcome = Some(Outcome::Cancelled);
                        break;
                    }
                }
            }
        }
    }

    if matches!(outcome, Some(Outcome::Rejected) | Some(Outcome::Expired)) {
        // Give in-flight connection tasks a moment to flush their PAIR_DENY.
        shared.notify.notify_waiters();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    endpoint.close().await;
    match outcome {
        Some(Outcome::Paired { node_id }) => shared.finish(InviteResult::Paired { node_id }).await,
        Some(Outcome::Rejected) => shared.finish(InviteResult::Rejected).await,
        Some(Outcome::Expired) => {
            shared.emit("expired", json!({}));
            shared.notifier.notify(Notification::InviteExpired {
                invite_id: shared.invite_id.clone(),
            });
            shared.finish(InviteResult::Expired).await;
        }
        _ => shared.finish(InviteResult::Expired).await,
    }
}

/// How long to wait for the client to finish its send side after writing a
/// terminal frame. A closing endpoint can only send CONNECTION_CLOSE frames,
/// so without this ack the verdict frame may never reach the client.
const VERDICT_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Drains the client's send stream until EOF (or timeout) so the terminal
/// frame we just wrote is delivered before the endpoint closes.
async fn wait_for_verdict_ack(recv: &mut RecvStream) {
    let _ = tokio::time::timeout(VERDICT_ACK_TIMEOUT, async {
        loop {
            match recv.read(&mut [0u8; 64]).await {
                Ok(Some(_)) => continue,
                _ => return,
            }
        }
    })
    .await;
}

/// Handles one pairing connection on the invite endpoint (§5).
///
/// The single pair slot is claimed by the accept loop before this task is
/// spawned; it is released here when the connection ends without a recorded
/// peer, so a client that vanished or failed its handshake cannot block a
/// legitimate retry.
async fn handle_pair_conn(conn: Connection, shared: Arc<InviteShared>) {
    handle_pair_conn_inner(conn, &shared).await;
    shared.release_pair_slot().await;
}

/// Refuses a pair connection that arrived while another one is active: only
/// one pair connection may be in progress per invite (§5).
async fn refuse_pair_busy(conn: Connection) {
    if let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let frame = PairingFrame::PairDeny {
            reason: PairDenyReason::Busy,
        };
        let _ = write_frame(&mut send, frame.msg_type(), &frame).await;
        let _ = send.finish();
        wait_for_verdict_ack(&mut recv).await;
    }
    conn.close(VarInt::from_u32(1), b"another pairing in progress");
}

async fn handle_pair_conn_inner(conn: Connection, shared: &InviteShared) {
    let remote = conn.remote_id();

    let (mut send, mut recv) = match conn.accept_bi().await {
        Ok(pair) => pair,
        Err(_) => {
            conn.close(VarInt::from_u32(1), b"handshake failed");
            return;
        }
    };

    macro_rules! reject {
        () => {{
            shared.delay.lock().await.escalate();
            conn.close(VarInt::from_u32(1), b"handshake failed");
            return;
        }};
    }

    match expect_frame::<PairingFrame>(&mut recv, TYPE_VERSION, limits::PAIRING_READ_TIMEOUT).await
    {
        Ok(PairingFrame::Version { version }) if version == limits::CODE_VERSION => {}
        _ => {
            reject!();
        }
    }
    match expect_frame::<PairingFrame>(&mut recv, TYPE_PAIR_HELLO, limits::PAIRING_READ_TIMEOUT)
        .await
    {
        Ok(PairingFrame::PairHello { .. }) => {}
        _ => {
            reject!();
        }
    }
    if !shared.state.is_name_free(&shared.name) {
        let frame = PairingFrame::PairDeny {
            reason: PairDenyReason::NameTaken,
        };
        let _ = write_frame(&mut send, frame.msg_type(), &frame).await;
        let _ = send.finish();
        wait_for_verdict_ack(&mut recv).await;
        reject!();
    }
    if write_frame(
        &mut send,
        PairingFrame::PairWait {}.msg_type(),
        &PairingFrame::PairWait {},
    )
    .await
    .is_err()
    {
        conn.close(VarInt::from_u32(1), b"handshake failed");
        return;
    }
    shared.emit(
        "pair_request",
        json!(PairRequestEventData {
            invite_id: shared.invite_id.clone(),
            node_id: remote.to_string(),
        }),
    );
    shared.notifier.notify(Notification::PairRequested {
        name: shared.name.clone(),
        node_id: remote.to_string(),
    });

    // A client is waiting; apply decision or timeouts (§5.3, §6.5). The
    // recv read detects a client that disconnects while waiting so it cannot
    // hold the pair slot (and the admin's prompt) for the full prompt
    // timeout: after PAIR_HELLO the client must stay silent, so any read
    // result means it is gone or misbehaving.
    let mut scratch = [0u8; 64];
    let deny = loop {
        tokio::select! {
            _ = shared.notify.notified() => {
                match shared.decision().await {
                    Some(true) => break None,
                    Some(false) => break Some(PairDenyReason::AdminDenied),
                    None => continue,
                }
            }
            read = recv.read(&mut scratch) => {
                match read {
                    Ok(None) | Err(_) => return,
                    Ok(Some(_)) => {
                        conn.close(VarInt::from_u32(1), b"handshake failed");
                        return;
                    }
                }
            }
            _ = tokio::time::sleep(limits::PROMPT_TIMEOUT) => break Some(PairDenyReason::Expired),
            _ = tokio::time::sleep_until(shared.deadline) => break Some(PairDenyReason::Expired),
        }
    };

    match deny {
        Some(reason) => {
            let frame = PairingFrame::PairDeny {
                reason: reason.clone(),
            };
            let _ = write_frame(&mut send, frame.msg_type(), &frame).await;
            let _ = send.finish();
            wait_for_verdict_ack(&mut recv).await;
            if reason == PairDenyReason::AdminDenied {
                shared.delay.lock().await.escalate();
            }
        }
        None => {
            let mut recorded = shared.peer_recorded.lock().await;
            if !*recorded {
                let peer = Peer {
                    name: shared.name.clone(),
                    node_id: remote.to_string(),
                    paired_at: fsio::now_rfc3339(),
                    last_seen: fsio::now_rfc3339(),
                };
                match shared.state.add_peer(peer) {
                    Ok(()) => {
                        *recorded = true;
                        drop(recorded);
                        shared.notifier.notify(Notification::PeerRegistered {
                            name: shared.name.clone(),
                            node_id: remote.to_string(),
                        });
                        {
                            shared.delay.lock().await.reset();
                        }
                        let frame = PairingFrame::PairConfirm {
                            node_id: *shared.server_node_id.as_bytes(),
                            name: shared.name.clone(),
                        };
                        let _ = write_frame(&mut send, frame.msg_type(), &frame).await;
                        let _ = send.finish();
                        wait_for_verdict_ack(&mut recv).await;
                        let _ = shared.outcome_tx.send(Outcome::Paired {
                            node_id: remote.to_string(),
                        });
                    }
                    Err(e) => {
                        drop(recorded);
                        tracing::warn!("pairing failed to record peer: {e}");
                        let frame = PairingFrame::PairDeny {
                            reason: PairDenyReason::ServerError,
                        };
                        let _ = write_frame(&mut send, frame.msg_type(), &frame).await;
                        let _ = send.finish();
                        wait_for_verdict_ack(&mut recv).await;
                        let _ = shared.outcome_tx.send(Outcome::Rejected);
                    }
                }
            } else {
                drop(recorded);
                // Unreachable while only one pair connection runs at a
                // time, but a racing connection can still land here after
                // the slot was released by a recorded peer; deny explicitly
                // rather than confirming an unregistered node id.
                let frame = PairingFrame::PairDeny {
                    reason: PairDenyReason::Busy,
                };
                let _ = write_frame(&mut send, frame.msg_type(), &frame).await;
                let _ = send.finish();
                wait_for_verdict_ack(&mut recv).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::EndpointAddr;
    use iroh::endpoint::SendStream;
    use iroh::endpoint::presets;
    use std::net::SocketAddr;
    use tmite_proto::frame::TYPE_PAIR_WAIT;

    fn test_shared(
        dir: &tempfile::TempDir,
        server_node_id: PublicKey,
    ) -> (
        Arc<InviteShared>,
        mpsc::UnboundedSender<InviteCmd>,
        oneshot::Receiver<InviteResult>,
        mpsc::UnboundedReceiver<Outcome>,
    ) {
        let state = State::load(&dir.path().join("state.toml")).unwrap();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (result_tx, result_rx) = oneshot::channel();
        let (outcome_tx, outcome_rx) = mpsc::unbounded_channel();
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(InviteShared {
            invite_id: "test".into(),
            name: "laptop".into(),
            deadline: tokio::time::Instant::now() + Duration::from_secs(60),
            state: Arc::new(state),
            decision: Mutex::new(None),
            notify: Notify::new(),
            cmd_rx: Mutex::new(cmd_rx),
            result_tx: Mutex::new(Some(result_tx)),
            outcome_tx,
            event_tx,
            notifier: Notifier::disabled(),
            request_id: 1,
            delay: Mutex::new(RejectDelay::new()),
            peer_recorded: Mutex::new(false),
            pair_busy: Mutex::new(false),
            server_node_id,
            entries: Arc::new(Mutex::new(std::collections::HashMap::new())),
        });
        (shared, cmd_tx, result_rx, outcome_rx)
    }

    async fn test_endpoint(sk: &SecretKey) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(sk.clone())
            .alpns(vec![PAIRING_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    async fn loopback_addr(ep: &Endpoint) -> SocketAddr {
        loop {
            if let Some(a) = ep.addr().ip_addrs().find(|s| s.ip().is_loopback()) {
                return *a;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn connect_and_hello(
        client_ep: &Endpoint,
        invite_ep: &Endpoint,
        invite_addr: SocketAddr,
    ) -> (Connection, SendStream, RecvStream) {
        let addr = EndpointAddr::new(invite_ep.id()).with_ip_addr(invite_addr);
        let conn = client_ep.connect(addr, PAIRING_ALPN).await.unwrap();
        let (mut send, recv) = conn.open_bi().await.unwrap();
        write_frame(
            &mut send,
            TYPE_VERSION,
            &PairingFrame::Version {
                version: limits::CODE_VERSION,
            },
        )
        .await
        .unwrap();
        let hello = PairingFrame::PairHello {
            client_version: "test".into(),
        };
        write_frame(&mut send, hello.msg_type(), &hello)
            .await
            .unwrap();
        (conn, send, recv)
    }

    async fn read_verdict(recv: &mut RecvStream) -> PairingFrame {
        let (_, frame) =
            crate::stream_io::read_frame::<PairingFrame>(recv, Duration::from_secs(10))
                .await
                .unwrap();
        frame
    }

    async fn expect_pair_wait(recv: &mut RecvStream) {
        let frame = expect_frame::<PairingFrame>(recv, TYPE_PAIR_WAIT, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(matches!(frame, PairingFrame::PairWait { .. }));
    }

    /// Regression for the concurrent-pair bug: a second pair connection
    /// arriving while one is active must get `PAIR_DENY { Busy }`, never a
    /// `PAIR_CONFIRM` for an unregistered node id.
    #[tokio::test(flavor = "multi_thread")]
    async fn second_concurrent_pair_connection_gets_busy_deny() {
        let dir = tempfile::TempDir::new().unwrap();
        let server_node_id = SecretKey::from_bytes(&[7u8; 32]).public();
        let (shared, cmd_tx, result_rx, outcome_rx) = test_shared(&dir, server_node_id);

        let invite_ep = test_endpoint(&SecretKey::from_bytes(&[1u8; 32])).await;
        let invite_addr = loopback_addr(&invite_ep).await;
        tokio::spawn(invite_serve(invite_ep.clone(), shared.clone(), outcome_rx));

        let client_a = test_endpoint(&SecretKey::from_bytes(&[2u8; 32])).await;
        let (conn_a, mut send_a, mut recv_a) =
            connect_and_hello(&client_a, &invite_ep, invite_addr).await;
        expect_pair_wait(&mut recv_a).await;

        let client_b = test_endpoint(&SecretKey::from_bytes(&[3u8; 32])).await;
        let (conn_b, mut send_b, mut recv_b) =
            connect_and_hello(&client_b, &invite_ep, invite_addr).await;
        let verdict_b = read_verdict(&mut recv_b).await;
        assert_eq!(
            verdict_b,
            PairingFrame::PairDeny {
                reason: PairDenyReason::Busy
            }
        );
        let _ = send_b.finish();
        drop(conn_b);
        drop(client_b);

        cmd_tx.send(InviteCmd::Decide(true)).unwrap();
        let verdict_a = read_verdict(&mut recv_a).await;
        match verdict_a {
            PairingFrame::PairConfirm { node_id, name } => {
                assert_eq!(node_id, *server_node_id.as_bytes());
                assert_eq!(name, "laptop");
            }
            other => panic!("expected PAIR_CONFIRM, got {other:?}"),
        }
        let _ = send_a.finish();

        let client_a_id = client_a.id().to_string();
        match tokio::time::timeout(Duration::from_secs(10), result_rx).await {
            Ok(Ok(InviteResult::Paired { node_id })) => {
                assert_eq!(node_id, client_a_id);
            }
            other => panic!("expected paired result, got {other:?}"),
        }
        assert!(
            !shared.state.is_name_free("laptop"),
            "peer must be recorded"
        );
        drop(conn_a);
        drop(client_a);
    }

    /// The pair slot must be released when a waiting client vanishes, so a
    /// legitimate retry gets a fresh PAIR_WAIT (design §5: reconnects are
    /// allowed while the admin is still deciding).
    #[tokio::test(flavor = "multi_thread")]
    async fn pair_slot_released_when_client_vanishes() {
        let dir = tempfile::TempDir::new().unwrap();
        let server_node_id = SecretKey::from_bytes(&[7u8; 32]).public();
        let (shared, _cmd_tx, _result_rx, outcome_rx) = test_shared(&dir, server_node_id);

        let invite_ep = test_endpoint(&SecretKey::from_bytes(&[1u8; 32])).await;
        let invite_addr = loopback_addr(&invite_ep).await;
        tokio::spawn(invite_serve(invite_ep.clone(), shared.clone(), outcome_rx));

        let client_a = test_endpoint(&SecretKey::from_bytes(&[2u8; 32])).await;
        let (conn_a, _send_a, mut recv_a) =
            connect_and_hello(&client_a, &invite_ep, invite_addr).await;
        expect_pair_wait(&mut recv_a).await;
        conn_a.close(VarInt::from_u32(0), b"gone");

        // Wait for the handler to notice the vanished client and release
        // the slot before the retry connects.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if !*shared.pair_busy.lock().await {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();

        let client_c = test_endpoint(&SecretKey::from_bytes(&[4u8; 32])).await;
        let (conn_c, _send_c, mut recv_c) =
            connect_and_hello(&client_c, &invite_ep, invite_addr).await;
        expect_pair_wait(&mut recv_c).await;
        drop(conn_c);
        drop(client_c);
    }
}
