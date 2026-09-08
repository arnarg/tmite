use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, VarInt};
use iroh::{PublicKey, SecretKey};
use serde_json::json;
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use zeroize::Zeroizing;

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
    request_id: u64,
    delay: Mutex<RejectDelay>,
    peer_recorded: Mutex<bool>,
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
    entries: Entries,
}

impl InviteManager {
    pub fn new(net_opts: NetOpts, state: Arc<State>) -> Self {
        Self {
            net_opts,
            state,
            entries: Arc::new(Mutex::new(std::collections::HashMap::new())),
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
            request_id,
            delay: Mutex::new(RejectDelay::new()),
            peer_recorded: Mutex::new(false),
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
    mut outcome_rx: mpsc::UnboundedReceiver<Outcome>,
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
                                let s = shared.clone();
                                tokio::spawn(handle_pair_conn(conn, s));
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

    let _ = invite_node_id;
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
async fn handle_pair_conn(conn: Connection, shared: Arc<InviteShared>) {
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

    // A client is waiting; apply decision or timeouts (§5.3, §6.5).
    let deny = loop {
        tokio::select! {
            _ = shared.notify.notified() => {
                match shared.decision().await {
                    Some(true) => break None,
                    Some(false) => break Some(PairDenyReason::AdminDenied),
                    None => continue,
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
                        {
                            shared.delay.lock().await.reset();
                        }
                        let frame = PairingFrame::PairConfirm {
                            node_id: *remote.as_bytes(),
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
                let frame = PairingFrame::PairConfirm {
                    node_id: *remote.as_bytes(),
                    name: shared.name.clone(),
                };
                let _ = write_frame(&mut send, frame.msg_type(), &frame).await;
                let _ = send.finish();
                wait_for_verdict_ack(&mut recv).await;
            }
        }
    }
}
