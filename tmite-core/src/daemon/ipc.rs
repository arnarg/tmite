use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::daemon::invite::InviteManager;
use crate::daemon::state::State;
use tmite_proto::ipc::{
    self, AllowParams, AllowResult, DecideParams, ErrorCode, InviteParams, InviteResult, LsResult,
    Method, Reply, Request, RevokeParams, RevokeResult, RmParams, RmResult, StatusResult,
    StopResult,
};

pub struct DaemonHandle {
    pub state: Arc<State>,
    pub invites: Arc<InviteManager>,
    pub node_id: String,
    pub version: String,
    pub started: Instant,
    pub stop_tx: mpsc::UnboundedSender<()>,
}

#[derive(Debug, thiserror::Error)]
pub enum IpcServerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Runs the NDJSON-over-unix-socket IPC server (§9).
pub async fn serve(socket_path: PathBuf, handle: Arc<DaemonHandle>) -> Result<(), IpcServerError> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&socket_path);
    let listener = tokio::net::UnixListener::bind(&socket_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660));
    }

    tracing::info!(path = %socket_path.display(), "IPC server listening");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let handle = handle.clone();
                tokio::spawn(handle_conn(stream, handle));
            }
            Err(e) => {
                tracing::warn!("ipc accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

async fn handle_conn(stream: UnixStream, handle: Arc<DaemonHandle>) {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    let (tx, mut rx) = mpsc::unbounded_channel::<Reply>();

    let writer = tokio::spawn(async move {
        while let Some(reply) = rx.recv().await {
            let mut line = serde_json::to_string(&reply).unwrap_or_default();
            line.push('\n');
            if write_half.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            let _ = write_half.flush().await;
        }
    });

    loop {
        let Ok(Some(line)) = lines.next_line().await else {
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let request = match ipc::parse_request(line) {
            Ok(req) => req,
            Err(e) => {
                // Malformed line: bad_request and close (§9.1).
                let _ = tx.send(Reply::error(0, ErrorCode::BadRequest, e.to_string()));
                break;
            }
        };
        let handle = handle.clone();
        let tx = tx.clone();
        tokio::spawn(dispatch(request, handle, tx));
    }
    drop(tx);
    let _ = writer.await;
}

async fn dispatch(request: Request, handle: Arc<DaemonHandle>, tx: mpsc::UnboundedSender<Reply>) {
    let id = request.id;
    let Some(method) = Method::parse(&request.method) else {
        let _ = tx.send(Reply::error(id, ErrorCode::BadRequest, "unknown method"));
        return;
    };
    let result = match method {
        Method::PeerInvite => dispatch_invite(request, handle, &tx).await,
        Method::PeerInviteDecide => dispatch_decide(request, handle).await,
        Method::PeerAllow => dispatch_allow(request, handle).await,
        Method::PeerRevoke => dispatch_revoke(request, handle).await,
        Method::PeerLs => dispatch_ls(handle).await,
        Method::PeerRm => dispatch_rm(request, handle).await,
        Method::DaemonStatus => dispatch_status(handle).await,
        Method::DaemonStop => {
            let _ = handle.stop_tx.send(());
            Ok(json!(StopResult { stopping: true }))
        }
    };
    match result {
        Ok(value) => {
            let _ = tx.send(Reply::result(id, value));
        }
        Err(err) => {
            let _ = tx.send(Reply::error(id, err.0, err.1));
        }
    }
}

type DispatchError = (ErrorCode, String);

fn err<E: std::fmt::Display>(code: ErrorCode, e: E) -> DispatchError {
    (code, e.to_string())
}

async fn dispatch_invite(
    request: Request,
    handle: Arc<DaemonHandle>,
    tx: &mpsc::UnboundedSender<Reply>,
) -> Result<serde_json::Value, DispatchError> {
    let params: InviteParams =
        serde_json::from_value(request.params).map_err(|e| err(ErrorCode::BadRequest, e))?;
    if params.name.trim().is_empty() {
        return Err(err(ErrorCode::BadRequest, "name must not be empty"));
    }

    let created = handle
        .invites
        .create(params.name.trim(), params.ttl, request.id, tx.clone())
        .await
        .map_err(|e| (e.error_code(), e.to_string()))?;

    // The invite task emits `code`, `pair_request`, and possibly `expired`
    // events on `tx`; we just await the terminal result.
    let result = created
        .result
        .await
        .map_err(|e| err(ErrorCode::Internal, format!("invite vanished: {e}")))?;
    Ok(match result {
        InviteResult::Paired { .. } => json!(result),
        _ => json!(result),
    })
}

async fn dispatch_decide(
    request: Request,
    handle: Arc<DaemonHandle>,
) -> Result<serde_json::Value, DispatchError> {
    let params: DecideParams =
        serde_json::from_value(request.params).map_err(|e| err(ErrorCode::BadRequest, e))?;
    handle
        .invites
        .decide(&params.invite_id, params.accept)
        .await
        .map_err(|e| match e {
            crate::daemon::invite::DecideError::NotFound => (ErrorCode::NotFound, e.to_string()),
            crate::daemon::invite::DecideError::Expired => {
                (ErrorCode::InviteExpired, e.to_string())
            }
        })?;
    Ok(json!({ "status": if params.accept { "accepted" } else { "rejected" } }))
}

async fn dispatch_allow(
    request: Request,
    handle: Arc<DaemonHandle>,
) -> Result<serde_json::Value, DispatchError> {
    let params: AllowParams =
        serde_json::from_value(request.params).map_err(|e| err(ErrorCode::BadRequest, e))?;
    if !crate::daemon::main_ep::valid_target(&params.target) {
        return Err(err(ErrorCode::BadRequest, "target must be host:port"));
    }
    let index = handle
        .state
        .add_rule(&params.peer, &params.target)
        .map_err(|e| (e.error_code(), e.to_string()))?;
    Ok(json!(AllowResult { rule_index: index }))
}

async fn dispatch_revoke(
    request: Request,
    handle: Arc<DaemonHandle>,
) -> Result<serde_json::Value, DispatchError> {
    let params: RevokeParams =
        serde_json::from_value(request.params).map_err(|e| err(ErrorCode::BadRequest, e))?;
    let removed = handle
        .state
        .remove_rule(&params.peer, &params.target)
        .map_err(|e| (e.error_code(), e.to_string()))?;
    Ok(json!(RevokeResult { removed }))
}

async fn dispatch_ls(handle: Arc<DaemonHandle>) -> Result<serde_json::Value, DispatchError> {
    let (peers, rules) = handle.state.snapshot();
    let peers: Vec<_> = peers
        .into_iter()
        .map(|p| tmite_proto::ipc::PeerInfo {
            name: p.name,
            node_id: p.node_id,
            paired_at: p.paired_at,
            last_seen: p.last_seen,
        })
        .collect();
    let rules: Vec<_> = rules
        .into_iter()
        .map(|r| tmite_proto::ipc::RuleInfo {
            peer: r.peer,
            target: r.target,
            created_at: r.created_at,
        })
        .collect();
    let invites = handle.invites.list().await;
    Ok(json!(LsResult {
        peers,
        rules,
        invites,
    }))
}

async fn dispatch_rm(
    request: Request,
    handle: Arc<DaemonHandle>,
) -> Result<serde_json::Value, DispatchError> {
    let params: RmParams =
        serde_json::from_value(request.params).map_err(|e| err(ErrorCode::BadRequest, e))?;
    let removed = handle
        .state
        .remove_peer(&params.peer, params.force)
        .map_err(|e| (e.error_code(), e.to_string()))?;
    Ok(json!(RmResult { removed }))
}

async fn dispatch_status(handle: Arc<DaemonHandle>) -> Result<serde_json::Value, DispatchError> {
    let (peers, rules) = handle.state.snapshot();
    Ok(json!(StatusResult {
        version: handle.version.clone(),
        node_id: handle.node_id.clone(),
        uptime_secs: handle.started.elapsed().as_secs(),
        peers: peers.len(),
        rules: rules.len(),
        invites: handle.invites.pending_count().await,
    }))
}
