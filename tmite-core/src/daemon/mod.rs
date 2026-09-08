use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::mpsc;

use crate::daemon::invite::InviteManager;
use crate::daemon::ipc::{DaemonHandle, serve};
use crate::daemon::state::State;
use crate::fsio::load_or_create_keypair;
use crate::net::NetOpts;

pub mod invite;
pub mod ipc;
pub mod main_ep;
pub mod state;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("fs error: {0}")]
    Fs(#[from] crate::fsio::FsError),
    #[error("state error: {0}")]
    State(#[from] state::StateError),
    #[error("ipc server error: {0}")]
    Ipc(#[from] ipc::IpcServerError),
    #[error("endpoint error: {0}")]
    Endpoint(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub data_dir: PathBuf,
    pub socket_path: PathBuf,
    pub idle_timeout: Duration,
    pub net_opts: NetOpts,
}

/// Assembles and runs the daemon until shutdown (§2).
pub async fn run(cfg: DaemonConfig) -> Result<(), DaemonError> {
    let keypair_path = cfg.data_dir.join("keypair");
    let secret_key = load_or_create_keypair(&keypair_path)?;
    let node_id = secret_key.public().to_string();

    let state = Arc::new(State::load(&cfg.data_dir.join("state.toml"))?);
    let invites = Arc::new(InviteManager::new(
        cfg.net_opts.clone(),
        state.clone(),
        secret_key.public(),
    ));

    let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
    let handle = Arc::new(DaemonHandle {
        state: state.clone(),
        invites: invites.clone(),
        node_id: node_id.clone(),
        version: crate::CRATE_VERSION.to_string(),
        started: std::time::Instant::now(),
        stop_tx,
    });

    let ipc_path = cfg.socket_path.clone();
    let ipc_handle = handle.clone();
    let _ipc_task = tokio::spawn(async move {
        if let Err(e) = serve(ipc_path, ipc_handle).await {
            tracing::error!("IPC server failed: {e}");
        }
    });

    let (router, _endpoint) =
        main_ep::spawn_main_endpoint(state.clone(), cfg.idle_timeout, &cfg.net_opts, secret_key)
            .await?;

    tracing::info!(
        node_id = %node_id,
        peers = state.snapshot().0.len(),
        "daemon ready"
    );

    let reason;
    tokio::select! {
        _ = stop_rx.recv() => {
            tracing::info!("daemon.stop received; shutting down");
            reason = "stopped";
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("ctrl-c received; shutting down");
            reason = "interrupted";
        }
    }

    router.shutdown().await.ok();
    let _ = std::fs::remove_file(&cfg.socket_path);
    tracing::info!("daemon shut down ({reason})");
    Ok(())
}
