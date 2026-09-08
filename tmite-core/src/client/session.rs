use iroh::endpoint::Connection;
use iroh::{Endpoint, PublicKey};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use thiserror::Error;
use tokio::sync::{Mutex, watch};

use crate::client::model::{SessionState, SessionStatus};
use crate::net::NetError;
use crate::stream_io::{self, FrameIoError};
use tmite_proto::alpn::DATA_ALPN;
use tmite_proto::frame::DataFrame;
use tmite_proto::limits;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("server unreachable: {0}")]
    Unreachable(String),
    #[error("dial timed out")]
    Timeout,
    #[error("net error: {0}")]
    Net(#[from] NetError),
}

/// Client session: one iroh connection to the server, established eagerly at
/// startup and re-established after connection-level failures (§7.4).
///
/// `hello` is an encoded SESSION frame; it is sent on a dedicated stream
/// after every successful dial so the daemon's status view knows the
/// client's announced listeners.
pub struct Session {
    ep: Endpoint,
    server_id: PublicKey,
    hello: Vec<u8>,
    conn: Mutex<Option<Connection>>,
    status_tx: watch::Sender<SessionStatus>,
    redials: AtomicU64,
    was_established: AtomicBool,
}

impl Session {
    pub fn new(ep: Endpoint, server_id: PublicKey, hello: Vec<u8>) -> Self {
        let (status_tx, _) = watch::channel(SessionStatus {
            state: SessionState::Dialing,
            redials: 0,
        });
        Self {
            ep,
            server_id,
            hello,
            conn: Mutex::new(None),
            status_tx,
            redials: AtomicU64::new(0),
            was_established: AtomicBool::new(false),
        }
    }

    /// Watch for session state changes (§7.4). The current value is
    /// readable immediately; updates are sent on every state transition.
    pub fn status(&self) -> watch::Receiver<SessionStatus> {
        self.status_tx.subscribe()
    }

    fn set_state(&self, state: SessionState) {
        let redials = self.redials.load(Ordering::Relaxed);
        self.status_tx.send_if_modified(|s| {
            if s.state == state && s.redials == redials {
                false
            } else {
                s.state = state;
                s.redials = redials;
                true
            }
        });
    }

    /// Returns a live connection, dialing first if needed. Called eagerly at
    /// startup; later calls re-dial only after connection-level failures.
    pub async fn get(&self) -> Result<Connection, SessionError> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.clone());
        }
        if self.was_established.load(Ordering::Relaxed) {
            self.redials.fetch_add(1, Ordering::Relaxed);
        }
        self.set_state(SessionState::Dialing);
        let conn = tokio::time::timeout(
            limits::EP_ONLINE_TIMEOUT,
            self.ep.connect(self.server_id, DATA_ALPN),
        )
        .await
        .map_err(|_| SessionError::Timeout)?
        .map_err(|e| SessionError::Unreachable(e.to_string()))?;

        // Defensive identity check: iroh guarantees this; assert anyway (§7.4).
        assert_eq!(conn.remote_id(), self.server_id, "pinned NodeId mismatch");
        if let Err(e) = self.send_hello(&conn).await {
            return Err(SessionError::Unreachable(format!("session hello: {e}")));
        }
        self.was_established.store(true, Ordering::Relaxed);
        self.set_state(SessionState::Established);
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Announces the local listeners on a dedicated control stream (§7.2).
    async fn send_hello(&self, conn: &Connection) -> Result<(), FrameIoError> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| FrameIoError::Io(std::io::Error::other(e.to_string())))?;
        send.write_all(&self.hello)
            .await
            .map_err(|e| FrameIoError::Io(std::io::Error::other(e.to_string())))?;
        let _ = send.finish();
        stream_io::expect_frame::<DataFrame>(
            &mut recv,
            tmite_proto::frame::TYPE_OK,
            limits::OK_DENY_WAIT,
        )
        .await?;
        Ok(())
    }

    /// Drops the cached connection after any connection-level failure.
    pub async fn invalidate(&self) {
        *self.conn.lock().await = None;
        self.set_state(SessionState::Reconnecting {
            since: Instant::now(),
        });
    }

    pub fn server_id(&self) -> PublicKey {
        self.server_id
    }
}
