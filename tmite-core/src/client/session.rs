use iroh::endpoint::Connection;
use iroh::{Endpoint, PublicKey};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::net::NetError;
use tmite_proto::alpn::DATA_ALPN;
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
pub struct Session {
    ep: Endpoint,
    server_id: PublicKey,
    conn: Mutex<Option<Connection>>,
}

impl Session {
    pub fn new(ep: Endpoint, server_id: PublicKey) -> Self {
        Self {
            ep,
            server_id,
            conn: Mutex::new(None),
        }
    }

    /// Returns a live connection, dialing first if needed. Called eagerly at
    /// startup; later calls re-dial only after connection-level failures.
    pub async fn get(&self) -> Result<Connection, SessionError> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.clone());
        }
        let conn = tokio::time::timeout(
            limits::EP_ONLINE_TIMEOUT,
            self.ep.connect(self.server_id, DATA_ALPN),
        )
        .await
        .map_err(|_| SessionError::Timeout)?
        .map_err(|e| SessionError::Unreachable(e.to_string()))?;

        // Defensive identity check: iroh guarantees this; assert anyway (§7.4).
        assert_eq!(conn.remote_id(), self.server_id, "pinned NodeId mismatch");
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Drops the cached connection after any connection-level failure.
    pub async fn invalidate(&self) {
        *self.conn.lock().await = None;
    }

    pub fn server_id(&self) -> PublicKey {
        self.server_id
    }
}
