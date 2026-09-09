//! Live data-plane session registry backing `tmite admin status` (pull model):
//! one entry per connected peer, with announced forwards (SESSION frame)
//! and on-demand iroh path snapshots.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use iroh::endpoint::Connection;

use tmite_proto::ipc::{ForwardInfo, PathInfo, PathKind, SessionInfo};

/// One announced local listener, from the client's SESSION frame.
#[derive(Debug, Clone)]
pub struct AnnouncedForward {
    pub local: String,
    pub target: String,
}

/// Per-connection state. Kept alive via `Arc` so in-flight stream handlers
/// can keep bumping `live` even while a replacement connection registers.
#[derive(Debug)]
pub struct SessionEntry {
    pub peer_name: String,
    pub node_id: String,
    pub connected_at: Instant,
    conn: Connection,
    forwards: Mutex<Vec<AnnouncedForward>>,
    live: Mutex<HashMap<String, usize>>,
}

impl SessionEntry {
    pub fn new(peer_name: String, node_id: String, conn: Connection) -> Arc<Self> {
        Arc::new(Self {
            peer_name,
            node_id,
            connected_at: Instant::now(),
            conn,
            forwards: Mutex::new(Vec::new()),
            live: Mutex::new(HashMap::new()),
        })
    }

    /// Replaces the announced forwards (a fresh SESSION frame per re-dial).
    pub fn set_forwards(&self, forwards: Vec<AnnouncedForward>) {
        *self.forwards.lock().expect("forwards lock poisoned") = forwards;
    }

    /// Counts a stream that got its OK and started relaying.
    pub fn forward_open(&self, target: &str) {
        *self
            .live
            .lock()
            .expect("live lock poisoned")
            .entry(target.to_string())
            .or_insert(0) += 1;
    }

    /// Counts a finished relay. Ignores unknown targets (stale close).
    pub fn forward_close(&self, target: &str) {
        let mut live = self.live.lock().expect("live lock poisoned");
        if let Some(count) = live.get_mut(target) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                live.remove(target);
            }
        }
    }

    fn snapshot(&self) -> SessionInfo {
        let forwards: Vec<ForwardInfo> = {
            let forwards = self.forwards.lock().expect("forwards lock poisoned");
            let live = self.live.lock().expect("live lock poisoned");
            forwards
                .iter()
                .map(|f| ForwardInfo {
                    local: f.local.clone(),
                    target: f.target.clone(),
                    live: live.get(&f.target).copied().unwrap_or(0),
                })
                .collect()
        };
        let paths = self
            .conn
            .paths()
            .iter()
            .map(|path| PathInfo {
                kind: if path.is_relay() {
                    PathKind::Relay
                } else {
                    PathKind::Direct
                },
                addr: Some(path.remote_addr().to_string()),
                selected: path.is_selected(),
                rtt_ms: Some(path.rtt().as_millis().min(u64::MAX as u128) as u64),
            })
            .collect();
        SessionInfo {
            connected_secs: self.connected_at.elapsed().as_secs(),
            forwards,
            paths,
        }
    }
}

/// Registry of live data-plane connections, keyed by lowercase node id.
#[derive(Debug, Clone, Default)]
pub struct Sessions {
    inner: Arc<Mutex<HashMap<String, Arc<SessionEntry>>>>,
}

impl Sessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts (or replaces, on client re-dial) the entry for a node id.
    pub fn register(&self, entry: Arc<SessionEntry>) {
        self.inner
            .lock()
            .expect("sessions lock poisoned")
            .insert(entry.node_id.to_lowercase(), entry);
    }

    /// Removes the entry only if it is still this connection's (a re-dial
    /// may have replaced it while the old accept loop was winding down).
    pub fn unregister(&self, entry: &Arc<SessionEntry>) {
        let mut sessions = self.inner.lock().expect("sessions lock poisoned");
        if sessions
            .get(&entry.node_id.to_lowercase())
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            sessions.remove(&entry.node_id.to_lowercase());
        }
    }

    /// Snapshots the given node's session state, if connected.
    pub fn peer_snapshot(&self, node_id_hex: &str) -> Option<SessionInfo> {
        self.inner
            .lock()
            .expect("sessions lock poisoned")
            .get(&node_id_hex.to_lowercase())
            .map(|entry| entry.snapshot())
    }
}
