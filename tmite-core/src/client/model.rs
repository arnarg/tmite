//! Plain view-model types for the `connect` TUI (§7.4).
//!
//! `tmite-core` produces and updates these; rendering lives in the `tmite`
//! binary. No terminal types here — everything is pure data so the model can
//! be unit-tested without a terminal.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

/// Session-level connectivity, mirrored from the client `Session` watch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Dialing,
    Established,
    Reconnecting { since: Instant },
}

/// Full session status: state plus the count of re-dials after the first
/// successful connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatus {
    pub state: SessionState,
    pub redials: u64,
}

/// One transport path to the server, from a `Connection::paths()` snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRow {
    pub remote_addr: String,
    pub relay: bool,
    pub selected: bool,
    /// `None` until the first RTT sample (e.g. just-opened paths).
    pub rtt: Option<Duration>,
    /// UDP datagram bytes including QUIC framing overhead.
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// A configured listener. Order matters: `ConnRow::spec` indexes into the
/// same list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRow {
    pub local: String,
    pub target: String,
}

/// One active proxied TCP connection. Only active connections are listed;
/// closed ones only bump `ConnectModel::closed_total`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnRow {
    pub id: u64,
    /// Local TCP client address, e.g. "127.0.0.1:55123".
    pub peer: String,
    /// Index into `ConnectModel::forwards`.
    pub spec: usize,
    pub opened_at: Instant,
    /// client → remote (local TCP read side).
    pub tx_bytes: u64,
    /// remote → client.
    pub rx_bytes: u64,
}

/// Everything the TUI renders. Owned by the terminal task in the `tmite`
/// binary; mutated only via [`ConnectModel::apply`].
#[derive(Debug, Clone, Default)]
pub struct ConnectModel {
    pub server_name: String,
    pub server_node: String,
    pub session: Option<SessionStatus>,
    pub started_at: Option<Instant>,
    pub paths: Vec<PathRow>,
    pub forwards: Vec<ForwardRow>,
    pub connections: Vec<ConnRow>,
    pub closed_total: u64,
    /// Byte totals folded in from closed connections (`ConnRow` counters are
    /// only kept for active ones). Undercounts ≤500 ms of traffic per close
    /// (the byte-tick interval); exact totals would need final bytes in the
    /// `ConnectionClosed` event.
    pub total_tx: u64,
    pub total_rx: u64,
    /// Transient warning/denied message with the instant it arrived.
    pub status: Option<(Instant, String)>,
}

impl ConnectModel {
    pub fn apply(&mut self, event: UiEvent) {
        match event {
            UiEvent::Server { name, node } => {
                self.server_name = name;
                self.server_node = node;
            }
            UiEvent::SessionState(status) => self.session = Some(status),
            UiEvent::Forwards(forwards) => self.forwards = forwards,
            UiEvent::Started => self.started_at = Some(Instant::now()),
            UiEvent::Paths(paths) => {
                self.paths = paths;
                self.paths.sort_by(|a, b| {
                    b.selected
                        .cmp(&a.selected)
                        .then(a.relay.cmp(&b.relay))
                        .then_with(|| a.remote_addr.cmp(&b.remote_addr))
                });
            }
            UiEvent::ConnectionOpened { id, peer, spec } => {
                if spec < self.forwards.len() {
                    self.connections.push(ConnRow {
                        id,
                        peer,
                        spec,
                        opened_at: Instant::now(),
                        tx_bytes: 0,
                        rx_bytes: 0,
                    });
                }
            }
            UiEvent::ConnectionBytes { id, tx, rx } => {
                if let Some(row) = self.connections.iter_mut().find(|c| c.id == id) {
                    row.tx_bytes = tx;
                    row.rx_bytes = rx;
                }
            }
            UiEvent::ConnectionClosed { id } => {
                if let Some(row) = self.connections.iter().find(|c| c.id == id) {
                    self.total_tx += row.tx_bytes;
                    self.total_rx += row.rx_bytes;
                }
                self.connections.retain(|c| c.id != id);
                self.closed_total += 1;
            }
            UiEvent::Notice(msg) => self.status = Some((Instant::now(), msg)),
        }
    }

    /// Active connection count per forward, indexed like `forwards`.
    pub fn active_per_forward(&self) -> Vec<usize> {
        let mut counts = vec![0; self.forwards.len()];
        for conn in &self.connections {
            if let Some(c) = counts.get_mut(conn.spec) {
                *c += 1;
            }
        }
        counts
    }
}

/// Events streamed to the TUI. The channel closing (senders dropped) means
/// `connect::run` has finished and the TUI should shut down.
#[derive(Debug, Clone)]
pub enum UiEvent {
    Server {
        name: String,
        node: String,
    },
    SessionState(SessionStatus),
    /// The configured forwards, sent once before any connection events.
    Forwards(Vec<ForwardRow>),
    /// Listeners are bound; the session clock starts.
    Started,
    /// Full path snapshot; replaces the previous list.
    Paths(Vec<PathRow>),
    ConnectionOpened {
        id: u64,
        peer: String,
        spec: usize,
    },
    ConnectionClosed {
        id: u64,
    },
    ConnectionBytes {
        id: u64,
        tx: u64,
        rx: u64,
    },
    /// Transient display-only message (warnings, denials).
    Notice(String),
}

/// Tracks active proxied connections and emits their lifecycle events.
pub struct ConnRegistry {
    events: mpsc::UnboundedSender<UiEvent>,
    inner: Mutex<RegistryInner>,
}

struct RegistryInner {
    next_id: u64,
    conns: HashMap<u64, Arc<ConnHandle>>,
}

pub struct ConnHandle {
    pub id: u64,
    pub spec: usize,
    pub peer: String,
    tx: AtomicU64,
    rx: AtomicU64,
    started: AtomicBool,
}

impl ConnHandle {
    /// Bytes copied client → remote (counted on the local TCP read side).
    pub fn tx(&self) -> &AtomicU64 {
        &self.tx
    }

    /// Bytes copied remote → client (counted on the stream recv side).
    pub fn rx(&self) -> &AtomicU64 {
        &self.rx
    }
}

impl ConnRegistry {
    pub fn new(events: mpsc::UnboundedSender<UiEvent>) -> Self {
        Self {
            events,
            inner: Mutex::new(RegistryInner {
                next_id: 0,
                conns: HashMap::new(),
            }),
        }
    }

    /// Allocates an id for an accepted TCP connection. Emits nothing yet;
    /// call [`ConnRegistry::admit`] once the server approved the FORWARD.
    pub fn create(self: &Arc<Self>, spec: usize, peer: String) -> Arc<ConnHandle> {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.next_id;
        inner.next_id += 1;
        let handle = Arc::new(ConnHandle {
            id,
            spec,
            peer,
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            started: AtomicBool::new(false),
        });
        inner.conns.insert(id, handle.clone());
        handle
    }

    /// Marks a connection as relaying and announces it to the TUI.
    pub fn admit(&self, handle: &ConnHandle) {
        if !handle.started.swap(true, Ordering::Relaxed) {
            let _ = self.events.send(UiEvent::ConnectionOpened {
                id: handle.id,
                peer: handle.peer.clone(),
                spec: handle.spec,
            });
        }
    }

    /// Removes a connection and announces its closure. Safe to call for
    /// handles that were never admitted (failed/denied dials); they still
    /// count toward the closed total so the footer reflects activity.
    pub fn close(self: &Arc<Self>, handle: &ConnHandle) {
        if self
            .inner
            .lock()
            .unwrap()
            .conns
            .remove(&handle.id)
            .is_some()
        {
            let _ = self
                .events
                .send(UiEvent::ConnectionClosed { id: handle.id });
        }
    }

    /// Byte counters of all started connections, for the periodic tick.
    pub fn snapshot(&self) -> Vec<(u64, u64, u64)> {
        self.inner
            .lock()
            .unwrap()
            .conns
            .values()
            .filter(|h| h.started.load(Ordering::Relaxed))
            .map(|h| {
                (
                    h.id,
                    h.tx.load(Ordering::Relaxed),
                    h.rx.load(Ordering::Relaxed),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> ConnectModel {
        let mut m = ConnectModel::default();
        m.apply(UiEvent::Server {
            name: "lab".into(),
            node: "z6h7".into(),
        });
        m.apply(UiEvent::SessionState(SessionStatus {
            state: SessionState::Dialing,
            redials: 0,
        }));
        m.forwards = vec![
            ForwardRow {
                local: "127.0.0.1:2222".into(),
                target: "localhost:22".into(),
            },
            ForwardRow {
                local: "127.0.0.1:5432".into(),
                target: "db:5432".into(),
            },
        ];
        m
    }

    #[test]
    fn paths_sorted_selected_first_then_direct() {
        let mut m = model();
        m.apply(UiEvent::Paths(vec![
            PathRow {
                remote_addr: "10.0.0.1:1".into(),
                relay: false,
                selected: false,
                rtt: None,
                tx_bytes: 0,
                rx_bytes: 0,
            },
            PathRow {
                remote_addr: "relay.url".into(),
                relay: true,
                selected: true,
                rtt: None,
                tx_bytes: 0,
                rx_bytes: 0,
            },
            PathRow {
                remote_addr: "10.0.0.2:2".into(),
                relay: false,
                selected: true,
                rtt: None,
                tx_bytes: 0,
                rx_bytes: 0,
            },
        ]));
        let addrs: Vec<&str> = m.paths.iter().map(|p| p.remote_addr.as_str()).collect();
        assert_eq!(addrs, ["10.0.0.2:2", "relay.url", "10.0.0.1:1"]);
    }

    #[test]
    fn connection_lifecycle_updates_model() {
        let mut m = model();
        m.apply(UiEvent::ConnectionOpened {
            id: 1,
            peer: "127.0.0.1:5".into(),
            spec: 1,
        });
        m.apply(UiEvent::ConnectionOpened {
            id: 2,
            peer: "127.0.0.1:6".into(),
            spec: 0,
        });
        assert_eq!(m.connections.len(), 2);
        assert_eq!(m.active_per_forward(), [1, 1]);

        m.apply(UiEvent::ConnectionBytes {
            id: 1,
            tx: 100,
            rx: 200,
        });
        assert_eq!(m.connections[0].tx_bytes, 100);
        assert_eq!(m.connections[0].rx_bytes, 200);

        m.apply(UiEvent::ConnectionClosed { id: 1 });
        assert_eq!(m.connections.len(), 1);
        assert_eq!(m.connections[0].id, 2);
        assert_eq!(m.closed_total, 1);
        assert_eq!(m.total_tx, 100);
        assert_eq!(m.total_rx, 200);
    }

    #[test]
    fn closed_unadmitted_connection_only_bumps_total() {
        let mut m = model();
        m.apply(UiEvent::ConnectionClosed { id: 7 });
        assert!(m.connections.is_empty());
        assert_eq!(m.closed_total, 1);
    }
}
