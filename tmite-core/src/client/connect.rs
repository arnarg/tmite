use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};
use tokio::time::MissedTickBehavior;

use crate::client::model::{ConnHandle, ConnRegistry, ForwardRow, PathRow, UiEvent};
use crate::client::session::{Session, SessionError};
use crate::fsio::{ClientStore, load_or_create_keypair, servers_toml_path};
use crate::net::{EndpointRole, NetOpts, build_endpoint};
use crate::stream_io::{read_frame, write_frame};
use n0_future::StreamExt;
use tmite_proto::alpn::DATA_ALPN;
use tmite_proto::frame::{DataDenyReason, DataFrame, SessionForward, TYPE_FORWARD, TYPE_VALIDATE};
use tmite_proto::limits;

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("invalid --fwd spec {spec:?}: {reason}")]
    BadSpec { spec: String, reason: &'static str },
    #[error("server {name:?} not found; pair first")]
    UnknownServer { name: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("fs error: {0}")]
    Fs(#[from] crate::fsio::FsError),
    #[error("forward to {target} not allowed: {reason:?}")]
    ForwardDenied {
        target: String,
        reason: DataDenyReason,
    },
    #[error("net error: {0}")]
    Net(#[from] crate::net::NetError),
    #[error("session error: {0}")]
    Session(#[from] SessionError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwdSpec {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub target: String,
}

/// Parses `SPEC` = `[LOCAL_ADDR:]LOCAL_PORT:TARGET` (§7.4). Target is
/// `host:port`; IPv6 target hosts are not supported in v0.1.
pub fn parse_fwd_spec(spec: &str) -> Result<FwdSpec, ConnectError> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (local_addr, local_port, target) = match parts.as_slice() {
        [port, thost, tport] => (None, *port, format!("{thost}:{tport}")),
        [laddr, port, thost, tport] => (Some(*laddr), *port, format!("{thost}:{tport}")),
        _ => {
            return Err(ConnectError::BadSpec {
                spec: spec.to_string(),
                reason: "expected [ADDR:]PORT:TARGET",
            });
        }
    };
    let local_port: u16 = local_port.parse().map_err(|_| ConnectError::BadSpec {
        spec: spec.to_string(),
        reason: "local port must be 1-65535",
    })?;
    let local_addr: IpAddr = match local_addr {
        Some(addr) => addr.parse().map_err(|_| ConnectError::BadSpec {
            spec: spec.to_string(),
            reason: "invalid local address",
        })?,
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    if !crate::daemon::main_ep::valid_target(&target) {
        return Err(ConnectError::BadSpec {
            spec: spec.to_string(),
            reason: "target must be host:port",
        });
    }
    Ok(FwdSpec {
        local_addr,
        local_port,
        target,
    })
}

pub struct ConnectParams {
    pub name: String,
    pub specs: Vec<FwdSpec>,
    pub data_dir: PathBuf,
    pub net_opts: NetOpts,
    /// TUI event channel (§7.4). When set, structured events are emitted,
    /// the plain-stdout UI is suppressed, and path/connection collectors
    /// run. `None` keeps the plain forwarding UI.
    pub events: Option<mpsc::UnboundedSender<UiEvent>>,
    /// Cooperative shutdown; the TUI signals `q`/Ctrl-C through it.
    pub shutdown: Arc<Notify>,
}

/// User-visible progress goes through tracing; the bin layer configures it.
pub trait ConnectUi: Send + Sync {
    fn listening(&self, spec: &FwdSpec);
    fn info(&self, msg: &str);
    fn warn(&self, msg: &str);
    fn denied(&self, target: &str, reason: &DataDenyReason);
    /// User-visible transport path change (printed to stdout).
    fn path(&self, msg: &str);
}

/// Runs `tmite connect`: binds listeners, connects eagerly, validates each
/// forward (§7.4), then accepts and relays.
pub async fn run(params: ConnectParams) -> Result<(), ConnectError> {
    let secret_key = load_or_create_keypair(&params.data_dir.join("keypair"))?;
    let store = ClientStore::load(&servers_toml_path(&params.data_dir))?;
    let entry = store
        .get(&params.name)
        .ok_or_else(|| ConnectError::UnknownServer {
            name: params.name.clone(),
        })?;
    let server_id: iroh::PublicKey =
        entry
            .node_id
            .parse()
            .map_err(|_| ConnectError::UnknownServer {
                name: params.name.clone(),
            })?;

    if let Some(tx) = &params.events {
        let _ = tx.send(UiEvent::Server {
            name: entry.name.clone(),
            node: server_id.to_string(),
        });
        let _ = tx.send(UiEvent::Forwards(
            params
                .specs
                .iter()
                .map(|spec| ForwardRow {
                    local: SocketAddr::new(spec.local_addr, spec.local_port).to_string(),
                    target: spec.target.clone(),
                })
                .collect(),
        ));
    }

    let endpoint = build_endpoint(
        secret_key,
        vec![DATA_ALPN.to_vec()],
        EndpointRole::Client,
        &params.net_opts,
    )
    .await?;

    let mut listeners = Vec::new();
    for (idx, spec) in params.specs.iter().enumerate() {
        let addr = SocketAddr::new(spec.local_addr, spec.local_port);
        let listener = TcpListener::bind(addr).await?;
        listeners.push((listener, idx));
    }

    // SESSION hello: announces the bound listeners for the daemon's status
    // view; sent on every (re)dial by the session (§7.2).
    let hello = DataFrame::Session {
        forwards: params
            .specs
            .iter()
            .map(|spec| SessionForward {
                local: SocketAddr::new(spec.local_addr, spec.local_port).to_string(),
                target: spec.target.clone(),
            })
            .collect(),
    };
    let hello = tmite_proto::frame::encode_frame(hello.msg_type(), &hello)
        .map_err(|e| ConnectError::Session(SessionError::Unreachable(e.to_string())))?;
    let session = Arc::new(Session::new(endpoint.clone(), server_id, hello));
    let registry = params
        .events
        .as_ref()
        .map(|tx| Arc::new(ConnRegistry::new(tx.clone())));

    // Eager connect + per-spec validation: fail fast before entering the
    // accept loop (§7.4).
    let conn = session.get().await?;
    for spec in &params.specs {
        validate_forward(&conn, spec).await?;
    }

    let ui: Arc<dyn ConnectUi> = match &params.events {
        Some(tx) => Arc::new(UiBridge { tx: tx.clone() }),
        None => Arc::new(ForwardingUi),
    };
    for (_, idx) in &listeners {
        ui.listening(&params.specs[*idx]);
    }
    if let Some(tx) = &params.events {
        let _ = tx.send(UiEvent::Started);
    }

    let shutdown = params.shutdown.clone();
    let mut tasks_path_watch = Vec::new();

    // Forward session state transitions (dialing/established/re-dials) to
    // the TUI; re-arms are unnecessary, the watch survives re-dials.
    if let Some(tx) = params.events.clone() {
        let watch_session = session.clone();
        let watch_shutdown = shutdown.clone();
        tasks_path_watch.push(tokio::spawn(async move {
            let mut rx = watch_session.status();
            let initial = rx.borrow_and_update().clone();
            if tx.send(UiEvent::SessionState(initial)).is_err() {
                return;
            }
            loop {
                tokio::select! {
                    _ = watch_shutdown.notified() => return,
                    changed = rx.changed() => match changed {
                        Ok(()) => {
                            let status = rx.borrow_and_update().clone();
                            if tx.send(UiEvent::SessionState(status)).is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    },
                }
            }
        }));
    }

    // Per-connection byte ticks for the TUI.
    if let Some(registry) = registry.clone() {
        let tx = params.events.clone().expect("registry implies events");
        let watch_shutdown = shutdown.clone();
        tasks_path_watch.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = watch_shutdown.notified() => return,
                    _ = interval.tick() => {
                        for (id, tx_bytes, rx_bytes) in registry.snapshot() {
                            if tx
                                .send(UiEvent::ConnectionBytes { id, tx: tx_bytes, rx: rx_bytes })
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                }
            }
        }));
    }

    // Watch transport paths until the connection drops; re-arm on re-dial.
    // TUI mode replaces per-event printing with periodic snapshots taken
    // from the current connection (covers re-dials automatically).
    let watch_session = session.clone();
    let watch_ui: Arc<dyn ConnectUi> = match &params.events {
        Some(tx) => Arc::new(UiBridge { tx: tx.clone() }),
        None => Arc::new(ForwardingUi),
    };
    let watch_events = params.events.clone();
    let watch_shutdown = shutdown.clone();
    tasks_path_watch.push(tokio::spawn(async move {
        loop {
            if let Some(tx) = &watch_events {
                let mut interval = tokio::time::interval(Duration::from_millis(500));
                interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = watch_shutdown.notified() => return,
                        _ = interval.tick() => {
                            let conn = match watch_session.get().await {
                                Ok(conn) => conn,
                                Err(_) => {
                                    let _ = tx.send(UiEvent::Paths(Vec::new()));
                                    continue;
                                }
                            };
                            let rows = snapshot_paths(&conn);
                            if tx.send(UiEvent::Paths(rows)).is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            let conn = match watch_session.get().await {
                Ok(conn) => conn,
                Err(e) => {
                    watch_ui.warn(&format!("cannot reach server for path watch: {e}"));
                    return;
                }
            };
            let mut events = conn.path_events();
            loop {
                let event = tokio::select! {
                    _ = watch_shutdown.notified() => return,
                    event = events.next() => event,
                };
                match event {
                    Some(iroh::endpoint::PathEvent::Opened { remote_addr, .. }) => {
                        watch_ui.path(&format!("path opened: {remote_addr}"));
                    }
                    Some(iroh::endpoint::PathEvent::Selected { remote_addr, .. }) => {
                        watch_ui.path(&format!("path selected: {remote_addr}"));
                    }
                    Some(iroh::endpoint::PathEvent::Closed { remote_addr, .. }) => {
                        watch_ui.path(&format!("path closed: {remote_addr}"));
                    }
                    Some(iroh::endpoint::PathEvent::Lagged { missed, .. }) => {
                        watch_ui.warn(&format!("path events lagged ({missed} dropped)"));
                    }
                    Some(_) => {}
                    None => break,
                }
            }
            watch_session.invalidate().await;
        }
    }));

    let mut tasks = Vec::new();
    for (listener, idx) in listeners {
        let session = session.clone();
        let ui = ui.clone();
        let registry = registry.clone();
        let shutdown = shutdown.clone();
        let spec = params.specs[idx].clone();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.notified() => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((tcp, peer)) => {
                                let session = session.clone();
                                let spec = spec.clone();
                                let ui = ui.clone();
                                let registry = registry.clone();
                                tokio::spawn(async move {
                                    handle_local(tcp, peer, session, spec, ui, registry, idx)
                                        .await;
                                });
                            }
                            Err(e) => {
                                ui.warn(&format!("accept failed: {e}"));
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            }
                        }
                    }
                }
            }
        }));
    }

    tokio::select! {
        _ = shutdown.notified() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    shutdown.notify_waiters();
    for task in tasks_path_watch.drain(..).chain(tasks.drain(..)) {
        task.abort();
    }
    endpoint.close().await;
    Ok(())
}

struct ForwardingUi;

/// ConnectUi that routes display strings into TUI events. `listening` is a
/// no-op: the forwards pane is seeded from the specs directly.
struct UiBridge {
    tx: mpsc::UnboundedSender<UiEvent>,
}

impl ConnectUi for UiBridge {
    fn listening(&self, _spec: &FwdSpec) {}
    fn info(&self, msg: &str) {
        let _ = self.tx.send(UiEvent::Notice(msg.to_string()));
    }
    fn warn(&self, msg: &str) {
        let _ = self.tx.send(UiEvent::Notice(msg.to_string()));
    }
    fn denied(&self, target: &str, reason: &DataDenyReason) {
        let _ = self.tx.send(UiEvent::Notice(format!(
            "forward to {target} denied: {reason:?}"
        )));
    }
    fn path(&self, msg: &str) {
        let _ = self.tx.send(UiEvent::Notice(msg.to_string()));
    }
}

/// Owned view of the connection's open paths for the TUI snapshot tick.
fn snapshot_paths(conn: &iroh::endpoint::Connection) -> Vec<PathRow> {
    conn.paths()
        .into_iter()
        .map(|p| {
            let rtt = p.rtt();
            PathRow {
                remote_addr: p.remote_addr().to_string(),
                relay: p.is_relay(),
                selected: p.is_selected(),
                rtt: if rtt.is_zero() { None } else { Some(rtt) },
                tx_bytes: p.stats().udp_tx.bytes,
                rx_bytes: p.stats().udp_rx.bytes,
            }
        })
        .collect()
}

impl ConnectUi for ForwardingUi {
    fn listening(&self, spec: &FwdSpec) {
        println!(
            "listening on {}:{} → {}",
            spec.local_addr, spec.local_port, spec.target
        );
    }
    fn info(&self, msg: &str) {
        tracing::info!("{msg}");
    }
    fn warn(&self, msg: &str) {
        tracing::warn!("{msg}");
    }
    fn denied(&self, target: &str, reason: &DataDenyReason) {
        tracing::warn!(%target, ?reason, "forward denied");
    }
    fn path(&self, msg: &str) {
        println!("{msg}");
    }
}

/// Startup fail-fast probe: asks the server whether `spec.target` would be
/// allowed, without dialing it (VALIDATE frame, §7.2).
async fn validate_forward(
    conn: &iroh::endpoint::Connection,
    spec: &FwdSpec,
) -> Result<(), ConnectError> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| ConnectError::Session(SessionError::Unreachable(e.to_string())))?;

    write_frame(
        &mut send,
        TYPE_VALIDATE,
        &DataFrame::Validate {
            target: spec.target.clone(),
        },
    )
    .await
    .map_err(|e| ConnectError::Session(SessionError::Unreachable(e.to_string())))?;

    let _ = send.finish();
    let reply = read_frame::<DataFrame>(&mut recv, limits::OK_DENY_WAIT)
        .await
        .map_err(|e| ConnectError::Session(SessionError::Unreachable(e.to_string())))?;

    match reply {
        (_, DataFrame::Ok {}) => Ok(()),
        (_, DataFrame::Deny { reason }) => Err(ConnectError::ForwardDenied {
            target: spec.target.clone(),
            reason,
        }),
        _ => Err(ConnectError::Session(SessionError::Unreachable(
            "unexpected reply to VALIDATE".into(),
        ))),
    }
}

/// Per accepted TCP conn: ensure session, open stream, FORWARD, await
/// OK/DENY, relay (§7.4). When a registry is present, the connection is
/// tracked and announced to the TUI; byte counters feed the periodic tick.
async fn handle_local(
    tcp: TcpStream,
    peer: SocketAddr,
    session: Arc<Session>,
    spec: FwdSpec,
    ui: Arc<dyn ConnectUi>,
    registry: Option<Arc<ConnRegistry>>,
    spec_idx: usize,
) {
    // Announce + auto-close: a guard so every early return (denied, dial
    // failure) still removes the connection from the TUI's totals.
    let conn_handle = registry
        .as_ref()
        .map(|reg| reg.create(spec_idx, peer.to_string()));
    struct ConnGuard {
        registry: Option<(Arc<ConnRegistry>, Arc<ConnHandle>)>,
    }
    impl Drop for ConnGuard {
        fn drop(&mut self) {
            if let Some((reg, handle)) = &self.registry {
                reg.close(handle);
            }
        }
    }
    let _guard = ConnGuard {
        registry: conn_handle
            .clone()
            .zip(registry.clone())
            .map(|(handle, reg)| (reg, handle)),
    };

    let plain_tx = AtomicU64::new(0);
    let plain_rx = AtomicU64::new(0);
    let (tx_counter, rx_counter): (&AtomicU64, &AtomicU64) = match &conn_handle {
        Some(handle) => (handle.tx(), handle.rx()),
        None => (&plain_tx, &plain_rx),
    };

    // Per-stream errors never touch session state; connection-level errors
    // reset it and we re-dial once here.
    for attempt in 0..2 {
        let conn = match session.get().await {
            Ok(conn) => conn,
            Err(e) => {
                ui.warn(&format!("cannot reach server: {e}"));
                return;
            }
        };

        let (mut send, mut recv) = match conn.open_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                session.invalidate().await;
                if attempt == 0 {
                    continue;
                }
                ui.warn(&format!("stream open failed: {e}"));
                return;
            }
        };

        if write_frame(
            &mut send,
            TYPE_FORWARD,
            &DataFrame::Forward {
                target: spec.target.clone(),
            },
        )
        .await
        .is_err()
        {
            session.invalidate().await;
            if attempt == 0 {
                continue;
            }
            ui.warn("failed to send FORWARD");
            return;
        }

        let reply = tokio::time::timeout(
            limits::OK_DENY_WAIT,
            crate::stream_io::read_frame::<DataFrame>(&mut recv, limits::OK_DENY_WAIT),
        )
        .await;
        match reply {
            Err(_) => {
                ui.warn("timed out awaiting FORWARD reply");
                return;
            }
            Ok(Err(e)) => {
                session.invalidate().await;
                if attempt == 0 {
                    continue;
                }
                ui.warn(&format!("lost connection while awaiting reply: {e}"));
                return;
            }
            Ok(Ok((_, DataFrame::Ok {}))) => {}
            Ok(Ok((_, DataFrame::Deny { reason }))) => {
                ui.denied(&spec.target, &reason);
                return;
            }
            Ok(Ok(_)) => {
                ui.warn("unexpected reply to FORWARD");
                return;
            }
        }

        if let (Some(reg), Some(handle)) = (&registry, &conn_handle) {
            reg.admit(handle);
        }

        relay_local(send, recv, tcp, tx_counter, rx_counter).await;
        return;
    }
}

/// Client-side relay with mandatory half-close propagation (§7.5), the
/// mirror of the daemon's `relay()` (main_ep.rs): iroh stream EOF ⇄ TCP FIN
/// in both directions. Without the `finish()` below, a local app closing its
/// socket never propagates FIN to the target and the relay deadlocks.
pub async fn relay_local(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    tcp: TcpStream,
    tx_counter: &AtomicU64,
    rx_counter: &AtomicU64,
) {
    use tokio::io::AsyncWriteExt as _;
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let up = async {
        // iroh stream → local app: on stream EOF propagate FIN to the socket.
        let res = crate::daemon::main_ep::pump_counted(
            &mut recv,
            &mut tcp_write,
            std::time::Duration::ZERO,
            rx_counter,
        )
        .await;
        let _ = tcp_write.shutdown().await;
        res
    };
    let down = async {
        // local app → iroh stream: on socket EOF propagate FIN on the stream.
        let res = crate::daemon::main_ep::pump_counted(
            &mut tcp_read,
            &mut send,
            std::time::Duration::ZERO,
            tx_counter,
        )
        .await;
        let _ = send.finish();
        res
    };
    let _ = tokio::join!(up, down);
}
