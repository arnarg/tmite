use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::client::session::{Session, SessionError};
use crate::fsio::{ClientStore, load_or_create_keypair, servers_toml_path};
use crate::net::{EndpointRole, NetOpts, build_endpoint};
use crate::stream_io::{read_frame, write_frame};
use tmite_proto::alpn::DATA_ALPN;
use tmite_proto::frame::{DataDenyReason, DataFrame, TYPE_FORWARD, TYPE_VALIDATE};
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
}

/// User-visible progress goes through tracing; the bin layer configures it.
pub trait ConnectUi: Send + Sync {
    fn listening(&self, spec: &FwdSpec);
    fn info(&self, msg: &str);
    fn warn(&self, msg: &str);
    fn denied(&self, target: &str, reason: &DataDenyReason);
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

    let endpoint = build_endpoint(
        secret_key,
        vec![DATA_ALPN.to_vec()],
        EndpointRole::Client,
        &params.net_opts,
    )
    .await?;
    let session = Arc::new(Session::new(endpoint.clone(), server_id));

    let mut listeners = Vec::new();
    for spec in &params.specs {
        let addr = SocketAddr::new(spec.local_addr, spec.local_port);
        let listener = TcpListener::bind(addr).await?;
        listeners.push((listener, spec.clone()));
    }

    // Eager connect + per-spec validation: fail fast before entering the
    // accept loop (§7.4).
    let conn = session.get().await?;
    for spec in &params.specs {
        validate_forward(&conn, spec).await?;
    }

    let ui: Arc<dyn ConnectUi> = Arc::new(ForwardingUi);
    for (_, spec) in &listeners {
        ui.listening(spec);
    }

    let shutdown = Arc::new(Notify::new());
    let mut tasks = Vec::new();
    for (listener, spec) in listeners {
        let session = session.clone();
        let ui: Arc<dyn ConnectUi> = Arc::new(ForwardingUi);
        let shutdown = shutdown.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.notified() => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((tcp, _peer)) => {
                                let session = session.clone();
                                let spec = spec.clone();
                                let ui = ui.clone();
                                tokio::spawn(async move {
                                    handle_local(tcp, session, spec, ui).await;
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
    for task in tasks {
        task.abort();
    }
    endpoint.close().await;
    Ok(())
}

struct ForwardingUi;

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
}

/// Startup fail-fast probe: asks the server whether `spec.target` would be
/// allowed, without dialing it (VALIDATE frame, §7.2).
async fn validate_forward(conn: &iroh::endpoint::Connection, spec: &FwdSpec) -> Result<(), ConnectError> {
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
/// OK/DENY, relay (§7.4).
async fn handle_local(
    tcp: TcpStream,
    session: Arc<Session>,
    spec: FwdSpec,
    ui: Arc<dyn ConnectUi>,
) {
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

        let (mut tcp_read, mut tcp_write) = tcp.into_split();
        let up = crate::daemon::main_ep::pump(&mut recv, &mut tcp_write, std::time::Duration::ZERO);
        tokio::pin!(up);
        let down =
            crate::daemon::main_ep::pump(&mut tcp_read, &mut send, std::time::Duration::ZERO);
        tokio::pin!(down);
        let _ = tokio::join!(up, down);
        return;
    }
}
