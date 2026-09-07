use std::path::PathBuf;

use iroh::PublicKey;
use iroh::SecretKey;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::fsio::{
    ClientStore, ServerEntry, load_or_create_keypair, now_rfc3339, servers_toml_path,
};
use crate::net::{EndpointRole, NetOpts, build_endpoint};
use crate::stream_io::{expect_frame, write_frame};
use tmite_proto::alpn::PAIRING_ALPN;
use tmite_proto::frame::{
    PairDenyReason, PairingFrame, TYPE_PAIR_CONFIRM, TYPE_PAIR_DENY, TYPE_PAIR_WAIT, TYPE_VERSION,
};
use tmite_proto::limits;
use tmite_proto::pairing::{CodeError, code_to_entropy, derive_invite_seed};

#[derive(Debug, Error)]
pub enum PairError {
    #[error(transparent)]
    InvalidCode(#[from] CodeError),
    #[error("invite endpoint unreachable")]
    Unreachable,
    #[error("pairing timed out awaiting the admin")]
    Timeout,
    #[error("admin denied pairing: {0:?}")]
    Denied(PairDenyReason),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("fs error: {0}")]
    Fs(#[from] crate::fsio::FsError),
    #[error("net error: {0}")]
    Net(#[from] crate::net::NetError),
    #[error(transparent)]
    Frame(#[from] crate::stream_io::FrameIoError),
}

impl PairError {
    /// Exit code mapping per design §10.1.
    pub fn exit_code(&self) -> i32 {
        match self {
            PairError::InvalidCode(_) => 2,
            PairError::Denied(PairDenyReason::AdminDenied) => 3,
            PairError::Denied(PairDenyReason::NameTaken)
            | PairError::Denied(PairDenyReason::ServerError) => 1,
            PairError::Timeout => 4,
            PairError::Unreachable | PairError::Net(_) => 5,
            _ => 1,
        }
    }
}

/// User-visible progress; the bin layer implements this with println!.
pub trait PairUi {
    fn info(&self, msg: &str);
    fn show_node_id(&self, id: &PublicKey);
    fn paired(&self, name: &str, server_id: &PublicKey);
}

pub struct PairParams {
    pub code: String,
    pub data_dir: PathBuf,
    pub client_version: String,
    pub net_opts: NetOpts,
    /// Local alias for the server; overrides the server-chosen name from
    /// `PAIR_CONFIRM` when set.
    pub name: Option<String>,
}

/// Runs the client side of the pairing flow (§5.1).
pub async fn run(params: PairParams, ui: &dyn PairUi) -> Result<String, PairError> {
    let entropy = Zeroizing::new(code_to_entropy(&params.code)?);
    let seed = Zeroizing::new(derive_invite_seed(&entropy));
    let invite_id = SecretKey::from_bytes(&seed).public();

    let secret_key = load_or_create_keypair(&params.data_dir.join("keypair"))?;
    let own_id = secret_key.public();
    ui.show_node_id(&own_id);
    ui.info("Connecting to invite server...");

    let endpoint = build_endpoint(
        secret_key,
        vec![PAIRING_ALPN.to_vec()],
        EndpointRole::Invite,
        &params.net_opts,
    )
    .await?;

    let conn = match tokio::time::timeout(
        limits::EP_ONLINE_TIMEOUT,
        endpoint.connect(invite_id, PAIRING_ALPN),
    )
    .await
    {
        Ok(Ok(conn)) => conn,
        Ok(Err(_)) => return Err(PairError::Unreachable),
        Err(_) => return Err(PairError::Timeout),
    };

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| PairError::Protocol(e.to_string()))?;

    write_frame(
        &mut send,
        TYPE_VERSION,
        &PairingFrame::Version {
            version: limits::CODE_VERSION,
        },
    )
    .await
    .map_err(protocol)?;
    write_frame(
        &mut send,
        PairingFrame::PairHello {
            client_version: params.client_version.clone(),
        }
        .msg_type(),
        &PairingFrame::PairHello {
            client_version: params.client_version,
        },
    )
    .await
    .map_err(protocol)?;

    expect_frame::<PairingFrame>(&mut recv, TYPE_PAIR_WAIT, limits::PAIRING_READ_TIMEOUT)
        .await
        .map_err(protocol)?;
    ui.info("Waiting for the server admin to confirm...");

    // Confirmation may legitimately take up to the 120 s prompt timeout plus
    // human latency; bound generously.
    let verdict = tokio::time::timeout(
        limits::PROMPT_TIMEOUT + limits::PAIRING_READ_TIMEOUT + limits::PAIRING_READ_TIMEOUT,
        async {
            let (t, frame) = crate::stream_io::read_frame::<PairingFrame>(
                &mut recv,
                limits::PAIRING_READ_TIMEOUT,
            )
            .await?;
            match frame {
                PairingFrame::PairConfirm { node_id, name } if t == TYPE_PAIR_CONFIRM => {
                    Ok((node_id, name))
                }
                PairingFrame::PairDeny { reason } if t == TYPE_PAIR_DENY => {
                    Err(PairError::Denied(reason))
                }
                _ => Err(PairError::Protocol(
                    "unexpected frame during pairing".into(),
                )),
            }
        },
    )
    .await
    .map_err(|_| PairError::Timeout)??;

    endpoint.close().await;

    let (server_id_bytes, name) = verdict;
    let server_id = PublicKey::from_bytes(&server_id_bytes)
        .map_err(|_| PairError::Protocol("invalid node id in confirm".into()))?;

    let store_path = servers_toml_path(&params.data_dir);
    let mut store = ClientStore::load(&store_path)?;
    let stored_name = params.name.clone().unwrap_or(name);
    store.upsert(ServerEntry {
        name: stored_name.clone(),
        node_id: server_id.to_string(),
        paired_at: now_rfc3339(),
    })?;
    store.save(&store_path)?;

    ui.paired(&stored_name, &server_id);
    Ok(stored_name)
}

fn protocol(e: crate::stream_io::FrameIoError) -> PairError {
    PairError::Protocol(e.to_string())
}
