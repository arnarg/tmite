use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use iroh::endpoint::{QuicTransportConfig, RelayMode, VarInt};
use iroh::{Endpoint, SecretKey, endpoint::presets};
use thiserror::Error;
use tmite_proto::limits;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("binding endpoint failed: {0}")]
    Bind(String),
    #[error("endpoint failed to come online within {secs:?}")]
    OnlineTimeout { secs: u64 },
    #[error("invalid relay url: {0}")]
    BadRelayUrl(String),
    #[error("invalid pkarr url: {0}")]
    BadPkarrUrl(String),
}

/// Custom infrastructure overrides (`--relay`, `--pkarr`).
#[derive(Debug, Clone, Default)]
pub struct NetOpts {
    pub relay_urls: Vec<String>,
    pub pkarr_url: Option<String>,
    /// Fixed UDP port for the daemon main endpoint (firewall pinning).
    /// Ignored for ephemeral (`Invite`) endpoints, which bind a random port.
    pub bind_port: Option<u16>,
}

/// Which role an endpoint plays; determines transport tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    /// Daemon main data-plane endpoint: caps incoming bidi streams at 256.
    Main,
    /// Ephemeral invite endpoint: default transport.
    Invite,
    /// Client endpoint: keep-alive + generous idle timeout.
    Client,
}

fn transport_config(role: EndpointRole) -> QuicTransportConfig {
    let builder = QuicTransportConfig::builder();
    match role {
        EndpointRole::Main => builder
            .max_concurrent_bidi_streams(VarInt::from_u32(limits::MAX_CONCURRENT_BIDI_STREAMS))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .build(),
        EndpointRole::Invite => builder.build(),
        EndpointRole::Client => builder
            .keep_alive_interval(limits::QUIC_KEEP_ALIVE)
            .max_idle_timeout(Some(iroh::endpoint::IdleTimeout::from(VarInt::from_u32(
                limits::QUIC_MAX_IDLE_TIMEOUT.as_millis() as u32,
            ))))
            .build(),
    }
}

/// Single endpoint construction path so option sets cannot diverge (design §11).
pub async fn build_endpoint(
    secret_key: SecretKey,
    alpns: Vec<Vec<u8>>,
    role: EndpointRole,
    opts: &NetOpts,
) -> Result<Endpoint, NetError> {
    let transport = transport_config(role);
    let custom = opts.pkarr_url.is_some() || !opts.relay_urls.is_empty();

    let builder = if custom {
        use iroh::address_lookup::pkarr::{PkarrPublisher, PkarrResolver};
        let mut builder = Endpoint::builder(presets::Minimal);
        if opts.relay_urls.is_empty() {
            builder = builder.relay_mode(RelayMode::Disabled);
        } else {
            let mut urls = Vec::new();
            for raw in &opts.relay_urls {
                let url: iroh::RelayUrl = raw
                    .parse()
                    .map_err(|_| NetError::BadRelayUrl(raw.clone()))?;
                urls.push(url);
            }
            builder = builder.relay_mode(RelayMode::custom(urls));
        }
        if let Some(raw) = &opts.pkarr_url {
            let url: url::Url = raw
                .parse()
                .map_err(|_| NetError::BadPkarrUrl(raw.clone()))?;
            builder = builder
                .address_lookup(PkarrPublisher::builder(url.clone()))
                .address_lookup(PkarrResolver::builder(url));
        }
        builder
    } else {
        Endpoint::builder(presets::N0)
    };

    let mut builder = builder
        .secret_key(secret_key)
        .alpns(alpns)
        .transport_config(transport);

    // If bind_port is set, invite endpoints will not be able
    // to bind to the port because it's occupied by the main
    // endpoint. Therefore we ignore this option when creating
    // invite endpoints only.
    if role != EndpointRole::Invite
        && let Some(port) = opts.bind_port
    {
        for addr in [
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
        ] {
            builder = builder
                .bind_addr(addr)
                .map_err(|e| NetError::Bind(e.to_string()))?;
        }
    }

    let endpoint = builder
        .bind()
        .await
        .map_err(|e| NetError::Bind(e.to_string()))?;

    tokio::time::timeout(limits::EP_ONLINE_TIMEOUT, endpoint.online())
        .await
        .map_err(|_| NetError::OnlineTimeout {
            secs: limits::EP_ONLINE_TIMEOUT.as_secs(),
        })?;
    Ok(endpoint)
}

/// Groups a 32-byte node id into 8-char hex blocks for display.
pub fn grouped_hex(id: &[u8]) -> String {
    let hexed: String = id.iter().map(|b| format!("{b:02x}")).collect();
    hexed
        .as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).expect("hex is utf8"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Escalating reject-delay schedule: 500 ms doubling to an 8 s cap.
#[derive(Debug)]
pub struct RejectDelay {
    current: Duration,
}

impl RejectDelay {
    pub fn new() -> Self {
        Self {
            current: limits::REJECT_DELAY_INITIAL,
        }
    }

    pub fn delay(&self) -> Duration {
        self.current
    }

    pub fn escalate(&mut self) {
        self.current = (self.current * 2).min(limits::REJECT_DELAY_MAX);
    }

    pub fn reset(&mut self) {
        self.current = limits::REJECT_DELAY_INITIAL;
    }
}

impl Default for RejectDelay {
    fn default() -> Self {
        Self::new()
    }
}
