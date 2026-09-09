//! Push notifications over ntfy (design §18). A [`Notifier`] is cloned into
//! the event sources (data plane, invite manager, IPC dispatch); a single
//! drain task consumes the channel, re-reads `ntfy.toml` per event (so
//! enabling/disabling needs no daemon restart), applies a per-event
//! cooldown, and POSTs to the ntfy server. Delivery failures are logged,
//! never fatal, and the data plane never blocks on a send.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ntfy::payload::Priority;
use ntfy::{Payload, dispatcher};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::fsio;

/// Minimum spacing between two notifications with the same
/// (event kind, subject) so a reconnecting peer or a reject loop cannot
/// flood the topic.
pub const COOLDOWN: Duration = Duration::from_secs(60);

const SEND_TIMEOUT: Duration = Duration::from_secs(10);

fn node_label() -> &'static str {
    static NODE: OnceLock<String> = OnceLock::new();
    NODE.get_or_init(|| {
        hostname::get()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "tmite".to_string())
    })
}
pub const NTFY_CONFIG_FILE: &str = "ntfy.toml";
pub const DEFAULT_NTFY_SERVER: &str = "https://ntfy.sh";

#[derive(Debug, thiserror::Error)]
pub enum NtfyError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("config error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("config error: {0}")]
    TomlSer(#[from] toml::ser::Error),
}

/// Contents of `${data_dir}/ntfy.toml`. The topic is the credential on the
/// default server (anyone who knows it can publish); the file is mode 0600.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtfyConfig {
    pub topic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

impl NtfyConfig {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(NTFY_CONFIG_FILE)
    }

    /// `Ok(None)` while the file is absent: notifications are disabled.
    pub fn load(data_dir: &Path) -> Result<Option<Self>, NtfyError> {
        match std::fs::read_to_string(Self::path(data_dir)) {
            Ok(text) => Ok(Some(toml::from_str(&text)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Atomic write (tempfile + rename) with mode 0600.
    pub fn save(&self, data_dir: &Path) -> Result<(), NtfyError> {
        let path = Self::path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("toml.tmp");
        {
            use std::io::Write as _;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(toml::to_string_pretty(self)?.as_bytes())?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// `Ok(true)` if a config file was removed.
    pub fn remove(data_dir: &Path) -> Result<bool, NtfyError> {
        match std::fs::remove_file(Self::path(data_dir)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub fn server_url(&self) -> &str {
        self.server.as_deref().unwrap_or(DEFAULT_NTFY_SERVER)
    }
}

/// Rejects a `--server` value that cannot be an ntfy base URL at
/// `tmite admin ntfy enable` time, so setup failures surface immediately.
pub fn validate_server_url(url: &str) -> Result<(), String> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("server must be an http(s) URL, got {url:?}"))
    }
}

/// 32 lowercase hex chars: valid ntfy topic charset, unguessable.
pub fn generate_topic() -> String {
    let mut bytes = [0u8; 16];
    tmite_proto::pairing::random_bytes(&mut bytes);
    fsio::hex(&bytes)
}

/// One daemon-side event worth notifying about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    PeerConnected {
        name: String,
        node_id: String,
    },
    PeerRejected {
        node_id: String,
    },
    PairRequested {
        name: String,
        node_id: String,
    },
    PeerRegistered {
        name: String,
        node_id: String,
    },
    InviteCreated {
        name: String,
        invite_id: String,
        ttl_secs: u64,
    },
    InviteExpired {
        invite_id: String,
    },
    RuleAdded {
        peer: String,
        target: String,
    },
    RuleRevoked {
        peer: String,
        target: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    PeerConnected,
    PeerRejected,
    PairRequested,
    PeerRegistered,
    InviteCreated,
    InviteExpired,
    RuleAdded,
    RuleRevoked,
}

impl Notification {
    fn kind(&self) -> Kind {
        match self {
            Notification::PeerConnected { .. } => Kind::PeerConnected,
            Notification::PeerRejected { .. } => Kind::PeerRejected,
            Notification::PairRequested { .. } => Kind::PairRequested,
            Notification::PeerRegistered { .. } => Kind::PeerRegistered,
            Notification::InviteCreated { .. } => Kind::InviteCreated,
            Notification::InviteExpired { .. } => Kind::InviteExpired,
            Notification::RuleAdded { .. } => Kind::RuleAdded,
            Notification::RuleRevoked { .. } => Kind::RuleRevoked,
        }
    }

    /// Subject the cooldown buckets on: peer name, node id, invite id, or
    /// the affected rule.
    fn key(&self) -> String {
        match self {
            Notification::PeerConnected { name, .. }
            | Notification::PairRequested { name, .. }
            | Notification::PeerRegistered { name, .. } => name.clone(),
            Notification::PeerRejected { node_id } => node_id.clone(),
            Notification::InviteCreated { invite_id, .. }
            | Notification::InviteExpired { invite_id } => invite_id.clone(),
            Notification::RuleAdded { peer, target }
            | Notification::RuleRevoked { peer, target } => {
                format!("{peer}/{target}")
            }
        }
    }

    fn payload(&self, topic: &str) -> Payload {
        let node = node_label();

        match self {
            Notification::PeerConnected { name, .. } => Payload::new(topic)
                .title(format!("{node}: peer connected"))
                .message(format!("peer {name:?} connected to the daemon"))
                .tags(["bell"]),
            Notification::PeerRejected { node_id } => Payload::new(topic)
                .priority(Priority::High)
                .title(format!("{node}: connection rejected"))
                .message(format!(
                    "unknown node {} tried to connect",
                    short_node_id(node_id)
                ))
                .tags(["warning", "key"]),
            Notification::PairRequested { name, node_id } => Payload::new(topic)
                .title(format!("{node}: pairing request"))
                .message(format!(
                    "client {} wants to pair as {name:?}; approve on the daemon host",
                    short_node_id(node_id)
                ))
                .tags(["key"]),
            Notification::PeerRegistered { name, node_id } => Payload::new(topic)
                .title(format!("{node}: new peer"))
                .message(format!(
                    "peer {name:?} ({}) registered",
                    short_node_id(node_id)
                ))
                .tags(["white_check_mark"]),
            Notification::InviteCreated { name, ttl_secs, .. } => Payload::new(topic)
                .title(format!("{node}: invite created"))
                .message(format!("invite for {name:?} created (valid {ttl_secs}s)"))
                .tags(["link"]),
            Notification::InviteExpired { .. } => Payload::new(topic)
                .title(format!("{node}: invite expired"))
                .message("an invite expired without a pairing")
                .tags(["hourglass"]),
            Notification::RuleAdded { peer, target } => Payload::new(topic)
                .title(format!("{node}: rule added"))
                .message(format!("peer {peer:?} may now reach {target}"))
                .tags(["unlock"]),
            Notification::RuleRevoked { peer, target } => Payload::new(topic)
                .title(format!("{node}: rule revoked"))
                .message(format!("peer {peer:?} can no longer reach {target}"))
                .tags(["lock"]),
        }
    }
}

fn short_node_id(node_id: &str) -> String {
    let mut short = node_id.chars().take(8).collect::<String>();
    if node_id.chars().count() > 8 {
        short.push('\u{2026}');
    }
    short
}

/// Cloneable event-source handle. `notify` never blocks and silently no-ops
/// when notifications are disabled or the drain task is gone.
#[derive(Debug, Clone, Default)]
pub struct Notifier {
    tx: Option<mpsc::UnboundedSender<Notification>>,
}

impl Notifier {
    /// Creates a notifier plus the receiver consumed by [`drain`].
    pub fn channel() -> (Self, mpsc::UnboundedReceiver<Notification>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx: Some(tx) }, rx)
    }

    /// No-op notifier for tests and daemon setups that never notify.
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn notify(&self, notification: Notification) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(notification);
        }
    }
}

/// Delivery abstraction so tests can capture notifications offline; the
/// real implementation POSTs to the ntfy server.
pub trait Sink {
    fn post(
        &self,
        config: &NtfyConfig,
        payload: &Payload,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

pub struct NtfySink;

impl Sink for NtfySink {
    async fn post(&self, config: &NtfyConfig, payload: &Payload) -> Result<(), String> {
        let dispatcher = dispatcher::builder(config.server_url())
            .build_async()
            .map_err(|e| e.to_string())?;
        match tokio::time::timeout(SEND_TIMEOUT, dispatcher.send(payload)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("send timed out".to_string()),
        }
    }
}

/// Sends the setup-verification notification behind `tmite admin ntfy test`.
pub async fn send_test(config: &NtfyConfig, message: &str) -> Result<(), String> {
    let payload = Payload::new(&config.topic)
        .title(format!("{}: test", node_label()))
        .message(message.to_string())
        .tags(["white_check_mark"]);
    NtfySink.post(config, &payload).await
}

struct Cooldown {
    window: Duration,
    last: HashMap<(Kind, String), Instant>,
}

impl Cooldown {
    fn new(window: Duration) -> Self {
        Self {
            window,
            last: HashMap::new(),
        }
    }

    /// `true` when the event may be sent; also records it.
    fn admit(&mut self, kind: Kind, key: &str) -> bool {
        let now = Instant::now();
        match self.last.get(&(kind, key.to_string())) {
            Some(t) if now.duration_since(*t) < self.window => false,
            _ => {
                self.last.insert((kind, key.to_string()), now);
                true
            }
        }
    }
}

/// Drain loop: one task per daemon, spawned by `daemon::run`. Re-reads
/// `ntfy.toml` before every send, so `tmite admin ntfy enable`/`disable` take
/// effect without a daemon restart.
pub async fn drain<S: Sink>(
    mut rx: mpsc::UnboundedReceiver<Notification>,
    data_dir: PathBuf,
    sink: S,
) {
    let mut cooldown = Cooldown::new(COOLDOWN);
    while let Some(notification) = rx.recv().await {
        if !cooldown.admit(notification.kind(), &notification.key()) {
            tracing::debug!(?notification, "ntfy notification suppressed by cooldown");
            continue;
        }
        let config = match NtfyConfig::load(&data_dir) {
            Ok(Some(config)) => config,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!("ntfy config unreadable, notification dropped: {e}");
                continue;
            }
        };
        if let Err(e) = sink
            .post(&config, &notification.payload(&config.topic))
            .await
        {
            tracing::warn!("ntfy send failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> NtfyConfig {
        NtfyConfig {
            topic: "abc123".to_string(),
            server: None,
        }
    }

    #[test]
    fn config_roundtrip_and_server_default() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = NtfyConfig {
            topic: "top1c".to_string(),
            server: Some("https://ntfy.example.com".to_string()),
        };
        config.save(dir.path()).unwrap();
        assert_eq!(NtfyConfig::load(dir.path()).unwrap(), Some(config.clone()));
        assert_eq!(config.server_url(), "https://ntfy.example.com");
        assert_eq!(sample_config().server_url(), DEFAULT_NTFY_SERVER);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(NtfyConfig::path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "ntfy.toml must be 0600");
        }
    }

    #[test]
    fn absent_config_means_disabled() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(NtfyConfig::load(dir.path()).unwrap(), None);
        assert!(!NtfyConfig::remove(dir.path()).unwrap());
        sample_config().save(dir.path()).unwrap();
        assert!(NtfyConfig::remove(dir.path()).unwrap());
        assert_eq!(NtfyConfig::load(dir.path()).unwrap(), None);
    }

    #[test]
    fn server_url_validation() {
        assert!(validate_server_url("https://ntfy.sh").is_ok());
        assert!(validate_server_url("http://ntfy.local:8080").is_ok());
        assert!(validate_server_url("ntfy.sh").is_err());
        assert!(validate_server_url("ftp://x").is_err());
    }

    #[test]
    fn cooldown_admits_first_and_after_window_only() {
        let mut cd = Cooldown::new(Duration::from_millis(30));
        assert!(cd.admit(Kind::PeerConnected, "laptop"));
        assert!(!cd.admit(Kind::PeerConnected, "laptop"));
        // A different subject or kind is never suppressed.
        assert!(cd.admit(Kind::PeerConnected, "phone"));
        assert!(cd.admit(Kind::PeerRejected, "laptop"));
        std::thread::sleep(Duration::from_millis(40));
        assert!(cd.admit(Kind::PeerConnected, "laptop"));
    }

    #[derive(Debug, Clone)]
    struct CapturingSink {
        tx: mpsc::UnboundedSender<String>,
    }

    impl Sink for CapturingSink {
        async fn post(&self, config: &NtfyConfig, payload: &Payload) -> Result<(), String> {
            self.tx
                .send(payload.message.clone().unwrap_or_default())
                .map_err(|e| e.to_string())?;
            assert_eq!(payload.topic, config.topic);
            Ok(())
        }
    }

    #[tokio::test]
    async fn drain_gates_on_config_and_cooldown() {
        let dir = tempfile::TempDir::new().unwrap();
        sample_config().save(dir.path()).unwrap();

        let (notifier, rx) = Notifier::channel();
        let (tx, mut delivered) = mpsc::unbounded_channel();
        tokio::spawn(drain(rx, dir.path().to_path_buf(), CapturingSink { tx }));

        notifier.notify(Notification::PeerConnected {
            name: "laptop".into(),
            node_id: "aa".into(),
        });
        notifier.notify(Notification::PeerConnected {
            name: "laptop".into(),
            node_id: "aa".into(),
        });
        notifier.notify(Notification::PeerRejected {
            node_id: "aa".into(),
        });

        drop(notifier);
        let first = delivered
            .recv()
            .await
            .expect("connect notification missing");
        let second = delivered.recv().await.expect("reject notification missing");
        assert!(first.contains("laptop"));
        assert!(second.contains("unknown node"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            delivered.try_recv().is_err(),
            "second connect must be suppressed by cooldown"
        );

        // Disabling (removing the file) silences everything.
        NtfyConfig::remove(dir.path()).unwrap();
        let (notifier, rx) = Notifier::channel();
        let (tx, mut delivered) = mpsc::unbounded_channel();
        tokio::spawn(drain(rx, dir.path().to_path_buf(), CapturingSink { tx }));
        notifier.notify(Notification::PeerConnected {
            name: "laptop".into(),
            node_id: "aa".into(),
        });
        drop(notifier);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            delivered.try_recv().is_err(),
            "no notification must be delivered while disabled"
        );
    }

    #[test]
    fn payload_contains_topic_and_message() {
        let payload = Notification::RuleAdded {
            peer: "laptop".into(),
            target: "localhost:22".into(),
        }
        .payload("top1c");
        assert_eq!(payload.topic, "top1c");
        assert!(payload.message.unwrap().contains("localhost:22"));
    }
}
