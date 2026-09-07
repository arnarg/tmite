use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tmite_proto::ipc::ErrorCode;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file corrupt: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("state file serialization failed: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("peer \"{0}\" already exists")]
    NameTaken(String),
    #[error("peer \"{0}\" not found")]
    NotFound(String),
    #[error("peer \"{0}\" has rules; use --force to delete them too")]
    PeerHasRules(String),
    #[error("peer limit reached ({})", tmite_proto::limits::MAX_PEERS)]
    PeerCap,
    #[error("rule limit reached ({})", tmite_proto::limits::MAX_RULES)]
    RuleCap,
}

impl StateError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            StateError::NameTaken(_) => ErrorCode::NameTaken,
            StateError::NotFound(_) => ErrorCode::NotFound,
            StateError::PeerHasRules(_) => ErrorCode::PeerHasRules,
            _ => ErrorCode::Internal,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Peer {
    pub name: String,
    pub node_id: String,
    pub paired_at: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    pub peer: String,
    pub target: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    #[serde(default, rename = "peers")]
    peers: Vec<Peer>,
    #[serde(default, rename = "rules")]
    rules: Vec<Rule>,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            version: 1,
            peers: Vec::new(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct State {
    path: PathBuf,
    inner: Mutex<PersistedState>,
}

impl State {
    /// Loads `path`, creating a default file if it does not exist.
    pub fn load(path: &Path) -> Result<Self, StateError> {
        let persisted = match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str::<PersistedState>(&text)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PersistedState::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path: path.to_path_buf(),
            inner: Mutex::new(persisted),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist_locked(state: &PersistedState, path: &Path) -> Result<(), StateError> {
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, toml::to_string_pretty(state)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn peer_by_node(&self, node_id_hex: &str) -> Option<Peer> {
        let state = self.inner.lock().expect("state lock poisoned");
        state
            .peers
            .iter()
            .find(|p| p.node_id.eq_ignore_ascii_case(node_id_hex))
            .cloned()
    }

    pub fn peer_by_name(&self, name: &str) -> Option<Peer> {
        let state = self.inner.lock().expect("state lock poisoned");
        state.peers.iter().find(|p| p.name == name).cloned()
    }

    pub fn is_name_free(&self, name: &str) -> bool {
        let state = self.inner.lock().expect("state lock poisoned");
        !state.peers.iter().any(|p| p.name == name)
    }

    /// Records a paired peer; the name-uniqueness recheck happens under the
    /// state lock, so this is atomic with respect to other pairings.
    pub fn add_peer(&self, peer: Peer) -> Result<(), StateError> {
        let mut state = self.inner.lock().expect("state lock poisoned");
        if state.peers.iter().any(|p| p.name == peer.name) {
            return Err(StateError::NameTaken(peer.name));
        }
        if state.peers.len() >= tmite_proto::limits::MAX_PEERS {
            return Err(StateError::PeerCap);
        }
        state.peers.push(peer);
        Self::persist_locked(&state, &self.path)
    }

    pub fn touch_last_seen(&self, node_id_hex: &str) {
        let mut state = self.inner.lock().expect("state lock poisoned");
        if let Some(peer) = state
            .peers
            .iter_mut()
            .find(|p| p.node_id.eq_ignore_ascii_case(node_id_hex))
        {
            peer.last_seen = crate::fsio::now_rfc3339();
            let _ = Self::persist_locked(&state, &self.path);
        }
    }

    pub fn add_rule(&self, peer: &str, target: &str) -> Result<usize, StateError> {
        let mut state = self.inner.lock().expect("state lock poisoned");
        if !state.peers.iter().any(|p| p.name == peer) {
            return Err(StateError::NotFound(peer.to_string()));
        }
        if state.rules.len() >= tmite_proto::limits::MAX_RULES {
            return Err(StateError::RuleCap);
        }
        let index = state
            .rules
            .iter()
            .position(|r| r.peer == peer && r.target == target);
        if let Some(existing) = index {
            return Ok(existing);
        }
        state.rules.push(Rule {
            peer: peer.to_string(),
            target: target.to_string(),
            created_at: crate::fsio::now_rfc3339(),
        });
        Self::persist_locked(&state, &self.path)?;
        Ok(state.rules.len() - 1)
    }

    pub fn remove_rule(&self, peer: &str, target: &str) -> Result<bool, StateError> {
        let mut state = self.inner.lock().expect("state lock poisoned");
        if !state.peers.iter().any(|p| p.name == peer) {
            return Err(StateError::NotFound(peer.to_string()));
        }
        let before = state.rules.len();
        state
            .rules
            .retain(|r| !(r.peer == peer && r.target == target));
        let removed = state.rules.len() != before;
        if removed {
            Self::persist_locked(&state, &self.path)?;
        }
        Ok(removed)
    }

    /// Exact-string ACL match for a peer at FORWARD time.
    pub fn rule_allows(&self, peer_name: &str, target: &str) -> bool {
        let state = self.inner.lock().expect("state lock poisoned");
        state
            .rules
            .iter()
            .any(|r| r.peer == peer_name && r.target == target)
    }

    pub fn remove_peer(&self, name: &str, force: bool) -> Result<bool, StateError> {
        let mut state = self.inner.lock().expect("state lock poisoned");
        if !state.peers.iter().any(|p| p.name == name) {
            return Ok(false);
        }
        let has_rules = state.rules.iter().any(|r| r.peer == name);
        if has_rules && !force {
            return Err(StateError::PeerHasRules(name.to_string()));
        }
        state.peers.retain(|p| p.name != name);
        state.rules.retain(|r| r.peer != name);
        Self::persist_locked(&state, &self.path)?;
        Ok(true)
    }

    pub fn snapshot(&self) -> (Vec<Peer>, Vec<Rule>) {
        let state = self.inner.lock().expect("state lock poisoned");
        (state.peers.clone(), state.rules.clone())
    }
}
