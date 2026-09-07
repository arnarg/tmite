use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// A message sent by the daemon: a result, an error, or a mid-request event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Reply {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Reply {
    pub fn result(id: u64, result: serde_json::Value) -> Self {
        Reply {
            id,
            result: Some(result),
            error: None,
            event: None,
            data: None,
        }
    }

    pub fn error(id: u64, code: ErrorCode, message: impl Into<String>) -> Self {
        Reply {
            id,
            result: None,
            error: Some(ErrorBody {
                code,
                message: message.into(),
            }),
            event: None,
            data: None,
        }
    }

    pub fn event(id: u64, event: &str, data: serde_json::Value) -> Self {
        Reply {
            id,
            result: None,
            error: None,
            event: Some(event.to_string()),
            data: Some(data),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub code: ErrorCode,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    NameTaken,
    NotFound,
    InviteCap,
    InviteExpired,
    PeerHasRules,
    Internal,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::BadRequest => write!(f, "bad_request"),
            ErrorCode::NameTaken => write!(f, "name_taken"),
            ErrorCode::NotFound => write!(f, "not_found"),
            ErrorCode::InviteCap => write!(f, "invite_cap"),
            ErrorCode::InviteExpired => write!(f, "invite_expired"),
            ErrorCode::PeerHasRules => write!(f, "peer_has_rules"),
            ErrorCode::Internal => write!(f, "internal"),
        }
    }
}

// ---------------------------------------------------------------------------
// Method params / results
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteParams {
    pub name: String,
    #[serde(default)]
    pub ttl: Option<u64>,
}

/// Data carried on the `code` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeEventData {
    pub invite_id: String,
    pub code: String,
    pub name: String,
    pub ttl_secs: u64,
}

/// Data carried on the `pair_request` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequestEventData {
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum InviteResult {
    Paired { node_id: String },
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecideParams {
    pub invite_id: String,
    pub accept: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowParams {
    pub peer: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowResult {
    pub rule_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeParams {
    pub peer: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResult {
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsResult {
    pub peers: Vec<PeerInfo>,
    pub rules: Vec<RuleInfo>,
    pub invites: Vec<InviteInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub name: String,
    pub node_id: String,
    pub paired_at: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    pub peer: String,
    pub target: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteInfo {
    pub invite_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmParams {
    pub peer: String,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmResult {
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResult {
    pub version: String,
    pub node_id: String,
    pub uptime_secs: u64,
    pub peers: usize,
    pub rules: usize,
    pub invites: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopResult {
    pub stopping: bool,
}

/// Methods accepted by the daemon's IPC server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    PeerInvite,
    PeerInviteDecide,
    PeerAllow,
    PeerRevoke,
    PeerLs,
    PeerRm,
    DaemonStatus,
    DaemonStop,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::PeerInvite => "peer.invite",
            Method::PeerInviteDecide => "peer.invite.decide",
            Method::PeerAllow => "peer.allow",
            Method::PeerRevoke => "peer.revoke",
            Method::PeerLs => "peer.ls",
            Method::PeerRm => "peer.rm",
            Method::DaemonStatus => "daemon.status",
            Method::DaemonStop => "daemon.stop",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "peer.invite" => Method::PeerInvite,
            "peer.invite.decide" => Method::PeerInviteDecide,
            "peer.allow" => Method::PeerAllow,
            "peer.revoke" => Method::PeerRevoke,
            "peer.ls" => Method::PeerLs,
            "peer.rm" => Method::PeerRm,
            "daemon.status" => Method::DaemonStatus,
            "daemon.stop" => Method::DaemonStop,
            _ => return None,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("ipc parse error: {0}")]
pub struct IpcParseError(pub String);

pub fn parse_request(line: &str) -> Result<Request, IpcParseError> {
    let req: Request = serde_json::from_str(line).map_err(|e| IpcParseError(e.to_string()))?;
    if Method::parse(&req.method).is_none() {
        return Err(IpcParseError(format!("unknown method {}", req.method)));
    }
    Ok(req)
}
