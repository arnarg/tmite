use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::limits::MAX_CONTROL_FRAME;

/// Wire framing: `u8 msg_type | u32be len | payload` (payload is JSON, UTF-8).
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("control frame too large ({len} bytes, max {max})")]
    TooLarge { len: usize, max: usize },
    #[error("invalid frame payload")]
    InvalidPayload(#[from] serde_json::Error),
    #[error("invalid frame header")]
    InvalidHeader,
    #[error("unexpected message type {0:#04x}")]
    UnexpectedType(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameType(pub u8);

pub fn frame_bytes(msg_type: u8, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_CONTROL_FRAME {
        return Err(FrameError::TooLarge {
            len: payload.len(),
            max: MAX_CONTROL_FRAME,
        });
    }
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(msg_type);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn encode_frame<T: Serialize>(msg_type: u8, payload: &T) -> Result<Vec<u8>, FrameError> {
    let json = serde_json::to_vec(payload)?;
    frame_bytes(msg_type, &json)
}

pub struct ParsedFrame {
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

/// Parses a complete frame (header + payload) from `buf`.
pub fn parse_frame(buf: &[u8]) -> Result<ParsedFrame, FrameError> {
    if buf.len() < 5 {
        return Err(FrameError::InvalidHeader);
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > MAX_CONTROL_FRAME {
        return Err(FrameError::TooLarge {
            len,
            max: MAX_CONTROL_FRAME,
        });
    }
    if buf.len() != 5 + len {
        return Err(FrameError::InvalidHeader);
    }
    Ok(ParsedFrame {
        msg_type: buf[0],
        payload: buf[5..].to_vec(),
    })
}

pub fn decode_payload<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T, FrameError> {
    serde_json::from_slice(payload).map_err(Into::into)
}

pub fn max_frame_len() -> usize {
    5 + MAX_CONTROL_FRAME
}

// ---------------------------------------------------------------------------
// Pairing frames (ALPN tmite-pair/1)
// ---------------------------------------------------------------------------

pub const TYPE_VERSION: u8 = 0x01;
pub const TYPE_PAIR_HELLO: u8 = 0x02;
pub const TYPE_PAIR_WAIT: u8 = 0x03;
pub const TYPE_PAIR_CONFIRM: u8 = 0x04;
pub const TYPE_PAIR_DENY: u8 = 0x05;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PairDenyReason {
    NameTaken,
    AdminDenied,
    Expired,
    ServerError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PairingFrame {
    Version { version: u16 },
    PairHello { client_version: String },
    PairWait {},
    PairConfirm { node_id: [u8; 32], name: String },
    PairDeny { reason: PairDenyReason },
}

impl PairingFrame {
    pub const fn msg_type(&self) -> u8 {
        match self {
            PairingFrame::Version { .. } => TYPE_VERSION,
            PairingFrame::PairHello { .. } => TYPE_PAIR_HELLO,
            PairingFrame::PairWait { .. } => TYPE_PAIR_WAIT,
            PairingFrame::PairConfirm { .. } => TYPE_PAIR_CONFIRM,
            PairingFrame::PairDeny { .. } => TYPE_PAIR_DENY,
        }
    }
}

// ---------------------------------------------------------------------------
// Data frames (ALPN tmite/1)
// ---------------------------------------------------------------------------

pub const TYPE_FORWARD: u8 = 0x01;
pub const TYPE_OK: u8 = 0x02;
pub const TYPE_DENY: u8 = 0x03;
pub const TYPE_VALIDATE: u8 = 0x04;
pub const TYPE_SESSION: u8 = 0x05;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataDenyReason {
    Unauthorized,
    TargetUnreachable { os_error: String },
    ServerError,
}

/// One announced local listener in a SESSION frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionForward {
    /// Local bind address as `addr:port` (as given to `--fwd`).
    pub local: String,
    /// Forward target as `host:port`.
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DataFrame {
    Forward { target: String },
    Validate { target: String },
    Ok {},
    Deny { reason: DataDenyReason },
    /// Sent once per connection right after dialing: announces the
    /// client's active local listeners for the daemon's status view.
    Session { forwards: Vec<SessionForward> },
}

impl DataFrame {
    pub const fn msg_type(&self) -> u8 {
        match self {
            DataFrame::Forward { .. } => TYPE_FORWARD,
            DataFrame::Validate { .. } => TYPE_VALIDATE,
            DataFrame::Ok { .. } => TYPE_OK,
            DataFrame::Deny { .. } => TYPE_DENY,
            DataFrame::Session { .. } => TYPE_SESSION,
        }
    }
}
