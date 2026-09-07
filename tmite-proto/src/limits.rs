use std::time::Duration;

pub const MAX_CONTROL_FRAME: usize = 4 * 1024;
pub const MAX_TARGET_LEN: usize = 256;
pub const MAX_CONCURRENT_BIDI_STREAMS: u32 = 256;
pub const MAX_PENDING_INVITES: usize = 8;
pub const MAX_PEERS: usize = 256;
pub const MAX_RULES: usize = 1024;

pub const PAIRING_READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(30);
pub const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const OK_DENY_WAIT: Duration = Duration::from_secs(30);
pub const EP_ONLINE_TIMEOUT: Duration = Duration::from_secs(45);
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

pub const DEFAULT_INVITE_TTL: u64 = 900;
pub const MAX_INVITE_TTL: u64 = 3600;

pub const REJECT_DELAY_INITIAL: Duration = Duration::from_millis(500);
pub const REJECT_DELAY_MAX: Duration = Duration::from_secs(8);

pub const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(15);
pub const QUIC_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub const INVITE_CODE_ENTROPY: usize = 5;
pub const PAIR_MAX_ATTEMPTS: usize = 3;

pub const CODE_VERSION: u16 = 1;
