use std::io::Write as _;
use std::path::{Path, PathBuf};

use iroh::SecretKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum FsError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("invalid keypair file: expected 64 hex chars")]
    BadKeypair,
    #[error("name {0:?} is already paired to a different server")]
    NameInUse(String),
}

pub fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn default_client_data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME")
        && !dir.is_empty()
    {
        return PathBuf::from(dir).join("tmite");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local/share/tmite")
}

/// Loads the hex-encoded 32-byte secret key at `path`, generating and writing
/// one (mode 0600) if the file does not exist.
pub fn load_or_create_keypair(path: &Path) -> Result<SecretKey, FsError> {
    if let Some(bytes) = read_secret_file(path)? {
        let hexed = String::from_utf8(bytes).map_err(|_| FsError::BadKeypair)?;
        let hexed = hexed.trim();
        if hexed.len() != 64 || !hexed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(FsError::BadKeypair);
        }
        let mut raw = Zeroizing::new([0u8; 32]);
        for (i, byte) in raw.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hexed[i * 2..i * 2 + 2], 16)
                .map_err(|_| FsError::BadKeypair)?;
        }
        Ok(SecretKey::from_bytes(&raw))
    } else {
        let sk = SecretKey::generate();
        write_secret_file(path, hex(&sk.to_bytes()).as_bytes())?;
        Ok(sk)
    }
}

fn read_secret_file(path: &Path) -> Result<Option<Vec<u8>>, FsError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), FsError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.write_all(b"\n")?;
    Ok(())
}

/// Writes bytes to a file with mode 0600, refusing to clobber silently
/// (used for the keypair created on first run).
pub fn ensure_private_dir(dir: &Path) -> Result<(), FsError> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dir)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Client server registry (servers.toml)
// ---------------------------------------------------------------------------

pub const SERVERS_FILE: &str = "servers.toml";

pub fn servers_toml_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SERVERS_FILE)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientStore {
    pub version: u32,
    #[serde(default, rename = "servers")]
    pub servers: Vec<ServerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub name: String,
    pub node_id: String,
    pub paired_at: String,
}

impl ClientStore {
    pub fn load(path: &Path) -> Result<Self, FsError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(toml::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                version: 1,
                servers: Vec::new(),
            }),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), FsError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, toml::to_string_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Inserts or updates an entry. Re-pairing the same server (same
    /// `node_id`) replaces its entry, including any rename. Using a name
    /// already bound to a different server is an error so that pairing with
    /// a second server can never silently overwrite an existing one.
    pub fn upsert(&mut self, entry: ServerEntry) -> Result<(), FsError> {
        let same_server = self.servers.iter().position(|s| s.node_id == entry.node_id);
        let name_taken = self
            .servers
            .iter()
            .any(|s| s.name == entry.name && s.node_id != entry.node_id);
        if name_taken {
            return Err(FsError::NameInUse(entry.name));
        }
        match same_server {
            Some(i) => self.servers[i] = entry,
            None => self.servers.push(entry),
        }
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&ServerEntry> {
        self.servers.iter().find(|s| s.name == name)
    }

    pub fn get_by_node_id(&self, node_id: &str) -> Option<&ServerEntry> {
        self.servers.iter().find(|s| s.node_id == node_id)
    }
}

pub fn now_rfc3339() -> String {
    humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string()
}
