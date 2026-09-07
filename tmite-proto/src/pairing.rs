use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use crate::limits::CODE_VERSION;
use crate::limits::INVITE_CODE_ENTROPY;

pub const KDF_SALT: &[u8] = b"tmite/v1";
pub const KDF_INFO_INVITE: &[u8] = b"invite";

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum CodeError {
    #[error("expected exactly 5 words, got {got}")]
    WrongWordCount { got: usize },
    #[error("unknown word: {0}")]
    UnknownWord(String),
    #[error("invalid final word")]
    LastWordInvalid,
    #[error("checksum mismatch")]
    ChecksumMismatch,
    #[error("malformed code")]
    Malformed,
}

/// Generates 5 bytes of fresh invite entropy.
pub fn generate_entropy() -> [u8; INVITE_CODE_ENTROPY] {
    let mut buf = [0u8; INVITE_CODE_ENTROPY];
    getrandom::fill(&mut buf).expect("system entropy unavailable");
    buf
}

/// Fills a buffer from the system entropy source.
pub fn random_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("system entropy unavailable");
}

fn checksum_byte(entropy: &[u8]) -> u8 {
    let digest = Sha256::digest(entropy);
    digest[0]
}

fn normalize_words(code: &str) -> Result<Vec<String>, CodeError> {
    let words: Vec<String> = code
        .split(|c: char| !(c.is_ascii_alphabetic() || c == '\''))
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .collect();
    if words.iter().any(|w| w.is_empty()) {
        return Err(CodeError::Malformed);
    }
    Ok(words)
}

fn word_index(word: &str) -> Option<usize> {
    mnemonic::MN_WORDS
        .iter()
        .position(|w| *w == word.as_bytes())
}

/// Encodes 5 bytes of entropy as 5 space-separated mnemonic words.
pub fn entropy_to_code(entropy: &[u8; INVITE_CODE_ENTROPY]) -> String {
    let mut input = [0u8; INVITE_CODE_ENTROPY + 1];
    input[..INVITE_CODE_ENTROPY].copy_from_slice(entropy);
    input[INVITE_CODE_ENTROPY] = checksum_byte(entropy);
    let encoded = mnemonic::to_string(input);
    normalize_words(&encoded)
        .expect("mnemonic encoding is always normalizable")
        .join(" ")
}

/// Decodes and validates a 5-word pairing code, returning the 5 entropy bytes.
pub fn code_to_entropy(code: &str) -> Result<[u8; INVITE_CODE_ENTROPY], CodeError> {
    let words = normalize_words(code)?;
    if words.len() != 5 {
        return Err(CodeError::WrongWordCount { got: words.len() });
    }
    for w in &words {
        if word_index(w).is_none() {
            return Err(CodeError::UnknownWord(w.clone()));
        }
    }
    // In a 6-byte encoding the 5th word encodes entropy[4] >> 10 … i.e. a
    // value below 41; a valid 5th word outside that range is rejected early
    // (it would otherwise decode as a 24-bit remainder word).
    let last_idx = word_index(&words[4]).expect("checked above");
    if last_idx >= 41 {
        return Err(CodeError::LastWordInvalid);
    }
    let joined = words.join("-");
    let mut out = [0u8; 64];
    let n = mnemonic::decode(joined.as_bytes(), &mut out[..]).map_err(|_| CodeError::Malformed)?;
    if n != 6 {
        return Err(CodeError::WrongWordCount { got: words.len() });
    }
    let entropy: [u8; INVITE_CODE_ENTROPY] = out[..INVITE_CODE_ENTROPY]
        .try_into()
        .map_err(|_| CodeError::Malformed)?;
    if checksum_byte(&entropy) != out[INVITE_CODE_ENTROPY] {
        return Err(CodeError::ChecksumMismatch);
    }
    Ok(entropy)
}

/// HKDF-SHA256 over the code entropy; output is the invite endpoint's secret key seed.
pub fn derive_invite_seed(entropy: &[u8; INVITE_CODE_ENTROPY]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), entropy);
    let mut okm = [0u8; 32];
    hk.expand(KDF_INFO_INVITE, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    okm
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairingTranscript {
    pub entropy_hex: String,
    pub words: Vec<String>,
    pub invite_seed_hex: String,
    pub invite_node_id_hex: String,
}
