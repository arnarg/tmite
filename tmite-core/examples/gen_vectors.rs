//! Regenerates `vectors/pairing.json`. Run: `cargo run -p tmite-core --example gen_vectors`
use std::str::FromStr;

use iroh::SecretKey;
use serde::Serialize;
use tmite_proto::pairing::{derive_invite_seed, entropy_to_code, generate_entropy};

#[derive(Serialize)]
struct Vector {
    entropy_hex: String,
    words: String,
    invite_seed_hex: String,
    invite_node_id_hex: String,
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
#[allow(clippy::vec_init_then_push)]
async fn main() {
    let mut vectors = Vec::new();

    // Edge case: all-zero entropy (valid for derivation; never generated in practice).
    vectors.push(vector(&[0u8; 5]));
    // All-0xff entropy.
    vectors.push(vector(&[0xff; 5]));
    // Single-bit extremes.
    vectors.push(vector(&[0x01, 0x00, 0x00, 0x00, 0x00]));
    vectors.push(vector(&[0x00, 0x00, 0x00, 0x00, 0x10]));
    // And 40 fresh random cases for volume.
    for _ in 0..40 {
        vectors.push(vector(&generate_entropy()));
    }

    let json = serde_json::to_string_pretty(&vectors).unwrap();
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors/pairing.json");
    std::fs::write(out, json + "\n").unwrap();
    println!("wrote vectors/pairing.json ({} vectors)", vectors.len());
}

fn vector(entropy: &[u8; 5]) -> Vector {
    let code = entropy_to_code(entropy);
    let seed = derive_invite_seed(entropy);
    let node_id = SecretKey::from_bytes(&seed).public();
    let _ = u8::from_str("0"); // keep FromStr import harmless if refactored
    Vector {
        entropy_hex: hex(entropy),
        words: code.clone(),
        invite_seed_hex: hex(&seed),
        invite_node_id_hex: node_id.to_string(),
    }
}
