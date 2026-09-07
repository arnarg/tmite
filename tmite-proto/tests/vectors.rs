use tmite_proto::frame::*;
use tmite_proto::ipc::*;
use tmite_proto::limits::MAX_CONTROL_FRAME;
use tmite_proto::pairing::*;

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// Pairing codec
// ---------------------------------------------------------------------------

#[test]
fn code_round_trip() {
    for _ in 0..200 {
        let entropy = generate_entropy();
        let code = entropy_to_code(&entropy);
        let words: Vec<&str> = code.split(' ').collect();
        assert_eq!(words.len(), 5, "code {code:?} must be 5 words");
        assert!(
            words
                .iter()
                .all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
        );
        let back = code_to_entropy(&code).unwrap();
        assert_eq!(back, entropy);
    }
}

#[test]
fn last_word_always_within_first_41() {
    let first41: Vec<String> = mnemonic::MN_WORDS[..41]
        .iter()
        .map(|w| String::from_utf8(w.to_vec()).unwrap())
        .collect();
    for _ in 0..100 {
        let entropy = generate_entropy();
        let code = entropy_to_code(&entropy);
        let last = code.split(' ').next_back().unwrap();
        assert!(
            first41.iter().any(|w| w == last),
            "last word {last:?} not in first 41"
        );
    }
}

#[test]
fn reject_wrong_word_count() {
    let entropy = generate_entropy();
    let code = entropy_to_code(&entropy);
    let words: Vec<&str> = code.split(' ').collect();
    let four = words[..4].join(" ");
    let six = format!("{code} {}", words[0]);
    for bad in [four, six, String::new(), "ocean".into()] {
        match code_to_entropy(&bad) {
            Err(CodeError::WrongWordCount { .. }) => {}
            other => panic!("{bad:?}: expected WrongWordCount, got {other:?}"),
        }
    }
}

#[test]
fn reject_unknown_word() {
    match code_to_entropy("ocean pixel falcon zzzz atlas") {
        Err(CodeError::UnknownWord(w)) => assert_eq!(w, "zzzz"),
        other => panic!("expected UnknownWord, got {other:?}"),
    }
}

#[test]
fn reject_checksum_mismatch() {
    // Take a valid code and replace one non-final word with other valid words
    // until the checksum no longer verifies (probability 255/256 per try).
    let entropy = generate_entropy();
    let mut words: Vec<String> = entropy_to_code(&entropy)
        .split(' ')
        .map(String::from)
        .collect();
    let mut found = false;
    for i in 0..41 {
        words[3] = String::from_utf8(mnemonic::MN_WORDS[i].to_vec()).unwrap();
        let candidate = words.join(" ");
        match code_to_entropy(&candidate) {
            Err(CodeError::ChecksumMismatch) => {
                found = true;
                break;
            }
            Ok(_) => continue,
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }
    assert!(found, "no checksum mismatch found among first 41 words");
}

#[test]
fn reject_invalid_last_word() {
    // Take a valid code and replace the last word with a word at index >= 41.
    let entropy = generate_entropy();
    let mut words: Vec<String> = entropy_to_code(&entropy)
        .split(' ')
        .map(String::from)
        .collect();
    words[4] = String::from_utf8(mnemonic::MN_WORDS[100].to_vec()).unwrap();
    match code_to_entropy(&words.join(" ")) {
        Err(CodeError::LastWordInvalid) => {}
        other => panic!("expected LastWordInvalid, got {other:?}"),
    }
}

#[test]
fn derivation_is_deterministic_and_version_anchored() {
    let entropy = [0u8; 5];
    let seed_a = derive_invite_seed(&entropy);
    let seed_b = derive_invite_seed(&entropy);
    assert_eq!(seed_a, seed_b);
    assert_ne!(seed_a, [0u8; 32]);
    // Changing one entropy bit changes the seed.
    let mut other = entropy;
    other[0] ^= 1;
    assert_ne!(derive_invite_seed(&other), seed_a);
}

#[test]
fn known_mnemonic_encoding() {
    // The mnemonic crate's own documented example pins the encoder behavior.
    let bytes = [101, 2, 240, 6, 108, 11, 20, 97];
    assert_eq!(
        mnemonic::to_string(bytes),
        "digital-apollo-aroma--rival-artist-rebel"
    );
}

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------

#[test]
fn frame_round_trip() {
    let f = DataFrame::Forward {
        target: "localhost:22".into(),
    };
    let bytes = encode_frame(f.msg_type(), &f).unwrap();
    assert_eq!(bytes[0], TYPE_FORWARD);
    let parsed = parse_frame(&bytes).unwrap();
    assert_eq!(parsed.msg_type, TYPE_FORWARD);
    let back: DataFrame = decode_payload(&parsed.payload).unwrap();
    assert_eq!(back, f);
}

#[test]
fn frame_truncation_rejected() {
    let f = PairingFrame::PairConfirm {
        node_id: [7u8; 32],
        name: "laptop".into(),
    };
    let bytes = encode_frame(f.msg_type(), &f).unwrap();
    for cut in [0usize, 1, 4, 5, bytes.len() - 1] {
        assert!(parse_frame(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    assert!(parse_frame(&bytes).is_ok());
}

#[test]
fn frame_over_limit_rejected() {
    let payload = vec![b'x'; MAX_CONTROL_FRAME + 1];
    assert!(frame_bytes(0x01, &payload).is_err());
    let header = [0u8, 0xff, 0xff, 0xff, 0xff];
    assert!(parse_frame(&header).is_err());
}

#[test]
fn frame_types_match_spec() {
    assert_eq!(TYPE_VERSION, 0x01);
    assert_eq!(TYPE_PAIR_HELLO, 0x02);
    assert_eq!(TYPE_PAIR_WAIT, 0x03);
    assert_eq!(TYPE_PAIR_CONFIRM, 0x04);
    assert_eq!(TYPE_PAIR_DENY, 0x05);
    assert_eq!(TYPE_FORWARD, 0x01);
    assert_eq!(TYPE_OK, 0x02);
    assert_eq!(TYPE_DENY, 0x03);
}

#[test]
fn pairing_frame_json_shape() {
    let bytes = encode_frame(
        TYPE_PAIR_DENY,
        &PairingFrame::PairDeny {
            reason: PairDenyReason::AdminDenied,
        },
    )
    .unwrap();
    let text = std::str::from_utf8(&bytes[5..]).unwrap();
    assert_eq!(text, r#"{"type":"pair_deny","reason":"admin_denied"}"#);
}

// ---------------------------------------------------------------------------
// IPC envelope
// ---------------------------------------------------------------------------

#[test]
fn ipc_request_parse() {
    let req = parse_request(r#"{"id": 7, "method": "peer.invite", "params": {"name": "laptop"}}"#)
        .unwrap();
    assert_eq!(req.id, 7);
    assert_eq!(req.method, "peer.invite");
    assert!(parse_request("{not json").is_err());
    assert!(parse_request(r#"{"id":1,"method":"nope"}"#).is_err());
}

#[test]
fn ipc_reply_shapes() {
    let ok = Reply::result(7, serde_json::json!({"status": "accepted"}));
    let line = serde_json::to_string(&ok).unwrap();
    assert_eq!(line, r#"{"id":7,"result":{"status":"accepted"}}"#);

    let err = Reply::error(7, ErrorCode::NameTaken, "peer \"laptop\" already exists");
    let line = serde_json::to_string(&err).unwrap();
    assert_eq!(
        line,
        r#"{"id":7,"error":{"code":"name_taken","message":"peer \"laptop\" already exists"}}"#
    );

    let ev = Reply::event(7, "pair_request", serde_json::json!({"node_id": "ab"}));
    let line = serde_json::to_string(&ev).unwrap();
    assert_eq!(
        line,
        r#"{"id":7,"event":"pair_request","data":{"node_id":"ab"}}"#
    );
}

#[test]
fn ipc_error_code_coverage() {
    for (code, s) in [
        (ErrorCode::BadRequest, "bad_request"),
        (ErrorCode::NameTaken, "name_taken"),
        (ErrorCode::NotFound, "not_found"),
        (ErrorCode::InviteCap, "invite_cap"),
        (ErrorCode::InviteExpired, "invite_expired"),
        (ErrorCode::PeerHasRules, "peer_has_rules"),
        (ErrorCode::Internal, "internal"),
    ] {
        assert_eq!(code.to_string(), s);
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, format!("\"{s}\""));
    }
}

// ---------------------------------------------------------------------------
// Golden vectors (regenerated file must match, CI diffs)
// ---------------------------------------------------------------------------

#[test]
fn golden_vectors_match() {
    let raw = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vectors/pairing.json"
    ));
    let vectors: Vec<Vector> = serde_json::from_str(raw).expect("vectors/pairing.json parses");
    assert!(vectors.len() >= 5, "need at least 5 vectors");
    for v in &vectors {
        let entropy_bytes = unhex(&v.entropy_hex);
        let entropy: [u8; 5] = entropy_bytes.clone().try_into().unwrap();
        let code = entropy_to_code(&entropy);
        assert_eq!(code.split(' ').count(), 5);
        for w in v.words.split(' ') {
            assert!(
                code.split(' ').any(|cw| cw == w),
                "vector word {w} missing from {code}"
            );
        }
        assert_eq!(hex(&derive_invite_seed(&entropy)), v.invite_seed_hex);
        assert_eq!(v.invite_node_id_hex.len(), 64, "node id is 64 hex chars");
    }
}

#[derive(serde::Deserialize)]
struct Vector {
    #[serde(rename = "entropy_hex")]
    entropy_hex: String,
    #[serde(rename = "words")]
    words: String,
    #[serde(rename = "invite_seed_hex")]
    invite_seed_hex: String,
    #[serde(rename = "invite_node_id_hex")]
    invite_node_id_hex: String,
}
