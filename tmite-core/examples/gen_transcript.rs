//! Regenerates `vectors/transcript.json` — the frozen pairing handshake
//! transcript for fixed inputs (design §14.2).
//! Run: `cargo run -p tmite-core --example gen_transcript`
use serde::Serialize;
use tmite_proto::frame::{PairingFrame, encode_frame};

#[derive(Serialize)]
struct Transcript {
    description: String,
    inputs: serde_json::Value,
    frames: Vec<FrameSpec>,
    transcript_hex: String,
}

#[derive(Serialize, Clone)]
struct FrameSpec {
    direction: String,
    msg_type: String,
    payload_json: String,
    frame_hex: String,
}

#[tokio::main]
async fn main() {
    let node_id = [0x11u8; 32];
    let name = "laptop";
    let client_version = "0.1.0";

    let mut frames = Vec::new();
    let push = |frames: &mut Vec<FrameSpec>, direction: &str, frame: &PairingFrame| {
        let bytes = encode_frame(frame.msg_type(), frame).unwrap();
        frames.push(FrameSpec {
            direction: direction.to_string(),
            msg_type: format!("{:#04x}", frame.msg_type()),
            payload_json: String::from_utf8(bytes[5..].to_vec()).unwrap(),
            frame_hex: bytes.iter().map(|b| format!("{b:02x}")).collect(),
        });
    };

    push(
        &mut frames,
        "client_to_server",
        &PairingFrame::Version { version: 1 },
    );
    push(
        &mut frames,
        "client_to_server",
        &PairingFrame::PairHello {
            client_version: client_version.to_string(),
        },
    );
    push(&mut frames, "server_to_client", &PairingFrame::PairWait {});
    push(
        &mut frames,
        "server_to_client",
        &PairingFrame::PairConfirm {
            node_id,
            name: name.to_string(),
        },
    );

    let transcript = Transcript {
        description: "Pairing handshake transcript (tmite-pair/1) for the given fixed inputs; both independently built parties must produce these exact bytes.".into(),
        inputs: serde_json::json!({
            "entropy_hex": "0000000000",
            "code": tmite_proto::pairing::entropy_to_code(&[0u8; 5]),
            "client_version": client_version,
            "confirm_node_id_hex": node_id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "confirm_name": name,
        }),
        frames: frames.clone(),
        transcript_hex: frames
            .iter()
            .map(|f| f.frame_hex.clone())
            .collect::<Vec<_>>()
            .concat(),
    };

    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors/transcript.json");
    std::fs::write(
        out,
        serde_json::to_string_pretty(&transcript).unwrap() + "\n",
    )
    .unwrap();
    println!("wrote vectors/transcript.json");
}
