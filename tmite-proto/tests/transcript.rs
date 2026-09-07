//! Verifies the frozen pairing transcript against the committed vector file
//! and the framing codec (design §14.2).

use tmite_proto::frame::{
    PairingFrame, TYPE_PAIR_CONFIRM, TYPE_PAIR_HELLO, TYPE_PAIR_WAIT, TYPE_VERSION, decode_payload,
    parse_frame,
};

#[test]
fn golden_transcript_matches() {
    let raw = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vectors/transcript.json"
    ));
    let v: serde_json::Value = serde_json::from_str(raw).unwrap();
    let expected_hex = v["transcript_hex"].as_str().unwrap();
    let frames = v["frames"].as_array().unwrap();

    assert_eq!(frames.len(), 4);
    let expected_frames = [
        PairingFrame::Version { version: 1 },
        PairingFrame::PairHello {
            client_version: "0.1.0".into(),
        },
        PairingFrame::PairWait {},
        PairingFrame::PairConfirm {
            node_id: [0x11u8; 32],
            name: "laptop".into(),
        },
    ];
    let expected_types = [
        TYPE_VERSION,
        TYPE_PAIR_HELLO,
        TYPE_PAIR_WAIT,
        TYPE_PAIR_CONFIRM,
    ];

    let mut concatenated = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        let frame_hex = frame["frame_hex"].as_str().unwrap();
        let expected =
            tmite_proto::frame::encode_frame(expected_frames[i].msg_type(), &expected_frames[i])
                .unwrap();
        let expected_hex_frame: String = expected.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(frame_hex, expected_hex_frame, "frame {i} byte mismatch");
        assert_eq!(
            frame["msg_type"].as_str().unwrap(),
            format!("{:#04x}", expected_types[i])
        );
        concatenated.extend_from_slice(&expected);
    }
    let concatenated_hex: String = concatenated.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(concatenated_hex, expected_hex);

    // Round-trip each frame through the streaming parser.
    for f in &expected_frames {
        let bytes = tmite_proto::frame::encode_frame(f.msg_type(), f).unwrap();
        let parsed = parse_frame(&bytes).unwrap();
        assert_eq!(parsed.msg_type, f.msg_type());
        let back: PairingFrame = decode_payload(&parsed.payload).unwrap();
        assert_eq!(&back, f);
    }
}
