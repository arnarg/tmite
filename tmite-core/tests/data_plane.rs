//! Data-plane integration tests over real loopback iroh endpoints
//! (design §14.3). Discovery is off; dialers pass direct addresses.

use std::time::Duration;

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, PublicKey, SecretKey};
use tempfile::TempDir;
use tmite_core::daemon::main_ep::DataPlaneHandler;
use tmite_core::daemon::sessions::Sessions;
use tmite_core::daemon::state::State;
use tmite_proto::alpn::DATA_ALPN;
use tmite_proto::frame::{DataDenyReason, DataFrame, SessionForward};

fn test_state(dir: &TempDir, server_id: &PublicKey) -> (Arc<State>, String) {
    let state = State::load(&dir.path().join("state.toml")).unwrap();
    let node_hex = server_id.to_string();
    state
        .add_peer(tmite_core::daemon::state::Peer {
            name: "laptop".into(),
            node_id: node_hex.clone(),
            paired_at: tmite_core::fsio::now_rfc3339(),
            last_seen: tmite_core::fsio::now_rfc3339(),
        })
        .unwrap();
    (Arc::new(state), node_hex)
}

use std::sync::Arc;

async fn test_endpoint(sk: &SecretKey) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(sk.clone())
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap()
}

struct Server {
    #[allow(dead_code)]
    endpoint: Endpoint,
    _router: Router,
    node_id: PublicKey,
    addr: std::net::SocketAddr,
    sessions: Sessions,
}

async fn spawn_server(state: Arc<State>, sk: &SecretKey) -> Server {
    let endpoint = test_endpoint(sk).await;
    let sessions = Sessions::new();
    let router = Router::builder(endpoint.clone())
        .accept(
            DATA_ALPN,
            DataPlaneHandler::new(state, sessions.clone(), Duration::ZERO),
        )
        .spawn();
    // Wait for the direct address to be known.
    let addr = loop {
        if let Some(a) = endpoint.addr().ip_addrs().find(|s| s.ip().is_loopback()) {
            break *a;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    Server {
        node_id: endpoint.id(),
        addr,
        endpoint,
        _router: router,
        sessions,
    }
}

async fn connect_client(client_ep: &Endpoint, server: &Server) -> iroh::endpoint::Connection {
    let addr = EndpointAddr::new(server.node_id).with_ip_addr(server.addr);
    client_ep.connect(addr, DATA_ALPN).await.unwrap()
}

/// Opens one data stream: sends FORWARD, returns the stream pair after
/// reading the server's reply (Ok or Deny).
async fn open_stream(
    conn: &iroh::endpoint::Connection,
    target: &str,
) -> Result<
    (
        iroh::endpoint::SendStream,
        iroh::endpoint::RecvStream,
        Option<DataFrame>,
    ),
    Box<dyn std::error::Error>,
> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let frame = DataFrame::Forward {
        target: target.to_string(),
    };
    let bytes = tmite_proto::frame::encode_frame(frame.msg_type(), &frame)?;
    send.write_all(&bytes).await?;
    let mut header = [0u8; 5];
    let reply =
        match tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut header)).await {
            Ok(Ok(_)) => {
                let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
                let mut payload = vec![0u8; len];
                recv.read_exact(&mut payload).await?;
                Some(tmite_proto::frame::decode_payload::<DataFrame>(&payload)?)
            }
            _ => None,
        };
    Ok((send, recv, reply))
}

/// Opens one data stream: sends VALIDATE (ACL probe, no dial), returns the
/// stream pair after reading the server's reply (Ok or Deny).
async fn open_validate_stream(
    conn: &iroh::endpoint::Connection,
    target: &str,
) -> Result<
    (
        iroh::endpoint::SendStream,
        iroh::endpoint::RecvStream,
        Option<DataFrame>,
    ),
    Box<dyn std::error::Error>,
> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let frame = DataFrame::Validate {
        target: target.to_string(),
    };
    let bytes = tmite_proto::frame::encode_frame(frame.msg_type(), &frame)?;
    send.write_all(&bytes).await?;
    let mut header = [0u8; 5];
    let reply =
        match tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut header)).await {
            Ok(Ok(_)) => {
                let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
                let mut payload = vec![0u8; len];
                recv.read_exact(&mut payload).await?;
                Some(tmite_proto::frame::decode_payload::<DataFrame>(&payload)?)
            }
            _ => None,
        };
    Ok((send, recv, reply))
}

fn sk_from_byte(b: u8) -> SecretKey {
    let mut seed = [b; 32];
    seed[31] = b;
    SecretKey::from_bytes(&seed)
}

/// Binds a TCP echo server on 127.0.0.1:0 and returns its `host:port`.
async fn spawn_echo_target() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (format!("127.0.0.1:{port}"), handle)
}

// ---------------------------------------------------------------------------
// The half-close test (the important one, §14.3)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn half_close_propagates_both_ways() {
    // Target: echoes a fixed reply after observing EOF on its read side.
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = format!("127.0.0.1:{}", target_listener.local_addr().unwrap().port());

    let target = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (mut sock, _) = target_listener.accept().await.unwrap();
        let mut buf = vec![0u8; 3];
        // Read exactly 3 payload bytes.
        sock.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"abc");
        // The client's half-close must arrive as EOF here.
        let mut extra = [0u8; 1];
        let n = sock.read(&mut extra).await.unwrap();
        assert_eq!(n, 0, "expected EOF after client half-close");
        // Reverse direction stays open: send the reply, then close.
        sock.write_all(b"HELLO").await.unwrap();
        sock.shutdown().await.unwrap();
        // And read until EOF for cleanliness.
        let mut drain = Vec::new();
        let _ = sock.read_to_end(&mut drain).await;
    });

    let dir = TempDir::new().unwrap();
    let server_sk = sk_from_byte(1);
    let client_sk = sk_from_byte(2);
    let (state, _) = test_state(&dir, &client_sk.public());
    state.add_rule("laptop", &target_addr).unwrap();
    let server = spawn_server(state, &server_sk).await;
    let client_ep = test_endpoint(&client_sk).await;
    let conn = connect_client(&client_ep, &server).await;

    let (mut send, mut recv, reply) = open_stream(&conn, &target_addr).await.unwrap();
    assert!(
        matches!(reply, Some(DataFrame::Ok {})),
        "expected OK, got {reply:?}"
    );

    // Client sends 3 bytes, then half-closes.
    send.write_all(b"abc").await.unwrap();
    send.finish().unwrap();

    // Reverse direction must stay open and deliver the target's reply.
    let mut buf = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(buf, b"HELLO");

    target.await.unwrap();
}

// ---------------------------------------------------------------------------
// Stream multiplexing: 64 concurrent streams over one connection (§14.3)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn multiplexed_streams() {
    let dir = TempDir::new().unwrap();
    let (target, _echo) = spawn_echo_target().await;
    let server_sk = sk_from_byte(3);
    let client_sk = sk_from_byte(4);
    let (state, _) = test_state(&dir, &client_sk.public());
    state.add_rule("laptop", &target).unwrap();
    let server = spawn_server(state, &server_sk).await;
    let client_ep = test_endpoint(&client_sk).await;
    let conn = connect_client(&client_ep, &server).await;

    let n = 64usize;
    let mut tasks = Vec::new();
    for i in 0..n {
        let conn = conn.clone();
        let target = target.clone();
        tasks.push(tokio::spawn(async move {
            let (mut send, mut recv, reply) = open_stream(&conn, &target).await.unwrap();
            assert!(
                matches!(reply, Some(DataFrame::Ok {})),
                "expected OK, got {reply:?}"
            );
            let payload = vec![b'a' + (i as u8) % 26; 1000 + i];
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut buf)
                .await
                .unwrap();
            assert_eq!(buf, payload, "echo mismatch on stream {i}");
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// Denial survival: a DENY on stream 1 must not affect stream 2 (§14.3)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn denial_survival() {
    let dir = TempDir::new().unwrap();
    let (target, _echo) = spawn_echo_target().await;
    let server_sk = sk_from_byte(5);
    let client_sk = sk_from_byte(6);
    let (state, _) = test_state(&dir, &client_sk.public());
    state.add_rule("laptop", &target).unwrap();
    let server = spawn_server(state, &server_sk).await;
    let client_ep = test_endpoint(&client_sk).await;
    let conn = connect_client(&client_ep, &server).await;

    let (send, _recv, reply) = open_stream(&conn, "127.0.0.1:9999").await.unwrap();
    match reply {
        Some(DataFrame::Deny {
            reason: DataDenyReason::Unauthorized,
        }) => {}
        other => panic!("expected DENY unauthorized, got {other:?}"),
    }
    drop(send);

    // The connection survives; a second stream still forwards.
    let (_send2, _recv2, reply2) = open_stream(&conn, &target).await.unwrap();
    assert!(matches!(reply2, Some(DataFrame::Ok {})));
}

// ---------------------------------------------------------------------------
// Target unreachable → DENY with reason (§7.2)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn target_unreachable() {
    let dir = TempDir::new().unwrap();
    let server_sk = sk_from_byte(7);
    let client_sk = sk_from_byte(8);
    let (state, _) = test_state(&dir, &client_sk.public());
    // Port 1 on loopback is not listening.
    state.add_rule("laptop", "127.0.0.1:1").unwrap();
    let server = spawn_server(state, &server_sk).await;
    let client_ep = test_endpoint(&client_sk).await;
    let conn = connect_client(&client_ep, &server).await;

    let (_send, _recv, reply) = open_stream(&conn, "127.0.0.1:1").await.unwrap();
    match reply {
        Some(DataFrame::Deny {
            reason: DataDenyReason::TargetUnreachable { .. },
        }) => {}
        other => panic!("expected DENY target_unreachable, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Unknown peer: connection closed, no frames parsed (§14.3)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn unknown_peer_closed_without_reply() {
    let dir = TempDir::new().unwrap();
    let server_sk = sk_from_byte(9);
    let (state, _) = test_state(&dir, &server_sk.public());
    let server = spawn_server(state, &server_sk).await;

    // An attacker endpoint (not in the peer table) connects.
    let attacker = test_endpoint(&sk_from_byte(10)).await;
    let addr = EndpointAddr::new(server.node_id).with_ip_addr(server.addr);
    let conn = attacker.connect(addr, DATA_ALPN).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    // Send a syntactically valid FORWARD; the server must never answer.
    let frame = DataFrame::Forward {
        target: "127.0.0.1:22".into(),
    };
    send.write_all(&tmite_proto::frame::encode_frame(frame.msg_type(), &frame).unwrap())
        .await
        .unwrap();
    let mut buf = [0u8; 5];
    let res = tokio::time::timeout(Duration::from_secs(3), recv.read_exact(&mut buf)).await;
    // Either timeout (nothing parsed) or stream/connection closed with error.
    match res {
        Err(_) => { /* no reply within 3s: good */ }
        Ok(Ok(_)) => panic!("attacker received a reply"),
        Ok(Err(_)) => { /* stream reset/closed: good */ }
    }
}

// ---------------------------------------------------------------------------
// Malformed first frame: stream closed, connection alive (§14.3)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn malformed_forward_does_not_kill_connection() {
    let dir = TempDir::new().unwrap();
    let (target, _echo) = spawn_echo_target().await;
    let server_sk = sk_from_byte(11);
    let client_sk = sk_from_byte(12);
    let (state, _) = test_state(&dir, &client_sk.public());
    state.add_rule("laptop", &target).unwrap();
    let server = spawn_server(state, &server_sk).await;
    let client_ep = test_endpoint(&client_sk).await;
    let conn = connect_client(&client_ep, &server).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    // Over-limit control frame.
    send.write_all(&[0x01, 0xff, 0xff, 0xff, 0xff])
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    // Stream gets no OK; it should end/reset, not hang forever.
    let _ = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await;

    // Connection must still be usable.
    let (_s2, _r2, reply) = open_stream(&conn, &target).await.unwrap();
    assert!(matches!(reply, Some(DataFrame::Ok {})));
}

// ---------------------------------------------------------------------------
// VALIDATE probes: ACL answer without dialing the target (§7.2, §7.4)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn validate_allowed_does_not_dial_target() {
    let dir = TempDir::new().unwrap();
    let server_sk = sk_from_byte(13);
    let client_sk = sk_from_byte(14);
    let (state, _) = test_state(&dir, &client_sk.public());
    // Rule exists, but the target is not listening: a FORWARD would deny with
    // TargetUnreachable. VALIDATE must answer OK without ever dialing.
    state.add_rule("laptop", "127.0.0.1:1").unwrap();
    let server = spawn_server(state, &server_sk).await;
    let client_ep = test_endpoint(&client_sk).await;
    let conn = connect_client(&client_ep, &server).await;

    let (_send, _recv, reply) = open_validate_stream(&conn, "127.0.0.1:1")
        .await
        .unwrap();
    assert!(matches!(reply, Some(DataFrame::Ok {})));

    // Sanity: the same target via FORWARD does dial and denies.
    let (_s, _r, fwd_reply) = open_stream(&conn, "127.0.0.1:1").await.unwrap();
    match fwd_reply {
        Some(DataFrame::Deny {
            reason: DataDenyReason::TargetUnreachable { .. },
        }) => {}
        other => panic!("expected DENY target_unreachable, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn validate_denied_without_rule() {
    let dir = TempDir::new().unwrap();
    let server_sk = sk_from_byte(15);
    let client_sk = sk_from_byte(16);
    let (state, _) = test_state(&dir, &client_sk.public());
    state.add_rule("laptop", "127.0.0.1:22").unwrap();
    let server = spawn_server(state, &server_sk).await;
    let client_ep = test_endpoint(&client_sk).await;
    let conn = connect_client(&client_ep, &server).await;

    let (_send, _recv, reply) = open_validate_stream(&conn, "10.0.0.1:80")
        .await
        .unwrap();
    match reply {
        Some(DataFrame::Deny {
            reason: DataDenyReason::Unauthorized,
        }) => {}
        other => panic!("expected DENY unauthorized, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// SESSION hello: announces forwards, live count follows relays (§7.2)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn session_hello_registers_forwards_and_live_counts() {
    let dir = TempDir::new().unwrap();
    let (target, _echo) = spawn_echo_target().await;
    let server_sk = sk_from_byte(17);
    let client_sk = sk_from_byte(18);
    let (state, _) = test_state(&dir, &client_sk.public());
    state.add_rule("laptop", &target).unwrap();
    let server = spawn_server(state, &server_sk).await;
    let client_ep = test_endpoint(&client_sk).await;
    let conn = connect_client(&client_ep, &server).await;

    // Send the SESSION hello on its own stream; the server replies OK.
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let frame = DataFrame::Session {
        forwards: vec![SessionForward {
            local: "127.0.0.1:2222".into(),
            target: target.clone(),
        }],
    };
    send.write_all(&tmite_proto::frame::encode_frame(frame.msg_type(), &frame).unwrap())
        .await
        .unwrap();
    send.finish().unwrap();
    let mut header = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload).await.unwrap();
    let reply: DataFrame = tmite_proto::frame::decode_payload(&payload).unwrap();
    assert!(matches!(reply, DataFrame::Ok {}));

    // The registry knows the announced forward, no live streams, and the
    // (relay or direct) path snapshot is non-empty.
    let node_hex = client_sk.public().to_string();
    let info = server
        .sessions
        .peer_snapshot(&node_hex)
        .expect("session registered");
    assert_eq!(info.forwards.len(), 1);
    assert_eq!(info.forwards[0].local, "127.0.0.1:2222");
    assert_eq!(info.forwards[0].target, target);
    assert_eq!(info.forwards[0].live, 0);
    assert!(!info.paths.is_empty(), "expected at least one open path");

    // Opening a forwarding stream bumps the live count; closing drops it.
    let (mut fwd_send, mut fwd_recv, reply) = open_stream(&conn, &target).await.unwrap();
    assert!(matches!(reply, Some(DataFrame::Ok {})));
    let info = server.sessions.peer_snapshot(&node_hex).unwrap();
    assert_eq!(info.forwards[0].live, 1);

    fwd_send.finish().unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::io::AsyncReadExt::read_to_end(&mut fwd_recv, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let info = server.sessions.peer_snapshot(&node_hex).unwrap();
    assert_eq!(info.forwards[0].live, 0);
}
