//! IPC server integration: scripted request/result sequences over a real
//! unix socket (§14.3). peer.invite is excluded (requires iroh relays);
//! it is exercised in the manual smoke flow.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use tmite_core::daemon::invite::InviteManager;
use tmite_core::daemon::ipc::{DaemonHandle, serve};
use tmite_core::daemon::state::State;

async fn start_daemon_ipc(dir: &tempfile::TempDir) -> (std::path::PathBuf, Arc<State>) {
    let state = Arc::new(State::load(&dir.path().join("state.toml")).unwrap());
    state
        .add_peer(tmite_core::daemon::state::Peer {
            name: "laptop".into(),
            node_id: "cc33".into(),
            paired_at: "t".into(),
            last_seen: "t".into(),
        })
        .unwrap();
    let invites = Arc::new(InviteManager::new(Default::default(), state.clone()));
    let (stop_tx, _stop_rx) = mpsc::unbounded_channel();
    let handle = Arc::new(DaemonHandle {
        state: state.clone(),
        invites,
        node_id: "ab12".into(),
        version: "0.1.0".into(),
        started: std::time::Instant::now(),
        stop_tx,
    });
    let path = dir.path().join("daemon.sock");
    tokio::spawn(serve(path.clone(), handle));
    // Wait for the socket to appear.
    for _ in 0..50 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(path.exists(), "socket not created");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o660, "IPC socket must be group-usable");
    }
    (path, state)
}

struct Client {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    write: tokio::net::unix::OwnedWriteHalf,
}

async fn connect(path: &std::path::Path) -> Client {
    let stream = UnixStream::connect(path).await.unwrap();
    let (r, w) = stream.into_split();
    Client {
        reader: BufReader::new(r),
        write: w,
    }
}

impl Client {
    async fn send(&mut self, id: u64, method: &str, params: serde_json::Value) {
        let line = json!({ "id": id, "method": method, "params": params });
        self.write
            .write_all(serde_json::to_string(&line).unwrap().as_bytes())
            .await
            .unwrap();
        self.write.write_all(b"\n").await.unwrap();
        self.write.flush().await.unwrap();
    }

    async fn reply(&mut self) -> serde_json::Value {
        let mut line = String::new();
        self.reader.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ipc_request_result_sequences() {
    let dir = tempfile::TempDir::new().unwrap();
    let (path, _state) = start_daemon_ipc(&dir).await;

    let mut c = connect(&path).await;
    c.send(
        1,
        "peer.allow",
        json!({"peer": "laptop", "target": "localhost:22"}),
    )
    .await;
    let r = c.reply().await;
    assert_eq!(r["id"], 1);
    assert_eq!(r["result"]["rule_index"], 0);

    // Unknown peer → not_found.
    c.send(2, "peer.allow", json!({"peer": "ghost", "target": "x:1"}))
        .await;
    let r = c.reply().await;
    assert_eq!(r["error"]["code"], "not_found");

    // peer.ls reflects the rule.
    c.send(3, "peer.ls", json!({})).await;
    let r = c.reply().await;
    assert_eq!(r["result"]["rules"][0]["peer"], "laptop");
    assert_eq!(r["result"]["rules"][0]["target"], "localhost:22");

    // peer.revoke removes it; second revoke reports removed=false.
    c.send(
        4,
        "peer.revoke",
        json!({"peer": "laptop", "target": "localhost:22"}),
    )
    .await;
    let r = c.reply().await;
    assert_eq!(r["result"]["removed"], true);
    c.send(
        5,
        "peer.revoke",
        json!({"peer": "laptop", "target": "localhost:22"}),
    )
    .await;
    let r = c.reply().await;
    assert_eq!(r["result"]["removed"], false);

    // daemon.status.
    c.send(6, "daemon.status", json!({})).await;
    let r = c.reply().await;
    assert_eq!(r["result"]["node_id"], "ab12");
    assert_eq!(r["result"]["peers"], 1);

    // rm of a missing peer → removed=false, not an error.
    c.send(7, "peer.rm", json!({"peer": "ghost"})).await;
    let r = c.reply().await;
    assert_eq!(r["result"]["removed"], false);

    // Unknown method is a parse error: bad_request, then close (§9.1).
    c.send(8, "nope.method", json!({})).await;
    let r = c.reply().await;
    assert_eq!(r["error"]["code"], "bad_request");
    let mut line = String::new();
    let n = c.reader.read_line(&mut line).await.unwrap();
    assert_eq!(n, 0, "daemon should close after a malformed request");

    // Malformed line → bad_request and the connection is closed (§9.1).
    let mut c3 = connect(&path).await;
    c3.write.write_all(b"not json\n").await.unwrap();
    c3.write.flush().await.unwrap();
    let r = c3.reply().await;
    assert_eq!(r["error"]["code"], "bad_request");
    let mut line = String::new();
    let n = c3.reader.read_line(&mut line).await.unwrap();
    assert_eq!(n, 0, "daemon should close after malformed line");

    // A second connection still works (state shared through the daemon).
    let mut c2 = connect(&path).await;
    c2.send(1, "daemon.status", json!({})).await;
    let r = c2.reply().await;
    assert_eq!(r["result"]["peers"], 1);
}
