use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, SecretKey};

#[tokio::test(flavor = "multi_thread")]
async fn iroh_smoke() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .try_init();
    let sk1 = SecretKey::generate();
    let sk2 = SecretKey::generate();
    let ep1 = Endpoint::builder(presets::Minimal)
        .secret_key(sk1)
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();
    let ep2 = Endpoint::builder(presets::Minimal)
        .secret_key(sk2)
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();

    let router = iroh::protocol::Router::builder(ep1.clone())
        .accept(b"smoke/1", Echo)
        .spawn();

    let addr = ep1
        .addr()
        .ip_addrs()
        .find(|s| s.ip().is_loopback())
        .copied()
        .expect("no loopback addr");
    eprintln!("dialing {addr}");

    let target = EndpointAddr::new(ep1.id()).with_ip_addr(addr);
    let conn = ep2.connect(target, b"smoke/1").await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    eprintln!("stream open");
    send.write_all(b"ping").await.unwrap();
    send.finish().ok();
    let mut buf = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut buf),
    )
    .await;
    match read {
        Ok(Ok(n)) => eprintln!("client read {n} bytes: {:?}", buf),
        Ok(Err(e)) => panic!("read failed: {e}"),
        Err(_) => panic!("timeout waiting for echo"),
    }
    assert_eq!(buf, b"ping");
    router.shutdown().await.ok();
    ep2.close().await;
}

#[derive(Debug, Clone)]
struct Echo;

impl iroh::protocol::ProtocolHandler for Echo {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        eprintln!("echo handler invoked");
        let res = async {
            let (mut send, mut recv) = conn.accept_bi().await?;
            eprintln!("echo: stream accepted");
            let mut buf = [0u8; 4];
            recv.read_exact(&mut buf).await?;
            eprintln!("echo: read {buf:?}");
            send.write_all(&buf).await?;
            eprintln!("echo: wrote reply");
            send.finish()?;
            eprintln!("echo: finished");
            conn.closed().await;
            eprintln!("echo: connection closed");
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        if let Err(e) = res {
            eprintln!("echo error: {e}");
        }
        Ok(())
    }
}
