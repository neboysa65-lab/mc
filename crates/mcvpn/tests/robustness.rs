//! Regression tests for server-side robustness bugs found by audit while
//! debugging "clients cannot connect at all" reports. Each of these was a
//! real defect; the tests fail on the old code.

use mc_protocol::login_crypto;
use mc_protocol::packets::{self, Handshake};
use mcvpn::client;
use mcvpn::config::{ClientConfig, ServerConfig};
use mcvpn::conn::Conn;
use mcvpn::device::mock::mock_pair;
use rand::RngCore;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;

fn server_cfg(port: u16, max_pending: u32, max_clients: u32) -> ServerConfig {
    ServerConfig {
        bind: "127.0.0.1".into(),
        port,
        token: "robust-token".into(),
        rsa_bits: 1024,
        max_pending,
        max_clients,
        per_ip_min_interval_ms: 0,
        auth_timeout_secs: 2,
        setup_nat: false,
        mock_device: true,
        ..Default::default()
    }
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn spawn_server(cfg: ServerConfig) {
    let (server_dev, internet) = mock_pair();
    std::mem::forget(internet);
    let (tx, rx) = watch::channel(false);
    std::mem::forget(tx);
    tokio::spawn(async move {
        let _ = mcvpn::server::run(cfg, server_dev, rx).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
}

fn client_cfg(port: u16, token: &str) -> ClientConfig {
    ClientConfig {
        server: "127.0.0.1".into(),
        port,
        token: token.into(),
        ..Default::default()
    }
}

/// Do the real Minecraft login by hand and return the connection in the
/// encrypted + compressed play state (so tests can send arbitrary frames).
async fn raw_login(port: u16) -> Conn {
    let mut conn = Conn::connect_host("127.0.0.1", port, Duration::from_secs(5))
        .await
        .unwrap();
    let hs = Handshake {
        protocol_version: 47,
        host: "127.0.0.1".into(),
        port,
        next_state: 2,
    };
    conn.send(&hs.encode()).await.unwrap();
    conn.send(
        &packets::LoginStart {
            name: "RawTester".into(),
        }
        .encode(),
    )
    .await
    .unwrap();
    let body = conn.recv().await.unwrap();
    let req = packets::EncryptionRequest::decode(&body).unwrap();
    let mut secret = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let (s, t) = login_crypto::client_encrypt_response(
        &req.public_key,
        &secret,
        &req.verify_token,
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    conn.send(
        &packets::EncryptionResponse {
            shared_secret: s,
            verify_token: t,
        }
        .encode(),
    )
    .await
    .unwrap();
    conn.enable_encryption(&secret);
    let body = conn.recv().await.unwrap();
    let sc = packets::SetCompression::decode(&body).unwrap();
    conn.set_compression(sc.threshold);
    let body = conn.recv().await.unwrap();
    packets::LoginSuccess::decode(&body).unwrap();
    conn
}

/// BUG: SessionGuard::drop decremented `active_sessions` even for sessions
/// that never authenticated (never incremented) -> u32 underflow -> every
/// later client was told "The server is full!" until the service restarted.
/// A single mistyped token bricked the whole server for everyone.
#[tokio::test]
async fn wrong_token_must_not_brick_the_server() {
    let port = free_port().await;
    spawn_server(server_cfg(port, 64, 16)).await;

    match client::connect(&client_cfg(port, "definitely-wrong")).await {
        Err(mcvpn::VpnError::Kick(_)) => {}
        Err(e) => panic!("expected a kick for a wrong token, got {e:?}"),
        Ok(_) => panic!("wrong token must not connect"),
    }
    // Give the server a moment to run the session's cleanup.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The right token must still work right after.
    let ok = client::connect(&client_cfg(port, "robust-token")).await;
    assert!(
        ok.is_ok(),
        "a failed attempt must not break later valid logins: {:?}",
        ok.err()
    );
}

/// Same underflow via a login that simply goes silent (auth timeout) and a
/// client that drops before authenticating.
#[tokio::test]
async fn silent_and_dropped_sessions_must_not_brick_the_server() {
    let port = free_port().await;
    spawn_server(server_cfg(port, 64, 16)).await;

    // (a) logs in, then never authenticates: server kicks after auth_timeout.
    let mut silent = raw_login(port).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), silent.recv()).await;
    // (b) logs in and disconnects immediately.
    drop(raw_login(port).await);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let ok = client::connect(&client_cfg(port, "robust-token")).await;
    assert!(
        ok.is_ok(),
        "server bricked by pre-auth exits: {:?}",
        ok.err()
    );
}

/// BUG: an empty COMPRESSED frame ([len=1][dataLen=0]) decoded to an empty
/// packet, and `body[0]` panicked; with panic=abort that killed the whole
/// server for every user, triggerable by anyone who completes the (public)
/// login handshake — no token needed.
#[tokio::test]
async fn empty_compressed_frame_does_not_crash_the_server() {
    let port = free_port().await;
    spawn_server(server_cfg(port, 64, 16)).await;

    let mut evil = raw_login(port).await;
    // Conn::send of an empty body produces exactly [0x01, 0x00].
    evil.send(&[]).await.unwrap();
    // Server must close (or kick) this connection. Skip the normal play-state
    // greeting (Join Game, brand) and look for the kick or a close.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, evil.recv()).await {
            Ok(Ok(body)) if body[0] == packets::play_id::CB_DISCONNECT => break,
            Ok(Ok(_)) => continue, // greeting / keep-alive
            Ok(Err(_)) => break,   // closed: fine
            Err(_) => panic!("server neither kicked nor closed the abusive connection"),
        }
    }
    // ...and keep serving everyone else.
    let ok = client::connect(&client_cfg(port, "robust-token")).await;
    assert!(ok.is_ok(), "server unusable after abuse: {:?}", ok.err());
}

/// BUG: the pending-login guard lived for the WHOLE play session, so
/// `max_pending` (default 64) silently capped concurrent connected clients
/// and new TCP connections were dropped at accept time.
#[tokio::test]
async fn max_pending_limits_logins_in_flight_not_live_sessions() {
    let port = free_port().await;
    spawn_server(server_cfg(port, 2, 64)).await;

    let mut live = Vec::new();
    for i in 0..6 {
        let c = client::connect(&client_cfg(port, "robust-token"))
            .await
            .unwrap_or_else(|e| panic!("client #{i} refused with max_pending=2: {e:?}"));
        live.push(c);
    }
    assert_eq!(live.len(), 6);
}

/// The max_clients cap must hold exactly (atomic reservation), and slots
/// must be released when sessions end.
#[tokio::test]
async fn max_clients_is_enforced_and_slots_are_released() {
    let port = free_port().await;
    spawn_server(server_cfg(port, 64, 2)).await;

    let a = client::connect(&client_cfg(port, "robust-token"))
        .await
        .unwrap();
    let b = client::connect(&client_cfg(port, "robust-token"))
        .await
        .unwrap();
    match client::connect(&client_cfg(port, "robust-token")).await {
        Err(mcvpn::VpnError::Kick(r)) => assert!(r.to_lowercase().contains("full"), "{r}"),
        Err(e) => panic!("expected server-full kick, got {e:?}"),
        Ok(_) => panic!("third client must be refused (max_clients=2)"),
    }
    drop(a);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let c = client::connect(&client_cfg(port, "robust-token")).await;
    assert!(c.is_ok(), "slot was not released: {:?}", c.err());
    drop(b);
}
