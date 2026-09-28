//! Minecraft-facing server: status ping decoy, login with real encryption,
//! and the play-state session that carries the tunnel.

use crate::config::ServerConfig;
use crate::conn::Conn;
use crate::error::{VpnError, VpnResult};
use crate::ip_pool::IpPool;
use crate::stats::{SharedStats, Stats};
use crate::tunnel::{self, Role, TunnelCrypto, TunnelInfo};
use mc_protocol::packets::{self, kick, play_id, CustomPayload, Handshake};
use mc_protocol::{McError, PROTOCOL_VERSION};
use rand::RngCore;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

pub struct Router {
    /// Client tunnel IP -> per-connection deliver channel (TUN -> client).
    by_ip: Mutex<HashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>>,
    /// Packets from clients -> TUN write side.
    tun_out: mpsc::Sender<Vec<u8>>,
}

impl Router {
    async fn deliver_batch(&self, batches: &mut HashMap<Ipv4Addr, Vec<Vec<u8>>>) {
        for (ip, pkts) in batches.drain() {
            let tx = self.by_ip.lock().unwrap().get(&ip).cloned();
            if let Some(tx) = tx {
                // Backpressure instead of drops; the receiving play loop
                // drains its channel in batches, so wakes coalesce.
                for pkt in pkts {
                    let _ = tx.send(pkt).await;
                }
            }
        }
    }

    #[allow(dead_code)]
    async fn deliver(&self, ip: Ipv4Addr, pkt: Vec<u8>) {
        let tx = self.by_ip.lock().unwrap().get(&ip).cloned();
        if let Some(tx) = tx {
            // Backpressure instead of drops: a slow client throttles itself.
            let _ = tx.send(pkt).await;
        }
    }
    fn register(&self, ip: Ipv4Addr, tx: mpsc::Sender<Vec<u8>>) {
        self.by_ip.lock().unwrap().insert(ip, tx);
    }
    fn unregister(&self, ip: Ipv4Addr) {
        self.by_ip.lock().unwrap().remove(&ip);
    }
}

pub struct ServerShared {
    pub cfg: ServerConfig,
    pub rsa: mc_protocol::login_crypto::ServerRsaKey,
    pub pool: Mutex<IpPool>,
    pub stats: SharedStats,
    pub router: Arc<Router>,
    pub pending: AtomicU32,
    pub active_sessions: AtomicU32,
    pub per_ip: Mutex<HashMap<IpAddr, Instant>>,
}

pub async fn run(
    cfg: ServerConfig,
    device: crate::device::DeviceHandle,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let pool = IpPool::new(&cfg.tunnel_cidr)?;
    let gw = pool.gateway();
    let prefix = pool.prefix();
    let stats: SharedStats = Arc::new(Stats::default());
    let (tun_out_tx, tun_out_rx) = mpsc::channel::<Vec<u8>>(1024);
    let router = Arc::new(Router { by_ip: Mutex::new(HashMap::new()), tun_out: tun_out_tx });

    let mut dev = device;
    let router_task = tokio::spawn({
        let router = Arc::clone(&router);
        let mut inbox = std::mem::replace(&mut dev.inbox, mpsc::channel(1).1);
        async move {
            // Drain bursts per wake and group by destination client.
            let mut batches: HashMap<Ipv4Addr, Vec<Vec<u8>>> = HashMap::new();
            while let Some(first) = inbox.recv().await {
                let mut batch = vec![first];
                while batch.len() < 256 {
                    match inbox.try_recv() {
                        Ok(p) => batch.push(p),
                        Err(_) => break,
                    }
                }
                for pkt in batch {
                    if pkt.len() >= 20 && pkt[0] >> 4 == 4 {
                        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                        batches.entry(dst).or_default().push(pkt);
                    }
                }
                router.deliver_batch(&mut batches).await;
            }
        }
    });

    let rsa = mc_protocol::login_crypto::ServerRsaKey::generate(cfg.rsa_bits, &mut rand::rngs::OsRng)?;
    let shared = Arc::new(ServerShared {
        cfg,
        rsa,
        pool: Mutex::new(pool),
        stats,
        router,
        pending: AtomicU32::new(0),
        active_sessions: AtomicU32::new(0),
        per_ip: Mutex::new(HashMap::new()),
    });

    let bind_addr: SocketAddr = format!("{}:{}", shared.cfg.bind, shared.cfg.port).parse()?;
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(
        "mcvpn server listening on {} (tunnel gw {} mtu {}, cidr {}/{})",
        bind_addr, gw, shared.cfg.mtu, gw, prefix
    );

    // device write pump: tunnel -> TUN
    let write_pump = tokio::spawn(async move {
        let outbox = dev.outbox.clone();
        let mut rx = tun_out_rx;
        while let Some(first) = rx.recv().await {
            let mut batch = vec![first];
            while batch.len() < 256 {
                match rx.try_recv() {
                    Ok(p) => batch.push(p),
                    Err(_) => break,
                }
            }
            for pkt in batch.drain(..) {
                let _ = outbox.send(pkt).await;
            }
        }
        dev.stop_device();
    });

    loop {
        tokio::select! {
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    tracing::info!("server shutting down");
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                if !throttle_ok(&shared, peer.ip()) {
                    drop(stream);
                    continue;
                }
                if shared.pending.load(Ordering::Relaxed) >= shared.cfg.max_pending {
                    drop(stream);
                    continue;
                }
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, shared).await {
                        tracing::debug!("connection ended: {e}");
                    }
                });
            }
        }
    }
    write_pump.abort();
    router_task.abort();
    Ok(())
}

fn throttle_ok(shared: &ServerShared, ip: IpAddr) -> bool {
    let min = Duration::from_millis(shared.cfg.per_ip_min_interval_ms);
    if min.is_zero() {
        return true;
    }
    let mut map = shared.per_ip.lock().unwrap();
    match map.get(&ip) {
        Some(t) if t.elapsed() < min => false,
        _ => {
            map.insert(ip, Instant::now());
            true
        }
    }
}

fn online_count(shared: &ServerShared) -> u32 {
    shared.active_sessions.load(Ordering::Relaxed).max(shared.cfg.fake_online)
}

async fn handle_conn(stream: TcpStream, shared: Arc<ServerShared>) -> VpnResult<()> {
    let mut conn = Conn::from_stream(stream);

    // --- Legacy probe detection (before any framing), like BungeeCord ---
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(10), conn.read_raw_exact(&mut first))
        .await
        .map_err(|_| VpnError::Timeout)?
        .map_err(VpnError::Io)?;
    if n == 0 {
        return Ok(());
    }
    if let Some(probe) = mc_protocol::legacy::detect(first[0], None) {
        let probe = match probe {
            mc_protocol::legacy::LegacyProbe::Ping(_) => {
                let mut second = [0u8; 1];
                let has_second = conn.read_raw_exact(&mut second).await.unwrap_or(0);
                let second = if has_second == 1 { Some(second[0]) } else { None };
                mc_protocol::legacy::detect(first[0], second).unwrap()
            }
            p => p,
        };
        return respond_legacy(conn, probe, &shared).await;
    }
    conn.seed(&first);

    // --- Handshake ---
    let body = recv_timeout(&mut conn, Duration::from_secs(10)).await?;
    let handshake = Handshake::decode(&body)?;
    match handshake.next_state {
        1 => status_flow(conn, &shared).await,
        2 => login_flow(conn, &shared, handshake).await,
        _ => Ok(()), // decode() already rejects other states
    }
}

async fn respond_legacy(
    mut conn: Conn,
    probe: mc_protocol::legacy::LegacyProbe,
    shared: &ServerShared,
) -> VpnResult<()> {
    let online = online_count(shared);
    let bytes = match probe {
        mc_protocol::legacy::LegacyProbe::Ping(true) => {
            mc_protocol::legacy::ping_response_v15(&shared.cfg.motd, online, shared.cfg.max_players)
        }
        mc_protocol::legacy::LegacyProbe::Ping(false) => {
            mc_protocol::legacy::ping_response_beta(&shared.cfg.motd, online, shared.cfg.max_players)
        }
        mc_protocol::legacy::LegacyProbe::Handshake => mc_protocol::legacy::handshake_response(),
    };
    conn.send_raw(&bytes).await?;
    Ok(())
}

async fn recv_timeout(conn: &mut Conn, d: Duration) -> VpnResult<Vec<u8>> {
    tokio::time::timeout(d, conn.recv()).await.map_err(|_| VpnError::Timeout)?
}

/// Server List Ping: handshake already parsed; answer status/ping and close.
async fn status_flow(mut conn: Conn, shared: &Arc<ServerShared>) -> VpnResult<()> {
    let body = recv_timeout(&mut conn, Duration::from_secs(10)).await?;
    use mc_protocol::packets::status_id;
    if body[0] == status_id::SB_REQUEST {
        let json = mc_protocol::slp::status_json(
            &shared.cfg.motd,
            online_count(shared),
            shared.cfg.max_players,
        );
        let resp = packets::StatusResponse { json }.encode();
        conn.send(&resp).await?;
        // Vanilla waits up to 30s for the ping request before closing.
        let ping_body = recv_timeout(&mut conn, Duration::from_secs(30)).await?;
        if ping_body[0] == status_id::SB_PING {
            let ping = packets::Ping::decode(&ping_body)?;
            conn.send(&packets::Pong { time: ping.time }.encode()).await?;
        }
    } else if body[0] == status_id::SB_PING {
        let ping = packets::Ping::decode(&body)?;
        conn.send(&packets::Pong { time: ping.time }.encode()).await?;
    }
    Ok(())
}

/// Login -> encryption -> play -> tunnel session.
async fn login_flow(
    mut conn: Conn,
    shared: &Arc<ServerShared>,
    handshake: Handshake,
) -> VpnResult<()> {
    use mc_protocol::packets::login_id;

    if !handshake.is_supported_version() {
        let reason = if handshake.protocol_version > PROTOCOL_VERSION {
            kick::outdated_server()
        } else {
            kick::outdated_client()
        };
        conn.send(&packets::LoginDisconnect { reason }.encode()).await?;
        return Ok(());
    }

    let body = recv_timeout(&mut conn, Duration::from_secs(10)).await?;
    if body[0] != login_id::SB_LOGIN_START {
        return Err(VpnError::Mc(McError::new("expected login start")));
    }
    let login_start = packets::LoginStart::decode(&body)?;

    shared.pending.fetch_add(1, Ordering::Relaxed);
    struct PendingGuard<'a>(&'a AtomicU32);
    impl Drop for PendingGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }
    let _pending_guard = PendingGuard(&shared.pending);

    // Vanilla online-mode behavior: send the encryption request.
    let mut verify_token = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut verify_token);
    let enc_req = packets::EncryptionRequest {
        server_id: String::new(),
        public_key: shared.rsa.public_key_der().to_vec(),
        verify_token: verify_token.to_vec(),
    };
    conn.send(&enc_req.encode()).await?;

    let body = recv_timeout(&mut conn, Duration::from_secs(10)).await?;
    if body[0] != login_id::SB_ENCRYPTION_RESPONSE {
        return Err(VpnError::Mc(McError::new("expected encryption response")));
    }
    let enc_resp = packets::EncryptionResponse::decode(&body)?;
    let (secret, token) = shared
        .rsa
        .decrypt_response(&enc_resp.shared_secret, &enc_resp.verify_token)?;
    if !tunnel::token_eq(&token, &verify_token) {
        let reason = kick::json("Failed to verify username!");
        conn.send(&packets::LoginDisconnect { reason }.encode()).await?;
        return Ok(());
    }
    conn.enable_encryption(&secret);

    // Vanilla order: Set Compression (sent uncompressed framing — the client
    // enables compression only after parsing this packet), then Login Success.
    conn.send(&packets::SetCompression { threshold: shared.cfg.compression_threshold as i32 }.encode())
        .await?;
    conn.set_compression(shared.cfg.compression_threshold as i32);
    let uuid = mc_protocol::login_crypto::offline_uuid_string(&login_start.name);
    conn.send(&packets::LoginSuccess { uuid, username: login_start.name.clone() }.encode())
        .await?;

    // --- Play state ---
    let entity_id: i32 = rand::rngs::OsRng.next_u32() as i32;
    let join = packets::JoinGame { entity_id, ..Default::default() };
    conn.send(&join.encode()).await?;
    let brand = CustomPayload { channel: packets::CHANNEL_BRAND.into(), data: b"vanilla".to_vec() };
    conn.send(&brand.encode_cb()).await?;

    play_session(conn, shared, login_start.name, secret).await
}

struct SessionGuard<'a> {
    shared: &'a Arc<ServerShared>,
    ip: Option<Ipv4Addr>,
}
impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if let Some(ip) = self.ip {
            self.shared.router.unregister(ip);
            self.shared.pool.lock().unwrap().release(ip);
        }
        self.shared.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn play_session(
    mut conn: Conn,
    shared: &Arc<ServerShared>,
    username: String,
    secret: [u8; 16],
) -> VpnResult<()> {
    use mc_protocol::packets::play_id::{SB_CLIENT_SETTINGS, SB_CUSTOM_PAYLOAD, SB_KEEP_ALIVE};

    let keepalive_interval = Duration::from_secs(shared.cfg.keepalive_secs);
    let mut keepalive_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + keepalive_interval,
        keepalive_interval,
    );
    let keepalive_timeout = keepalive_interval.saturating_mul(3);
    let mut pending_keepalive: Option<(u32, Instant)> = None;

    let mut session = SessionGuard { shared, ip: None };
    let mut crypto: Option<TunnelCrypto> = None;
    let mut to_client_rx: Option<mpsc::Receiver<Vec<u8>>> = None;
    let mut auth_deadline = Some(Instant::now() + Duration::from_secs(shared.cfg.auth_timeout_secs));

    loop {
        let auth_wait = match (auth_deadline, crypto.is_none()) {
            (Some(d), true) => d.saturating_duration_since(Instant::now()),
            _ => Duration::MAX,
        };
        let body = tokio::select! {
            b = conn.recv() => b?,
            _ = tokio::time::sleep(auth_wait), if crypto.is_none() => {
                let reason = kick::not_whitelisted();
                conn.send(&packets::PlayDisconnect { reason }.encode()).await?;
                break;
            }
            _ = keepalive_tick.tick() => {
                if let Some((_, sent)) = pending_keepalive {
                    if sent.elapsed() > keepalive_timeout {
                        let reason = kick::timed_out();
                        let _ = conn.send(&packets::PlayDisconnect { reason }.encode()).await;
                        break;
                    }
                }
                let id: u32 = rand::rngs::OsRng.next_u32() % 2_000_000;
                pending_keepalive = Some((id, Instant::now()));
                conn.send(&packets::PlayKeepAlive { id }.encode()).await?;
                continue;
            }
            pkt = async {
                match to_client_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(pkt) = pkt else { break };
                if let Some(c) = crypto.as_mut() {
                    // Drain queued TUN packets for this client and coalesce.
                    let mut batch = vec![pkt];
                    while batch.len() < 128 {
                        match to_client_rx.as_mut().unwrap().try_recv() {
                            Ok(p) => batch.push(p),
                            Err(_) => break,
                        }
                    }
                    let mut frames = Vec::with_capacity(batch.len());
                    let mut failed = false;
                    for pkt in batch {
                        match c.seal(&pkt) {
                            Ok(sealed) => {
                                frames.push(
                                    CustomPayload {
                                        channel: packets::CHANNEL_TUNNEL.into(),
                                        data: tunnel::encode_data(sealed),
                                    }
                                    .encode_cb(),
                                );
                            }
                            Err(_) => {
                                failed = true;
                                break;
                            }
                        }
                    }
                    if failed || conn.send_batch(frames).await.is_err() {
                        break;
                    }
                }
                continue;
            }
        };

        let id = body[0];
        match id {
            SB_KEEP_ALIVE => {
                let ka = packets::PlayKeepAlive::decode(&body)?;
                if let Some((pid, _)) = pending_keepalive {
                    if ka.id == pid {
                        pending_keepalive = None;
                    }
                }
            }
            SB_CLIENT_SETTINGS => {
                let _ = packets::ClientSettings::decode(&body)?; // validated, ignored (vanilla stores it)
            }
            SB_CUSTOM_PAYLOAD => {
                let cp = CustomPayload::decode_sb(&body)?;
                match cp.channel.as_str() {
                    packets::CHANNEL_BRAND => {
                        tracing::debug!(brand = ?String::from_utf8_lossy(&cp.data), "client brand");
                    }
                    packets::CHANNEL_REGISTER | packets::CHANNEL_UNREGISTER => {
                        tracing::debug!(channels = ?String::from_utf8_lossy(&cp.data), "plugin channel registration");
                    }
                    packets::CHANNEL_TUNNEL => {
                        match tunnel::decode(&cp.data)? {
                            tunnel::TunnelMsg::Auth { nonce, token } => {
                                if crypto.is_some() {
                                    let reason = kick::internal_error();
                                    conn.send(&packets::PlayDisconnect { reason }.encode()).await?;
                                    break;
                                }
                                if !tunnel::token_eq(&token, shared.cfg.token.as_bytes()) {
                                    tracing::warn!(?username, "bad tunnel token, kicking");
                                    let reason = kick::not_whitelisted();
                                    conn.send(&packets::PlayDisconnect { reason }.encode()).await?;
                                    break;
                                }
                                if shared.active_sessions.load(Ordering::Relaxed)
                                    >= shared.cfg.max_clients
                                {
                                    let reason = kick::server_full();
                                    conn.send(&packets::PlayDisconnect { reason }.encode()).await?;
                                    break;
                                }
                                let ip = shared.pool.lock().unwrap().allocate();
                                let Some(ip) = ip else {
                                    let reason = kick::server_full();
                                    conn.send(&packets::PlayDisconnect { reason }.encode()).await?;
                                    break;
                                };
                                crypto = Some(TunnelCrypto::derive(&secret, &nonce, Role::Server)?);
                                let (netmask, gateway) = {
                                    let pool = shared.pool.lock().unwrap();
                                    (pool.netmask().octets(), pool.gateway().octets())
                                };
                                let info = TunnelInfo {
                                    ip: ip.octets(),
                                    netmask,
                                    gateway,
                                    mtu: shared.cfg.mtu,
                                    dns: shared
                                        .cfg
                                        .dns
                                        .iter()
                                        .filter_map(|d| d.parse::<Ipv4Addr>().ok())
                                        .map(|d| d.octets())
                                        .collect(),
                                };
                                let ok = CustomPayload {
                                    channel: packets::CHANNEL_TUNNEL.into(),
                                    data: tunnel::encode_auth_ok(&info),
                                };
                                conn.send(&ok.encode_cb()).await?;
                                let (tx, rx) = mpsc::channel(1024);
                                shared.router.register(ip, tx);
                                to_client_rx = Some(rx);
                                session.ip = Some(ip);
                                shared.active_sessions.fetch_add(1, Ordering::Relaxed);
                                auth_deadline = None;
                                tracing::info!(?username, ip = %ip, "tunnel session established");
                            }
                            tunnel::TunnelMsg::Data(sealed) => {
                                let Some(c) = crypto.as_mut() else { continue };
                                match c.open(&sealed) {
                                    Ok(ip_packet) => {
                                        if ip_packet.len() >= 20 && ip_packet[0] >> 4 == 4 {
                                            let src = Ipv4Addr::new(
                                                ip_packet[12],
                                                ip_packet[13],
                                                ip_packet[14],
                                                ip_packet[15],
                                            );
                                            if shared.pool.lock().unwrap().contains(src) {
                                                shared.stats.add_down(ip_packet.len() as u64);
                                                if shared
                                                    .router
                                                    .tun_out
                                                    .send(ip_packet)
                                                    .await
                                                    .is_err()
                                                {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(?username, error = %e, "bad DATA message, kicking");
                                        let reason = kick::internal_error();
                                        conn.send(&packets::PlayDisconnect { reason }.encode()).await?;
                                        break;
                                    }
                                }
                            }
                            tunnel::TunnelMsg::Ping(v) => {
                                if crypto.is_some() {
                                    let pong = CustomPayload {
                                        channel: packets::CHANNEL_TUNNEL.into(),
                                        data: tunnel::encode_pong(v),
                                    };
                                    conn.send(&pong.encode_cb()).await?;
                                }
                            }
                            tunnel::TunnelMsg::Close(_) => {
                                tracing::info!(?username, "tunnel closed by client");
                                break;
                            }
                            _ => {}
                        }
                    }
                    other => {
                        tracing::debug!(channel = other, "ignored plugin channel");
                    }
                }
            }
            _ if play_id::sb_known_1_8(id) => {
                // Valid 1.8 serverbound play packet we don't need: ignore
                // silently, like a vanilla server processing it without acting.
            }
            _ => {
                tracing::debug!(packet = id, "unknown serverbound play packet, kicking");
                let reason = kick::internal_error();
                conn.send(&packets::PlayDisconnect { reason }.encode()).await?;
                break;
            }
        }
    }
    Ok(())
}
