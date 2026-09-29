//! JNI bridge for the Android app. Two-phase lifecycle mirrors VpnService:
//! 1. `nativeConnect` performs the full Minecraft login + tunnel auth and
//!    returns the assigned tunnel config. The TCP socket is established
//!    BEFORE the VpnService is up, so it never loops into the tunnel.
//! 2. Kotlin establishes the VpnService and passes the TUN fd to
//!    `nativeStart`, which runs the device <-> tunnel pumps.

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring};
use jni::JNIEnv;
use mcvpn::client::{self, Connected};
use mcvpn::config::ClientConfig;
use mcvpn::device;
use mcvpn::stats::{SharedStats, Stats};
use mcvpn::VpnError;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
/// 0 idle, 1 connecting, 2 connected, 3 error, 4 = session ended ("closed")
/// — the app polls this to clean up when the tunnel dies.
static STATE: AtomicU8 = AtomicU8::new(0);

struct AndroidSession {
    connected: Option<Connected>,
    driver: Option<(
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<mcvpn::VpnResult<()>>,
    )>,
    stats: SharedStats,
}

static SESSION: Mutex<Option<AndroidSession>> = Mutex::new(None);

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("mcvpn=info"))
            .try_init();
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

fn jstr(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|j| j.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn reason(e: &VpnError) -> String {
    match e {
        VpnError::Kick(r) => format!("kicked: {r}"),
        other => other.to_string(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mcvpn_client_TunnelService_nativeConnect(
    mut env: JNIEnv,
    _class: JClass,
    jserver: JString,
    port: jint,
    jtoken: JString,
) -> jstring {
    let server: String = match env.get_string(&jserver) {
        Ok(s) => s.into(),
        Err(_) => return jstr(&mut env, r#"{"ok":false,"error":"bad server arg"}"#),
    };
    let token: String = match env.get_string(&jtoken) {
        Ok(s) => s.into(),
        Err(_) => return jstr(&mut env, r#"{"ok":false,"error":"bad token arg"}"#),
    };

    STATE.store(1, Ordering::Relaxed);
    let cfg = ClientConfig {
        server,
        port: port.max(0) as u16,
        token,
        // Android reconnect needs socket protection via the VpnService API;
        // the app drives reconnections manually instead.
        auto_reconnect: false,
        ..Default::default()
    };
    let stats: SharedStats = Arc::new(Stats::default());
    let result = runtime().block_on(async {
        tokio::time::timeout(
            Duration::from_secs(20),
            client::connect_with_stats(&cfg, Arc::clone(&stats)),
        )
        .await
    });
    match result {
        Ok(Ok(connected)) => {
            let info = connected.info().clone();
            let ip = format!(
                "{}.{}.{}.{}",
                info.ip[0], info.ip[1], info.ip[2], info.ip[3]
            );
            let gw = format!(
                "{}.{}.{}.{}",
                info.gateway[0], info.gateway[1], info.gateway[2], info.gateway[3]
            );
            let mask = format!(
                "{}.{}.{}.{}",
                info.netmask[0], info.netmask[1], info.netmask[2], info.netmask[3]
            );
            let dns: Vec<String> = info
                .dns
                .iter()
                .map(|d| format!("{}.{}.{}.{}", d[0], d[1], d[2], d[3]))
                .collect();
            let prefix_len = u32::from(std::net::Ipv4Addr::from(info.netmask)).count_ones();
            let json = serde_json::json!({
                "ok": true,
                "ip": ip,
                "gateway": gw,
                "netmask": mask,
                "prefix_len": prefix_len,
                "mtu": info.mtu,
                "dns": dns,
            })
            .to_string();
            *SESSION.lock().unwrap() = Some(AndroidSession {
                connected: Some(connected),
                driver: None,
                stats,
            });
            STATE.store(2, Ordering::Relaxed);
            jstr(&mut env, &json)
        }
        Ok(Err(e)) => {
            STATE.store(3, Ordering::Relaxed);
            let json = serde_json::json!({ "ok": false, "error": reason(&e) }).to_string();
            jstr(&mut env, &json)
        }
        Err(_) => {
            STATE.store(3, Ordering::Relaxed);
            jstr(&mut env, r#"{"ok":false,"error":"connection timed out"}"#)
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mcvpn_client_TunnelService_nativeStart(
    _env: JNIEnv,
    _class: JClass,
    fd: jint,
) -> jboolean {
    let mut guard = SESSION.lock().unwrap();
    let Some(session) = guard.as_mut() else {
        return 0;
    };
    let Some(connected) = session.connected.take() else {
        return 0;
    };
    let device = device::fd::from_raw_fd("mcvpn-tun", fd);
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = runtime().spawn(async move {
        let result = connected.attach_device(device, rx).await;
        STATE.store(4, Ordering::Relaxed);
        result
    });
    session.driver = Some((tx, handle));
    1
}

#[no_mangle]
pub extern "system" fn Java_com_mcvpn_client_TunnelService_nativeStop(
    _env: JNIEnv,
    _class: JClass,
) {
    let mut guard = SESSION.lock().unwrap();
    if let Some(session) = guard.as_mut() {
        if let Some((tx, handle)) = session.driver.take() {
            let _ = tx.send(true);
            let _ = runtime()
                .block_on(async { tokio::time::timeout(Duration::from_secs(3), handle).await });
        }
        session.connected = None;
    }
    *guard = None;
    STATE.store(0, Ordering::Relaxed);
}

#[no_mangle]
pub extern "system" fn Java_com_mcvpn_client_TunnelService_nativeGetStats(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let state = match STATE.load(Ordering::Relaxed) {
        0 => "idle",
        1 => "connecting",
        2 => "connected",
        4 => "closed",
        _ => "error",
    };
    let guard = SESSION.lock().unwrap();
    let (up, down, rtt) = match guard.as_ref() {
        Some(s) => {
            let snap = s.stats.snapshot();
            (snap.up_bytes, snap.down_bytes, snap.rtt_ms)
        }
        None => (0, 0, 0),
    };
    drop(guard);
    let json = serde_json::json!({
        "state": state,
        "up": up,
        "down": down,
        "rtt": rtt,
    })
    .to_string();
    jstr(&mut env, &json)
}
