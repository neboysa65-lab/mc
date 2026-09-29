//! Windows device via WinTun (the same driver WireGuard-for-Windows uses).
//! Requires wintun.dll next to the exe (or on PATH) and admin rights for
//! adapter creation and routes.

use super::DeviceHandle;
use crate::error::{VpnError, VpnResult};
use crate::tunnel::TunnelInfo;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

pub const ADAPTER_NAME: &str = "mcvpn";

fn dll_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")))
        .unwrap_or_else(|| PathBuf::from("wintun.dll"))
}

fn add_routes(ip: &Ipv4Addr) {
    // Split default route: two /1 routes via the adapter's own address.
    for net in ["0.0.0.0", "128.0.0.0"] {
        let _ = std::process::Command::new("route")
            .args([
                "add",
                net,
                "mask",
                "128.0.0.0",
                &ip.to_string(),
                "metric",
                "1",
            ])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output();
    }
}

fn remove_routes(ip: &Ipv4Addr) {
    for net in ["0.0.0.0", "128.0.0.0"] {
        let _ = std::process::Command::new("route")
            .args(["delete", net, "mask", "128.0.0.0", &ip.to_string()])
            .creation_flags(0x08000000)
            .output();
    }
}

pub fn open(info: &TunnelInfo) -> VpnResult<DeviceHandle> {
    let wintun = unsafe { wintun::load_from_path(dll_path()) }
        .or_else(|_| unsafe { wintun::load() })
        .map_err(|e| VpnError::Device(format!("failed to load wintun.dll: {e}")))?;
    let adapter = match wintun::Adapter::open(&wintun, ADAPTER_NAME) {
        Ok(a) => a,
        Err(_) => {
            wintun::Adapter::create(&wintun, ADAPTER_NAME, ADAPTER_NAME, None).map_err(|e| {
                VpnError::Device(format!(
                    "wintun adapter create failed (run as Administrator): {e}"
                ))
            })?
        }
    };
    let _ = adapter.set_mtu(info.mtu as usize);
    let ip = Ipv4Addr::from(info.ip);
    let mask = Ipv4Addr::from(info.netmask);
    adapter
        .set_address(ip)
        .map_err(|e| VpnError::Device(format!("set address failed: {e}")))?;
    let _ = adapter.set_netmask(mask);
    let dns: Vec<std::net::IpAddr> = info
        .dns
        .iter()
        .map(|d| std::net::IpAddr::V4(Ipv4Addr::from(*d)))
        .collect();
    if !dns.is_empty() {
        let _ = adapter.set_dns_servers(&dns);
    }
    add_routes(&ip);

    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| VpnError::Device(format!("wintun session failed: {e}")))?,
    );

    let (inbox_tx, inbox_rx) = mpsc::channel::<Vec<u8>>(512);
    let (outbox_tx, mut outbox_rx) = mpsc::channel::<Vec<u8>>(512);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_reader = Arc::clone(&stop);
    let stop_writer = Arc::clone(&stop);
    let reader_session = Arc::clone(&session);

    std::thread::Builder::new()
        .name("wintun-rd".into())
        .spawn(move || loop {
            if stop_reader.load(Ordering::Relaxed) {
                break;
            }
            match reader_session.receive_blocking() {
                Ok(pkt) => {
                    if inbox_tx.blocking_send(pkt.bytes().to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    // Session was shut down.
                    break;
                }
            }
        })
        .map_err(|e| VpnError::Device(format!("thread spawn: {e}")))?;

    let writer_session = Arc::clone(&session);
    std::thread::Builder::new()
        .name("wintun-wr".into())
        .spawn(move || {
            while let Some(pkt) = outbox_rx.blocking_recv() {
                if stop_writer.load(Ordering::Relaxed) {
                    break;
                }
                if let Ok(size) = u16::try_from(pkt.len()) {
                    if let Ok(mut p) = writer_session.allocate_send_packet(size) {
                        p.bytes_mut().copy_from_slice(&pkt);
                        writer_session.send_packet(p);
                    }
                }
            }
        })
        .map_err(|e| VpnError::Device(format!("thread spawn: {e}")))?;

    let cleanup_ip = ip;
    let cleanup_session = Arc::clone(&session);
    Ok(DeviceHandle {
        inbox: inbox_rx,
        outbox: outbox_tx,
        name: ADAPTER_NAME.to_string(),
        stop: Some(stop),
        cleanup: Some(Box::new(move || {
            let _ = cleanup_session.shutdown();
            remove_routes(&cleanup_ip);
        })),
    })
}
