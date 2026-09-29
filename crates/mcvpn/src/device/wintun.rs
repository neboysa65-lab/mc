//! Windows device via WinTun (the same driver WireGuard-for-Windows uses).
//! Requires wintun.dll next to the exe and Administrator rights (the
//! embedded manifest auto-elevates; see mcvpn-gui/build.rs).
//!
//! All OS configuration (address, DNS, MTU, routes) is done with our own
//! netsh/route calls: hidden (CREATE_NO_WINDOW — the wintun crate's built-in
//! netsh calls flash console windows) and CHECKED — a failed route no longer
//! leaves the client "connected" while traffic bypasses the tunnel.

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
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn dll_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")))
        .unwrap_or_else(|| PathBuf::from("wintun.dll"))
}

fn run_checked(cmd: &str, args: &[&str]) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    let out = std::process::Command::new(cmd)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    #[cfg(not(target_os = "windows"))]
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    if out.status.success() {
        Ok(text)
    } else {
        Err(format!("{cmd} {} failed: {}", args.join(" "), text.trim()))
    }
}

fn run_ignored(cmd: &str, args: &[&str]) {
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new(cmd)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    #[cfg(not(target_os = "windows"))]
    let _ = std::process::Command::new(cmd).args(args).output();
}

/// Set address + netmask on the adapter. Checked: without an address the
/// routes below cannot work, so a failure here must fail the connection.
fn set_address(adapter: &str, ip: &Ipv4Addr, mask: &Ipv4Addr) -> Result<(), String> {
    run_checked(
        "netsh",
        &[
            "interface",
            "ip",
            "set",
            "address",
            &format!("name={adapter}"),
            "source=static",
            &format!("address={ip}"),
            &format!("mask={mask}"),
        ],
    )
    .map(|_| ())
}

fn set_dns(adapter: &str, dns: &[[u8; 4]]) -> Result<(), String> {
    let Some(first) = dns.first() else {
        return Ok(());
    };
    let f = Ipv4Addr::from(*first);
    run_checked(
        "netsh",
        &[
            "interface",
            "ip",
            "set",
            "dnsservers",
            &format!("name={adapter}"),
            "source=static",
            &format!("address={f}"),
            "validate=no",
        ],
    )
    .map(|_| ())?;
    for (i, d) in dns.iter().enumerate().skip(1) {
        let d = Ipv4Addr::from(*d);
        run_checked(
            "netsh",
            &[
                "interface",
                "ip",
                "add",
                "dnsservers",
                &format!("name={adapter}"),
                &format!("address={d}"),
                &format!("index={}", i + 1),
                "validate=no",
            ],
        )
        .map(|_| ())?;
    }
    Ok(())
}

/// MTU is best-effort: some Windows builds reject the subinterface form and
/// the default (1400) still works for the data plane.
fn set_mtu(adapter: &str, mtu: u16) {
    let _ = run_checked(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "subinterface",
            adapter,
            &format!("mtu={mtu}"),
            "store=active",
        ],
    );
}

/// Install the split-default routes through the adapter. CHECKED: if these
/// fail, traffic bypasses the tunnel — the client must report it loudly
/// instead of showing "connected" with the user's real IP.
fn add_routes(ip: &Ipv4Addr) -> Result<(), String> {
    for net in ["0.0.0.0", "128.0.0.0"] {
        let spec = [
            "add",
            net,
            "mask",
            "128.0.0.0",
            &ip.to_string(),
            "metric",
            "1",
        ];
        match run_checked("route", &spec) {
            Ok(_) => {}
            // A leftover route from a previous run: update it instead.
            Err(add_err) => {
                let change = [
                    "change",
                    net,
                    "mask",
                    "128.0.0.0",
                    &ip.to_string(),
                    "metric",
                    "1",
                ];
                if run_checked("route", &change).is_err() {
                    return Err(format!(
                        "route {net} could not be installed (tried add and change): {add_err}"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn remove_routes(ip: &Ipv4Addr) {
    for net in ["0.0.0.0", "128.0.0.0"] {
        run_ignored(
            "route",
            &["delete", net, "mask", "128.0.0.0", &ip.to_string()],
        );
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
    let adapter_name = adapter
        .get_name()
        .map_err(|e| VpnError::Device(format!("wintun adapter name: {e}")))?;

    let ip = Ipv4Addr::from(info.ip);
    let mask = Ipv4Addr::from(info.netmask);
    set_address(&adapter_name, &ip, &mask)
        .map_err(|e| VpnError::Device(format!("adapter address: {e}")))?;
    set_dns(&adapter_name, &info.dns).map_err(|e| VpnError::Device(format!("adapter DNS: {e}")))?;
    set_mtu(&adapter_name, info.mtu);
    add_routes(&ip)
        .map_err(|e| VpnError::Device(format!("routing (traffic would bypass the tunnel): {e}")))?;

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
                Err(_) => break, // session shut down
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
