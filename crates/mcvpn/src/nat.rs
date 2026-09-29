//! Linux NAT for the tunnel (MASQUERADE + FORWARD rules, idempotent,
//! tagged with iptables comments for clean teardown).

use crate::error::{VpnError, VpnResult};
use std::process::Command;

pub const COMMENT: &str = "mcvpn";

fn iptables(verb: &str, args: &[String]) -> VpnResult<()> {
    let out = Command::new("iptables")
        .arg("-w")
        .arg(verb)
        .args(args)
        .arg("-m")
        .arg("comment")
        .arg("--comment")
        .arg(COMMENT)
        .output()
        .map_err(|e| VpnError::Device(format!("iptables not available: {e}")))?;
    if !out.status.success() {
        return Err(VpnError::Device(format!(
            "iptables {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn have_rule(args: &[String]) -> bool {
    Command::new("iptables")
        .arg("-C")
        .args(args)
        .arg("-m")
        .arg("comment")
        .arg("--comment")
        .arg(COMMENT)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn add(args: &[String]) -> VpnResult<()> {
    if have_rule(args) {
        return Ok(());
    }
    iptables("-A", args)
}

/// FORWARD rules are INSERTED (not appended) so pre-existing firewall
/// chains (ufw etc.) cannot drop tunnel traffic before our rules match.
fn add_forward(args: &[String]) -> VpnResult<()> {
    if have_rule(args) {
        return Ok(());
    }
    iptables("-I", args)
}

fn del_all(args: &[String]) {
    while have_rule(args) {
        if iptables("-D", args).is_err() {
            break;
        }
    }
}

pub fn setup(tunnel_cidr: &str, tun_iface: &str) -> VpnResult<()> {
    // Enable IPv4 forwarding (runtime; install script persists it).
    let out = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output()
        .map_err(|e| VpnError::Device(format!("sysctl failed: {e}")))?;
    if !out.status.success() {
        return Err(VpnError::Device("failed to enable ip_forward".into()));
    }

    add(&[
        "-t".into(),
        "nat".into(),
        "POSTROUTING".into(),
        "-s".into(),
        tunnel_cidr.into(),
        "!".into(),
        "-o".into(),
        tun_iface.into(),
        "-j".into(),
        "MASQUERADE".into(),
    ])?;
    add_forward(&[
        "FORWARD".into(),
        "-i".into(),
        tun_iface.into(),
        "-j".into(),
        "ACCEPT".into(),
    ])?;
    add_forward(&[
        "FORWARD".into(),
        "-o".into(),
        tun_iface.into(),
        "-m".into(),
        "conntrack".into(),
        "--ctstate".into(),
        "RELATED,ESTABLISHED".into(),
        "-j".into(),
        "ACCEPT".into(),
    ])?;
    Ok(())
}

pub fn teardown(tunnel_cidr: &str, tun_iface: &str) {
    del_all(&[
        "-t".into(),
        "nat".into(),
        "POSTROUTING".into(),
        "-s".into(),
        tunnel_cidr.into(),
        "!".into(),
        "-o".into(),
        tun_iface.into(),
        "-j".into(),
        "MASQUERADE".into(),
    ]);
    del_all(&[
        "FORWARD".into(),
        "-i".into(),
        tun_iface.into(),
        "-j".into(),
        "ACCEPT".into(),
    ]);
    del_all(&[
        "FORWARD".into(),
        "-o".into(),
        tun_iface.into(),
        "-m".into(),
        "conntrack".into(),
        "--ctstate".into(),
        "RELATED,ESTABLISHED".into(),
        "-j".into(),
        "ACCEPT".into(),
    ]);
}
