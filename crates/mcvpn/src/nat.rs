//! Linux NAT for the tunnel (MASQUERADE + FORWARD rules, idempotent, tagged
//! with iptables comments for clean teardown).
//!
//! iptables requires the TABLE OPTION BEFORE THE COMMAND
//! (`iptables -t nat -A POSTROUTING ...`); `-A -t nat ...` is rejected with
//! "Bad argument" — v0.1.1 shipped exactly that, so MASQUERADE was never
//! installed on real hosts and every client showed "connected" with no
//! internet. The argv order is now pinned by the unit tests below.

use crate::error::{VpnError, VpnResult};
use std::process::Command;

pub const COMMENT: &str = "mcvpn";

/// Full iptables argv for one invocation: `-w [table] COMMAND spec... -m
/// comment --comment mcvpn`. The table-before-command order is load-bearing.
fn argv(verb: &str, table: Option<&str>, spec: &[&str]) -> Vec<String> {
    let mut v = Vec::with_capacity(4 + spec.len());
    v.push("-w".into());
    if let Some(t) = table {
        v.push("-t".into());
        v.push(t.into());
    }
    v.push(verb.into());
    for s in spec {
        v.push((*s).to_string());
    }
    v.push("-m".into());
    v.push("comment".into());
    v.push("--comment".into());
    v.push(COMMENT.into());
    v
}

fn run(args: &[String]) -> VpnResult<()> {
    let out = Command::new("iptables")
        .args(args)
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

fn exists(table: Option<&str>, spec: &[&str]) -> bool {
    Command::new("iptables")
        .args(argv("-C", table, spec))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Insert a rule at the HEAD of the chain (so pre-existing firewall chains
/// like ufw cannot shadow it) unless an identical rule is already present.
fn insert(table: Option<&str>, spec: &[&str]) -> VpnResult<()> {
    if exists(table, spec) {
        return Ok(());
    }
    run(&argv("-I", table, spec))
}

fn delete_all(table: Option<&str>, spec: &[&str]) {
    while exists(table, spec) {
        if run(&argv("-D", table, spec)).is_err() {
            break;
        }
    }
}

pub fn setup(tunnel_cidr: &str, tun_iface: &str) -> VpnResult<()> {
    // Enable IPv4 forwarding (runtime; install.sh persists it via sysctl.d).
    let out = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output()
        .map_err(|e| VpnError::Device(format!("sysctl failed: {e}")))?;
    if !out.status.success() {
        return Err(VpnError::Device("failed to enable ip_forward".into()));
    }

    insert(
        Some("nat"),
        &[
            "POSTROUTING",
            "-s",
            tunnel_cidr,
            "!",
            "-o",
            tun_iface,
            "-j",
            "MASQUERADE",
        ],
    )?;
    insert(None, &["FORWARD", "-i", tun_iface, "-j", "ACCEPT"])?;
    insert(
        None,
        &[
            "FORWARD",
            "-o",
            tun_iface,
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    )?;
    Ok(())
}

pub fn teardown(tunnel_cidr: &str, tun_iface: &str) {
    delete_all(
        Some("nat"),
        &[
            "POSTROUTING",
            "-s",
            tunnel_cidr,
            "!",
            "-o",
            tun_iface,
            "-j",
            "MASQUERADE",
        ],
    );
    delete_all(None, &["FORWARD", "-i", tun_iface, "-j", "ACCEPT"]);
    delete_all(
        None,
        &[
            "FORWARD",
            "-o",
            tun_iface,
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_option_comes_before_the_command() {
        // v0.1.1 shipped `-A -t nat ...` and iptables rejected it with
        // "Bad argument `nat`" — MASQUERADE never installed, clients had no
        // internet. This pins the correct order forever.
        let v = argv(
            "-I",
            Some("nat"),
            &[
                "POSTROUTING",
                "-s",
                "100.64.0.0/10",
                "!",
                "-o",
                "mcvpn0",
                "-j",
                "MASQUERADE",
            ],
        );
        assert_eq!(
            v,
            vec![
                "-w",
                "-t",
                "nat",
                "-I",
                "POSTROUTING",
                "-s",
                "100.64.0.0/10",
                "!",
                "-o",
                "mcvpn0",
                "-j",
                "MASQUERADE",
                "-m",
                "comment",
                "--comment",
                COMMENT,
            ]
        );
    }

    #[test]
    fn filter_rules_have_no_table_option() {
        let v = argv("-I", None, &["FORWARD", "-i", "mcvpn0", "-j", "ACCEPT"]);
        assert_eq!(
            v,
            vec![
                "-w",
                "-I",
                "FORWARD",
                "-i",
                "mcvpn0",
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                COMMENT,
            ]
        );
    }
}
