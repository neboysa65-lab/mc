//! Linux TUN device (server + desktop client). Opens /dev/net/tun via the
//! TUNSETIFF ioctl and brings the interface up with iproute2.

use super::DeviceHandle;
use crate::error::{VpnError, VpnResult};
use std::io;
use std::os::fd::RawFd;

#[repr(C)]
struct IfReq {
    name: [u8; 16],
    flags: i16,
    _pad: [u8; 22],
}

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;

/// Open a TUN device and bring it up. `addr_cidr` is the address with
/// prefix (gateway on the server, assigned client IP on a client).
pub fn open(name: &str, addr_cidr: &str, mtu: u16) -> VpnResult<DeviceHandle> {
    let fd = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(VpnError::Device(format!(
            "failed to open /dev/net/tun: {} (are you root?)",
            io::Error::last_os_error()
        )));
    }
    let mut req = IfReq {
        name: [0; 16],
        flags: IFF_TUN | IFF_NO_PI,
        _pad: [0; 22],
    };
    let name_bytes = name.as_bytes();
    if name_bytes.len() >= 15 {
        unsafe { libc::close(fd) };
        return Err(VpnError::Device("tun name too long".into()));
    }
    req.name[..name_bytes.len()].copy_from_slice(name_bytes);
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &mut req as *mut _) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(VpnError::Device(format!("TUNSETIFF failed: {e}")));
    }
    let real_name = String::from_utf8_lossy(&req.name)
        .trim_end_matches('\0')
        .to_string();

    // Interface up + address + MTU via iproute2 (same commands admins use).
    run(&["ip", "addr", "flush", "dev", &real_name])?;
    run(&["ip", "addr", "add", addr_cidr, "dev", &real_name])?;
    run(&[
        "ip",
        "link",
        "set",
        "dev",
        &real_name,
        "mtu",
        &mtu.to_string(),
        "up",
    ])?;

    let fd: RawFd = fd;
    Ok(super::fd::from_raw_fd(&real_name, fd))
}

fn run(cmd: &[&str]) -> VpnResult<()> {
    let out = std::process::Command::new(cmd[0])
        .args(&cmd[1..])
        .output()
        .map_err(|e| VpnError::Device(format!("failed to run {}: {e}", cmd[0])))?;
    if !out.status.success() {
        return Err(VpnError::Device(format!(
            "{} failed: {}",
            cmd[0],
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn constants_match_linux() {
        assert_eq!(super::IFF_TUN, 0x0001);
        assert_eq!(super::IFF_NO_PI, 0x1000);
    }

    // If root + /dev/net/tun are available, do a real device smoke test.
    #[test]
    fn open_real_tun_if_root() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dev = super::open("mcvpnt0", "100.127.255.254/10", 1400);
        let dev = match dev {
            Ok(d) => d,
            Err(_) => return, // container without CAP_NET_ADMIN: acceptable
        };
        let out = std::process::Command::new("ip")
            .args(["addr", "show", "dev", "mcvpnt0"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("mtu 1400"));
        dev.stop_device();
        drop(dev);
        let _ = std::process::Command::new("ip")
            .args(["link", "del", "dev", "mcvpnt0"])
            .output();
    }
}
