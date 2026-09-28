use crate::error::{VpnError, VpnResult};
use std::collections::HashSet;
use std::net::Ipv4Addr;

/// Simple sequential allocator over a CIDR (default 100.64.0.0/10).
pub struct IpPool {
    base: u32,
    prefix: u8,
    used: HashSet<u32>,
    next: u32,
}

impl IpPool {
    pub fn new(cidr: &str) -> VpnResult<Self> {
        let (net, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| VpnError::Device(format!("bad cidr {cidr}")))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| VpnError::Device(format!("bad prefix in {cidr}")))?;
        if prefix > 32 || prefix < 8 {
            return Err(VpnError::Device("prefix must be 8..=32".into()));
        }
        let net: Ipv4Addr = net
            .parse()
            .map_err(|_| VpnError::Device(format!("bad network in {cidr}")))?;
        let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        let base = u32::from(net) & mask;
        Ok(IpPool { base, prefix, used: HashSet::new(), next: base + 2 })
    }

    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base + 1)
    }

    pub fn netmask(&self) -> Ipv4Addr {
        let mask: u32 = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
        Ipv4Addr::from(mask)
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask: u32 = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
        (u32::from(ip) & mask) == self.base
    }

    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        // Lowest-first allocation: deterministic and reuses released IPs.
        let first = self.base + 2;
        let last = self.broadcast() - 1;
        if last < first {
            return None;
        }
        for candidate in first..=last {
            if self.used.insert(candidate) {
                self.next = candidate + 1;
                return Some(Ipv4Addr::from(candidate));
            }
        }
        None
    }

    fn broadcast(&self) -> u32 {
        let host_bits = 32 - self.prefix;
        let base = self.base;
        if host_bits >= 32 {
            u32::MAX
        } else {
            base | ((1u32 << host_bits) - 1)
        }
    }

    pub fn release(&mut self, ip: Ipv4Addr) {
        self.used.remove(&u32::from(ip));
    }

    pub fn in_use(&self) -> usize {
        self.used.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_from_cgnat() {
        let mut p = IpPool::new("100.64.0.0/10").unwrap();
        assert_eq!(p.gateway().to_string(), "100.64.0.1");
        let a = p.allocate().unwrap();
        let b = p.allocate().unwrap();
        assert_eq!(a.to_string(), "100.64.0.2");
        assert_eq!(b.to_string(), "100.64.0.3");
        assert_eq!(p.in_use(), 2);
        p.release(a);
        let c = p.allocate().unwrap();
        assert_eq!(c.to_string(), "100.64.0.2");
        assert!(p.contains("100.100.1.1".parse().unwrap()));
        assert!(!p.contains("100.0.0.1".parse().unwrap()));
    }

    #[test]
    fn small_pool_exhausts() {
        let mut p = IpPool::new("10.0.0.0/30").unwrap();
        // /30 = 4 addresses: network, gateway, one host, broadcast.
        assert!(p.allocate().is_some());
        assert!(p.allocate().is_none());
        let mut p = IpPool::new("10.0.0.0/29").unwrap();
        for _ in 0..5 {
            assert!(p.allocate().is_some());
        }
        assert!(p.allocate().is_none());
    }
}
