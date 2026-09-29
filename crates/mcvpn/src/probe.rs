//! Tiny IPv4/ICMP packet builder for data-plane probes (server self-test,
//! verification harness). Not used for tunnel data, only diagnostics.

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

fn fix_ip(pkt: &mut [u8]) {
    let total = pkt.len();
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[10..12].copy_from_slice(&[0, 0]);
    let c = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
    let _ = total;
}

/// ICMP echo request from `src` to `dst` with valid IPv4 + ICMP checksums.
pub fn icmp_echo_request(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16) -> Vec<u8> {
    let payload = [0x6Du8; 32]; // 'm'
    let mut icmp = vec![8u8, 0, 0, 0];
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(&payload);
    let c = checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());

    let total = 20 + icmp.len();
    let mut pkt = Vec::with_capacity(total);
    pkt.push(0x45);
    pkt.push(0);
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x6D, 0x40, 0x00, 0x40, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&icmp);
    fix_ip(&mut pkt);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_has_valid_checksums() {
        let pkt = icmp_echo_request([100, 64, 0, 1], [100, 64, 0, 1], 1, 1);
        assert_eq!(pkt.len(), 20 + 8 + 32);
        // A valid checksum makes the 16-bit sum over the header = 0xFFFF
        // (its one's complement is 0).
        let sum = checksum_parts(&pkt[..20]);
        assert_eq!(sum, 0xFFFF, "bad IP checksum");
        let ihl = 20;
        let sum = checksum_parts(&pkt[ihl..]);
        assert_eq!(sum, 0xFFFF, "bad ICMP checksum");
    }

    fn checksum_parts(data: &[u8]) -> u16 {
        // !checksum(x) with checksum embedded must equal 0.
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum as u16
    }
}
