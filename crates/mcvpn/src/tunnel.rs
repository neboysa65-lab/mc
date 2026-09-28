//! Inner tunnel protocol carried inside MW|Tunnel custom payload packets.
//!
//! Outer stream = byte-exact Minecraft 1.8.9 (login encryption: RSA +
//! AES/CFB8, exactly BungeeCord's stack). Inside, every DATA message is
//! additionally sealed with AES-256-GCM using per-direction keys derived
//! via HKDF-SHA256 from the Minecraft shared secret and a per-session
//! nonce, so IP packets get strong integrity (CFB8 alone is malleable).

use crate::error::{VpnError, VpnResult};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::generic_array::GenericArray;

type Nonce = GenericArray<u8, U12>;

pub const VER: u8 = 1;
pub const MSG_AUTH: u8 = 0x01;
pub const MSG_AUTH_OK: u8 = 0x02;
pub const MSG_DATA: u8 = 0x03;
pub const MSG_PING: u8 = 0x04;
pub const MSG_PONG: u8 = 0x05;
pub const MSG_CLOSE: u8 = 0x06;

const HKDF_INFO: &[u8] = b"mcvpn/tunnel/v1";

#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub mtu: u16,
    pub dns: Vec<[u8; 4]>,
}

#[derive(Debug)]
pub enum TunnelMsg {
    Auth { nonce: [u8; 16], token: Vec<u8> },
    AuthOk(TunnelInfo),
    Data(Vec<u8>),
    Ping(u64),
    Pong(u64),
    Close(u8),
}

pub fn encode_auth(nonce: &[u8; 16], token: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(3 + token.len());
    m.push(MSG_AUTH);
    m.push(VER);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&(token.len() as u16).to_be_bytes());
    m.extend_from_slice(token);
    m
}

pub fn encode_auth_ok(info: &TunnelInfo) -> Vec<u8> {
    let mut m = Vec::with_capacity(2 + 15 + info.dns.len() * 4);
    m.push(MSG_AUTH_OK);
    m.extend_from_slice(&info.ip);
    m.extend_from_slice(&info.netmask);
    m.extend_from_slice(&info.gateway);
    m.extend_from_slice(&info.mtu.to_be_bytes());
    m.push(info.dns.len() as u8);
    for d in &info.dns {
        m.extend_from_slice(d);
    }
    m
}

pub fn encode_data(sealed: Vec<u8>) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + sealed.len());
    m.push(MSG_DATA);
    m.extend_from_slice(&sealed);
    m
}

pub fn encode_ping(v: u64) -> Vec<u8> {
    let mut m = vec![MSG_PING];
    m.extend_from_slice(&v.to_be_bytes());
    m
}

pub fn encode_pong(v: u64) -> Vec<u8> {
    let mut m = vec![MSG_PONG];
    m.extend_from_slice(&v.to_be_bytes());
    m
}

pub fn encode_close(reason: u8) -> Vec<u8> {
    vec![MSG_CLOSE, reason]
}

pub fn decode(msg: &[u8]) -> VpnResult<TunnelMsg> {
    let bad = || VpnError::Crypto("malformed tunnel message".into());
    let mut r = msg;
    let t = r.first().copied().ok_or_else(bad)?;
    r = &r[1..];
    Ok(match t {
        MSG_AUTH => {
            if r.len() < 3 || r[0] != VER {
                return Err(bad());
            }
            let nonce: [u8; 16] = r[1..17].try_into().map_err(|_| bad())?;
            let tlen = u16::from_be_bytes([r[17], r[18]]) as usize;
            let rest = &r[19..];
            if rest.len() != tlen || tlen > 4096 {
                return Err(bad());
            }
            TunnelMsg::Auth { nonce, token: rest.to_vec() }
        }
        MSG_AUTH_OK => {
            if r.len() < 15 {
                return Err(bad());
            }
            let ip: [u8; 4] = r[0..4].try_into().unwrap();
            let netmask: [u8; 4] = r[4..8].try_into().unwrap();
            let gateway: [u8; 4] = r[8..12].try_into().unwrap();
            let mtu = u16::from_be_bytes([r[12], r[13]]);
            let n = r[14] as usize;
            let rest = &r[15..];
            if rest.len() != n * 4 || n > 8 || mtu < 576 || mtu > 32000 {
                return Err(bad());
            }
            TunnelMsg::AuthOk(TunnelInfo {
                ip,
                netmask,
                gateway,
                mtu,
                dns: rest.chunks_exact(4).map(|c| c.try_into().unwrap()).collect(),
            })
        }
        MSG_DATA => TunnelMsg::Data(r.to_vec()),
        MSG_PING if r.len() == 8 => TunnelMsg::Ping(u64::from_be_bytes(r.try_into().unwrap())),
        MSG_PONG if r.len() == 8 => TunnelMsg::Pong(u64::from_be_bytes(r.try_into().unwrap())),
        MSG_CLOSE if r.len() == 1 => TunnelMsg::Close(r[0]),
        _ => return Err(bad()),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Per-direction AES-256-GCM keys derived from the Minecraft shared secret.
pub struct TunnelCrypto {
    send: Aes256Gcm,
    recv: Aes256Gcm,
    send_ctr: u128,
    recv_ctr: u128,
}

impl TunnelCrypto {
    pub fn derive(shared_secret: &[u8; 16], nonce: &[u8; 16], role: Role) -> VpnResult<Self> {
        let hk = Hkdf::<Sha256>::new(Some(nonce), shared_secret);
        let mut okm = [0u8; 64];
        hk.expand(HKDF_INFO, &mut okm)
            .map_err(|_| VpnError::Crypto("hkdf failed".into()))?;
        let (client_key, server_key) = okm.split_at(32);
        let (send, recv) = match role {
            Role::Client => (client_key, server_key),
            Role::Server => (server_key, client_key),
        };
        Ok(TunnelCrypto {
            send: Aes256Gcm::new_from_slice(send).expect("32 byte key"),
            recv: Aes256Gcm::new_from_slice(recv).expect("32 byte key"),
            send_ctr: 0,
            recv_ctr: 0,
        })
    }

    fn nonce(ctr: u128) -> Nonce {
        GenericArray::clone_from_slice(&ctr.to_be_bytes()[4..])
    }

    /// Seal an IP packet: 12-byte counter nonce + ciphertext+tag.
    pub fn seal(&mut self, ip_packet: &[u8]) -> VpnResult<Vec<u8>> {
        if self.send_ctr == u128::MAX {
            return Err(VpnError::Crypto("nonce space exhausted".into()));
        }
        let ctr = self.send_ctr;
        self.send_ctr += 1;
        let n = Self::nonce(ctr);
        let ct = self
            .send
            .encrypt(&n, ip_packet)
            .map_err(|_| VpnError::Crypto("aes-gcm seal failed".into()))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&n);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a sealed DATA blob. Counters must arrive in strict order
    /// (anti-replay); duplicates or gaps are rejected.
    pub fn open(&mut self, blob: &[u8]) -> VpnResult<Vec<u8>> {
        if blob.len() < 12 + 16 {
            return Err(VpnError::Crypto("sealed blob too short".into()));
        }
        let (n, ct) = blob.split_at(12);
        let ctr = {
            let mut b = [0u8; 16];
            b[4..].copy_from_slice(n);
            u128::from_be_bytes(b)
        };
        if ctr < self.recv_ctr {
            return Err(VpnError::Crypto("replayed or reordered counter".into()));
        }
        if ctr > self.recv_ctr {
            return Err(VpnError::Crypto("counter gap (dropped packets?)".into()));
        }
        let pt = self
            .recv
            .decrypt(&Self::nonce(ctr), ct)
            .map_err(|_| VpnError::Crypto("aes-gcm open failed".into()))?;
        self.recv_ctr += 1;
        Ok(pt)
    }
}

/// Constant-time token comparison.
pub fn token_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> TunnelInfo {
        TunnelInfo {
            ip: [100, 64, 0, 2],
            netmask: [255, 192, 0, 0],
            gateway: [100, 64, 0, 1],
            mtu: 1400,
            dns: vec![[1, 1, 1, 1]],
        }
    }

    #[test]
    fn tunnel_msg_roundtrip() {
        let auth = encode_auth(&[7u8; 16], b"tok");
        assert!(matches!(
            decode(&auth).unwrap(),
            TunnelMsg::Auth { .. }
        ));
        let ok = encode_auth_ok(&info());
        let TunnelMsg::AuthOk(i) = decode(&ok).unwrap() else {
            panic!()
        };
        assert_eq!(i.ip, [100, 64, 0, 2]);
        assert_eq!(i.mtu, 1400);
        assert_eq!(i.dns, vec![[1, 1, 1, 1]]);
        let ping = encode_ping(42);
        assert!(matches!(decode(&ping).unwrap(), TunnelMsg::Ping(42)));
        assert!(decode(&[MSG_PING, 1, 2]).is_err());
    }

    #[test]
    fn crypto_seal_open_and_replay() {
        let secret = [9u8; 16];
        let nonce = [3u8; 16];
        let mut client = TunnelCrypto::derive(&secret, &nonce, Role::Client).unwrap();
        let mut server = TunnelCrypto::derive(&secret, &nonce, Role::Server).unwrap();

        let p1 = vec![0x45, 1, 2, 3, 4, 5, 6, 7, 8];
        let p2 = vec![0x45, 9, 9, 9];
        let s1 = client.seal(&p1).unwrap();
        let s2 = client.seal(&p2).unwrap();
        assert_eq!(server.open(&s1).unwrap(), p1);
        assert_eq!(server.open(&s2).unwrap(), p2);

        // Replay is rejected.
        assert!(server.open(&s1).is_err());
        // Out-of-order (gap) is rejected.
        let s3 = client.seal(&p1).unwrap();
        let s4 = client.seal(&p2).unwrap();
        assert!(server.open(&s4).is_err());
        assert_eq!(server.open(&s3).unwrap(), p1);

        // Tampering is rejected.
        let mut t = client.seal(&p1).unwrap();
        let last = t.len() - 1;
        t[last] ^= 0x01;
        assert!(server.open(&t).is_err());

        // Wrong keys (different nonce) cannot open.
        let mut other = TunnelCrypto::derive(&secret, &[4u8; 16], Role::Server).unwrap();
        let s = client.seal(&p1).unwrap();
        assert!(other.open(&s).is_err());
    }
}
