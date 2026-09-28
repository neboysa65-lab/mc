//! mcvpn core: a VPN whose transport is a byte-exact Minecraft Java 1.8.9
//! connection (see mc-protocol). IP packets are carried inside play-state
//! custom payload packets on a registered plugin channel, wrapped in the
//! exact login encryption (RSA + AES/CFB8) real BungeeCord/vanilla servers
//! use, plus an inner AEAD layer for packet integrity.

pub mod client;
pub mod config;
pub mod conn;
pub mod device;
pub mod error;
pub mod ip_pool;
pub mod nat;
pub mod server;
pub mod stats;
pub mod tunnel;

pub use error::{VpnError, VpnResult};

/// Default tunnel MTU (fits comfortably inside MC custom payload limits).
pub const DEFAULT_MTU: u16 = 1400;

/// Derive a Minecraft-valid username ([A-Za-z0-9_], <=16 chars) from the
/// auth token. Deterministic per token, looks like a regular player name.
pub fn derive_username(token: &str) -> String {
    use sha2::{Digest, Sha256};
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
    let digest = Sha256::digest(token.as_bytes());
    digest
        .iter()
        .take(16)
        .map(|b| CHARSET[*b as usize % CHARSET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn usernames_are_valid_mc_names() {
        let u = super::derive_username("hunter2");
        assert_eq!(u.len(), 16);
        assert!(u.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        assert_eq!(u, super::derive_username("hunter2"));
        assert_ne!(u, super::derive_username("hunter3"));
    }
}
