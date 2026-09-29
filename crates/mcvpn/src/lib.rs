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
pub mod logbuf;
pub mod nat;
pub mod probe;
pub mod server;
pub mod stats;
pub mod tunnel;

pub use error::{VpnError, VpnResult};

/// Default tunnel MTU (fits comfortably inside MC custom payload limits).
pub const DEFAULT_MTU: u16 = 1400;

/// Generate a plausible Minecraft username ([A-Za-z0-9_], 5..=12 chars).
/// Per-connection random: one shared token used by many people must not
/// produce the same "player" connecting from dozens of IPs — that is a
/// correlation fingerprint visible even before encryption starts.
pub fn random_username() -> String {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
    const LETTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let len = rng.gen_range(5..=12);
    let mut name = String::with_capacity(len);
    for i in 0..len {
        let pool = if i == 0 {
            LETTERS
        } else if rng.gen_bool(0.15) {
            CHARSET
        } else {
            LETTERS
        };
        name.push(pool[rng.gen_range(0..pool.len())] as char);
    }
    name
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    #[test]
    fn usernames_look_like_real_players() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let u = super::random_username();
            assert!((5..=12).contains(&u.len()), "bad length {u}");
            assert!(u.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
            let first = u.chars().next().unwrap();
            assert!(first.is_ascii_alphabetic(), "must start with a letter: {u}");
            seen.insert(u);
        }
        // 1000 draws from a big space: near-zero collisions (no reuse pattern).
        assert!(seen.len() > 990, "names not random enough: {}", seen.len());
    }
}
