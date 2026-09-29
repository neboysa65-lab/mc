//! AES/CFB8 stream cipher exactly as vanilla/BungeeCord use it:
//! `Cipher.getInstance("AES/CFB8/NoPadding")` (NIST SP 800-38A 8-bit feedback)
//! with the shared secret as both key and IV, applied to the raw TCP stream
//! in both directions after the encryption response is processed.
//! Implemented over the audited RustCrypto AES block cipher and pinned
//! against OpenSSL golden vectors in the tests below.

use aes::Aes128;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyInit};

/// Shared secret length used by Minecraft (AES-128).
pub const SHARED_SECRET_LEN: usize = 16;

type Block16 = GenericArray<u8, cipher::consts::U16>;

pub struct McCipher {
    aes: Aes128,
    iv: Block16,
    encrypting: bool,
}

impl McCipher {
    pub fn new(shared_secret: &[u8; SHARED_SECRET_LEN], encrypting: bool) -> Self {
        // Minecraft quirk: IV equals the key.
        let key = Block16::from(*shared_secret);
        let aes = Aes128::new(&key);
        McCipher {
            aes,
            iv: key,
            encrypting,
        }
    }

    /// Transform data in place, advancing the CFB8 feedback state.
    pub fn process(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            let mut block = self.iv;
            self.aes.encrypt_block(&mut block);
            let ks = block[0];
            // The ciphertext byte always feeds the IV, input in decrypt mode.
            let ct = if self.encrypting { *b ^ ks } else { *b };
            *b ^= ks;
            self.iv.copy_within(1.., 0);
            self.iv[15] = ct;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn openssl_golden_vector() {
        // openssl enc -aes-128-cfb8 -K 303132...6566 -iv (same)
        let secret = *b"0123456789abcdef";
        let mut enc = McCipher::new(&secret, true);
        let mut data =
            b"The quick brown fox jumps over the lazy dog. CFB8 keystream check 0123456789"
                .to_vec();
        enc.process(&mut data);
        assert_eq!(
            hex(&data),
            "2686540e23130de191bc82166f1bab04e2cff68c517c28896f1f1cf127cfb9272f848bfbfb3c09e38b90daae08e126d202a430b0563c3bbabdfc8069c5445d0f83fb6d2160fa873e9a9e94c2"
        );
        let mut dec = McCipher::new(&secret, false);
        dec.process(&mut data);
        assert_eq!(
            data,
            b"The quick brown fox jumps over the lazy dog. CFB8 keystream check 0123456789"
                .to_vec()
        );
        let mut small = b"abc".to_vec();
        McCipher::new(&secret, true).process(&mut small);
        assert_eq!(hex(&small), "132071");
    }

    #[test]
    fn cfb8_roundtrip() {
        let secret: [u8; 16] = [0x42; 16];
        let mut enc = McCipher::new(&secret, true);
        let mut dec = McCipher::new(&secret, false);
        let mut data = b"hello minecraft cfb8 stream".to_vec();
        enc.process(&mut data);
        assert_ne!(data, b"hello minecraft cfb8 stream".to_vec());
        dec.process(&mut data);
        assert_eq!(data, b"hello minecraft cfb8 stream".to_vec());
    }

    #[test]
    fn cfb8_streaming_equivalence() {
        // Processing in chunks must equal processing at once (stream cipher).
        let secret: [u8; 16] = [0x17; 16];
        let plain: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let mut a = plain.clone();
        McCipher::new(&secret, true).process(&mut a);
        let mut b = plain.clone();
        {
            let mut enc = McCipher::new(&secret, true);
            for chunk in b.chunks_mut(7) {
                enc.process(chunk);
            }
        }
        assert_eq!(a, b);
    }
}
