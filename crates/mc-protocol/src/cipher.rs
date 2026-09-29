//! AES/CFB8 stream cipher exactly as vanilla/BungeeCord use it:
//! `Cipher.getInstance("AES/CFB8/NoPadding")` (NIST SP 800-38A 8-bit feedback)
//! with the shared secret as both key and IV, applied to the raw TCP stream
//! in both directions after the encryption response is processed.
//! Implemented over the audited RustCrypto AES block cipher and pinned
//! against OpenSSL golden vectors in the tests below.
//!
//! PERFORMANCE MODEL. CFB8 runs one AES block per *byte*, so it is the most
//! CPU-hungry part of the transport:
//!
//! * **decrypt** is embarrassingly parallel: the keystream byte for position
//!   `i` needs AES over ciphertext bytes `[i-16, i)`, all of which are known
//!   up front. We hand whole batches of independent blocks to the AES
//!   backend (8-way pipelined AES-NI / ARMv8 crypto, 4-way bitsliced in
//!   software) instead of one block at a time.
//! * **encrypt** is inherently serial (byte `i` depends on ciphertext byte
//!   `i-1`), so it is latency-bound. We only remove the avoidable costs: a
//!   sliding window instead of a 15-byte memmove per byte.
//!
//! On aarch64 the AES/PMULL backends must be enabled with
//! `--cfg aes_armv8 --cfg polyval_armv8` (see `.cargo/config.toml`); without
//! them phones fall back to software AES and are ~10x slower.

use aes::Aes128;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyInit};

/// Shared secret length used by Minecraft (AES-128).
pub const SHARED_SECRET_LEN: usize = 16;

type Block16 = GenericArray<u8, cipher::consts::U16>;

/// Stream positions handled per batch.
const BATCH: usize = 64;

pub struct McCipher {
    aes: Aes128,
    /// Last 16 ciphertext bytes (the CFB8 shift register).
    iv: [u8; 16],
    encrypting: bool,
    /// Decrypt-only scratch: the independent blocks of one batch.
    scratch: Vec<Block16>,
}

impl McCipher {
    pub fn new(shared_secret: &[u8; SHARED_SECRET_LEN], encrypting: bool) -> Self {
        // Minecraft quirk: IV equals the key.
        let key = Block16::from(*shared_secret);
        let aes = Aes128::new(&key);
        McCipher {
            aes,
            iv: *shared_secret,
            encrypting,
            scratch: if encrypting {
                Vec::new()
            } else {
                vec![Block16::default(); BATCH]
            },
        }
    }

    /// Transform data in place, advancing the CFB8 feedback state.
    pub fn process(&mut self, data: &mut [u8]) {
        if self.encrypting {
            self.encrypt(data);
        } else {
            self.decrypt(data);
        }
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        // window = iv || ciphertext produced so far; block i is window[i..i+16].
        let mut win = [0u8; 16 + BATCH];
        for chunk in data.chunks_mut(BATCH) {
            let n = chunk.len();
            win[..16].copy_from_slice(&self.iv);
            for (i, byte) in chunk.iter_mut().enumerate() {
                let mut block = Block16::clone_from_slice(&win[i..i + 16]);
                self.aes.encrypt_block(&mut block);
                let ct = *byte ^ block[0];
                *byte = ct;
                win[16 + i] = ct;
            }
            self.iv.copy_from_slice(&win[n..n + 16]);
        }
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        let mut win = [0u8; 16 + BATCH];
        for chunk in data.chunks_mut(BATCH) {
            let n = chunk.len();
            win[..16].copy_from_slice(&self.iv);
            win[16..16 + n].copy_from_slice(chunk); // ciphertext
            for (i, block) in self.scratch[..n].iter_mut().enumerate() {
                block.copy_from_slice(&win[i..i + 16]);
            }
            // All `n` blocks are independent: one batched call.
            self.aes.encrypt_blocks(&mut self.scratch[..n]);
            for (byte, block) in chunk.iter_mut().zip(self.scratch[..n].iter()) {
                *byte ^= block[0];
            }
            self.iv.copy_from_slice(&win[n..n + 16]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, RngCore, SeedableRng};

    fn hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The original one-block-per-byte implementation, kept as the oracle
    /// the optimized paths must match bit for bit.
    fn reference(secret: &[u8; 16], encrypting: bool, data: &mut [u8]) {
        let key = Block16::from(*secret);
        let aes = Aes128::new(&key);
        let mut iv = key;
        for b in data.iter_mut() {
            let mut block = iv;
            aes.encrypt_block(&mut block);
            let ks = block[0];
            let ct = if encrypting { *b ^ ks } else { *b };
            *b ^= ks;
            iv.copy_within(1.., 0);
            iv[15] = ct;
        }
    }

    #[test]
    fn openssl_golden_vector() {
        // openssl enc -aes-128-cfb8 -K 303132...6566 -iv (same)
        let secret = *b"0123456789abcdef";
        let mut enc = McCipher::new(&secret, true);
        let mut data =
            b"The quick brown fox jumps over the lazy dog. CFB8 keystream check 0123456789".to_vec();
        enc.process(&mut data);
        assert_eq!(
            hex(&data),
            "2686540e23130de191bc82166f1bab04e2cff68c517c28896f1f1cf127cfb9272f848bfbfb3c09e38b90daae08e126d202a430b0563c3bbabdfc8069c5445d0f83fb6d2160fa873e9a9e94c2"
        );
        let mut dec = McCipher::new(&secret, false);
        dec.process(&mut data);
        assert_eq!(
            data,
            b"The quick brown fox jumps over the lazy dog. CFB8 keystream check 0123456789".to_vec()
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

    #[test]
    fn optimized_paths_match_the_reference_for_every_edge_length() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
        // Lengths around every internal boundary (16-byte register, 64-byte batch).
        let lens = [
            0usize, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 79, 80, 81, 127, 128, 129, 255, 256,
            257, 1000, 1400, 4096, 65_537,
        ];
        for &len in &lens {
            let mut secret = [0u8; 16];
            rng.fill_bytes(&mut secret);
            let mut plain = vec![0u8; len];
            rng.fill_bytes(&mut plain);

            let mut want_ct = plain.clone();
            reference(&secret, true, &mut want_ct);

            let mut got_ct = plain.clone();
            McCipher::new(&secret, true).process(&mut got_ct);
            assert_eq!(got_ct, want_ct, "encrypt mismatch at len {len}");

            let mut got_pt = want_ct.clone();
            McCipher::new(&secret, false).process(&mut got_pt);
            assert_eq!(got_pt, plain, "decrypt mismatch at len {len}");
        }
    }

    #[test]
    fn random_chunking_never_changes_the_result() {
        // The receive path sees arbitrary TCP read sizes; the send path arbitrary
        // frame sizes. State must carry correctly across every split.
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for _ in 0..50 {
            let mut secret = [0u8; 16];
            rng.fill_bytes(&mut secret);
            let len = rng.gen_range(1..6000);
            let mut plain = vec![0u8; len];
            rng.fill_bytes(&mut plain);

            let mut want = plain.clone();
            reference(&secret, true, &mut want);

            let mut ct = plain.clone();
            let mut enc = McCipher::new(&secret, true);
            let mut off = 0;
            while off < ct.len() {
                let n = rng.gen_range(1..300).min(ct.len() - off);
                enc.process(&mut ct[off..off + n]);
                off += n;
            }
            assert_eq!(ct, want);

            let mut pt = ct.clone();
            let mut dec = McCipher::new(&secret, false);
            let mut off = 0;
            while off < pt.len() {
                let n = rng.gen_range(1..300).min(pt.len() - off);
                dec.process(&mut pt[off..off + n]);
                off += n;
            }
            assert_eq!(pt, plain);
        }
    }
}
