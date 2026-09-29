//! zlib (Minecraft packet compression), with strict claimed-size validation
//! matching Velocity: decompressed size must equal the claimed size exactly.
//!
//! Two ways to produce a compressed frame:
//! * [`deflate`]: real compression (level 6) for compressible packets;
//! * [`deflate_stored_into`]: a *valid* zlib stream made of stored blocks —
//!   what zlib itself emits for incompressible input, produced without
//!   spending any CPU on match finding. Every tunnel data frame carries
//!   AEAD ciphertext, which is random: running deflate over it cost ~10x
//!   more than all of the encryption combined and saved nothing. The bytes
//!   on the wire are the same size zlib's own fallback would produce.

use crate::error::McError;
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use std::io::{Read, Write};

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::with_capacity(data.len() / 2), Compression::new(6));
    e.write_all(data).expect("in-memory zlib write");
    e.finish().expect("in-memory zlib finish")
}

/// Maximum payload of one stored deflate block.
const STORED_MAX: usize = 65_535;

/// Exact length of the stream [`deflate_stored_into`] writes for `n` input bytes.
pub fn stored_zlib_len(n: usize) -> usize {
    let blocks = n.div_ceil(STORED_MAX).max(1);
    2 + n + 5 * blocks + 4
}

pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    // Largest n such that 255*n*(n+1)/2 + (n+1)*(MOD-1) fits in u32.
    const NMAX: usize = 5552;
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(NMAX) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// Append a zlib stream of stored (uncompressed) deflate blocks for `data`.
pub fn deflate_stored_into(data: &[u8], out: &mut Vec<u8>) {
    out.reserve(stored_zlib_len(data.len()));
    // CMF/FLG for "no compression": 0x7801 is divisible by 31.
    out.extend_from_slice(&[0x78, 0x01]);
    if data.is_empty() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
    } else {
        let mut chunks = data.chunks(STORED_MAX).peekable();
        while let Some(c) = chunks.next() {
            out.push(u8::from(chunks.peek().is_none())); // BFINAL, BTYPE=00
            let len = c.len() as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(c);
        }
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
}

/// Fast path for streams made only of stored blocks (what we send). Returns
/// `None` for anything else — compressed blocks, bad checksums, trailing
/// bytes — so the caller falls back to the full inflater with identical
/// acceptance rules.
fn inflate_stored_only(data: &[u8], claimed: usize) -> Option<Vec<u8>> {
    if data.len() < 2 + 5 + 4 || data[0] & 0x0F != 8 || data[1] & 0x20 != 0 {
        return None; // not deflate, or a preset dictionary
    }
    if (u16::from(data[0]) << 8 | u16::from(data[1])) % 31 != 0 {
        return None;
    }
    let mut pos = 2;
    let mut out = Vec::with_capacity(claimed);
    loop {
        let head = *data.get(pos)?;
        if head & 0x06 != 0 {
            return None; // BTYPE != stored
        }
        let len = u16::from_le_bytes([*data.get(pos + 1)?, *data.get(pos + 2)?]);
        let nlen = u16::from_le_bytes([*data.get(pos + 3)?, *data.get(pos + 4)?]);
        if len != !nlen {
            return None;
        }
        let body = data.get(pos + 5..pos + 5 + len as usize)?;
        if out.len() + body.len() > claimed {
            return None;
        }
        out.extend_from_slice(body);
        pos += 5 + len as usize;
        if head & 1 == 1 {
            break;
        }
    }
    let tail = data.get(pos..pos + 4)?;
    if pos + 4 != data.len() || out.len() != claimed {
        return None;
    }
    if u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]) != adler32(&out) {
        return None;
    }
    Some(out)
}

pub fn inflate(data: &[u8], claimed: usize) -> Result<Vec<u8>, McError> {
    if claimed > crate::frame::MAX_UNCOMPRESSED {
        return Err(McError::new("uncompressed size exceeds hard cap"));
    }
    if let Some(out) = inflate_stored_only(data, claimed) {
        return Ok(out);
    }
    let mut out = Vec::with_capacity(claimed);
    // Cap output at claimed+1 so a lying claimed size cannot OOM us.
    let mut d = ZlibDecoder::new(data).take(claimed as u64 + 1);
    d.read_to_end(&mut out)
        .map_err(|e| McError::new(format!("zlib inflate failed: {e}")))?;
    if out.len() != claimed {
        return Err(McError::new(format!(
            "decompressed size {} does not match claimed {}",
            out.len(),
            claimed
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_known_vectors() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        // Longer than NMAX to exercise the modular reduction.
        let big = vec![0xFFu8; 100_000];
        let mut a = 1u64;
        let mut b = 0u64;
        for &x in &big {
            a = (a + x as u64) % 65_521;
            b = (b + a) % 65_521;
        }
        assert_eq!(adler32(&big), ((b << 16) | a) as u32);
    }

    #[test]
    fn stored_stream_is_a_valid_zlib_stream_for_a_real_inflater() {
        // The reference implementation (flate2/miniz) must accept our stream
        // for every size around the 65535-byte block boundary.
        for n in [0usize, 1, 255, 256, 1300, 65_534, 65_535, 65_536, 131_070, 200_000] {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
            let mut z = Vec::new();
            deflate_stored_into(&data, &mut z);
            assert_eq!(z.len(), stored_zlib_len(n), "length formula at {n}");
            let mut got = Vec::new();
            ZlibDecoder::new(&z[..]).read_to_end(&mut got).unwrap();
            assert_eq!(got, data, "flate2 rejected/garbled our stored stream at {n}");
        }
    }

    #[test]
    fn inflate_accepts_stored_fast_path_and_real_deflate() {
        let data: Vec<u8> = (0..5000).map(|i| (i % 13) as u8).collect();
        let mut stored = Vec::new();
        deflate_stored_into(&data, &mut stored);
        assert_eq!(inflate(&stored, data.len()).unwrap(), data);
        assert_eq!(inflate(&deflate(&data), data.len()).unwrap(), data);
    }

    #[test]
    fn inflate_rejects_tampering_and_lies() {
        let data = vec![0x5Au8; 1000];
        let mut z = Vec::new();
        deflate_stored_into(&data, &mut z);
        // Wrong claimed size.
        assert!(inflate(&z, 999).is_err());
        assert!(inflate(&z, 1001).is_err());
        // Flipped payload bit -> checksum mismatch.
        let mut bad = z.clone();
        bad[100] ^= 1;
        assert!(inflate(&bad, 1000).is_err());
        // Truncated.
        assert!(inflate(&z[..z.len() - 1], 1000).is_err());
        // Absurd claimed size never allocates.
        assert!(inflate(&z, crate::frame::MAX_UNCOMPRESSED + 1).is_err());
    }
}
