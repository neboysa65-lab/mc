//! Data-path CPU benchmark: how many Mbit/s can ONE core push through the
//! exact per-packet pipeline the tunnel uses?
//!
//!   cargo run --release -p mcvpn --example bench_crypto
//!   # what a phone WITHOUT hardware AES does (software AES/GHASH):
//!   RUSTFLAGS="--cfg aes_force_soft --cfg polyval_force_soft" \
//!     cargo run --release -p mcvpn --example bench_crypto

use mc_protocol::cipher::McCipher;
use mc_protocol::frame::{encode_frame_into, FrameParser};
use mcvpn::tunnel::{Role, TunnelCrypto};
use std::time::Instant;

const PKT: usize = 1300;
const N: usize = 4000;

fn mbit(bytes: usize, secs: f64) -> f64 {
    bytes as f64 * 8.0 / secs / 1e6
}

fn main() {
    let secret = [7u8; 16];
    let nonce = [9u8; 16];
    let pkt: Vec<u8> = (0..PKT).map(|i| (i * 31 % 251) as u8).collect();

    // --- raw CFB8, 1 MiB stream ---
    let mut buf = vec![0x5Au8; 1 << 20];
    let mut enc = McCipher::new(&secret, true);
    let t = Instant::now();
    enc.process(&mut buf);
    let e = t.elapsed().as_secs_f64();
    let mut dec = McCipher::new(&secret, false);
    let t = Instant::now();
    dec.process(&mut buf);
    let d = t.elapsed().as_secs_f64();
    println!("cfb8 encrypt (serial)   : {:8.1} Mbit/s", mbit(1 << 20, e));
    println!("cfb8 decrypt            : {:8.1} Mbit/s", mbit(1 << 20, d));

    // --- AES-256-GCM seal/open of {PKT}-byte packets ---
    let mut a = TunnelCrypto::derive(&secret, &nonce, Role::Client).unwrap();
    let mut b = TunnelCrypto::derive(&secret, &nonce, Role::Server).unwrap();
    let t = Instant::now();
    let mut sealed = Vec::with_capacity(N);
    for _ in 0..N {
        sealed.push(a.seal(&pkt).unwrap());
    }
    let s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    for x in &sealed {
        b.open(x).unwrap();
    }
    let o = t.elapsed().as_secs_f64();
    println!("gcm seal                : {:8.1} Mbit/s", mbit(N * PKT, s));
    println!("gcm open                : {:8.1} Mbit/s", mbit(N * PKT, o));

    // --- full UPLOAD pipeline per packet: seal -> MC frame(+zlib) -> CFB8 ---
    let mut a = TunnelCrypto::derive(&secret, &nonce, Role::Client).unwrap();
    let mut enc = McCipher::new(&secret, true);
    let mut wire: Vec<u8> = Vec::with_capacity(N * (PKT + 64));
    let t = Instant::now();
    for _ in 0..N {
        let sealed = a.seal(&pkt).unwrap();
        let mut body = vec![0x17u8, 9];
        body.extend_from_slice(b"MW|Tunnel");
        body.push(0x03);
        body.extend_from_slice(&sealed);
        let start = wire.len();
        encode_frame_into(&body, Some(256), &mut wire);
        enc.process(&mut wire[start..]);
    }
    let up = t.elapsed().as_secs_f64();
    let wire_len = wire.len();
    println!(
        "UPLOAD   pipeline/core  : {:8.1} Mbit/s   ({} B on wire for {} B of IP)",
        mbit(N * PKT, up),
        wire_len,
        N * PKT
    );

    // --- full DOWNLOAD pipeline: CFB8 -> frame parse(+inflate) -> GCM open ---
    let mut b = TunnelCrypto::derive(&secret, &nonce, Role::Server).unwrap();
    let mut dec = McCipher::new(&secret, false);
    let mut parser = FrameParser::new();
    let t = Instant::now();
    let mut got = 0usize;
    for chunk in wire.chunks_mut(16384) {
        dec.process(chunk);
        parser.push(chunk);
        while let Some(body) = parser.next_packet(Some(256)).unwrap() {
            let sealed = &body[2 + 9 + 1..];
            let ip = b.open(sealed).unwrap();
            got += ip.len();
        }
    }
    let down = t.elapsed().as_secs_f64();
    assert_eq!(got, N * PKT);
    println!("DOWNLOAD pipeline/core  : {:8.1} Mbit/s", mbit(N * PKT, down));
}
