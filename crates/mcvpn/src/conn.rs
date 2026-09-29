//! One Minecraft connection: framing, encryption and compression state on
//! top of a TCP stream. `recv`/`send` keep all live state in `self` (plus
//! the OS socket buffer), so the play-state `select!` loops can await
//! `recv` cancel-safely.

use crate::error::{VpnError, VpnResult};
use mc_protocol::cipher::{McCipher, SHARED_SECRET_LEN};
use mc_protocol::frame::FrameParser;
use socket2::{SockRef, TcpKeepalive};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Reusable read buffer. Big reads keep the syscall count (and the
/// decrypt batches) efficient at high throughput.
const READ_BUF: usize = 64 * 1024;

/// Unsent bytes allowed in the kernel socket buffer before writers wait.
/// Without it Linux autotunes the send buffer to megabytes and every packet
/// queues behind them: throughput is unchanged, but latency under load
/// (bufferbloat) explodes. In-flight data is not counted, so fast paths
/// still fill the pipe.
#[cfg(any(target_os = "linux", target_os = "android"))]
const NOTSENT_LOWAT: libc::c_int = 128 * 1024;

pub struct Conn {
    stream: TcpStream,
    parser: FrameParser,
    dec: Option<McCipher>,
    enc: Option<McCipher>,
    threshold: Option<u32>,
    rbuf: Vec<u8>,
}

impl Conn {
    fn new(stream: TcpStream) -> Self {
        Conn {
            stream,
            parser: FrameParser::new(),
            dec: None,
            enc: None,
            threshold: None,
            rbuf: Vec::new(),
        }
    }

    pub async fn connect(addr: SocketAddr, timeout: Duration) -> std::io::Result<Self> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
        Self::apply_socket_opts(&stream, false);
        Ok(Self::new(stream))
    }

    /// Connect by hostname (or IP) + port; hostnames resolve through the
    /// system resolver, like every real VPN client ("vpn.example.com").
    pub async fn connect_host(host: &str, port: u16, timeout: Duration) -> std::io::Result<Self> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect((host, port))).await??;
        Self::apply_socket_opts(&stream, false);
        Ok(Self::new(stream))
    }

    /// Wrap an accepted (server-side) connection.
    pub fn from_stream(stream: TcpStream) -> Self {
        Self::apply_socket_opts(&stream, true);
        Self::new(stream)
    }

    fn apply_socket_opts(stream: &TcpStream, server_side: bool) {
        let _ = stream.set_nodelay(true);
        let sock = SockRef::from(stream);
        // OS-level keepalive as a backstop for dead peers.
        let _ = sock.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(30))
                .with_interval(Duration::from_secs(5)),
        );
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd;
            let fd = stream.as_raw_fd();
            // TCP_NOTSENT_LOWAT = 25 on Linux/Android.
            set_tcp_int(fd, 25, NOTSENT_LOWAT);
            if server_side {
                // BBR keeps throughput up on lossy mobile paths (5G) where
                // loss-based CUBIC collapses, and keeps queues short.
                // Per-socket, best effort (needs the tcp_bbr module).
                set_tcp_congestion(fd, b"bbr");
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _ = server_side;
    }

    pub fn seed(&mut self, bytes: &[u8]) {
        self.parser.push(bytes);
    }

    pub fn enable_encryption(&mut self, secret: &[u8; SHARED_SECRET_LEN]) {
        self.dec = Some(McCipher::new(secret, false));
        self.enc = Some(McCipher::new(secret, true));
    }

    pub fn set_compression(&mut self, threshold: i32) {
        self.threshold = if threshold >= 0 {
            Some(threshold as u32)
        } else {
            None
        };
    }

    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }

    /// Read exactly one raw (decrypted, decompressed) packet body.
    /// Cancel-safe: all state lives in `self` and nothing is awaited after
    /// bytes have been taken from the socket.
    pub async fn recv(&mut self) -> VpnResult<Vec<u8>> {
        loop {
            if let Some(body) = self.parser.next_packet(self.threshold)? {
                return Ok(body);
            }
            if self.rbuf.is_empty() {
                self.rbuf.resize(READ_BUF, 0);
            }
            let n = self.stream.read(&mut self.rbuf).await?;
            if n == 0 {
                return Err(VpnError::Io(std::io::ErrorKind::UnexpectedEof.into()));
            }
            let data = &mut self.rbuf[..n];
            if let Some(d) = self.dec.as_mut() {
                d.process(data);
            }
            self.parser.push(data);
        }
    }

    /// Non-blocking: return the next packet if one is already fully
    /// buffered (lets play loops drain bursts without extra awaits).
    pub fn try_recv_buffered(&mut self) -> Option<Vec<u8>> {
        self.parser.next_packet(self.threshold).ok().flatten()
    }

    /// Append the framed + encrypted packet to `out` (for batched writes).
    /// `incompressible`: the body is AEAD ciphertext, so skip deflate.
    fn encode_into(&mut self, body: &[u8], out: &mut Vec<u8>, incompressible: bool) {
        let start = out.len();
        if incompressible {
            mc_protocol::frame::encode_frame_into_incompressible(body, self.threshold, out);
        } else {
            mc_protocol::frame::encode_frame_into(body, self.threshold, out);
        }
        if let Some(e) = self.enc.as_mut() {
            e.process(&mut out[start..]);
        }
    }

    /// Frame + compress + encrypt + write one control packet body.
    pub async fn send(&mut self, body: &[u8]) -> VpnResult<()> {
        let mut frame = Vec::with_capacity(body.len() + 8);
        self.encode_into(body, &mut frame, false);
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Coalesce several tunnel data packets into a single TCP write. These
    /// bodies carry AEAD ciphertext, which never compresses.
    pub async fn send_batch<I: IntoIterator<Item = Vec<u8>>>(
        &mut self,
        bodies: I,
    ) -> VpnResult<()> {
        let mut out = Vec::new();
        for body in bodies {
            self.encode_into(&body, &mut out, true);
        }
        if out.is_empty() {
            return Ok(());
        }
        self.stream.write_all(&out).await?;
        Ok(())
    }

    /// Raw write used for legacy ping responses (no framing).
    pub async fn send_raw(&mut self, bytes: &[u8]) -> VpnResult<()> {
        self.stream.write_all(bytes).await?;
        Ok(())
    }

    /// Raw read of a few bytes (legacy probe detection only).
    pub async fn read_raw_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read_exact(buf).await.map(|_| buf.len())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_tcp_int(fd: std::os::fd::RawFd, opt: libc::c_int, val: libc::c_int) {
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            opt,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_tcp_congestion(fd: std::os::fd::RawFd, name: &[u8]) {
    // TCP_CONGESTION = 13 on Linux/Android.
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            13,
            name.as_ptr() as *const libc::c_void,
            name.len() as libc::socklen_t,
        );
    }
}
