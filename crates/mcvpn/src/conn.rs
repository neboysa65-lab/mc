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

pub struct Conn {
    stream: TcpStream,
    parser: FrameParser,
    dec: Option<McCipher>,
    enc: Option<McCipher>,
    threshold: Option<u32>,
}

impl Conn {
    pub async fn connect(addr: SocketAddr, timeout: Duration) -> std::io::Result<Self> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
        Self::apply_socket_opts(&stream);
        Ok(Conn {
            stream,
            parser: FrameParser::new(),
            dec: None,
            enc: None,
            threshold: None,
        })
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        Self::apply_socket_opts(&stream);
        Conn {
            stream,
            parser: FrameParser::new(),
            dec: None,
            enc: None,
            threshold: None,
        }
    }

    fn apply_socket_opts(stream: &TcpStream) {
        let _ = stream.set_nodelay(true);
        let sock = SockRef::from(stream);
        // OS-level keepalive as a backstop for dead peers.
        let _ = sock.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(30))
                .with_interval(Duration::from_secs(5)),
        );
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
    pub async fn recv(&mut self) -> VpnResult<Vec<u8>> {
        loop {
            if let Some(body) = self.parser.next_packet(self.threshold)? {
                return Ok(body);
            }
            let mut chunk = [0u8; 16384];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(VpnError::Io(std::io::ErrorKind::UnexpectedEof.into()));
            }
            let data = &mut chunk[..n];
            if let Some(d) = self.dec.as_mut() {
                d.process(data);
            }
            self.parser.push(data);
        }
    }

    /// Append the framed + encrypted packet to `out` (for batched writes).
    fn encode_into(&mut self, body: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        mc_protocol::frame::encode_frame_into(body, self.threshold, out);
        if let Some(e) = self.enc.as_mut() {
            e.process(&mut out[start..]);
        }
    }

    /// Frame + compress + encrypt + write one packet body.
    pub async fn send(&mut self, body: &[u8]) -> VpnResult<()> {
        let mut frame = Vec::with_capacity(body.len() + 8);
        self.encode_into(body, &mut frame);
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Coalesce several packet bodies into a single TCP write.
    pub async fn send_batch<I: IntoIterator<Item = Vec<u8>>>(
        &mut self,
        bodies: I,
    ) -> VpnResult<()> {
        let mut out = Vec::new();
        for body in bodies {
            self.encode_into(&body, &mut out);
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
