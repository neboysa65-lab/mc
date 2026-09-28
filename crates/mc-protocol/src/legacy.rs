//! Pre-1.7 legacy server list ping, exactly as a vanilla 1.8.9 server answers.

use crate::buf::{Reader, Writer};
use crate::error::McResult;
use crate::{PROTOCOL_VERSION, VERSION_NAME};

pub enum LegacyProbe {
    /// 0xFE [0x01]: v1.4/1.5-style ping; bool = "newer" format.
    Ping(bool),
    /// 0x02: legacy connect attempt.
    Handshake,
}

/// Detect a legacy probe from the first byte(s) buffered on a new connection.
/// Returns Ok(None) if the bytes are a normal (VarInt-framed) protocol start.
pub fn detect(first: u8, second: Option<u8>) -> Option<LegacyProbe> {
    match first {
        // BungeeCord semantics: v1_5 ("newer") format iff the second byte is 0x01.
        0xFE => Some(LegacyProbe::Ping(second == Some(0x01))),
        0x02 => Some(LegacyProbe::Handshake),
        _ => None,
    }
}

/// Legacy "kick" packet: 0xFF + UTF-16BE length + message.
pub fn legacy_kick(message: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(0xFF);
    w.i16(message.encode_utf16().count() as i16);
    for unit in message.encode_utf16() {
        w.i16(unit as i16);
    }
    w.out
}

/// Response to the v1.4/1.5-style ping (0xFE 0x01), vanilla 1.8.9 semantics:
/// §1, protocol 127 (meaning "vanilla"), version, MOTD, online, max, NUL-separated.
pub fn ping_response_v15(motd: &str, online: u32, max: u32) -> Vec<u8> {
    let msg = format!(
        "\u{00A7}1\u{0}127\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
        VERSION_NAME, motd, online, max
    );
    legacy_kick(&msg)
}

/// Response to the beta-era ping (0xFE alone): MOTD§online§max.
pub fn ping_response_beta(motd: &str, online: u32, max: u32) -> Vec<u8> {
    let msg = format!("{motd}\u{00A7}{online}\u{00A7}{max}");
    legacy_kick(&msg)
}

/// Vanilla-ish legacy handshake (0x02 connect) refusal.
pub fn handshake_response() -> Vec<u8> {
    legacy_kick(&format!("Outdated client! I'm running {VERSION_NAME}"))
}

pub fn protocol_number() -> i32 {
    PROTOCOL_VERSION
}

/// Read a legacy ping's optional second byte; returns v1_5 flag.
pub fn parse_ping_second(body: &[u8]) -> McResult<bool> {
    let mut r = Reader::new(body);
    let first = r.u8()?;
    if first != 0xFE {
        return Err(crate::McError::new("not a legacy ping"));
    }
    Ok(r.u8()? == 0x01)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v15_response_golden() {
        let resp = ping_response_v15("A Minecraft Server", 0, 20);
        // len will be message UTF-16 units; compute from message
        let msg = "\u{00A7}1\u{0}127\u{0}1.8.9\u{0}A Minecraft Server\u{0}0\u{0}20";
        assert_eq!(resp[0], 0xFF);
        assert_eq!(
            i16::from_be_bytes([resp[1], resp[2]]),
            msg.encode_utf16().count() as i16
        );
        // Body: UTF-16BE of msg
        let mut body = Vec::new();
        for u in msg.encode_utf16() {
            body.extend_from_slice(&u.to_be_bytes());
        }
        assert_eq!(&resp[3..], &body[..]);
    }

    #[test]
    fn detect_kinds() {
        assert!(matches!(detect(0xFE, Some(0x01)), Some(LegacyProbe::Ping(true))));
        assert!(matches!(detect(0xFE, None), Some(LegacyProbe::Ping(false))));
        assert!(matches!(detect(0x02, None), Some(LegacyProbe::Handshake)));
        assert!(detect(0x0F, None).is_none()); // normal VarInt frame start
    }
}
