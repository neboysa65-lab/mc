//! The exact packet set needed by the transport, protocol 47 (1.8.9).

use crate::buf::{Reader, Writer};
use crate::error::{McError, McResult};
use crate::{PROTOCOL_VERSION, VERSION_NAME};

// ---- Packet IDs, protocol 47 ----
pub mod handshake_id {
    pub const HANDSHAKE: u8 = 0x00;
}
pub mod status_id {
    pub const SB_REQUEST: u8 = 0x00;
    pub const SB_PING: u8 = 0x01;
    pub const CB_RESPONSE: u8 = 0x00;
    pub const CB_PONG: u8 = 0x01;
}
pub mod login_id {
    pub const SB_LOGIN_START: u8 = 0x00;
    pub const SB_ENCRYPTION_RESPONSE: u8 = 0x01;
    pub const CB_DISCONNECT: u8 = 0x00;
    pub const CB_ENCRYPTION_REQUEST: u8 = 0x01;
    pub const CB_LOGIN_SUCCESS: u8 = 0x02;
    pub const CB_SET_COMPRESSION: u8 = 0x03;
}
pub mod play_id {
    pub const SB_KEEP_ALIVE: u8 = 0x00;
    pub const SB_CHAT: u8 = 0x01;
    pub const SB_PLAYER: u8 = 0x03;
    pub const SB_CLIENT_SETTINGS: u8 = 0x15;
    pub const SB_CUSTOM_PAYLOAD: u8 = 0x17;
    pub const CB_KEEP_ALIVE: u8 = 0x00;
    pub const CB_JOIN_GAME: u8 = 0x01;
    pub const CB_CUSTOM_PAYLOAD: u8 = 0x3F;
    pub const CB_DISCONNECT: u8 = 0x40;

    /// All serverbound play packet IDs valid in 1.8 (unknown ones get kicked,
    /// exactly like a vanilla/Velocity server does).
    pub fn sb_known_1_8(id: u8) -> bool {
        matches!(id, 0x00..=0x19)
    }
    /// Clientbound play IDs valid in 1.8 (client logs+ignores others).
    pub fn cb_known_1_8(id: u8) -> bool {
        matches!(id, 0x00..=0x48)
    }
}

// Well-known plugin channel names (1.8-era, pre-1.13 style).
pub const CHANNEL_BRAND: &str = "MC|Brand";
pub const CHANNEL_REGISTER: &str = "REGISTER";
pub const CHANNEL_UNREGISTER: &str = "UNREGISTER";
/// mcvpn's tunnel plugin channel, 1.8 channel naming style.
pub const CHANNEL_TUNNEL: &str = "MW|Tunnel";

fn packet_id(body: &[u8]) -> McResult<(u8, Reader<'_>)> {
    let mut r = Reader::new(body);
    let id = r.u8()?;
    Ok((id, r))
}

// ---- Handshaking ----

#[derive(Debug, Clone)]
pub struct Handshake {
    pub protocol_version: i32,
    pub host: String,
    pub port: u16,
    pub next_state: u32,
}

impl Handshake {
    pub fn encode_into(&self, w: &mut Writer) {
        w.varint(self.protocol_version as u32);
        w.string(&self.host);
        w.u16(self.port);
        w.varint(self.next_state);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(handshake_id::HANDSHAKE);
        self.encode_into(&mut w);
        w.out
    }

    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != handshake_id::HANDSHAKE {
            return Err(McError::new("expected handshake packet"));
        }
        let protocol_version = r.varint()? as i32;
        let host = r.string(255)?;
        let port = r.u16()?;
        let next_state = r.varint()?;
        r.assert_end()?;
        if next_state != 1 && next_state != 2 {
            return Err(McError::new("invalid next state in handshake"));
        }
        Ok(Handshake {
            protocol_version,
            host,
            port,
            next_state,
        })
    }

    pub fn is_supported_version(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

// ---- Status ----

#[derive(Debug, Clone, Default)]
pub struct StatusRequest;

impl StatusRequest {
    pub fn encode(&self) -> Vec<u8> {
        vec![status_id::SB_REQUEST]
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, r) = packet_id(body)?;
        if id != status_id::SB_REQUEST {
            return Err(McError::new("expected status request"));
        }
        r.assert_end()?;
        Ok(StatusRequest)
    }
}

#[derive(Debug, Clone)]
pub struct Ping {
    pub time: i64,
}

impl Ping {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(status_id::SB_PING);
        w.i64(self.time);
        w.out
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != status_id::SB_PING {
            return Err(McError::new("expected ping"));
        }
        let time = r.i64()?;
        r.assert_end()?;
        Ok(Ping { time })
    }
}

#[derive(Debug, Clone)]
pub struct StatusResponse {
    pub json: String,
}

impl StatusResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(status_id::CB_RESPONSE);
        w.string(&self.json);
        w.out
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != status_id::CB_RESPONSE {
            return Err(McError::new("expected status response"));
        }
        let json = r.string(32767)?;
        r.assert_end()?;
        Ok(StatusResponse { json })
    }
}

#[derive(Debug, Clone)]
pub struct Pong {
    pub time: i64,
}

impl Pong {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(status_id::CB_PONG);
        w.i64(self.time);
        w.out
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != status_id::CB_PONG {
            return Err(McError::new("expected pong"));
        }
        let time = r.i64()?;
        r.assert_end()?;
        Ok(Pong { time })
    }
}

// ---- Login ----

#[derive(Debug, Clone)]
pub struct LoginStart {
    pub name: String,
}

impl LoginStart {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(login_id::SB_LOGIN_START);
        w.string(&self.name);
        w.out
    }

    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != login_id::SB_LOGIN_START {
            return Err(McError::new("expected login start"));
        }
        let name = r.string(16)?;
        r.assert_end()?;
        if !is_valid_username(&name) {
            return Err(McError::new("invalid characters in username"));
        }
        Ok(LoginStart { name })
    }
}

/// Vanilla online-mode name rule: [a-zA-Z0-9_], length 1..=16.
pub fn is_valid_username(name: &str) -> bool {
    (1..=16).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone)]
pub struct EncryptionRequest {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: Vec<u8>,
}

impl EncryptionRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(login_id::CB_ENCRYPTION_REQUEST);
        w.string(&self.server_id);
        w.array_short(&self.public_key);
        w.array_short(&self.verify_token);
        w.out
    }

    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != login_id::CB_ENCRYPTION_REQUEST {
            return Err(McError::new("expected encryption request"));
        }
        let server_id = r.string(20)?;
        let public_key = r.array_short(8192)?;
        let verify_token = r.array_short(512)?;
        r.assert_end()?;
        Ok(EncryptionRequest {
            server_id,
            public_key,
            verify_token,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EncryptionResponse {
    pub shared_secret: Vec<u8>,
    pub verify_token: Vec<u8>,
}

impl EncryptionResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(login_id::SB_ENCRYPTION_RESPONSE);
        w.array_short(&self.shared_secret);
        w.array_short(&self.verify_token);
        w.out
    }

    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != login_id::SB_ENCRYPTION_RESPONSE {
            return Err(McError::new("expected encryption response"));
        }
        let shared_secret = r.array_short(512)?;
        let verify_token = r.array_short(512)?;
        r.assert_end()?;
        Ok(EncryptionResponse {
            shared_secret,
            verify_token,
        })
    }
}

#[derive(Debug, Clone)]
pub struct LoginDisconnect {
    pub reason: String,
}

impl LoginDisconnect {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(login_id::CB_DISCONNECT);
        w.string(&self.reason);
        w.out
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != login_id::CB_DISCONNECT {
            return Err(McError::new("expected login disconnect"));
        }
        let reason = r.string(32767)?;
        r.assert_end()?;
        Ok(LoginDisconnect { reason })
    }
}

#[derive(Debug, Clone)]
pub struct SetCompression {
    pub threshold: i32,
}

impl SetCompression {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(login_id::CB_SET_COMPRESSION);
        w.varint(self.threshold as u32);
        w.out
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != login_id::CB_SET_COMPRESSION {
            return Err(McError::new("expected set compression"));
        }
        let threshold = r.varint()? as i32;
        r.assert_end()?;
        if threshold < -1 {
            return Err(McError::new("invalid compression threshold"));
        }
        Ok(SetCompression { threshold })
    }
}

#[derive(Debug, Clone)]
pub struct LoginSuccess {
    pub uuid: String,
    pub username: String,
}

impl LoginSuccess {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(login_id::CB_LOGIN_SUCCESS);
        w.string(&self.uuid);
        w.string(&self.username);
        w.out
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != login_id::CB_LOGIN_SUCCESS {
            return Err(McError::new("expected login success"));
        }
        let uuid = r.string(36)?;
        let username = r.string(16)?;
        r.assert_end()?;
        Ok(LoginSuccess { uuid, username })
    }
}

// ---- Play (1.8.9) ----

#[derive(Debug, Clone)]
pub struct PlayKeepAlive {
    pub id: u32,
}

impl PlayKeepAlive {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(play_id::CB_KEEP_ALIVE);
        w.varint(self.id);
        w.out
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != play_id::SB_KEEP_ALIVE {
            return Err(McError::new("expected play keep-alive"));
        }
        let ka = r.varint()?;
        r.assert_end()?;
        Ok(PlayKeepAlive { id: ka })
    }
}

/// Join Game (clientbound 0x01) exactly as 1.8 serializes it.
#[derive(Debug, Clone)]
pub struct JoinGame {
    pub entity_id: i32,
    pub game_mode: u8,
    pub dimension: i8,
    pub difficulty: u8,
    pub max_players: u8,
    pub level_type: String,
    pub reduced_debug_info: bool,
}

impl Default for JoinGame {
    fn default() -> Self {
        JoinGame {
            entity_id: 0,
            game_mode: 0,
            dimension: 0,
            difficulty: 2,
            max_players: 20,
            level_type: "default".to_string(),
            reduced_debug_info: false,
        }
    }
}

impl JoinGame {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(play_id::CB_JOIN_GAME);
        w.i32(self.entity_id);
        w.u8(self.game_mode);
        w.i8(self.dimension);
        w.u8(self.difficulty);
        w.u8(self.max_players);
        w.string(&self.level_type);
        w.boolean(self.reduced_debug_info);
        w.out
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != play_id::CB_JOIN_GAME {
            return Err(McError::new("expected join game"));
        }
        let entity_id = r.i32()?;
        let game_mode = r.u8()?;
        let dimension = r.i8()?;
        let difficulty = r.u8()?;
        let max_players = r.u8()?;
        let level_type = r.string(16)?;
        let reduced_debug_info = r.boolean()?;
        r.assert_end()?;
        Ok(JoinGame {
            entity_id,
            game_mode,
            dimension,
            difficulty,
            max_players,
            level_type,
            reduced_debug_info,
        })
    }
}

/// Client Settings (serverbound 0x15), 1.8 layout (no main hand).
#[derive(Debug, Clone)]
pub struct ClientSettings {
    pub locale: String,
    pub view_distance: u8,
    pub chat_flags: u8,
    pub chat_colors: bool,
    pub skin_parts: u8,
}

impl Default for ClientSettings {
    fn default() -> Self {
        ClientSettings {
            locale: "en_US".to_string(),
            view_distance: 8,
            chat_flags: 0,
            chat_colors: true,
            skin_parts: 0x7F,
        }
    }
}

impl ClientSettings {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(play_id::SB_CLIENT_SETTINGS);
        w.string(&self.locale);
        w.u8(self.view_distance);
        w.u8(self.chat_flags);
        w.boolean(self.chat_colors);
        w.u8(self.skin_parts);
        w.out
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != play_id::SB_CLIENT_SETTINGS {
            return Err(McError::new("expected client settings"));
        }
        let locale = r.string(16)?;
        let view_distance = r.u8()?;
        let chat_flags = r.u8()?;
        let chat_colors = r.boolean()?;
        let skin_parts = r.u8()?;
        r.assert_end()?;
        Ok(ClientSettings {
            locale,
            view_distance,
            chat_flags,
            chat_colors,
            skin_parts,
        })
    }
}

/// Idle Player update (serverbound 0x03): vanilla sends this every tick.
#[derive(Debug, Clone)]
pub struct PlayerTick {
    pub on_ground: bool,
}

impl PlayerTick {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(play_id::SB_PLAYER);
        w.boolean(self.on_ground);
        w.out
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != play_id::SB_PLAYER {
            return Err(McError::new("expected player tick"));
        }
        let on_ground = r.boolean()?;
        r.assert_end()?;
        Ok(PlayerTick { on_ground })
    }
}

#[derive(Debug, Clone)]
pub struct CustomPayload {
    pub channel: String,
    pub data: Vec<u8>,
}

impl CustomPayload {
    /// Serverbound (0x17): channel <= 20 chars, payload <= 32767 bytes.
    pub fn encode_sb(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(play_id::SB_CUSTOM_PAYLOAD);
        w.string(&self.channel);
        w.bytes(&self.data);
        w.out
    }

    /// Clientbound (0x3F).
    pub fn encode_cb(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(play_id::CB_CUSTOM_PAYLOAD);
        w.string(&self.channel);
        w.bytes(&self.data);
        w.out
    }

    pub fn decode_sb(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != play_id::SB_CUSTOM_PAYLOAD {
            return Err(McError::new("expected serverbound custom payload"));
        }
        let channel = r.string(20)?;
        let data = r.rest().to_vec();
        if data.len() > 32767 {
            return Err(McError::new("plugin payload too large"));
        }
        Ok(CustomPayload { channel, data })
    }

    pub fn decode_cb(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != play_id::CB_CUSTOM_PAYLOAD {
            return Err(McError::new("expected clientbound custom payload"));
        }
        let channel = r.string(20)?;
        let data = r.rest().to_vec();
        if data.len() > 1024 * 1024 {
            return Err(McError::new("plugin payload too large"));
        }
        Ok(CustomPayload { channel, data })
    }
}

#[derive(Debug, Clone)]
pub struct PlayDisconnect {
    pub reason: String,
}

impl PlayDisconnect {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(play_id::CB_DISCONNECT);
        w.string(&self.reason);
        w.out
    }
    pub fn decode(body: &[u8]) -> McResult<Self> {
        let (id, mut r) = packet_id(body)?;
        if id != play_id::CB_DISCONNECT {
            return Err(McError::new("expected play disconnect"));
        }
        let reason = r.string(32767)?;
        r.assert_end()?;
        Ok(PlayDisconnect { reason })
    }
}

/// Vanilla-style kick reasons (JSON chat component strings).
pub mod kick {
    use crate::packets::*;

    pub fn json(text: &str) -> String {
        serde_json::json!({ "text": text }).to_string()
    }
    pub fn outdated_client() -> String {
        json(&format!("Outdated client! I'm running {VERSION_NAME}"))
    }
    pub fn outdated_server() -> String {
        json(&format!(
            "Outdated server! I'm still running {VERSION_NAME}"
        ))
    }
    pub fn timed_out() -> String {
        json("Timed out")
    }
    pub fn internal_error() -> String {
        json("Internal Exception: io.netty.handler.codec.DecoderException")
    }
    pub fn not_whitelisted() -> String {
        json("You are not whitelisted on this server!")
    }
    pub fn server_full() -> String {
        json("The server is full!")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_golden() {
        // Handshake for 1.8.9, host "127.0.0.1", port 25565, next state 1.
        let hs = Handshake {
            protocol_version: 47,
            host: "127.0.0.1".into(),
            port: 25565,
            next_state: 1,
        };
        let mut frame = Vec::new();
        let body = hs.encode();
        frame.push(body.len() as u8);
        frame.extend_from_slice(&body);
        assert_eq!(
            frame,
            vec![
                0x0F, 0x00, 0x2F, 0x09, b'1', b'2', b'7', b'.', b'0', b'.', b'0', b'.', b'1', 0x63,
                0xDD, 0x01
            ]
        );
        let back = Handshake::decode(&body).unwrap();
        assert_eq!(back.host, "127.0.0.1");
        assert_eq!(back.port, 25565);
        assert_eq!(back.next_state, 1);
    }

    #[test]
    fn login_start_roundtrip_and_validation() {
        let p = LoginStart {
            name: "xK9_mZq4".into(),
        };
        let dec = LoginStart::decode(&p.encode()).unwrap();
        assert_eq!(dec.name, "xK9_mZq4");
        assert!(!is_valid_username("bad name"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("way-too-long-username"));
        assert!(!is_valid_username("№"));
    }

    #[test]
    fn encryption_packets_structure() {
        let req = EncryptionRequest {
            server_id: String::new(),
            public_key: vec![1, 2, 3, 4],
            verify_token: vec![9, 9, 9, 9],
        };
        let dec = EncryptionRequest::decode(&req.encode()).unwrap();
        assert_eq!(dec.public_key, vec![1, 2, 3, 4]);
        assert_eq!(dec.verify_token, vec![9, 9, 9, 9]);
        assert_eq!(dec.server_id, "");

        let resp = EncryptionResponse {
            shared_secret: vec![7u8; 16],
            verify_token: vec![9, 9, 9, 9],
        };
        let dec = EncryptionResponse::decode(&resp.encode()).unwrap();
        assert_eq!(dec.shared_secret, vec![7u8; 16]);
    }

    #[test]
    fn join_game_roundtrip() {
        let jg = JoinGame {
            entity_id: 12345,
            game_mode: 0,
            dimension: 0,
            difficulty: 2,
            max_players: 20,
            level_type: "default".into(),
            reduced_debug_info: false,
        };
        let dec = JoinGame::decode(&jg.encode()).unwrap();
        assert_eq!(dec.entity_id, 12345);
        assert_eq!(dec.max_players, 20);
    }

    #[test]
    fn client_settings_roundtrip() {
        let cs = ClientSettings::default();
        let dec = ClientSettings::decode(&cs.encode()).unwrap();
        assert_eq!(dec.locale, "en_US");
        assert_eq!(dec.skin_parts, 0x7F);
    }

    #[test]
    fn custom_payload_caps() {
        let big = CustomPayload {
            channel: CHANNEL_TUNNEL.into(),
            data: vec![0u8; 32768],
        };
        assert!(CustomPayload::decode_sb(&big.encode_sb()).is_err());
        let ok = CustomPayload {
            channel: CHANNEL_TUNNEL.into(),
            data: vec![0u8; 1400],
        };
        let dec = CustomPayload::decode_sb(&ok.encode_sb()).unwrap();
        assert_eq!(dec.channel, CHANNEL_TUNNEL);
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut body = LoginStart { name: "abc".into() }.encode();
        body.push(0x00);
        assert!(LoginStart::decode(&body).is_err());
    }
}
