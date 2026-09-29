use serde::{Deserialize, Serialize};
use std::path::Path;

fn d_bind() -> String {
    "0.0.0.0".into()
}
fn d_motd() -> String {
    "A Minecraft Server".into()
}
fn d_dns() -> Vec<String> {
    vec!["1.1.1.1".into(), "8.8.8.8".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Minecraft listen port (25565 for full camouflage).
    #[serde(default = "d_bind")]
    pub bind: String,
    #[serde(default = "d_port")]
    pub port: u16,
    /// Shared auth token clients must present after login encryption.
    #[serde(default)]
    pub token: String,
    #[serde(default = "d_motd")]
    pub motd: String,
    /// SLP "max players" and constant fake "online" count.
    #[serde(default = "d_max_players")]
    pub max_players: u32,
    #[serde(default = "d_fake_online")]
    pub fake_online: u32,
    /// MC packet compression threshold; 256 matches BungeeCord/vanilla defaults.
    #[serde(default = "d_compression_threshold")]
    pub compression_threshold: u32,
    /// Play-state keep-alive interval (vanilla 1.8 sends every 15s).
    #[serde(default = "d_keepalive")]
    pub keepalive_secs: u64,
    /// RSA login key size in bits. 1024 matches vanilla/BungeeCord exactly —
    /// a 2048-bit key makes the Encryption Request ~130 bytes longer than
    /// every real 1.8.9 server's, which is itself a fingerprint. Session
    /// security does not rest on it (inner AES-256-GCM + token auth do).
    #[serde(default = "d_rsa_bits")]
    pub rsa_bits: usize,
    /// CGNAT range the tunnel assigns client IPs from.
    #[serde(default = "d_tunnel_cidr")]
    pub tunnel_cidr: String,
    #[serde(default = "d_mtu")]
    pub mtu: u16,
    /// DNS resolvers advertised to clients (routed through the tunnel).
    #[serde(default = "d_dns")]
    pub dns: Vec<String>,
    #[serde(default = "d_max_clients")]
    pub max_clients: u32,
    /// Max concurrent unfinished handshakes/logins.
    #[serde(default = "d_max_pending")]
    pub max_pending: u32,
    /// Min interval between new connections from the same IP (BungeeCord throttle).
    #[serde(default = "d_per_ip_min_interval_ms")]
    pub per_ip_min_interval_ms: u64,
    #[serde(default = "d_setup_nat")]
    pub setup_nat: bool,
    /// Seconds a connected client gets to authenticate before being kicked.
    #[serde(default = "d_auth_timeout")]
    pub auth_timeout_secs: u64,
    /// Accept plaintext (unencrypted) mock device for tests.
    #[serde(default, skip_serializing)]
    pub mock_device: bool,
}

fn d_port() -> u16 {
    25565
}
fn d_max_players() -> u32 {
    20
}
fn d_fake_online() -> u32 {
    0
}
fn d_compression_threshold() -> u32 {
    256
}
fn d_keepalive() -> u64 {
    15
}
fn d_rsa_bits() -> usize {
    1024
}
fn d_tunnel_cidr() -> String {
    "100.64.0.0/10".into()
}
fn d_mtu() -> u16 {
    1400
}
fn d_max_clients() -> u32 {
    256
}
fn d_max_pending() -> u32 {
    64
}
fn d_per_ip_min_interval_ms() -> u64 {
    1000
}
fn d_setup_nat() -> bool {
    true
}
fn d_auth_timeout() -> u64 {
    10
}

impl Default for ServerConfig {
    fn default() -> Self {
        toml::from_str("").expect("all defaults")
    }
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("serializable")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server hostname (also used as the handshake host string, like a real client).
    #[serde(default)]
    pub server: String,
    #[serde(default = "d_port")]
    pub port: u16,
    #[serde(default)]
    pub token: String,
    /// Send vanilla-like 20Hz idle player updates (traffic realism).
    #[serde(default = "d_stealth_tick")]
    pub stealth_tick: bool,
    /// Tunnel-level RTT probe interval in seconds.
    #[serde(default = "d_ping_interval")]
    pub ping_interval_secs: u64,
    /// Reconnect automatically on network errors with backoff.
    #[serde(default = "d_auto_reconnect")]
    pub auto_reconnect: bool,
}

fn d_stealth_tick() -> bool {
    true
}
fn d_ping_interval() -> u64 {
    5
}
fn d_auto_reconnect() -> bool {
    true
}

impl ClientConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        toml::from_str("").expect("all defaults")
    }
}
