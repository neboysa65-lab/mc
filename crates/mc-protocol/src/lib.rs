//! Byte-exact Minecraft Java Edition 1.8.9 (protocol 47) wire protocol.
//!
//! Covers only the states and packets needed for a VPN transport that is
//! indistinguishable from a real vanilla 1.8.9 server/client on the wire:
//! handshake, server list ping (incl. legacy), login with encryption, set
//! compression, and the play-state packets used for keep-alive and plugin
//! channel traffic.

pub mod buf;
pub mod cipher;
pub mod compress;
pub mod error;
pub mod frame;
pub mod legacy;
pub mod login_crypto;
pub mod packets;
pub mod slp;
pub mod state;

pub use error::McError;
pub use state::{Direction, State};

/// Protocol version of Minecraft 1.8.9.
pub const PROTOCOL_VERSION: i32 = 47;
pub const VERSION_NAME: &str = "1.8.9";
