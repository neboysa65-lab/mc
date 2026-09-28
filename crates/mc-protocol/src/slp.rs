//! Server List Ping response JSON, vanilla 1.8.9 field set and order.

use crate::{PROTOCOL_VERSION, VERSION_NAME};

pub fn status_json(motd: &str, online: u32, max: u32) -> String {
    serde_json::json!({
        "version": { "name": VERSION_NAME, "protocol": PROTOCOL_VERSION },
        "players": { "max": max, "online": online, "sample": [] },
        "description": motd
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slp_golden() {
        let s = status_json("A Minecraft Server", 0, 20);
        assert_eq!(
            s,
            "{\"version\":{\"name\":\"1.8.9\",\"protocol\":47},\"players\":{\"max\":20,\"online\":0,\"sample\":[]},\"description\":\"A Minecraft Server\"}"
        );
    }
}
