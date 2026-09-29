//! Server List Ping response JSON, vanilla 1.8.9 field set and order.

use crate::{PROTOCOL_VERSION, VERSION_NAME};

pub fn status_json(motd: &str, online: u32, max: u32) -> String {
    // Byte-exact with vanilla/BungeeCord 1.8.9:
    // - "description" is a chat component OBJECT ({"text": ...}), not a string
    // - "sample" is omitted entirely when there are no players
    serde_json::json!({
        "version": { "name": VERSION_NAME, "protocol": PROTOCOL_VERSION },
        "players": players_json(online, max),
        "description": { "text": motd },
    })
    .to_string()
}

fn players_json(online: u32, max: u32) -> serde_json::Value {
    if online == 0 {
        return serde_json::json!({ "max": max, "online": online });
    }
    // A busy server shows a player sample; plausible, deterministic entries.
    const NAMES: [&str; 6] = ["AlexB", "Kai_99", "MiraQ", "Tobi_s", "Nova7", "JunoX"];
    let n = (online as usize).min(NAMES.len());
    let sample: Vec<serde_json::Value> = NAMES[..n]
        .iter()
        .map(|name| {
            serde_json::json!({
                "name": name,
                "id": crate::login_crypto::offline_uuid_string(name)
            })
        })
        .collect();
    serde_json::json!({ "max": max, "online": online, "sample": sample })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slp_golden() {
        let s = status_json("A Minecraft Server", 0, 20);
        assert_eq!(
            s,
            "{\"version\":{\"name\":\"1.8.9\",\"protocol\":47},\"players\":{\"max\":20,\"online\":0},\"description\":{\"text\":\"A Minecraft Server\"}}"
        );
    }
}
