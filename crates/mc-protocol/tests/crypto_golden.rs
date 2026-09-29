//! Byte-level golden tests for login crypto, pinned against a committed RSA
//! key fixture and Java-compatible offline UUIDs.

use mc_protocol::login_crypto::{offline_uuid_string, ServerRsaKey};
use mc_protocol::packets::EncryptionRequest;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

const KEY_PEM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/test-1024.pem");

const PUBKEY_DER_HEX: &str = "30819f300d06092a864886f70d010101050003818d0030818902818100c78599089483aeaac21918ae6439385a673288bb28573034082fae37ba235e450ce2f74fa26ad72d5332aadb9ff4744ab99fb2140229772a9330f0f46e9c1fee02e2656b77ddc5d62098d57564b18496e87e552af6a3021033d95eb8d087c4fef731d3e4829319641765fe2f877c7d7cc511d1a6f3fdb4684a9095db23b184eb0203010001";

const ENC_REQUEST_HEX: &str = "010000a230819f300d06092a864886f70d010101050003818d0030818902818100c78599089483aeaac21918ae6439385a673288bb28573034082fae37ba235e450ce2f74fa26ad72d5332aadb9ff4744ab99fb2140229772a9330f0f46e9c1fee02e2656b77ddc5d62098d57564b18496e87e552af6a3021033d95eb8d087c4fef731d3e4829319641765fe2f877c7d7cc511d1a6f3fdb4684a9095db23b184eb0203010001000409090909";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn offline_uuid_matches_java() {
    // UUID.nameUUIDFromBytes("OfflinePlayer:Notch".getBytes())
    let dash = |h: &str| -> String {
        format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        )
    };
    assert_eq!(
        offline_uuid_string("Notch"),
        dash("b50ad385829d3141a2167e7d7539ba7f")
    );
    assert_eq!(
        offline_uuid_string("xK9_mZq4"),
        dash("4fc89ba6f70338208d38c13f0130be54")
    );
}

#[test]
fn encryption_request_golden_bytes() {
    let pem = std::fs::read_to_string(KEY_PEM).unwrap();
    let private = RsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
    let key = ServerRsaKey::from_private_key(private);

    // SPKI DER of the fixture key must match the pinned bytes.
    assert_eq!(key.public_key_der(), unhex(PUBKEY_DER_HEX).as_slice());

    let req = EncryptionRequest {
        server_id: String::new(),
        public_key: key.public_key_der().to_vec(),
        verify_token: vec![9, 9, 9, 9],
    };
    let bytes = req.encode();
    assert_eq!(bytes, unhex(ENC_REQUEST_HEX));

    // And it must round-trip through the strict parser.
    let dec = EncryptionRequest::decode(&bytes).unwrap();
    assert_eq!(dec.server_id, "");
    assert_eq!(dec.public_key.len(), 162);
    assert_eq!(dec.verify_token, vec![9, 9, 9, 9]);
}
