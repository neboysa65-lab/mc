//! Login encryption, byte-compatible with vanilla/BungeeCord:
//! RSA PKCS#1 v1.5 (`RSA/ECB/PKCS1Padding`) over the X.509 SPKI-encoded
//! public key, AES-128 shared secret, plus the classic offline UUID.

use crate::cipher::SHARED_SECRET_LEN;
use crate::error::{McError, McResult};
use md5::{Digest, Md5};
use rand_core::CryptoRngCore;
use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

pub struct ServerRsaKey {
    private: RsaPrivateKey,
    public_der: Vec<u8>,
}

impl ServerRsaKey {
    /// Wrap an existing RSA private key (e.g. loaded from a config/fixture).
    pub fn from_private_key(private: RsaPrivateKey) -> Self {
        let public = RsaPublicKey::from(&private);
        let public_der = public
            .to_public_key_der()
            .expect("SPKI encode failed")
            .as_bytes()
            .to_vec();
        ServerRsaKey { private, public_der }
    }

    pub fn generate(bits: usize, rng: &mut impl CryptoRngCore) -> McResult<Self> {
        let private = RsaPrivateKey::new(rng, bits)
            .map_err(|e| McError::new(format!("RSA keygen failed: {e}")))?;
        let public = RsaPublicKey::from(&private);
        let public_der = public
            .to_public_key_der()
            .map_err(|e| McError::new(format!("SPKI encode failed: {e}")))?
            .as_bytes()
            .to_vec();
        Ok(ServerRsaKey { private, public_der })
    }

    pub fn public_key_der(&self) -> &[u8] {
        &self.public_der
    }

    /// Decrypt the client's encryption response; returns the shared secret and verify token.
    pub fn decrypt_response(
        &self,
        enc_secret: &[u8],
        enc_token: &[u8],
    ) -> McResult<([u8; SHARED_SECRET_LEN], Vec<u8>)> {
        let mut rng = OsRng;
        let secret = self
            .private
            .decrypt_blinded(&mut rng, Pkcs1v15Encrypt, enc_secret)
            .map_err(|_| McError::new("failed to decrypt shared secret"))?;
        let token = self
            .private
            .decrypt_blinded(&mut rng, Pkcs1v15Encrypt, enc_token)
            .map_err(|_| McError::new("failed to decrypt verify token"))?;
        if secret.len() != SHARED_SECRET_LEN {
            return Err(McError::new("shared secret is not 16 bytes"));
        }
        let mut arr = [0u8; SHARED_SECRET_LEN];
        arr.copy_from_slice(&secret);
        Ok((arr, token))
    }
}

/// Client side: encrypt shared secret and verify token with the server's
/// X.509 SPKI public key (PKCS#1 v1.5), as vanilla does.
pub fn client_encrypt_response(
    server_public_der: &[u8],
    shared_secret: &[u8; SHARED_SECRET_LEN],
    verify_token: &[u8],
    rng: &mut impl CryptoRngCore,
) -> McResult<(Vec<u8>, Vec<u8>)> {
    let public = RsaPublicKey::from_public_key_der(server_public_der)
        .map_err(|e| McError::new(format!("invalid server public key: {e}")))?;
    let secret = public
        .encrypt(rng, Pkcs1v15Encrypt, shared_secret)
        .map_err(|e| McError::new(format!("RSA encrypt failed: {e}")))?;
    let token = public
        .encrypt(rng, Pkcs1v15Encrypt, verify_token)
        .map_err(|e| McError::new(format!("RSA encrypt failed: {e}")))?;
    Ok((secret, token))
}

/// Java `UUID.nameUUIDFromBytes("OfflinePlayer:" + name)`: MD5 v3 UUID with
/// version/variant bits set, dashed lowercase, as vanilla 1.8 sends it.
pub fn offline_uuid_string(name: &str) -> String {
    let mut h = Md5::digest(format!("OfflinePlayer:{name}").as_bytes());
    h[6] = (h[6] & 0x0F) | 0x30; // version 3
    h[8] = (h[8] & 0x3F) | 0x80; // RFC 4122 variant
    let b = &h;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    #[test]
    fn rsa_login_roundtrip() {
        let mut rng = OsRng;
        let server = ServerRsaKey::generate(2048, &mut rng).unwrap();
        let mut secret = [0u8; 16];
        rng.fill_bytes(&mut secret);
        let token = [0xABu8; 4];
        let (enc_secret, enc_token) =
            client_encrypt_response(server.public_key_der(), &secret, &token, &mut rng).unwrap();
        let (dec_secret, dec_token) =
            server.decrypt_response(&enc_secret, &enc_token).unwrap();
        assert_eq!(dec_secret, secret);
        assert_eq!(dec_token, token);
    }
}
