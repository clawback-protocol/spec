// Clawback Protocol — Receiver Module
//
// The Receiver:
// - Presents share_token to Broker
// - Receives encrypted blob + share_key
// - Decrypts locally
// - Loses access instantly on revocation (next request → 403)
//
// TODO: Implement HTTP client calls to Broker service

use anyhow::Result;
use crate::crypto::EncryptedPayload;

pub struct Receiver;

impl Receiver {
    /// Decrypt a payload using the share key received from the Broker
    pub fn decrypt(share_key_bytes: &[u8], payload: &EncryptedPayload) -> Result<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, Nonce, aead::{Aead, KeyInit}};
        let cipher = ChaCha20Poly1305::new_from_slice(share_key_bytes)?;
        let nonce = Nonce::from_slice(&payload.nonce);
        let plaintext = cipher
            .decrypt(nonce, payload.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed — access may have been revoked: {}", e))?;
        Ok(plaintext)
    }
}
