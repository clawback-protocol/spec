// Clawback Protocol — Sender Module
//
// The Sender owns the data:
// - Generates and holds master key (NEVER transmitted)
// - Encrypts plaintext locally
// - Registers payload with Broker
// - Issues share tokens to recipients
// - Revokes shares
//
// TODO: Implement HTTP client calls to Broker service

use anyhow::Result;
use std::collections::HashMap;
use uuid::Uuid;
use crate::crypto::{MasterKey, PayloadId, ShareId, EncryptedPayload};

pub struct Sender {
    master_key: MasterKey,
    payloads: HashMap<PayloadId, EncryptedPayload>,
}

impl Sender {
    pub fn new() -> Self {
        Self {
            master_key: MasterKey::generate(),
            payloads: HashMap::new(),
        }
    }

    /// Encrypt plaintext and prepare for broker registration
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(PayloadId, ShareId, EncryptedPayload, Vec<u8>)> {
        let payload_id = PayloadId::new_v4();
        let share_id = ShareId::new_v4();

        // Derive share key for initial recipient
        let share_key = self.master_key.derive_share_key(&share_id);

        // Encrypt with share key (PoC model — full PRE uses enc_key separately)
        use chacha20poly1305::{ChaCha20Poly1305, Nonce, aead::{Aead, KeyInit}};
        use rand::RngCore;
        let cipher = ChaCha20Poly1305::new_from_slice(share_key.as_bytes())?;
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let payload = EncryptedPayload { ciphertext, nonce: nonce_bytes };
        let key_bytes = share_key.as_bytes().to_vec();

        Ok((payload_id, share_id, payload, key_bytes))
    }

    /// Issue a new share for an existing payload
    pub fn issue_share(&self, payload_id: &PayloadId) -> (ShareId, Vec<u8>) {
        let share_id = ShareId::new_v4();
        let share_key = self.master_key.derive_share_key(&share_id);
        (share_id, share_key.as_bytes().to_vec())
    }
}
