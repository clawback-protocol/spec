// Clawback Protocol — Sender Module
//
// The Sender owns the data:
// - Generates master key per payload (NEVER transmitted)
// - Encrypts plaintext locally via EncKey (HKDF-derived from master key)
// - In simulated PRE, share_key = enc_key for all recipients
// - Issues share tokens, delegates revocation to broker

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use crate::crypto::{MasterKey, EncKey, PayloadId, ShareId, EncryptedPayload};

struct PayloadEntry {
    _master_key: MasterKey,
    enc_key: EncKey,
}

pub struct Sender {
    payloads: HashMap<PayloadId, PayloadEntry>,
}

impl Sender {
    pub fn new() -> Self {
        Self {
            payloads: HashMap::new(),
        }
    }

    /// Encrypt plaintext and prepare for broker registration.
    /// Returns (payload_id, share_id, encrypted_payload, share_key_bytes).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(PayloadId, ShareId, EncryptedPayload, Vec<u8>)> {
        let master_key = MasterKey::generate();
        let enc_key = master_key.derive_enc_key();
        let payload_id = PayloadId::new_v4();
        let share_id = ShareId::new_v4();

        let encrypted = enc_key.encrypt(plaintext)?;
        let share_key_bytes = enc_key.as_bytes().to_vec();

        self.payloads.insert(payload_id, PayloadEntry {
            _master_key: master_key,
            enc_key,
        });

        Ok((payload_id, share_id, encrypted, share_key_bytes))
    }

    /// Issue a new share for an existing payload.
    /// Returns (share_id, share_key_bytes) — same enc_key for simulated PRE.
    pub fn issue_share(&self, payload_id: &PayloadId) -> Result<(ShareId, Vec<u8>)> {
        let entry = self.payloads.get(payload_id)
            .ok_or_else(|| anyhow!("unknown payload"))?;
        let share_id = ShareId::new_v4();
        Ok((share_id, entry.enc_key.as_bytes().to_vec()))
    }
}
