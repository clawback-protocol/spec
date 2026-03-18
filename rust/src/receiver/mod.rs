// Clawback Protocol — Receiver Module
//
// The Receiver:
// - Presents share_token to Broker
// - Receives encrypted blob + share_key
// - Decrypts locally via ShareKey
// - Loses access instantly on revocation (next request → 403)

use anyhow::Result;
use crate::crypto::{ShareKey, EncryptedPayload};

pub struct Receiver;

impl Receiver {
    /// Decrypt a payload using the share key bytes received from the Broker.
    /// Constructs a ShareKey from raw bytes, then decrypts the EncryptedPayload.
    pub fn decrypt(share_key_bytes: &[u8], payload: &EncryptedPayload) -> Result<Vec<u8>> {
        let share_key = ShareKey::from_bytes(share_key_bytes)?;
        share_key.decrypt(payload)
    }
}
