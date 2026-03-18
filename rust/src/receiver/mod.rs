// Clawback Protocol — Receiver Module (True PRE)
//
// The Receiver:
// - Holds own key pair (SecretKey, PublicKey)
// - Shares PublicKey with sender for kfrag generation
// - Receives cfrags (re-encrypted capsule fragments) from broker
// - Decrypts locally using own SecretKey + cfrags + sender's PublicKey
// - Loses access instantly on revocation (broker can't produce cfrags)

use anyhow::{Result, anyhow};
use crate::crypto::{
    SecretKey, PublicKey, Capsule, VerifiedCapsuleFrag,
};

pub struct Receiver {
    sk: SecretKey,
}

impl Receiver {
    /// Create a new receiver with a fresh key pair
    pub fn new() -> Self {
        Self { sk: SecretKey::random() }
    }

    /// Return this receiver's public key (for sender to generate kfrags)
    pub fn public_key(&self) -> PublicKey {
        self.sk.public_key()
    }

    /// Decrypt a re-encrypted payload using cfrags from the broker.
    /// Requires the sender's delegating public key, the capsule, and cfrags.
    pub fn decrypt(
        &self,
        delegating_pk: &PublicKey,
        capsule: &Capsule,
        cfrags: Vec<VerifiedCapsuleFrag>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let plaintext = umbral_pre::decrypt_reencrypted(
            &self.sk, delegating_pk, capsule, cfrags, ciphertext,
        ).map_err(|e| anyhow!("decryption failed: {e}"))?;
        Ok(plaintext.to_vec())
    }
}
