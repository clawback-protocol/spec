// Clawback Protocol — Sender Module (True PRE)
//
// The Sender owns the data:
// - Generates a key pair per payload (SecretKey never transmitted)
// - Encrypts plaintext to own PublicKey via Umbral
// - Generates re-encryption key fragments (kfrags) delegating to each receiver
// - Delegates revocation to broker (broker destroys kfrags)

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use crate::crypto::{PayloadId, ShareId, SecretKey, PublicKey, Signer, Capsule, VerifiedKeyFrag};

struct PayloadEntry {
    delegating_sk: SecretKey,
    signer: Signer,
}

/// Result of encrypting a payload — everything the broker needs to store
pub struct EncryptResult {
    pub payload_id: PayloadId,
    pub share_id: ShareId,
    pub capsule: Capsule,
    pub ciphertext: Vec<u8>,
    pub kfrags: Vec<VerifiedKeyFrag>,
    pub delegating_pk: PublicKey,
    pub verifying_pk: PublicKey,
}

/// Result of issuing a new share — kfrags for the broker
pub struct ShareResult {
    pub share_id: ShareId,
    pub kfrags: Vec<VerifiedKeyFrag>,
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

    /// Encrypt plaintext and generate kfrags for a specific receiver.
    /// The sender encrypts to their own public key; kfrags delegate decryption
    /// to the receiver via the broker's re-encryption.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        receiver_pk: &PublicKey,
    ) -> Result<EncryptResult> {
        let delegating_sk = SecretKey::random();
        let signer = Signer::new(SecretKey::random());

        // Derive delegating public key for encryption
        let delegating_pk = delegating_sk.public_key();

        // Encrypt to sender's own public key
        let (capsule, ciphertext) = umbral_pre::encrypt(&delegating_pk, plaintext)
            .map_err(|e| anyhow!("encryption failed: {e}"))?;

        // Generate kfrags delegating decryption to receiver
        let kfrags = umbral_pre::generate_kfrags(
            &delegating_sk, receiver_pk, &signer,
            1, 1, true, true,
        );

        let payload_id = PayloadId::new_v4();
        let share_id = ShareId::new_v4();

        // Derive again for the result (originals stored in PayloadEntry)
        let result_pk = delegating_sk.public_key();
        let result_vk = signer.verifying_key();

        self.payloads.insert(payload_id, PayloadEntry {
            delegating_sk,
            signer,
        });

        Ok(EncryptResult {
            payload_id,
            share_id,
            capsule,
            ciphertext: ciphertext.to_vec(),
            kfrags: kfrags.to_vec(),
            delegating_pk: result_pk,
            verifying_pk: result_vk,
        })
    }

    /// Issue a new share for an existing payload to a different receiver.
    /// Generates fresh kfrags targeted at the new receiver's public key.
    pub fn issue_share(
        &self,
        payload_id: &PayloadId,
        receiver_pk: &PublicKey,
    ) -> Result<ShareResult> {
        let entry = self.payloads.get(payload_id)
            .ok_or_else(|| anyhow!("unknown payload"))?;

        let kfrags = umbral_pre::generate_kfrags(
            &entry.delegating_sk, receiver_pk, &entry.signer,
            1, 1, true, true,
        );

        let share_id = ShareId::new_v4();
        Ok(ShareResult { share_id, kfrags: kfrags.to_vec() })
    }
}
