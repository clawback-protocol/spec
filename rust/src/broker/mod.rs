<<<<<<< HEAD
// Clawback Protocol — Broker Module (True PRE)
//
// The Broker is a semi-trusted proxy:
// - Stores encrypted payloads + capsules (never sees plaintext)
// - Holds kfrags (re-encryption key fragments) per share
// - On fetch: re-encrypts capsule using kfrags → produces cfrags
// - On revoke: destroys kfrags → re-encryption permanently impossible
// - Logs tamper-evident destruction receipts

use std::collections::HashMap;
use anyhow::{Result, anyhow};
use crate::crypto::{
    PayloadId, ShareId, PublicKey, Capsule,
    VerifiedKeyFrag, VerifiedCapsuleFrag,
    generate_destruction_proof, hash_ciphertext, reencrypt,
};
=======
// Clawback Protocol — Broker Module
//
// The Broker is a zero-knowledge intermediary:
// - Stores encrypted payloads (never sees plaintext)
// - Manages per-share keys
// - Enforces revocation instantly
// - Logs destruction receipts (append-only)
//
// TODO: Implement HTTP service using axum

use std::collections::HashMap;
use anyhow::{Result, anyhow};
use crate::crypto::{PayloadId, ShareId, generate_destruction_proof, hash_ciphertext};
>>>>>>> origin/main

/// Status of a share
#[derive(Debug, Clone, PartialEq)]
pub enum ShareStatus {
    Active,
    Revoked,
}

<<<<<<< HEAD
/// A stored share — kfrags + receiver identity + status
pub struct Share {
    pub kfrags: Vec<VerifiedKeyFrag>,
    pub receiver_pk: PublicKey,
    pub status: ShareStatus,
}

/// A stored payload — ciphertext + capsule + sender identity
pub struct StoredPayload {
    pub ciphertext: Vec<u8>,
    pub capsule: Capsule,
    pub delegating_pk: PublicKey,
    pub verifying_pk: PublicKey,
    pub shares: HashMap<ShareId, Share>,
}

/// Result of a broker fetch — re-encrypted material for the receiver
#[derive(Debug)]
pub struct FetchResult {
    pub ciphertext: Vec<u8>,
    pub capsule: Capsule,
    pub cfrags: Vec<VerifiedCapsuleFrag>,
    pub delegating_pk: PublicKey,
}

/// Destruction receipt — tamper-evident proof of kfrag destruction
=======
/// A stored share — key + status
#[derive(Debug, Clone)]
pub struct Share {
    pub share_key: Vec<u8>,
    pub status: ShareStatus,
}

/// A stored payload — ciphertext + nonce + shares
#[derive(Debug)]
pub struct StoredPayload {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub shares: HashMap<ShareId, Share>,
}

/// Destruction receipt — tamper-evident proof of key destruction
>>>>>>> origin/main
#[derive(Debug, Clone, serde::Serialize)]
pub struct DestructionReceipt {
    pub payload_id: String,
    pub share_id: String,
    pub data_hash: String,
    pub revoked_at: String,
    pub destruction_proof: String,
    pub status: String,
}

<<<<<<< HEAD
/// Broker — in-memory PRE proxy (replace with persistent storage for production)
=======
/// Broker — in-memory store (replace with persistent storage for production)
>>>>>>> origin/main
pub struct Broker {
    payloads: HashMap<PayloadId, StoredPayload>,
    receipts: Vec<DestructionReceipt>,
    secret: Vec<u8>,
}

impl Broker {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            payloads: HashMap::new(),
            receipts: Vec::new(),
            secret: secret.to_vec(),
        }
    }

<<<<<<< HEAD
    /// Register an encrypted payload with its capsule, sender identity, and initial share
=======
    /// Register an encrypted payload with an initial share key
>>>>>>> origin/main
    pub fn register(
        &mut self,
        payload_id: PayloadId,
        ciphertext: Vec<u8>,
<<<<<<< HEAD
        capsule: Capsule,
        delegating_pk: PublicKey,
        verifying_pk: PublicKey,
        share_id: ShareId,
        kfrags: Vec<VerifiedKeyFrag>,
        receiver_pk: PublicKey,
    ) {
        let mut shares = HashMap::new();
        shares.insert(share_id, Share {
            kfrags,
            receiver_pk,
            status: ShareStatus::Active,
        });
        self.payloads.insert(payload_id, StoredPayload {
            ciphertext,
            capsule,
            delegating_pk,
            verifying_pk,
            shares,
        });
    }

    /// Add a new share (new receiver) to an existing payload
=======
        nonce: [u8; 12],
        share_id: ShareId,
        share_key: Vec<u8>,
    ) {
        let mut shares = HashMap::new();
        shares.insert(share_id, Share { share_key, status: ShareStatus::Active });
        self.payloads.insert(payload_id, StoredPayload { ciphertext, nonce, shares });
    }

    /// Add a new share to an existing payload
>>>>>>> origin/main
    pub fn add_share(
        &mut self,
        payload_id: &PayloadId,
        share_id: ShareId,
<<<<<<< HEAD
        kfrags: Vec<VerifiedKeyFrag>,
        receiver_pk: PublicKey,
    ) -> Result<()> {
        let payload = self.payloads.get_mut(payload_id)
            .ok_or_else(|| anyhow!("Payload not found"))?;
        payload.shares.insert(share_id, Share {
            kfrags,
            receiver_pk,
            status: ShareStatus::Active,
        });
        Ok(())
    }

    /// Fetch: re-encrypt capsule using stored kfrags → return cfrags to receiver.
    /// This is the core PRE operation — broker transforms the capsule without
    /// ever learning the plaintext or any secret key.
=======
        share_key: Vec<u8>,
    ) -> Result<()> {
        let payload = self.payloads.get_mut(payload_id)
            .ok_or_else(|| anyhow!("Payload not found"))?;
        payload.shares.insert(share_id, Share { share_key, status: ShareStatus::Active });
        Ok(())
    }

    /// Fetch ciphertext + share key for a receiver
    /// Returns error if share is revoked or not found
>>>>>>> origin/main
    pub fn fetch(
        &self,
        payload_id: &PayloadId,
        share_id: &ShareId,
<<<<<<< HEAD
    ) -> Result<FetchResult> {
=======
    ) -> Result<(&Vec<u8>, &[u8; 12], &Vec<u8>)> {
>>>>>>> origin/main
        let payload = self.payloads.get(payload_id)
            .ok_or_else(|| anyhow!("Payload not found"))?;
        let share = payload.shares.get(share_id)
            .ok_or_else(|| anyhow!("Share not found"))?;
<<<<<<< HEAD

        match share.status {
            ShareStatus::Revoked => Err(anyhow!("REVOKED")),
            ShareStatus::Active => {
                // Perform re-encryption: kfrags → cfrags
                let cfrags: Vec<VerifiedCapsuleFrag> = share.kfrags.iter()
                    .map(|kfrag| reencrypt(&payload.capsule, kfrag.clone()))
                    .collect();

                Ok(FetchResult {
                    ciphertext: payload.ciphertext.clone(),
                    capsule: payload.capsule.clone(),
                    cfrags,
                    delegating_pk: payload.delegating_pk,
                })
            }
        }
    }

    /// Revoke a share — destroys kfrags, generates destruction receipt.
    /// Without kfrags, the broker can never produce cfrags again.
=======
        match share.status {
            ShareStatus::Revoked => Err(anyhow!("REVOKED")),
            ShareStatus::Active => Ok((&payload.ciphertext, &payload.nonce, &share.share_key)),
        }
    }

    /// Revoke a share — destroys share key, generates destruction receipt
>>>>>>> origin/main
    pub fn revoke(
        &mut self,
        payload_id: &PayloadId,
        share_id: &ShareId,
    ) -> Result<DestructionReceipt> {
        let payload = self.payloads.get_mut(payload_id)
            .ok_or_else(|| anyhow!("Payload not found"))?;
        let share = payload.shares.get_mut(share_id)
            .ok_or_else(|| anyhow!("Share not found"))?;

        share.status = ShareStatus::Revoked;
        let data_hash = hash_ciphertext(&payload.ciphertext);
        let revoked_at = chrono::Utc::now().to_rfc3339();
        let destruction_proof = generate_destruction_proof(
            &self.secret,
            payload_id,
            &revoked_at,
        );

        let receipt = DestructionReceipt {
            payload_id: payload_id.to_string(),
            share_id: share_id.to_string(),
            data_hash,
            revoked_at,
            destruction_proof,
            status: "DESTROYED".to_string(),
        };

        self.receipts.push(receipt.clone());

<<<<<<< HEAD
        // Destroy kfrags — without these, re-encryption is permanently impossible
        share.kfrags.clear();
=======
        // Zero out the share key from memory
        share.share_key.iter_mut().for_each(|b| *b = 0);
        share.share_key.clear();
>>>>>>> origin/main

        Ok(receipt)
    }

    /// Get all destruction receipts for a payload
    pub fn get_receipts(&self, payload_id: &PayloadId) -> Vec<&DestructionReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.payload_id == payload_id.to_string())
            .collect()
    }
}
