// Clawback Protocol — Broker Module (Umbral PRE)
//
// The Broker is a zero-knowledge intermediary:
// - Stores encrypted payloads (never sees plaintext)
// - Holds kfrags (re-encryption key fragments) per share — NOT encryption keys
// - Re-encrypts capsule fragments for receivers without accessing plaintext
// - Enforces revocation by destroying kfrags — re-encryption impossible
// - Logs destruction receipts (append-only)

use std::collections::HashMap;
use anyhow::{Result, anyhow};
use crate::crypto::{PayloadId, ShareId, generate_destruction_proof, hash_ciphertext};
use umbral_pre::{VerifiedKeyFrag, PublicKey};

/// A stored share — kfrags + receiver public key
#[derive(Debug)]
pub struct Share {
    pub kfrags: Vec<VerifiedKeyFrag>,
    pub receiver_pk: PublicKey,
}

/// A stored payload — ciphertext + nonce + capsule data + shares
#[derive(Debug)]
pub struct StoredPayload {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub capsule_json: String,
    pub capsule_ciphertext_b64: String,
    pub delegating_pk_json: String,
    pub verifying_pk: PublicKey,
    pub shares: HashMap<ShareId, Share>,
}

/// Destruction receipt — tamper-evident proof of kfrag destruction
#[derive(Debug, Clone, serde::Serialize)]
pub struct DestructionReceipt {
    pub payload_id: String,
    pub share_id: String,
    pub data_hash: String,
    pub revoked_at: String,
    pub destruction_proof: String,
    pub status: String,
}

/// Result of fetching a payload for a receiver (after re-encryption)
#[derive(Debug)]
pub struct FetchResult {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub capsule: umbral_pre::Capsule,
    pub capsule_ciphertext: Vec<u8>,
    pub cfrags: Vec<umbral_pre::VerifiedCapsuleFrag>,
    pub delegating_pk: PublicKey,
}

/// Broker — in-memory store
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

    /// Register an encrypted payload with Umbral PRE kfrags
    pub fn register(
        &mut self,
        payload_id: PayloadId,
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        capsule_json: String,
        capsule_ciphertext_b64: String,
        delegating_pk_json: String,
        verifying_pk: PublicKey,
        share_id: ShareId,
        kfrags: Vec<VerifiedKeyFrag>,
        receiver_pk: PublicKey,
    ) {
        let mut shares = HashMap::new();
        shares.insert(share_id, Share { kfrags, receiver_pk });
        self.payloads.insert(payload_id, StoredPayload {
            ciphertext,
            nonce,
            capsule_json,
            capsule_ciphertext_b64,
            delegating_pk_json,
            verifying_pk,
            shares,
        });
    }

    /// Add a new share (kfrags) to an existing payload
    pub fn add_share(
        &mut self,
        payload_id: &PayloadId,
        share_id: ShareId,
        kfrags: Vec<VerifiedKeyFrag>,
        receiver_pk: PublicKey,
    ) -> Result<()> {
        let payload = self.payloads.get_mut(payload_id)
            .ok_or_else(|| anyhow!("Payload not found"))?;
        payload.shares.insert(share_id, Share { kfrags, receiver_pk });
        Ok(())
    }

    /// Fetch payload data and re-encrypt capsule for a receiver.
    /// Returns references to the stored payload data and the share's kfrags.
    pub fn get_payload(&self, payload_id: &PayloadId) -> Result<&StoredPayload> {
        self.payloads.get(payload_id)
            .ok_or_else(|| anyhow!("Payload not found"))
    }

    /// Get a specific share's kfrags (cloned for re-encryption)
    pub fn get_share_kfrags(
        &self,
        payload_id: &PayloadId,
        share_id: &ShareId,
    ) -> Result<Vec<VerifiedKeyFrag>> {
        let payload = self.payloads.get(payload_id)
            .ok_or_else(|| anyhow!("Payload not found"))?;
        let share = payload.shares.get(share_id)
            .ok_or_else(|| anyhow!("REVOKED"))?;
        Ok(share.kfrags.iter().cloned().collect())
    }

    /// Revoke a share — destroys kfrags, generates destruction receipt
    pub fn revoke(
        &mut self,
        payload_id: &PayloadId,
        share_id: &ShareId,
    ) -> Result<DestructionReceipt> {
        let payload = self.payloads.get_mut(payload_id)
            .ok_or_else(|| anyhow!("Payload not found"))?;

        if !payload.shares.contains_key(share_id) {
            return Err(anyhow!("Share not found or already revoked"));
        }

        let data_hash = hash_ciphertext(&payload.ciphertext);
        let revoked_at = chrono::Utc::now().to_rfc3339();
        let destruction_proof = generate_destruction_proof(
            &self.secret,
            payload_id,
            &revoked_at,
        );

        // DESTROY the kfrags — re-encryption is now mathematically impossible
        payload.shares.remove(share_id);

        let receipt = DestructionReceipt {
            payload_id: payload_id.to_string(),
            share_id: share_id.to_string(),
            data_hash,
            revoked_at,
            destruction_proof,
            status: "DESTROYED".to_string(),
        };

        self.receipts.push(receipt.clone());
        Ok(receipt)
    }

    /// Fetch and re-encrypt for a receiver. Returns all data needed for decryption.
    pub fn fetch_for_receiver(
        &self,
        payload_id: &PayloadId,
        share_id: &ShareId,
    ) -> Result<FetchResult> {
        let payload = self.payloads.get(payload_id)
            .ok_or_else(|| anyhow!("Payload not found"))?;
        let share = payload.shares.get(share_id)
            .ok_or_else(|| anyhow!("REVOKED"))?;

        let capsule: umbral_pre::Capsule = serde_json::from_str(&payload.capsule_json)
            .map_err(|e| anyhow!("capsule parse: {}", e))?;
        let delegating_pk: PublicKey = serde_json::from_str(&payload.delegating_pk_json)
            .map_err(|e| anyhow!("delegating_pk parse: {}", e))?;
        let capsule_ciphertext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &payload.capsule_ciphertext_b64,
        ).map_err(|e| anyhow!("capsule_ct decode: {}", e))?;

        let cfrags: Vec<umbral_pre::VerifiedCapsuleFrag> = share.kfrags.iter()
            .map(|kf| crate::reencrypt_for_receiver(&capsule, kf.clone()))
            .collect();

        Ok(FetchResult {
            ciphertext: payload.ciphertext.clone(),
            nonce: payload.nonce,
            capsule,
            capsule_ciphertext,
            cfrags,
            delegating_pk,
        })
    }

    /// Get all destruction receipts for a payload
    pub fn get_receipts(&self, payload_id: &PayloadId) -> Vec<&DestructionReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.payload_id == payload_id.to_string())
            .collect()
    }
}
