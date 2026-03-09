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
use uuid::Uuid;
use crate::crypto::{PayloadId, ShareId, generate_destruction_proof, hash_ciphertext};

/// Status of a share
#[derive(Debug, Clone, PartialEq)]
pub enum ShareStatus {
    Active,
    Revoked,
}

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
#[derive(Debug, Clone, serde::Serialize)]
pub struct DestructionReceipt {
    pub payload_id: String,
    pub share_id: String,
    pub data_hash: String,
    pub revoked_at: String,
    pub destruction_proof: String,
    pub status: String,
}

/// Broker — in-memory store (replace with persistent storage for production)
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

    /// Register an encrypted payload with an initial share key
    pub fn register(
        &mut self,
        payload_id: PayloadId,
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        share_id: ShareId,
        share_key: Vec<u8>,
    ) {
        let mut shares = HashMap::new();
        shares.insert(share_id, Share { share_key, status: ShareStatus::Active });
        self.payloads.insert(payload_id, StoredPayload { ciphertext, nonce, shares });
    }

    /// Add a new share to an existing payload
    pub fn add_share(
        &mut self,
        payload_id: &PayloadId,
        share_id: ShareId,
        share_key: Vec<u8>,
    ) -> Result<()> {
        let payload = self.payloads.get_mut(payload_id)
            .ok_or_else(|| anyhow!("Payload not found"))?;
        payload.shares.insert(share_id, Share { share_key, status: ShareStatus::Active });
        Ok(())
    }

    /// Fetch ciphertext + share key for a receiver
    /// Returns error if share is revoked or not found
    pub fn fetch(
        &self,
        payload_id: &PayloadId,
        share_id: &ShareId,
    ) -> Result<(&Vec<u8>, &[u8; 12], &Vec<u8>)> {
        let payload = self.payloads.get(payload_id)
            .ok_or_else(|| anyhow!("Payload not found"))?;
        let share = payload.shares.get(share_id)
            .ok_or_else(|| anyhow!("Share not found"))?;
        match share.status {
            ShareStatus::Revoked => Err(anyhow!("REVOKED")),
            ShareStatus::Active => Ok((&payload.ciphertext, &payload.nonce, &share.share_key)),
        }
    }

    /// Revoke a share — destroys share key, generates destruction receipt
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

        // Zero out the share key from memory
        share.share_key.iter_mut().for_each(|b| *b = 0);
        share.share_key.clear();

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
