// Clawback Protocol — Sender Module (Umbral PRE)
//
// The Sender owns the data:
// - Has an Umbral keypair (secret key never transmitted)
// - Encrypts plaintext with a random data key (ChaCha20-Poly1305)
// - Uses Umbral to encrypt the data key to sender's public key
// - Generates kfrags for each receiver
// - Registers encrypted blob + kfrags with broker

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use umbral_pre::{Capsule, PublicKey};
use crate::crypto::{
    PayloadId, ShareId, SenderKeys, EncryptedPayload,
    encrypt_with_data_key, umbral_encrypt_data_key, generate_share_kfrags,
};

struct PayloadEntry {
    capsule: Capsule,
    capsule_ciphertext: Box<[u8]>,
}

pub struct Sender {
    pub keys: SenderKeys,
    payloads: HashMap<PayloadId, PayloadEntry>,
}

impl Sender {
    pub fn new() -> Self {
        Self {
            keys: SenderKeys::generate(),
            payloads: HashMap::new(),
        }
    }

    /// Encrypt plaintext and prepare for broker registration with Umbral PRE.
    /// Returns (payload_id, share_id, encrypted_payload, capsule, capsule_ciphertext, kfrags_json).
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        receiver_pk: &PublicKey,
    ) -> Result<SenderEncryptResult> {
        let payload_id = PayloadId::new_v4();
        let share_id = ShareId::new_v4();

        // Step 1: Encrypt plaintext with random data key
        let (data_key, encrypted) = encrypt_with_data_key(plaintext)?;

        // Step 2: Umbral-encrypt data key to sender's public key
        let (capsule, capsule_ct) = umbral_encrypt_data_key(&self.keys.public_key, &data_key)?;

        // Step 3: Generate kfrags for the receiver
        let kfrags = generate_share_kfrags(&self.keys, receiver_pk, 1, 1);

        self.payloads.insert(payload_id, PayloadEntry {
            capsule: capsule.clone(),
            capsule_ciphertext: capsule_ct.clone(),
        });

        Ok(SenderEncryptResult {
            payload_id,
            share_id,
            encrypted,
            capsule,
            capsule_ciphertext: capsule_ct,
            kfrags: kfrags.to_vec(),
        })
    }

    /// Issue a new share for an existing payload.
    pub fn issue_share(
        &self,
        payload_id: &PayloadId,
        receiver_pk: &PublicKey,
    ) -> Result<SenderShareResult> {
        if !self.payloads.contains_key(payload_id) {
            return Err(anyhow!("unknown payload"));
        }
        let share_id = ShareId::new_v4();
        let kfrags = generate_share_kfrags(&self.keys, receiver_pk, 1, 1);
        Ok(SenderShareResult {
            share_id,
            kfrags: kfrags.to_vec(),
        })
    }
}

pub struct SenderEncryptResult {
    pub payload_id: PayloadId,
    pub share_id: ShareId,
    pub encrypted: EncryptedPayload,
    pub capsule: Capsule,
    pub capsule_ciphertext: Box<[u8]>,
    pub kfrags: Vec<umbral_pre::VerifiedKeyFrag>,
}

pub struct SenderShareResult {
    pub share_id: ShareId,
    pub kfrags: Vec<umbral_pre::VerifiedKeyFrag>,
}
