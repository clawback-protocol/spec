// Clawback Protocol — Receiver Module (Umbral PRE)
//
// The Receiver:
// - Has its own Umbral keypair (sk_receiver, pk_receiver)
// - Exposes its public key for sender to generate kfrags
// - Receives re-encrypted capsule fragments (cfrags) from broker
// - Uses Umbral to decrypt the data key from cfrags
// - Decrypts the payload with the recovered data key
// - Loses access instantly on revocation (broker deletes kfrags → no cfrags possible)

use anyhow::Result;
use umbral_pre::{Capsule, PublicKey, SecretKey, VerifiedCapsuleFrag};
use crate::crypto::{EncryptedPayload, decrypt_with_data_key, decrypt_reencrypted};

pub struct Receiver {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl Receiver {
    pub fn new() -> Self {
        let secret_key = SecretKey::random();
        let public_key = secret_key.public_key();
        Self { secret_key, public_key }
    }

    /// Decrypt a payload using Umbral PRE re-encrypted capsule fragments.
    pub fn decrypt_umbral(
        &self,
        sender_pk: &PublicKey,
        capsule: &Capsule,
        cfrags: impl IntoIterator<Item = VerifiedCapsuleFrag>,
        capsule_ciphertext: &[u8],
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>> {
        // Step 1: Recover data key via Umbral
        let data_key = decrypt_reencrypted(
            &self.secret_key,
            sender_pk,
            capsule,
            cfrags,
            capsule_ciphertext,
        )?;

        // Step 2: Decrypt payload with recovered data key
        decrypt_with_data_key(&data_key, payload)
    }
}
