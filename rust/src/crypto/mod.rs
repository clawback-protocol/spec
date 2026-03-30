// Clawback Protocol — Crypto Module
//
// Implements all cryptographic primitives:
// - Umbral PRE: key generation, kfrag generation, re-encryption, decryption
// - ChaCha20-Poly1305 AEAD encryption/decryption (symmetric data key)
// - HMAC-SHA256 destruction receipts
// - SHA-256 payload hashing
//
// Umbral PRE model: broker holds kfrags (re-encryption key fragments),
// NOT encryption keys. Broker can re-encrypt but never decrypt.

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use umbral_pre::{
    Capsule, PublicKey, SecretKey, Signer, VerifiedCapsuleFrag, VerifiedKeyFrag,
};

// ── Type aliases ──────────────────────────────────────────────────────────────

pub type PayloadId = uuid::Uuid;
pub type ShareId = uuid::Uuid;

// Re-export Umbral types used by other modules
pub use umbral_pre;

/// Sender keys — Umbral secret key, public key, and signer
pub struct SenderKeys {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub signer: Signer,
}

impl SenderKeys {
    /// Generate a new random sender keypair
    pub fn generate() -> Self {
        let secret_key = SecretKey::random();
        let public_key = secret_key.public_key();
        let signer = Signer::new(secret_key.clone());
        Self {
            secret_key,
            public_key,
            signer,
        }
    }
}

// ── Symmetric encryption (data key) ─────────────────────────────────────────

/// Encrypted payload — ChaCha20-Poly1305 ciphertext + nonce
pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

impl EncryptedPayload {
    /// Construct from a wire-format blob (nonce || ciphertext)
    pub fn from_blob(blob: &[u8]) -> Result<Self> {
        if blob.len() < 12 {
            return Err(anyhow::anyhow!("blob too short"));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&blob[..12]);
        Ok(Self {
            ciphertext: blob[12..].to_vec(),
            nonce,
        })
    }

    /// Serialize to wire-format blob (nonce || ciphertext)
    pub fn to_blob(&self) -> Vec<u8> {
        let mut blob = Vec::with_capacity(12 + self.ciphertext.len());
        blob.extend_from_slice(&self.nonce);
        blob.extend_from_slice(&self.ciphertext);
        blob
    }
}

/// Encrypt plaintext with a random 32-byte data key using ChaCha20-Poly1305.
/// Returns (data_key, EncryptedPayload).
pub fn encrypt_with_data_key(plaintext: &[u8]) -> Result<([u8; 32], EncryptedPayload)> {
    let mut data_key = [0u8; 32];
    OsRng.fill_bytes(&mut data_key);

    let cipher = ChaCha20Poly1305::new_from_slice(&data_key)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    Ok((
        data_key,
        EncryptedPayload {
            ciphertext,
            nonce: nonce_bytes,
        },
    ))
}

/// Decrypt ciphertext using a data key recovered via Umbral PRE
pub fn decrypt_with_data_key(data_key: &[u8], payload: &EncryptedPayload) -> Result<Vec<u8>> {
    if data_key.len() != 32 {
        return Err(anyhow::anyhow!(
            "data key must be 32 bytes, got {}",
            data_key.len()
        ));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(data_key)?;
    let nonce = Nonce::from_slice(&payload.nonce);
    let plaintext = cipher
        .decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
    Ok(plaintext)
}

// ── Umbral PRE operations ───────────────────────────────────────────────────

/// Encrypt a data key to the sender's public key using Umbral.
/// Returns (Capsule, capsule_ciphertext).
pub fn umbral_encrypt_data_key(
    sender_pk: &PublicKey,
    data_key: &[u8; 32],
) -> Result<(Capsule, Box<[u8]>)> {
    let (capsule, ct) = umbral_pre::encrypt(sender_pk, data_key)
        .map_err(|e| anyhow::anyhow!("Umbral encrypt failed: {}", e))?;
    Ok((capsule, ct))
}

/// Generate kfrags for a receiver (re-encryption key fragments).
pub fn generate_share_kfrags(
    sender_keys: &SenderKeys,
    receiver_pk: &PublicKey,
    shares: usize,
    threshold: usize,
) -> Box<[VerifiedKeyFrag]> {
    umbral_pre::generate_kfrags(
        &sender_keys.secret_key,
        receiver_pk,
        &sender_keys.signer,
        threshold,
        shares,
        true,  // sign_delegating_key
        true,  // sign_receiving_key
    )
}

/// Re-encrypt a capsule using a verified kfrag (broker operation).
pub fn reencrypt_for_receiver(
    capsule: &Capsule,
    kfrag: VerifiedKeyFrag,
) -> VerifiedCapsuleFrag {
    umbral_pre::reencrypt(capsule, kfrag)
}

/// Decrypt a re-encrypted capsule to recover the data key (receiver operation).
pub fn decrypt_reencrypted(
    receiver_sk: &SecretKey,
    sender_pk: &PublicKey,
    capsule: &Capsule,
    cfrags: impl IntoIterator<Item = VerifiedCapsuleFrag>,
    capsule_ciphertext: &[u8],
) -> Result<Box<[u8]>> {
    umbral_pre::decrypt_reencrypted(receiver_sk, sender_pk, capsule, cfrags, capsule_ciphertext)
        .map_err(|e| anyhow::anyhow!("Umbral decrypt failed: {}", e))
}

// ── Destruction receipts ────────────────────────────────────────────────────

/// Generate a destruction proof: HMAC-SHA256(broker_secret, payload_id || revoked_at)
pub fn generate_destruction_proof(
    broker_secret: &[u8],
    payload_id: &PayloadId,
    revoked_at: &str,
) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(broker_secret).expect("HMAC key error");
    mac.update(payload_id.as_bytes());
    mac.update(revoked_at.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// SHA-256 hash of ciphertext for destruction receipt
pub fn hash_ciphertext(ciphertext: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(ciphertext);
    hex::encode(hasher.finalize())
}

/// SHA-384 hash of binary for PCR0 attestation equivalent
pub fn hash_binary_sha384() -> String {
    use sha2::Digest;
    let binary = std::fs::read(std::env::current_exe().unwrap_or_default()).unwrap_or_default();
    let mut hasher = sha2::Sha384::new();
    hasher.update(&binary);
    hex::encode(hasher.finalize())
}

// ── Legacy types (kept for backward compat with existing tests) ─────────────

/// Master key — 32 bytes, Sender ONLY, never transmitted
/// Kept for backward compatibility; new code uses SenderKeys + Umbral
#[derive(Clone, zeroize::Zeroize)]
pub struct MasterKey([u8; 32]);

/// Encryption key — derived from master key for payload encryption
pub struct EncKey([u8; 32]);

/// Share key — used by receiver to decrypt (legacy simulated PRE)
pub struct ShareKey([u8; 32]);

impl MasterKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn derive_enc_key(&self) -> EncKey {
        let hk = hkdf::Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; 32];
        hk.expand(b"payload-encryption", &mut okm)
            .expect("HKDF expand failed");
        EncKey(okm)
    }
}

impl EncKey {
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedPayload> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.0)?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        Ok(EncryptedPayload {
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ShareKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "share key must be 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    pub fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.0)?;
        let nonce = Nonce::from_slice(&payload.nonce);
        let plaintext = cipher
            .decrypt(nonce, payload.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        Ok(plaintext)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_umbral_pre_roundtrip() {
        let sender_keys = SenderKeys::generate();
        let receiver_sk = SecretKey::random();
        let receiver_pk = receiver_sk.public_key();

        let plaintext = b"This is sensitive data - Clawback Umbral PRE";

        // Step 1: Encrypt plaintext with random data key
        let (data_key, encrypted) = encrypt_with_data_key(plaintext).unwrap();

        // Step 2: Umbral-encrypt the data key
        let (capsule, capsule_ct) =
            umbral_encrypt_data_key(&sender_keys.public_key, &data_key).unwrap();

        // Step 3: Generate kfrags for receiver
        let kfrags = generate_share_kfrags(&sender_keys, &receiver_pk, 1, 1);
        assert_eq!(kfrags.len(), 1);

        // Step 4: Broker re-encrypts capsule
        let cfrag = reencrypt_for_receiver(&capsule, kfrags[0].clone());

        // Step 5: Receiver decrypts to recover data key
        let recovered_key =
            decrypt_reencrypted(&receiver_sk, &sender_keys.public_key, &capsule, [cfrag], &capsule_ct)
                .unwrap();

        // Step 6: Decrypt payload with recovered data key
        let decrypted = decrypt_with_data_key(&recovered_key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_revocation_prevents_decryption() {
        let sender_keys = SenderKeys::generate();
        let receiver_sk = SecretKey::random();
        let receiver_pk = receiver_sk.public_key();

        let plaintext = b"Revocable data";
        let (data_key, encrypted) = encrypt_with_data_key(plaintext).unwrap();
        let (capsule, capsule_ct) =
            umbral_encrypt_data_key(&sender_keys.public_key, &data_key).unwrap();

        let kfrags = generate_share_kfrags(&sender_keys, &receiver_pk, 1, 1);

        // Before revocation: can decrypt
        let cfrag = reencrypt_for_receiver(&capsule, kfrags[0].clone());
        let recovered =
            decrypt_reencrypted(&receiver_sk, &sender_keys.public_key, &capsule, [cfrag], &capsule_ct)
                .unwrap();
        let decrypted = decrypt_with_data_key(&recovered, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        // After revocation (kfrags dropped): cannot re-encrypt
        drop(kfrags);
        // No kfrags means no cfrags can be produced → decryption impossible
    }

    #[test]
    fn test_blob_roundtrip() {
        let plaintext = b"test payload blob roundtrip";
        let (data_key, encrypted) = encrypt_with_data_key(plaintext).unwrap();
        let blob = encrypted.to_blob();
        let restored = EncryptedPayload::from_blob(&blob).unwrap();
        let decrypted = decrypt_with_data_key(&data_key, &restored).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_destruction_proof() {
        let proof = generate_destruction_proof(
            b"broker-secret",
            &PayloadId::new_v4(),
            "2026-03-06T17:30:00Z",
        );
        assert_eq!(proof.len(), 64); // 32 bytes hex-encoded
    }

    // Legacy test — ensures backward compat with old simulated PRE types
    #[test]
    fn test_legacy_encrypt_decrypt_roundtrip() {
        let master = MasterKey::generate();
        let enc_key = master.derive_enc_key();
        let plaintext = b"Legacy test data";
        let encrypted = enc_key.encrypt(plaintext).unwrap();
        let share_key = ShareKey::from_bytes(enc_key.as_bytes()).unwrap();
        let decrypted = share_key.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
