// Clawback Protocol — Crypto Module
//
<<<<<<< HEAD
// True Proxy Re-Encryption via Umbral (arXiv:1707.06140).
//
// Key hierarchy:
//   Sender key pair (SecretKey, PublicKey) — sender owns, never shared
//   Receiver key pair (SecretKey, PublicKey) — receiver owns
//   KeyFrags — re-encryption key fragments, held by broker
//   Capsule — encapsulated symmetric key, stored alongside ciphertext
//
// Flow:
//   1. Sender encrypts to own PublicKey → (Capsule, ciphertext)
//   2. Sender generates kfrags delegating decryption to receiver's PublicKey
//   3. Broker stores kfrags, performs re-encryption on fetch → cfrags
//   4. Receiver decrypts with own SecretKey + cfrags
//   5. Revocation = broker destroys kfrags → re-encryption impossible

// Re-export Umbral PRE types used across the protocol
pub use umbral_pre::{
    encrypt, decrypt_original, decrypt_reencrypted,
    generate_kfrags, reencrypt,
    Capsule, CapsuleFrag, KeyFrag, VerifiedCapsuleFrag, VerifiedKeyFrag,
    PublicKey, SecretKey, Signer,
};

use hmac::{Hmac, Mac};
=======
// Implements all cryptographic primitives:
// - X25519 key generation (master key)
// - HKDF-SHA256 key derivation (enc_key)
// - ChaCha20-Poly1305 AEAD encryption/decryption
// - HMAC-SHA256 destruction receipts
// - SHA-256 payload hashing
//
// Simulated PRE model: share_key = enc_key for all recipients.
// In production PRE (Umbral), each share would get a re-encryption key instead.

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
>>>>>>> origin/main
use sha2::Sha256;

// ── Type aliases ──────────────────────────────────────────────────────────────

pub type PayloadId = uuid::Uuid;
pub type ShareId = uuid::Uuid;

<<<<<<< HEAD
=======
/// Master key — 32 bytes, Sender ONLY, never transmitted
#[derive(Clone, zeroize::Zeroize)]
pub struct MasterKey([u8; 32]);

/// Encryption key — derived from master key for payload encryption.
/// In the simulated PRE model, this is also the share key given to each recipient.
pub struct EncKey([u8; 32]);

/// Share key — used by receiver to decrypt. In simulated PRE, bytes == enc_key.
pub struct ShareKey([u8; 32]);

// ── Key generation ────────────────────────────────────────────────────────────

impl MasterKey {
    /// Generate a new random master key
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Derive the encryption key for payload encryption
    /// enc_key = HKDF(master_key, salt=[], info="payload-encryption")
    pub fn derive_enc_key(&self) -> EncKey {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; 32];
        hk.expand(b"payload-encryption", &mut okm)
            .expect("HKDF expand failed");
        EncKey(okm)
    }
}

// ── Encryption ────────────────────────────────────────────────────────────────

/// Encrypted payload — ciphertext + nonce
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

impl EncKey {
    /// Encrypt plaintext using ChaCha20-Poly1305
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

    /// Return raw bytes (for broker registration as share_key in simulated PRE)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ShareKey {
    /// Construct from raw bytes (received from broker)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!("share key must be 32 bytes, got {}", bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Decrypt ciphertext using ChaCha20-Poly1305
    pub fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.0)?;
        let nonce = Nonce::from_slice(&payload.nonce);
        let plaintext = cipher
            .decrypt(nonce, payload.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        Ok(plaintext)
    }

    /// Return raw bytes for broker storage
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

>>>>>>> origin/main
// ── Destruction receipts ──────────────────────────────────────────────────────

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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
<<<<<<< HEAD
    fn test_pre_encrypt_decrypt_original() {
        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();

        let plaintext = b"This is sensitive data - Reese";
        let (capsule, ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();

        let decrypted = decrypt_original(&delegating_sk, &capsule, &ciphertext).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_pre_full_roundtrip() {
        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();
        let signer = Signer::new(SecretKey::random());

        let receiving_sk = SecretKey::random();
        let receiving_pk = receiving_sk.public_key();

        let plaintext = b"Shared with recipient via PRE";
        let (capsule, ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();

        let verified_kfrags = generate_kfrags(
            &delegating_sk, &receiving_pk, &signer,
            1, 1, true, true,
        );

        let cfrags: Vec<VerifiedCapsuleFrag> = verified_kfrags.iter()
            .map(|vkf| reencrypt(&capsule, vkf.clone()))
            .collect();

        let decrypted = decrypt_reencrypted(
            &receiving_sk, &delegating_pk, &capsule, cfrags, &ciphertext,
        ).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_pre_multiple_receivers() {
        let delegating_sk = SecretKey::random();
        let delegating_pk = delegating_sk.public_key();
        let signer = Signer::new(SecretKey::random());

        let plaintext = b"Shared with multiple recipients";
        let (capsule, ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();

        for _ in 0..2 {
            let receiving_sk = SecretKey::random();
            let receiving_pk = receiving_sk.public_key();

            let verified_kfrags = generate_kfrags(
                &delegating_sk, &receiving_pk, &signer,
                1, 1, true, true,
            );
            let cfrags: Vec<VerifiedCapsuleFrag> = verified_kfrags.iter()
                .map(|vkf| reencrypt(&capsule, vkf.clone()))
                .collect();

            let decrypted = decrypt_reencrypted(
                &receiving_sk, &delegating_pk, &capsule, cfrags, &ciphertext,
            ).unwrap();
            assert_eq!(&*decrypted, plaintext);
        }
=======
    fn test_encrypt_decrypt_roundtrip() {
        let master = MasterKey::generate();
        let enc_key = master.derive_enc_key();

        let plaintext = b"This is sensitive data - Reese";
        let encrypted = enc_key.encrypt(plaintext).unwrap();

        // In simulated PRE, share_key == enc_key
        let share_key = ShareKey::from_bytes(enc_key.as_bytes()).unwrap();
        let decrypted = share_key.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_multiple_shares_decrypt_same_ciphertext() {
        let master = MasterKey::generate();
        let enc_key = master.derive_enc_key();

        let plaintext = b"Shared with multiple recipients";
        let encrypted = enc_key.encrypt(plaintext).unwrap();

        // Both shares get the same enc_key bytes (simulated PRE)
        let share_1 = ShareKey::from_bytes(enc_key.as_bytes()).unwrap();
        let share_2 = ShareKey::from_bytes(enc_key.as_bytes()).unwrap();

        assert_eq!(share_1.decrypt(&encrypted).unwrap(), plaintext);
        assert_eq!(share_2.decrypt(&encrypted).unwrap(), plaintext);
    }

    #[test]
    fn test_blob_roundtrip() {
        let master = MasterKey::generate();
        let enc_key = master.derive_enc_key();
        let encrypted = enc_key.encrypt(b"test payload").unwrap();

        let blob = encrypted.to_blob();
        let restored = EncryptedPayload::from_blob(&blob).unwrap();

        let share_key = ShareKey::from_bytes(enc_key.as_bytes()).unwrap();
        assert_eq!(share_key.decrypt(&restored).unwrap(), b"test payload");
>>>>>>> origin/main
    }

    #[test]
    fn test_destruction_proof() {
        let proof = generate_destruction_proof(
            b"broker-secret",
            &PayloadId::new_v4(),
            "2026-03-06T17:30:00Z",
        );
<<<<<<< HEAD
        assert_eq!(proof.len(), 64);
=======
        assert_eq!(proof.len(), 64); // 32 bytes hex-encoded
>>>>>>> origin/main
    }
}
