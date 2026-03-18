// Clawback Protocol — Crypto Module
//
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
use sha2::Sha256;

// ── Type aliases ──────────────────────────────────────────────────────────────

pub type PayloadId = uuid::Uuid;
pub type ShareId = uuid::Uuid;

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
    }

    #[test]
    fn test_destruction_proof() {
        let proof = generate_destruction_proof(
            b"broker-secret",
            &PayloadId::new_v4(),
            "2026-03-06T17:30:00Z",
        );
        assert_eq!(proof.len(), 64);
    }
}
