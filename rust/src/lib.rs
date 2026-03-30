// Clawback Protocol — Rust Core Library
//
// This library implements the cryptographic primitives and protocol logic
// for the Clawback Protocol using Umbral Proxy Re-Encryption.
//
// Module structure:
//   crypto/   — Umbral PRE, ChaCha20-Poly1305, HMAC destruction receipts
//   broker/   — kfrag storage, re-encryption, revocation, receipt logging
//   sender/   — encrypt, kfrag generation, register
//   receiver/ — Umbral decryption, data key recovery

pub mod crypto;
pub mod broker;
pub mod sender;
pub mod receiver;

// Re-export core types
pub use crypto::{
    SenderKeys, EncryptedPayload, PayloadId, ShareId,
    encrypt_with_data_key, umbral_encrypt_data_key, generate_share_kfrags,
    reencrypt_for_receiver, decrypt_reencrypted, decrypt_with_data_key,
    hash_binary_sha384,
    // Legacy types (backward compat)
    MasterKey, ShareKey, EncKey,
};
