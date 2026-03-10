// Clawback Protocol — Rust Core Library
//
// This library implements the cryptographic primitives and protocol logic
// for the Clawback Protocol.
//
// Module structure:
//   crypto/   — key generation, encryption, HKDF derivation, HMAC receipts
//   broker/   — storage, share key management, revocation, receipt logging
//   sender/   — encrypt, register, share, revoke
//   receiver/ — fetch, decrypt

pub mod crypto;
pub mod broker;
pub mod sender;
pub mod receiver;

// Re-export core types
pub use crypto::{MasterKey, ShareKey, EncKey, EncryptedPayload, PayloadId, ShareId};
