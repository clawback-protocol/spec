// Clawback Protocol — Rust Core Library
//
// True Proxy Re-Encryption via Umbral (arXiv:1707.06140).
//
// Module structure:
//   crypto/   — Umbral PRE types, destruction receipts, ciphertext hashing
//   broker/   — PRE proxy: stores kfrags, re-encrypts on fetch, revokes
//   sender/   — encrypts to own key, generates kfrags per receiver
//   receiver/ — holds key pair, decrypts with cfrags from broker

pub mod crypto;
pub mod broker;
pub mod sender;
pub mod receiver;

// Re-export core types
pub use crypto::{
    SecretKey, PublicKey, Signer,
    Capsule, VerifiedKeyFrag, VerifiedCapsuleFrag,
    PayloadId, ShareId,
};
