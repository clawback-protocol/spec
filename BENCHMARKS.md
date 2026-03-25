# Clawback Protocol — Benchmark Results (Simulated PRE)
_Architecture: Simulated PRE (share_key = enc_key) | Rust implementation_

## Summary
Stress tests exercise the simulated PRE protocol: key generation, encryption/decryption,
broker operations, full lifecycle, revocation correctness, and edge cases.

> **Note**: These benchmarks reflect the **simulated PRE** model where the broker holds
> the actual decryption key. Performance characteristics will change when true Proxy
> Re-Encryption (Umbral) is implemented, as re-encryption adds per-fetch computation.

## Architecture

| Component | Current (Simulated PRE) | Planned (True Umbral PRE) |
|-----------|------------------------|--------------------------|
| Key model | Random master key + HKDF | Sender/receiver EC key pairs |
| Encryption | ChaCha20-Poly1305 direct | Umbral encrypt() (KEM + DEM) |
| Sharing | share_key == enc_key for all | Per-receiver kfrags via generate_kfrags() |
| Broker role | Key locker (holds share_key = enc_key) | PRE proxy (re-encrypts capsule → cfrags) |
| Receiver | Stateless (uses share_key) | Holds own key pair, decrypts with cfrags |
| Revocation | Delete share_key | Destroy kfrags (no more re-encryption) |
| Broker can decrypt? | **Yes** (holds enc_key) | **No** (holds only re-encryption keys) |
| Share key isolation? | **No** (all shares = same key) | **Yes** (cfrags are receiver-specific) |

## Stress Tests

| Test | Description |
|------|-------------|
| Key generation | MasterKey::generate() + HKDF derivation throughput |
| Encrypt/decrypt | ChaCha20-Poly1305 at 64B, 1KB, 64KB payload sizes |
| Blob roundtrip | Nonce+ciphertext serialization/deserialization |
| Destruction proofs | HMAC-SHA256 generation + SHA-256 hashing |
| Broker register + fetch | In-memory store and retrieval |
| Broker revoke + receipt | Key destruction + receipt generation |
| Multi-share (50x50) | 50 payloads x 50 shares, selective revocation |
| Full lifecycle (1K) | Encrypt → register → fetch → decrypt → revoke → denied |
| Receipt integrity | HMAC determinism + field correctness |
| Double revoke | Idempotent revocation behavior |
| Nonexistent lookups | Bogus payload/share rejection |
| Selective revocation | Revoke share A, verify share B unaffected |
| Wrong key rejection | Different sender's key cannot decrypt |

## Key Limitations to Note

- **Broker holds decryption key**: The simulated PRE model stores enc_key on the broker. Benchmark numbers for "broker fetch" do not include the re-encryption computation that true PRE would require.
- **No per-share key isolation**: All shares use identical key bytes. The "selective revocation" test verifies broker access-control isolation, not cryptographic key isolation.
- **Destruction receipts are broker assertions**: HMAC receipts prove the broker claims destruction, not that destruction independently occurred.

## Test Files
- `rust/tests/stress_test.rs` — stress and throughput tests
- `rust/tests/verify_test.rs` — destruction receipt verifier tests
