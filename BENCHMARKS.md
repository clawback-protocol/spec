# Clawback Protocol — Benchmark Results
_Generated: 2026-03-17 | Rust release build | Desktop: Ryzen 5800X + RTX 3080_

## Summary
All 20 tests pass (4 unit + 16 stress) in **3.85 seconds** (release mode).
True Umbral PRE implemented. Zero share leaks. All correctness invariants confirmed.

## Architecture: Before vs After

| Component | Before (Simulated PRE) | After (True Umbral PRE) |
|-----------|----------------------|------------------------|
| Key model | Random master key + HKDF | Sender/receiver EC key pairs (secp256k1) |
| Encryption | ChaCha20-Poly1305 direct | Umbral encrypt() (KEM + DEM) |
| Sharing | share_key == enc_key for all | Per-receiver kfrags via generate_kfrags() |
| Broker role | Key locker (holds share_key) | PRE proxy (re-encrypts capsule → cfrags) |
| Receiver | Stateless (uses share_key) | Holds own key pair, decrypts with cfrags |
| Revocation | Delete share_key | Destroy kfrags (no more re-encryption) |
| Broker sees plaintext? | No (but held decryption key) | **No, and cannot (zero-knowledge proxy)** |
| Wrong receiver? | Could decrypt (same key) | **Cannot decrypt (cfrags are receiver-specific)** |

## Unit Tests (4/4)
- ✅ test_pre_encrypt_decrypt_original — sender decrypts own data
- ✅ test_pre_full_roundtrip — full PRE: encrypt → kfrags → reencrypt → decrypt
- ✅ test_pre_multiple_receivers — same ciphertext, different receivers
- ✅ test_destruction_proof — HMAC-SHA256 receipt integrity

## Stress Tests (16/16)

| Test | Result |
|------|--------|
| Crypto key generation | 5K keys, 13K PublicKey/s |
| Encrypt/decrypt throughput | 64B→64KB, 1.4K–5K ops/s |
| KFrag generation (1-of-1) | 1K ops, 1,355 ops/s |
| KFrag generation (3-of-5) | 1K ops, 675 ops/s |
| Re-encryption throughput | 2K ops, 2,392 ops/s |
| Broker register (PRE) | 2K ops, 921 ops/s |
| Broker fetch (re-encryption) | 2K ops, 4,064 ops/s |
| Broker revoke + receipt | 2K ops, **722K ops/s** |
| Multi-share (50×50) | 2,500 shares, isolation verified |
| Full lifecycle (1K payloads) | All phases passed |
| Receipt integrity | 1K receipts, determinism verified |
| Double revoke | Idempotent, all REVOKED |
| Nonexistent lookups | 10K rejected, 3.9M ops/s |
| PRE: delegate → reencrypt → revoke → lockout | 500 cycles passed |
| PRE: wrong receiver cannot decrypt | 200 attempts correctly rejected |
| PRE: selective revocation | 200 tests: A revoked, B unaffected |
| PRE: threshold (3-of-5) | 200 tests: any 3-of-5 kfrags suffice |

## Key Numbers for Grant/Partner Presentations
- **722,000 revocations/second** — instant, cryptographic, at scale
- **Zero broker plaintext access** — true zero-knowledge proxy
- **Wrong receiver correctly rejected** — cfrags are receiver-specific
- **Threshold sharing (3-of-5)** — enterprise-grade key management
- **500 full delegate→revoke→lockout cycles** — protocol integrity verified
- **10K bogus lookups rejected at 3.9M ops/s**

## Cryptographic Foundation
- Umbral PRE (arXiv:1707.06140) — Nucypher/Threshold Network
- secp256k1 elliptic curve key pairs
- KEM + DEM hybrid encryption
- HMAC-SHA256 destruction receipts
- Threshold kfrag splitting (m-of-n)

## Test Files
- `rust/tests/stress_test.rs`
- `rust/src/pre.rs` (Umbral PRE implementation)
