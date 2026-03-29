# CLAUDE.md — Clawback Protocol

This file gives Claude Code the context needed to contribute effectively.

---

## What This Is

**Clawback Protocol** is an open protocol for cryptographically enforced, revocable, time-limited data sharing with provable destruction.

> "You shared it. You can unshare it."

Core properties:
- Sender encrypts locally — broker never sees plaintext
- Each recipient gets a unique per-share derived key (never the master key)
- Revocation is instant — broker destroys the share key
- Destruction is provable — HMAC receipt logged append-only
- Zero trust required from receiver

Trademark: USPTO Serial No. 99657348 (filed 2026-03-06)
Owner: Secundus Nulli LLC / Eternal Light Trust
License: AGPLv3

---

## Repo Structure

```
clawback-protocol/spec/
├── CLAUDE.md              ← you are here
├── README.md              ← public-facing overview
├── ROADMAP.md             ← what's next
├── CONTRIBUTING.md        ← how to contribute
│
├── spec/                  ← protocol specification (authoritative)
│   ├── SPEC-v0.1.md      ← formal protocol spec
│   └── whitepaper/
│       └── whitepaper-v0.1.md
│
├── poc/                   ← Python proof-of-concept (WORKING, do not break)
│   ├── broker/app.py     ← Broker service (port 8010)
│   ├── sender/app.py     ← Sender service (port 8011)
│   ├── receiver/app.py   ← Receiver service (port 8012)
│   ├── run_demo.sh       ← Full lifecycle demo script
│   └── requirements.txt
│
├── rust/                  ← Production Rust implementation (IN PROGRESS)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── crypto/       ← X25519, ChaCha20-Poly1305, HKDF primitives
│       ├── broker/       ← Broker logic
│       ├── sender/       ← Sender logic
│       └── receiver/     ← Receiver logic
│
├── sdk/                   ← Client libraries (PLANNED)
│   ├── python/           ← Python SDK
│   └── javascript/       ← JS/WASM SDK
│
└── docs/
    └── ARCHITECTURE.md   ← Technical architecture
```

---

## Cryptographic Design

### Key Hierarchy
```
master_key  (32 bytes, Sender ONLY, never transmitted)
     │
     ├── enc_key  = HKDF(master_key, salt, info="payload-encryption")
     │   └── Encrypts payload with ChaCha20-Poly1305
     │
     └── share_key_N = HKDF(master_key, salt, info=share_id_N)
         └── Unique per recipient — stored on Broker
         └── Receiver decrypts using this key
```

### Protocol Flow
1. Sender generates master_key (X25519)
2. Sender encrypts plaintext → ciphertext (ChaCha20-Poly1305 + enc_key)
3. Sender derives share_key for recipient (HKDF)
4. Sender registers (payload_id, ciphertext, share_key) with Broker
5. Sender issues share_token (share_id UUID) to Receiver
6. Receiver presents share_token → Broker returns (ciphertext, share_key)
7. Receiver decrypts locally
8. Sender revokes → Broker deletes share_key → generates destruction receipt
9. Receiver's next request → HTTP 403 REVOKED

### Destruction Receipt Schema
```json
{
  "payload_id": "uuid",
  "share_id": "uuid",
  "data_hash": "sha256(ciphertext)",
  "revoked_at": "ISO-8601 timestamp",
  "destruction_proof": "HMAC-SHA256(broker_secret, payload_id + revoked_at)",
  "status": "DESTROYED"
}
```

---

## Current State

### ✅ Working (poc/ branch)
- Full Python/Flask PoC — broker, sender, receiver
- Complete lifecycle demo: encrypt → share → receive → revoke → 403 → receipt
- Run with: `bash poc/run_demo.sh`
- Crypto: `cryptography` Python library (X25519, ChaCha20-Poly1305, HKDF, HMAC)

### 🔨 In Progress
- Rust core implementation (rust/ directory)
- Whitepaper draft (spec/whitepaper/)

### 📋 Planned
- True Proxy Re-Encryption via Umbral (NuCypher)
- ZK destruction proofs (snarkjs/circom)
- TTL auto-expiry on share tokens
- Multi-recipient selective revocation
- Python SDK, JavaScript/WASM SDK

---

## Rust Implementation Guide

The Rust implementation should use these crates:
- `x25519-dalek` — X25519 key exchange
- `chacha20poly1305` — AEAD encryption
- `hkdf` + `sha2` — Key derivation
- `hmac` + `sha2` — Destruction receipts
- `uuid` — Share/payload IDs
- `axum` or `actix-web` — HTTP services
- `serde` + `serde_json` — Serialization
- `tokio` — Async runtime

**Priority order for Rust implementation:**
1. `crypto/` module — key generation, encryption, HKDF derivation, HMAC receipts
2. `broker/` module — storage, share key management, revocation, receipt logging
3. `sender/` module — encrypt, register, share, revoke
4. `receiver/` module — fetch, decrypt

**Key constraint:** Master key must NEVER be transmitted or logged. Zero plaintext on broker.

---

## Security Properties to Preserve

1. **Confidentiality** — Broker holds only ciphertext, never plaintext or enc_key
2. **Revocation soundness** — Post-revocation access must return 403
3. **Share isolation** — Revoking share N does not affect share M
4. **Destruction verifiability** — Receipt must be tamper-evident and append-only

---

## What NOT to Do

- Do NOT store master_key anywhere outside the Sender
- Do NOT log plaintext at any service
- Do NOT use ECB mode or MD5/SHA1 for anything
- Do NOT skip AEAD authentication (use ChaCha20-Poly1305, not raw ChaCha20)
- Do NOT break the existing Python PoC — it is the reference implementation

---

## Running the PoC

```bash
pip install flask cryptography requests
bash poc/run_demo.sh
```

---

## Contact / Ownership

Founder: Maurice Ferdinand
Entity: Secundus Nulli LLC d/b/a Clawback Protocol
Email: hello@clawbackprotocol.org
GitHub: github.com/clawback-protocol
