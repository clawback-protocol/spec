# Clawback Protocol — Proof of Concept

> **"You shared it. You can unshare it."**
>
> Cryptographic data revocation using Umbral Proxy Re-Encryption with provable destruction.

---

## What This Is

This PoC demonstrates the core cryptographic primitive behind the Clawback Protocol:
**data access can be revoked at any time, by design, not by policy.**

There's no "please delete this" request. No trust required. When you revoke, the broker's re-encryption key fragments (kfrags) are destroyed and the data becomes mathematically inaccessible — even to the broker itself.

---

## Architecture

```
 ┌────────────────────────────────────────────────────────────┐
 │                    Clawback Protocol (Umbral PRE)           │
 │                                                             │
 │   ┌─────────┐   (1) register blob + capsule + kfrags       │
 │   │  Sender │──────────────────────────────────►           │
 │   │ :8011   │   (6) revoke → destroy kfrags                │
 │   └─────────┘──────────────────────────────────►           │
 │        │                                ┌────────────┐      │
 │        │ (2) share_token                │   Broker   │      │
 │        ▼                                │   :8010    │      │
 │   ┌──────────┐  (4) fetch + re-encrypt  │ (ZK proxy) │      │
 │   │ Receiver │──── share_id ──────────►│            │      │
 │   │  :8012   │◄─── blob + cfrags ─────│            │      │
 │   │          │                          └────────────┘      │
 │   └──────────┘                               │              │
 │        │  (5) Umbral decrypt                 │ (7) receipt  │
 │        │      (receiver's own key)           │ + attestation│
 │        ▼                                     ▼              │
 │   plaintext                          receipts.jsonl         │
 └────────────────────────────────────────────────────────────┘
 (3) Receiver publishes public key via GET /public_key
```

### Three Services

| Service | Port | Role |
|---------|------|------|
| **Broker** | 8010 | Zero-knowledge proxy. Re-encrypts capsule fragments. Never holds encryption keys. |
| **Sender** | 8011 | Owns the data. Encrypts, generates kfrags per receiver, revokes. |
| **Receiver** | 8012 | Has own Umbral keypair. Decrypts via re-encrypted capsule fragments. |

---

## Crypto Stack

### Umbral Proxy Re-Encryption

The protocol uses [Umbral PRE](https://github.com/nucypher/rust-umbral) (arXiv:1707.06140) — a threshold proxy re-encryption scheme where the broker can transform ciphertext from sender to receiver **without ever being able to decrypt it**.

```
Sender:
  data_key    = random 32 bytes
  ciphertext  = ChaCha20-Poly1305(plaintext, data_key)
  capsule, ct = umbral.encrypt(sender_pk, data_key)
  kfrags      = generate_kfrags(sender_sk, receiver_pk, ...)

Broker (zero-knowledge):
  stores: ciphertext, capsule, kfrags
  on fetch: cfrag = reencrypt(capsule, kfrag)  ← cannot decrypt!
  returns: ciphertext, capsule, cfrags

Receiver:
  data_key  = decrypt_reencrypted(receiver_sk, sender_pk, capsule, cfrags, ct)
  plaintext = ChaCha20-Poly1305.decrypt(ciphertext, data_key)
```

### Why This Is Stronger Than Key Storage

| Property | Old (simulated) | Current (Umbral PRE) |
|----------|-----------------|---------------------|
| Broker holds encryption key? | Yes (share_key = enc_key) | **No** (holds kfrags only) |
| Compromised broker can decrypt? | Yes | **No** (mathematically impossible) |
| Wrong receiver can decrypt? | Yes (same key) | **No** (cfrags are receiver-specific) |
| Revocation mechanism | Delete key (policy-based) | Destroy kfrags (mathematical) |

### Cryptographic Attestation

Destruction receipts include signed attestation documents with a SHA-384 code hash (PCR0), compatible with AWS Nitro Enclave attestation format:

```json
{
  "payload_id": "uuid",
  "share_id": "uuid",
  "data_hash": "sha256(ciphertext)",
  "revoked_at": "2026-03-30T04:58:00+00:00",
  "destruction_proof": "HMAC(broker_secret, payload_id + revoked_at)",
  "attestation": {
    "provider": "simulated",
    "pcrs": { "pcr0": "sha384 of broker source" },
    "signature": "ed25519 signature",
    "timestamp": "ISO-8601",
    "module_id": "enclave-id"
  },
  "status": "DESTROYED"
}
```

Verify any receipt: `GET /broker/attestation` returns the current code hash. Compare `pcrs.pcr0` against the published release hash.

---

## Quick Start

### Prerequisites

```bash
pip install flask cryptography requests umbral cbor2
```

### Run the PII Revocation Demo

```bash
cd /path/to/clawback-poc
python3 demo_pii_signup.py
```

This runs 6 automated checks:
1. Encrypt PII payload (Umbral PRE)
2. Receiver decrypts via re-encrypted capsule fragments
3. User revokes — kfrags destroyed on broker
4. Re-access denied (HTTP 403)
5. Destruction receipt verified
6. Attestation document signature verified

### Run the Shell Demo

```bash
./run_demo.sh
```

### Run Services Individually

```bash
# Terminal 1
python3 broker/app.py

# Terminal 2
python3 sender/app.py

# Terminal 3
python3 receiver/app.py
```

---

## API Reference

### Broker (port 8010)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/health` | Health check |
| `GET`  | `/attestation` | Current attestation document (transparency log) |
| `POST` | `/register` | Register encrypted blob + capsule + kfrags |
| `POST` | `/add_share` | Add new kfrags for an existing payload |
| `GET`  | `/fetch/{payload_id}?share_id=X` | Re-encrypt capsule, return cfrags (403 if revoked) |
| `POST` | `/revoke/{payload_id}` | Destroy kfrags, log receipt with attestation |
| `GET`  | `/receipts/{payload_id}` | Get all destruction receipts |

### Sender (port 8011)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/encrypt` | Encrypt plaintext, generate kfrags, register with broker |
| `POST` | `/share/{payload_id}` | Issue a new share (new kfrags for new receiver) |
| `POST` | `/revoke/{payload_id}` | Revoke a share (destroys kfrags on broker) |

### Receiver (port 8012)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/public_key` | Receiver's Umbral public key (sender needs this for kfrags) |
| `POST` | `/receive` | Fetch re-encrypted cfrags + decrypt with own key |

---

## Rust Implementation

Production-quality Rust implementation in `rust/`:

```bash
cd rust
cargo build    # 5 binaries: broker, sender, receiver, clawback-verify, libclawback
cargo test     # 28 tests: 5 unit + 13 stress + 10 verify
```

Crates: `umbral-pre`, `chacha20poly1305`, `axum`, `tokio`, `serde`

---

## PCC Alignment

Clawback implements the same two core properties as Apple's Private Cloud Compute:

| Property | Apple PCC | Clawback |
|----------|-----------|----------|
| Zero-knowledge processing | Custom silicon + Secure Enclave | Umbral PRE (broker cannot decrypt) |
| Cryptographic attestation | Hardware-signed PCR measurements | Ed25519-signed attestation (Nitro-ready) |
| Transparency log | Published software images | `GET /attestation` + published PCR0 |
| Verifiable by third parties | Certificate chain to Apple root CA | Certificate chain to AWS Nitro root CA (Phase 2b) |

See `docs/PCC-INTEGRATION.md` for full analysis.

---

## Project

**Clawback Protocol** — Open source privacy-preserving data revocation
Owner: Secundus Nulli LLC / Eternal Light Trust
USPTO: Serial No. 99657348
License: AGPLv3
Domains: clawbackprotocol.org / clawbackprotocol.com
GitHub: github.com/clawback-protocol

> *The internet was built to never forget. Clawback makes forgetting a first-class operation.*
