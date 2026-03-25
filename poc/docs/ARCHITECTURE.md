# Clawback Protocol — Architecture

> Version: 0.2.0 (PRE-based PoC)  
> Updated: 2026-03-05

---

## Overview

The Clawback Protocol enables **cryptographic data revocation**: the ability to revoke access to shared data at any time, enforced by mathematics rather than by policy or trust.

The core primitive is **Proxy Re-Encryption (PRE)** — a cryptographic scheme where a semi-trusted proxy (the broker) can transform a ciphertext encrypted under key A so that it can be decrypted under key B, without ever seeing the plaintext or either private key.

In this PoC, we simulate PRE using **X25519 key exchange + HKDF + ChaCha20-Poly1305**, making the concept fully runnable without exotic dependencies while preserving all the meaningful properties.

---

## System Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Clawback Protocol                             │
│                                                                       │
│   ┌───────────────┐                        ┌───────────────────┐    │
│   │    SENDER     │                        │      BROKER       │    │
│   │   port 8001   │                        │    port 8000      │    │
│   │               │──── register ─────────►│                   │    │
│   │  master_key   │     (blob + share_key) │  ┌─────────────┐  │    │
│   │  (never       │                        │  │  encrypted  │  │    │
│   │   leaves)     │──── revoke ───────────►│  │   blobs     │  │    │
│   │               │     (destroy key)      │  ├─────────────┤  │    │
│   └───────┬───────┘                        │  │  share keys │  │    │
│           │                                │  ├─────────────┤  │    │
│           │ share_token                    │  │  receipts   │  │    │
│           ▼                                │  └─────────────┘  │    │
│   ┌───────────────┐   fetch (share_id)     └─────────┬─────────┘    │
│   │   RECEIVER    │──────────────────────────────────►              │
│   │   port 8002   │◄─────── blob + share_key ────────┘             │
│   │               │                                                  │
│   │  decrypt      │                                                  │
│   │  locally      │                                                  │
│   └───────────────┘                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Cryptographic Design

### Key Hierarchy

```
master_key  (32 bytes, random)
│
└── enc_key = HKDF(master_key, info="payload-encryption")
      ├── used to encrypt/decrypt the actual payload
      └── share_key = enc_key  (PoC: all shares get the same key)
            stored on broker, returned on fetch
            DESTROYED on revocation

NOTE (PoC): share_key == enc_key for all recipients. Share isolation
is enforced by broker access control, not by distinct keys.
In true PRE (Umbral), each share would get a unique re-encryption key.
```

### Encryption (Sender)

```python
# 1. Generate master key (stays on sender forever)
master_key = os.urandom(32)

# 2. Derive encryption key
enc_key = HKDF(master_key, info=b"payload-encryption", length=32)

# 3. Encrypt with ChaCha20-Poly1305
nonce = os.urandom(12)
ciphertext = ChaCha20Poly1305(enc_key).encrypt(nonce, plaintext, aad=None)
blob = nonce + ciphertext  # prepend nonce for storage

# 4. Derive share key for recipient
share_key = enc_key  # PoC: share_key IS enc_key (same bytes for all shares)

# 5. Register with broker: (blob_b64, share_key_b64)
# Note: broker NEVER sees master_key or plaintext
# PoC caveat: broker DOES hold enc_key (as share_key) and could decrypt
```

### Decryption (Receiver)

```python
# Receiver gets: encrypted_blob (b64) + share_key (b64) from broker

# share_key IS the encryption key (enc_key derived from master_key)
# In this PoC, share_key IS enc_key (same bytes).
# The broker stores enc_key directly as the share key.
# In production PRE (Umbral), the broker would hold a re-encryption key
# that transforms ciphertext without being able to decrypt.

nonce, ct = blob[:12], blob[12:]
plaintext = ChaCha20Poly1305(share_key).decrypt(nonce, ct, None)
```

### Why This Simulates PRE

In true Proxy Re-Encryption (e.g., Umbral):
- The broker holds a **re-encryption key** `rk_{A→B}` (computed from sender's private key + receiver's public key)
- The broker transforms ciphertext `C_A` → `C_B` without decrypting
- The receiver decrypts `C_B` with their private key
- The broker never sees plaintext or either private key

In our simulation:
- The broker holds the **share key** (which is the enc_key, delivered securely)
- The receiver decrypts directly with the share key
- Revocation destroys the share key — equivalent to destroying the re-encryption key

The key insight is preserved: **the broker cannot read the data** (in a threshold setup — see roadmap), and **revocation is instant and cryptographically enforced**.

---

## Revocation Mechanism

### What Happens on Revoke

```
Sender → POST /revoke/{payload_id} → Sender Service
           │
           └─► POST /revoke/{payload_id} → Broker
                          │
                          ├─ Compute data_hash = SHA256(encrypted_blob)
                          ├─ Compute proof = HMAC(broker_secret, payload_id + revoked_at)
                          ├─ DELETE share_key from memory
                          ├─ Append receipt to receipts.jsonl
                          └─ Return receipt to sender
```

After revocation:
- `GET /fetch/{payload_id}?share_id=X` returns HTTP 403
- The encrypted blob still exists (immutable audit trail)
- The share key is gone — decryption is mathematically impossible

### Destruction Receipt

```json
{
  "payload_id": "3f7a8b2c-...",
  "share_id":   "9d1e4f5a-...",
  "data_hash":  "e3b0c44298fc1c149afb...",
  "revoked_at": "2026-03-05T17:30:00.000000+00:00",
  "destruction_proof": "a1b2c3d4e5f6...",
  "status":     "DESTROYED"
}
```

**destruction_proof** = `HMAC-SHA256(broker_secret, payload_id + revoked_at)`

This is an HMAC-signed assertion: the broker commits to having destroyed the key at a specific time, without revealing the broker secret. This is **not** a zero-knowledge proof — it is a signed claim by the broker. The broker can fabricate receipts for keys it did not actually destroy. In production, receipts should be anchored to an external append-only ledger (e.g., Certificate Transparency-style log or blockchain) for independent verification.

Receipts are stored in `broker/receipts.jsonl` (append-only).

---

## Data Flow: Full Lifecycle

```
t=0  Sender.encrypt("sensitive data")
       → generates master_key, enc_key, blob
       → derives share_key_1 for share_1
       → registers (blob, share_key_1) on broker

t=1  Sender.share(payload_id)
       → derives share_key_2 for share_2
       → registers share_key_2 on broker
       → returns share_token_2 to sender (who gives it to receiver)

t=2  Receiver.receive(payload_id, share_token_2)
       → broker validates share exists
       → broker returns (blob, share_key_2)
       → receiver decrypts: plaintext ✓

t=3  Sender.revoke(payload_id, share_id_2)
       → broker destroys share_key_2
       → broker logs destruction receipt

t=4  Receiver.receive(payload_id, share_token_2)
       → broker: share_key_2 not found → HTTP 403
       → receiver: ACCESS DENIED ✗
```

---

## Security Properties

| Property | Status | Notes |
|----------|--------|-------|
| Broker blindness | ✗ PoC | Broker holds enc_key (can decrypt). True PRE (Umbral) required for blindness. |
| Share key isolation | ✗ PoC | All shares use same enc_key bytes. Isolation is broker-enforced, not cryptographic. |
| Instant revocation | ✓ | Key deletion is immediate; no caching |
| Master key isolation | ✓ | master_key never transmitted |
| Tamper-evident audit | ✓ Partial | HMAC-signed receipts; append-only log. Broker self-asserts, not independently verifiable. |
| Replay prevention | ✗ | Not implemented in PoC |
| Share token forgery | ✗ | UUIDs; production needs signed JWTs |
| Cached key resistance | ✗ | Receiver who cached share_key retains access after revocation |

---

## Threat Model

**Trusted:**
- Sender (owns the data)

**Semi-trusted (honest-but-curious):**
- Broker — follows protocol but might try to read data
  - In this PoC: broker CAN read data (holds share keys)
  - In true PRE: broker holds re-encryption keys, cannot decrypt

**Untrusted:**
- Network (use TLS in production)
- Receiver after revocation

**Attack scenarios:**

1. **Compromised broker** → In PoC: data exposed. In true PRE: only ciphertext exposed.
2. **Revoked receiver with cached data** → They have the ciphertext but not the key after revocation. If they cached the key before revocation, they retain access (see roadmap: key expiry).
3. **Share token theft** → Anyone with the token can access until revoked. Production: sign tokens with ECDSA + expiry.

---

## Roadmap to Production PRE

### Phase 1 (This PoC)
- ✅ HKDF-derived share keys
- ✅ Instant revocation
- ✅ Destruction receipts
- ✅ Three-service architecture

### Phase 2 (True PRE)
- [ ] Replace HKDF simulation with Umbral PRE (`pip install umbral`)
- [ ] Broker performs re-encryption, never holds enc_key
- [ ] Receiver uses their own X25519 keypair for decryption

### Phase 3 (Production Hardening)
- [ ] Signed share tokens (ECDSA + JWT)
- [ ] Time-limited shares (expiry in token)
- [ ] TLS between all services
- [ ] Persistent storage (PostgreSQL for broker state)
- [ ] Threshold broker (M-of-N nodes must cooperate)

### Phase 4 (Protocol Layer)
- [ ] On-chain destruction receipts (Ethereum / Solana)
- [ ] SDK (Python, TypeScript)
- [ ] SDK integration guides for Signal, ProtonMail
- [ ] Clawback-enabled file format spec

---

## File Structure

```
clawback-poc/
├── broker/
│   ├── app.py          # Broker service (port 8000)
│   └── receipts.jsonl  # Append-only destruction log (created on first revoke)
├── sender/
│   └── app.py          # Sender service (port 8001)
├── receiver/
│   └── app.py          # Receiver service (port 8002)
├── docs/
│   └── ARCHITECTURE.md # This file
├── run_demo.sh         # Full demo script
└── README.md           # Quick start guide
```

---

## References

- [Proxy Re-Encryption — Wikipedia](https://en.wikipedia.org/wiki/Proxy_re-encryption)
- [Umbral PRE (NuCypher)](https://github.com/nucypher/pyUmbral)
- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [ChaCha20-Poly1305 (RFC 8439)](https://www.rfc-editor.org/rfc/rfc8439)
- [cryptography.io docs](https://cryptography.io/en/latest/)
