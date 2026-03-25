# Clawback Protocol — Proof of Concept

> **"You shared it. You can unshare it."**
> 
> A working demonstration of cryptographic data revocation using Proxy Re-Encryption (PRE) principles.

---

## What This Is

This PoC demonstrates the core cryptographic primitive behind the Clawback Protocol:  
**data access can be revoked at any time, by design, not by policy.**

There's no "please delete this" request. No trust required. When you revoke, the key is destroyed on the broker and the data becomes mathematically inaccessible.

---

## Architecture

```
 ┌──────────────────────────────────────────────────────┐
 │                  Clawback Protocol                    │
 │                                                       │
 │   ┌─────────┐   (1) register blob+share_key          │
 │   │  Sender │──────────────────────────────►         │
 │   │ :8001   │   (5) revoke → destroy share_key       │
 │   └─────────┘──────────────────────────────►         │
 │        │                              ┌────────────┐  │
 │        │ (2) share_token              │   Broker   │  │
 │        ▼                              │   :8000    │  │
 │   ┌──────────┐  (3) fetch blob +      │            │  │
 │   │ Receiver │──── share_key ────────►│            │  │
 │   │  :8002   │◄─── encrypted blob ───│            │  │
 │   │          │     + share_key        └────────────┘  │
 │   └──────────┘                             │           │
 │        │  (4) decrypt locally              │ (6) log   │
 │        ▼                                   ▼           │
 │   plaintext                        receipts.jsonl      │
 └──────────────────────────────────────────────────────┘
```

### Three Services

| Service | Port | Role |
|---------|------|------|
| **Broker** | 8000 | Semi-trusted intermediary. Stores encrypted blobs + share keys. Never sees plaintext, but holds decryption keys in this PoC (see [Limitations](#limitations)). |
| **Sender** | 8001 | Owns the data. Encrypts, shares, revokes. Master key never leaves. |
| **Receiver** | 8002 | Fetches blob + share key from broker. Decrypts locally. |

---

## Crypto Stack

All crypto via the `cryptography` Python library.

### Simulated PRE Flow

True Proxy Re-Encryption (like Umbral/NuCypher) re-encrypts ciphertext on the broker so the receiver can decrypt with their own key. We simulate the key concept cleanly:

```
master_key = random 32 bytes              (Sender only, never shared)
enc_key    = HKDF(master_key, info="payload-encryption")
ciphertext = ChaCha20Poly1305.encrypt(plaintext, enc_key)

share_key  = enc_key                             ← same key per share (simulated PRE)
```

The broker stores `(ciphertext, share_key)`. The receiver gets both and decrypts.  
The sender revokes by telling the broker to delete `share_key`.  
Without the key, decryption is impossible. The master key never left the sender.

### Why This Works

- **Master key isolation**: Sender's master key is never transmitted anywhere
- **Instant revocation**: Broker deletes the share key → access gone immediately
- **No plaintext on broker**: Broker stores only ciphertext — never sees raw data

### Limitations (PoC)

> **Important**: In this PoC, the broker holds the actual decryption key (`share_key == enc_key`). A compromised broker could decrypt any payload it stores. True Proxy Re-Encryption (Umbral) — where the broker holds only re-encryption keys and *cannot* decrypt — is on the [roadmap](#whats-next).

- **Broker holds decryption-equivalent key**: The share key stored on the broker is the encryption key itself. This is the simulated PRE tradeoff — revocation works, but broker blindness requires true PRE.
- **All shares use the same key**: Share isolation is enforced by the broker (access control), not by cryptographic key separation. Revoking share A doesn't change the key for share B — they are the same bytes.
- **Cached keys survive revocation**: If a receiver copies the share key before revocation, they retain the ability to decrypt. Revocation only prevents future broker-mediated access.
- **Destruction receipts are broker assertions**: The HMAC receipt proves the broker *claims* it destroyed the key. It does not independently prove destruction occurred. Production would anchor receipts to an external append-only ledger.

### Destruction Receipts

When a share is revoked, the broker generates a cryptographic receipt (HMAC-signed, not a ZK proof):

```json
{
  "payload_id": "uuid",
  "share_id": "uuid",
  "data_hash": "sha256 of encrypted blob",
  "revoked_at": "2026-03-05T17:30:00+00:00",
  "destruction_proof": "HMAC(broker_secret, payload_id + revoked_at)",
  "status": "DESTROYED"
}
```

This provides a tamper-evident audit trail proving the key was destroyed at a specific time.

---

## Quick Start

### Prerequisites

```bash
pip install flask cryptography requests
```

### Run the Full Demo

```bash
cd /Users/macminski/clawback-poc
./run_demo.sh
```

This will:
1. Start all three services
2. Encrypt "This is sensitive data - Reese"
3. Share with receiver → decrypt successfully
4. Revoke the share
5. Receiver tries again → REVOKED
6. Print the destruction receipt
7. Shut everything down

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

### Broker (port 8000)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/register` | Register encrypted blob + first share key |
| `POST` | `/add_share` | Add a new share key for an existing payload |
| `GET`  | `/fetch/{payload_id}?share_id=X` | Fetch blob + share key (403 if revoked) |
| `POST` | `/revoke/{payload_id}` | Destroy a share key, log receipt |
| `GET`  | `/receipts/{payload_id}` | Get all destruction receipts |

### Sender (port 8001)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/encrypt` | Encrypt plaintext, register with broker |
| `POST` | `/share/{payload_id}` | Issue a new share token |
| `POST` | `/revoke/{payload_id}` | Revoke a share (destroys key on broker) |

### Receiver (port 8002)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/receive` | Fetch + decrypt with share token |

---

## Example: Manual cURL Flow

```bash
# 1. Encrypt
curl -X POST http://localhost:8001/encrypt \
  -H 'Content-Type: application/json' \
  -d '{"plaintext": "hello clawback"}'

# 2. Receive (use payload_id and share_token from above)
curl -X POST http://localhost:8002/receive \
  -H 'Content-Type: application/json' \
  -d '{"payload_id": "...", "share_token": "..."}'

# 3. Revoke
curl -X POST http://localhost:8001/revoke/{payload_id} \
  -H 'Content-Type: application/json' \
  -d '{"share_id": "..."}'

# 4. Try to receive again (expect 403)
curl -X POST http://localhost:8002/receive \
  -H 'Content-Type: application/json' \
  -d '{"payload_id": "...", "share_token": "..."}'

# 5. Get destruction receipt
curl http://localhost:8000/receipts/{payload_id}
```

---

## What's Next

This PoC proves the concept. The roadmap:

- **True PRE**: Replace HKDF simulation with Umbral PRE (NuCypher) for real proxy re-encryption where the broker never holds a plaintext-equivalent key
- **Signed share tokens**: Replace bare UUIDs with signed JWTs (ECDSA) so share tokens are unforgeable
- **Time-limited shares**: Embed expiry in share tokens — auto-revoke after N hours
- **Threshold access**: M-of-N broker nodes must cooperate to serve a key
- **On-chain receipts**: Log destruction proofs to a blockchain for public auditability
- **SDK**: Python/JS client library wrapping the full flow

---

## Project

**Clawback Protocol** — Open source privacy-preserving data revocation  
Domains: clawbackprotocol.org / clawbackprotocol.com  
GitHub: github.com/clawback-protocol

> *The internet was built to never forget. Clawback makes forgetting a first-class operation.*
