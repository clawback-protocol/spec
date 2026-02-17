# Clawback Protocol — Specification v0.1 (DRAFT)

**Status:** Draft — Not for public distribution
**Version:** 0.1.0
**Author:** Reese
**Date:** 2026-02-17
**License:** TBD (AGPLv3 intended)

---

## Abstract

The Clawback Protocol is an open standard for **revocable, time-limited, and verifiable data sharing** between users and services. It enables individuals to share personal data with cryptographically enforced constraints — including scope limitations, automatic expiration, and provable destruction — without relying on trust or terms of service compliance.

The protocol is designed as an infrastructure layer that existing applications integrate, not a standalone consumer product.

---

## 1. Introduction

### 1.1 Problem Statement

Current data-sharing models operate on a **transfer-of-custody** paradigm: when a user provides personal data to a service, the service gains unrestricted custody of that data. Restrictions are governed solely by legal agreements (terms of service, privacy policies) which are:

- Unilaterally authored by the data recipient
- Rarely read or understood by the data subject
- Difficult and expensive to enforce
- Routinely violated without consequence

The result is a systemic imbalance where data subjects have no practical control over their personal information once shared.

### 1.2 Proposed Solution

The Clawback Protocol replaces transfer-of-custody with a **scoped-access** model. Data is never transferred — instead, the recipient receives a **time-limited, scope-restricted access credential** that is cryptographically enforced. When the access window closes, the recipient can no longer access the data, and destruction is provable.

### 1.3 Design Goals

1. **User sovereignty** — The data subject retains control at all times
2. **Minimal disclosure** — Share only what is necessary, nothing more
3. **Enforced expiration** — Access revocation is cryptographic, not policy-based
4. **Provable destruction** — Verifiable proof that access has been terminated
5. **Interoperability** — Any application can integrate via standard SDKs
6. **Simplicity** — Developers can implement basic flows in hours, not weeks
7. **Offline-capable** — Core vault functionality requires no internet connection

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Data Subject** | The individual who owns the personal data |
| **Data Requester** | The service or entity requesting access to personal data |
| **Clawback Credential** | A cryptographic token granting scoped, time-limited access to specific data |
| **Vault** | The data subject's local, encrypted storage for personal data |
| **Access Window** | The defined time period during which a credential is valid |
| **Scope** | The specific data fields a credential grants access to |
| **Revocation Proof** | Cryptographic evidence that a credential has been invalidated and data access terminated |
| **Disclosure Proof** | A zero-knowledge proof that verifies a claim without revealing underlying data |

---

## 3. Architecture Overview

```
┌──────────────┐                          ┌──────────────────┐
│              │   1. Request Access       │                  │
│    Data      │◄─────────────────────────│   Data           │
│    Subject   │                          │   Requester      │
│              │   2. Issue Credential     │                  │
│   ┌──────┐  │─────────────────────────►│   ┌───────────┐  │
│   │Vault │  │                          │   │Integration│  │
│   └──────┘  │   3. Access Data          │   │   (SDK)   │  │
│              │◄─────────────────────────│   └───────────┘  │
│              │                          │                  │
│              │   4. Window Expires       │                  │
│              │   ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ►│                  │
│              │                          │                  │
│              │   5. Revocation Proof     │                  │
│              │◄─────────────────────────│                  │
└──────────────┘                          └──────────────────┘
```

### 3.1 Components

**Client-Side (Data Subject)**
- **Vault**: Encrypted local storage (AES-256-GCM, Argon2 key derivation)
- **Credential Engine**: Issues, manages, and revokes Clawback Credentials
- **Proof Generator**: Creates zero-knowledge disclosure proofs

**Server-Side (Data Requester)**
- **SDK Integration**: Library that handles credential acceptance, data access, and revocation
- **Compliance Layer**: Enforces access window constraints and generates revocation proofs

**Shared Infrastructure**
- **Revocation Registry**: Decentralized ledger or bulletin board for publishing revocation proofs (public verifiability)

---

## 4. Core Flows

### 4.1 Scoped Data Sharing (Full Disclosure)

For cases where the requester needs to see actual data (e.g., shipping address for delivery).

```
1. Requester → Subject:  ACCESS_REQUEST {
                           requester_id,
                           scope: ["shipping_address"],
                           purpose: "order_fulfillment",
                           requested_window: 72h
                         }

2. Subject reviews request in Vault UI
   Subject approves with modifications (e.g., reduces window to 24h)

3. Subject → Requester:  CLAWBACK_CREDENTIAL {
                           credential_id,
                           encrypted_payload,     // the actual data
                           decryption_key,         // time-locked or revocable
                           scope: ["shipping_address"],
                           window_start: <timestamp>,
                           window_end: <timestamp + 24h>,
                           revocation_endpoint
                         }

4. Requester decrypts and uses data within window

5. Window expires OR Subject manually revokes:
   - Decryption key becomes invalid
   - Requester's SDK auto-deletes cached plaintext
   - Requester generates REVOCATION_PROOF

6. Requester → Subject:  REVOCATION_PROOF {
                           credential_id,
                           destruction_timestamp,
                           proof_hash,
                           method: "cryptographic_expiry"
                         }

7. Proof optionally published to Revocation Registry
```

### 4.2 Zero-Knowledge Verification (No Disclosure)

For cases where the requester only needs to verify a fact (e.g., age verification).

```
1. Requester → Subject:  VERIFY_REQUEST {
                           requester_id,
                           claim: "age >= 18",
                           purpose: "age_gate"
                         }

2. Subject's Vault generates ZK proof from stored DOB

3. Subject → Requester:  DISCLOSURE_PROOF {
                           claim: "age >= 18",
                           proof: <zero_knowledge_proof>,
                           valid_at: <timestamp>
                         }

4. Requester verifies proof cryptographically
   Result: TRUE/FALSE — never sees actual DOB
```

### 4.3 Credential Revocation (Early Termination)

The data subject can revoke access at any time before the window expires.

```
1. Subject → Requester:  REVOKE {
                           credential_id,
                           reason: "user_initiated"
                         }

2. Requester SDK:
   - Invalidates decryption key
   - Deletes cached plaintext
   - Generates revocation proof

3. Requester → Subject:  REVOCATION_PROOF { ... }
```

---

## 5. Credential Structure

### 5.1 Clawback Credential Schema

```json
{
  "version": "clawback/1.0",
  "credential_id": "uuid-v4",
  "issued_at": "ISO-8601 timestamp",
  "issuer": {
    "id": "data subject public key or DID",
    "vault_version": "string"
  },
  "recipient": {
    "id": "data requester public key or DID",
    "name": "human-readable service name"
  },
  "scope": {
    "fields": ["field_name_1", "field_name_2"],
    "purpose": "stated purpose string",
    "purpose_code": "enumerated purpose category"
  },
  "access_window": {
    "start": "ISO-8601 timestamp",
    "end": "ISO-8601 timestamp",
    "renewable": false,
    "max_accesses": null
  },
  "payload": {
    "encryption": "AES-256-GCM",
    "encrypted_data": "base64-encoded ciphertext",
    "key_delivery": "time-lock | revocable | hybrid"
  },
  "revocation": {
    "endpoint": "URL or DID endpoint",
    "method": "cryptographic_expiry | active_revocation | hybrid",
    "registry": "optional revocation registry URI"
  },
  "signature": "issuer signature over credential"
}
```

### 5.2 Supported Scope Fields (Standard Set)

```
identity.full_name
identity.date_of_birth
identity.nationality
identity.government_id
identity.photo

contact.email
contact.phone
contact.address

financial.payment_card
financial.bank_account
financial.billing_address

verification.age_over_18
verification.age_over_21
verification.is_resident_of
verification.is_human
```

Applications may define custom scope fields prefixed with their namespace:
`app.servicename.custom_field`

---

## 6. Cryptographic Mechanisms

### 6.1 Encryption
- **Vault encryption**: AES-256-GCM with Argon2id key derivation from master password
- **Credential payload**: AES-256-GCM with per-credential ephemeral key
- **Key exchange**: X25519 Diffie-Hellman for establishing shared secrets

### 6.2 Time-Lock Mechanism
For enforcing access windows without requiring active revocation:
- **Timed-release cryptography**: Decryption key is derived such that it becomes computationally infeasible to use after the window expires
- **Approach**: Witness encryption or verifiable delay functions (VDFs)
- *Note: Exact mechanism TBD in v0.2 — active area of research*

### 6.3 Zero-Knowledge Proofs
For disclosure proofs (verification without revealing data):
- **Bulletproofs** for range proofs (e.g., age >= 18)
- **zk-SNARKs** for more complex assertions
- **Framework**: Circom + SnarkJS (JS), Bellman (Rust)

### 6.4 Revocation Proofs
- Hash-based commitment: Requester commits to data hash at receipt, publishes deletion commitment with same hash
- Merkle proof of non-inclusion in active credential set
- Optional smart contract verification on public chain

---

## 7. SDK Interface (Reference)

### 7.1 Data Subject (Client SDK)

```
clawback.vault.create(master_password) → Vault
clawback.vault.unlock(master_password) → Session
clawback.vault.store(field, value) → void
clawback.vault.get(field) → value

clawback.credential.issue({
  recipient,
  scope,
  window,
  purpose
}) → ClawbackCredential

clawback.credential.revoke(credential_id) → RevocationProof
clawback.credential.list() → [Credential]
clawback.credential.status(credential_id) → Status

clawback.proof.disclose({
  claim,
  from_field
}) → DisclosureProof
```

### 7.2 Data Requester (Server SDK)

```
clawback.request.create({
  scope,
  purpose,
  window
}) → AccessRequest

clawback.credential.accept(credential) → void
clawback.credential.access(credential_id) → DecryptedData | null
clawback.credential.destroy(credential_id) → RevocationProof

clawback.proof.verify(disclosure_proof) → boolean
```

---

## 8. Trust Model

### 8.1 What We Trust
- The cryptographic primitives (AES-256, X25519, Argon2, Bulletproofs)
- The data subject's device (vault integrity)
- The protocol implementation (open source, auditable)

### 8.2 What We Do NOT Trust
- The data requester's willingness to delete data voluntarily
- Terms of service or privacy policies
- Any centralized server or cloud provider
- The network (all transmissions encrypted end-to-end)

### 8.3 Known Limitations (V1)
- **Screenshot/screen capture**: If data is displayed to a human operator, they can photograph it. The protocol limits digital persistence, not visual observation.
- **Compromised requester SDK**: A malicious requester could modify their SDK to cache data. Mitigation: attestation and audit mechanisms (V2+).
- **Key management**: If the data subject loses their master password, data is unrecoverable. This is a feature, not a bug.

---

## 9. Compliance Mapping

The Clawback Protocol is designed to exceed requirements of:

| Regulation | Relevant Right | How Clawback Addresses It |
|-----------|---------------|--------------------------|
| GDPR (EU) | Right to erasure (Art. 17) | Provable destruction via revocation proofs |
| GDPR | Data minimization (Art. 5) | Scoped credentials limit disclosure |
| GDPR | Purpose limitation (Art. 5) | Purpose declared and locked in credential |
| CCPA (CA) | Right to delete | Automated via access window expiry |
| CCPA | Right to know | Credential audit trail shows all sharing |
| CCPA | Right to opt-out of sale | Data never transferred — nothing to sell |

---

## 10. Roadmap

### v0.1 (Current)
- Protocol specification draft
- Core flow definitions
- Credential schema

### v0.2
- Finalize cryptographic mechanism selection
- Reference SDK (Rust + TypeScript)
- Test vectors and interoperability tests

### v0.3
- Demo application (proof of concept)
- Security audit (community review)
- Developer documentation

### v1.0
- Stable specification
- Production-ready SDKs (Rust, TypeScript, Python)
- Integration guides for common platforms
- Formal security audit

---

## Appendix A: Comparison with Existing Standards

| Standard | Focus | Clawback Difference |
|----------|-------|-------------------|
| W3C Verifiable Credentials | Credential issuance & verification | Adds enforced expiration + provable destruction |
| DIDComm | Secure messaging between DIDs | Clawback builds on top — uses DIDComm as transport |
| OAuth 2.0 | Authorization delegation | OAuth grants access; Clawback enforces revocation |
| OIDC | Identity verification | OIDC reveals claims; Clawback can prove without revealing |

---

## Appendix B: Glossary

- **DID**: Decentralized Identifier (W3C standard)
- **VDF**: Verifiable Delay Function
- **ZKP**: Zero-Knowledge Proof
- **zk-SNARK**: Zero-Knowledge Succinct Non-Interactive Argument of Knowledge
- **GCM**: Galois/Counter Mode (authenticated encryption)
- **Argon2id**: Memory-hard key derivation function

---

*This specification is a working draft. All mechanisms are subject to revision based on security analysis and community feedback.*

*© 2026 Clawback Protocol Contributors. All rights reserved until public release under chosen license.*
