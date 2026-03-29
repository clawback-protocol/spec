# Clawback Verified Execution — PCC Architecture Alignment

> How Apple's Private Cloud Compute model validates Clawback's approach to provable data destruction.

---

## Overview

Apple's Private Cloud Compute (PCC) solves a fundamental trust problem: how do you prove to a user that a cloud server is running exactly the code it claims, with zero ability for even the operator to access user data?

PCC achieves this through five guarantees:
1. **Stateless computation** — no user data persists after the request completes
2. **Enforceable guarantees** — privacy is technically enforced, not policy-based
3. **No privileged runtime access** — even Apple engineers cannot inspect data during processing
4. **Non-targetability** — impossible to direct attacks at specific users
5. **Verifiable transparency** — published software images, transparency log, third-party auditable

The Clawback Protocol implements the same architectural principles for a different domain: **provable data destruction** rather than AI inference. The broker is Clawback's equivalent of PCC's processing node — a component that must prove it handled data correctly without requiring trust.

---

## Current State vs. PCC

| PCC Property | Clawback Status | Notes |
|---|---|---|
| Stateless computation | IMPLEMENTED | Broker never persists plaintext; only stores ciphertext + share keys |
| Enforceable guarantees | POLICY-BASED | Share key deletion is enforced by broker code, but a compromised broker could retain keys. Requires TEE for cryptographic enforcement |
| No privileged access | SIMULATED | Broker operator could theoretically access memory-resident share keys. TEE would make this impossible |
| Verifiable transparency | PARTIAL | Destruction receipts with HMAC proofs are logged and verifiable. Missing: TEE-signed attestation proving the exact code that produced the receipt |
| Non-targetability | NOT YET | No anonymization layer. Broker knows which payload_id maps to which share. Network-level targeting possible |

---

## The Trust Gap

Today, Clawback's security model requires trusting that the broker:
- Actually deletes share keys on revocation (not just returning 403 while retaining them)
- Doesn't log plaintext-equivalent keys during normal operation
- Doesn't serve false destruction receipts
- Runs the published open-source code

PCC closes this gap with **hardware-rooted attestation**: the device cryptographically verifies the exact code running on the server before sending any data. The server's secure enclave will only unseal keys if the software image matches the published hash.

Clawback can achieve the same properties without custom silicon by using commodity TEE platforms.

---

## Roadmap to Clawback Verified Execution

### Phase 1 (Current): Simulated Attestation

**Status:** Implemented in this commit.

The broker generates a simulated attestation document with each destruction receipt:
```json
{
  "provider": "simulated",
  "code_hash": "sha256 of broker source file",
  "enclave_id": "local-dev",
  "attested_at": "ISO-8601 timestamp",
  "pcr0": "simulated-not-real-tee",
  "note": "Simulated attestation. In production: AWS Nitro Enclave signed document."
}
```

This establishes the **interface contract** — all consumers of destruction receipts already receive and can parse attestation documents. When real TEE attestation is available, the schema stays the same but `provider` changes from `"simulated"` to `"aws-nitro"` and the document gains a cryptographic signature.

**What this proves:** Nothing cryptographically. The code hash is self-reported. This phase is about interface readiness, not security.

### Phase 2: AWS Nitro Enclave

**Target:** Single-cloud deployment with cryptographic attestation.

| Component | Implementation |
|-----------|---------------|
| Runtime | AWS Nitro Enclave (isolated VM with no persistent storage, no SSH, no admin access) |
| Attestation | Nitro attestation document signed by AWS Nitro root CA |
| Code verification | PCR0 = SHA-384 of enclave image; published in transparency log |
| Key management | KMS policy: keys only accessible to enclaves with matching PCR values |
| Receipt signing | Each destruction receipt includes the Nitro attestation document |

**Destruction receipt with real attestation:**
```json
{
  "payload_id": "uuid",
  "share_id": "uuid",
  "data_hash": "sha256(ciphertext)",
  "revoked_at": "ISO-8601",
  "destruction_proof": "HMAC(broker_secret, payload_id + revoked_at)",
  "attestation": {
    "provider": "aws-nitro",
    "pcr0": "sha384 of enclave image",
    "pcr1": "sha384 of kernel",
    "pcr2": "sha384 of application",
    "signed_by": "aws-nitro-root-ca",
    "certificate": "DER-encoded X.509",
    "signature": "base64 ECDSA signature over receipt fields"
  },
  "status": "DESTROYED"
}
```

**What this proves:** The exact code that processed the revocation matches the published open-source code. The broker operator cannot have modified it, even with root access to the host.

### Phase 3: Hardware-Agnostic TEE

**Target:** Multi-cloud, multi-provider attestation.

| Technology | Platform | Attestation Mechanism |
|------------|----------|----------------------|
| AWS Nitro Enclaves | AWS | Nitro attestation document + AWS root CA |
| AMD SEV-SNP | AWS/Azure/GCP | VCEK-signed attestation report |
| Intel TDX | Azure/GCP | TD Quote signed by Intel SGX QE |
| ARM CCA | ARM servers | Realm token signed by CCA attestation service |

The broker abstracts over TEE providers:
1. At startup, detect which TEE is available
2. Generate attestation documents in the platform-native format
3. Wrap in a Clawback-standard envelope with `provider` field
4. Publish enclave image hashes to a transparency log (append-only, publicly auditable)

Verification becomes: "Does the attestation chain to a trusted root CA? Does the code hash match the published image? Was the receipt signed inside the enclave?"

---

## Why This Matters

### GDPR Right to Erasure (Article 17)

GDPR gives individuals the right to request deletion of personal data. Today, compliance is based on policy: companies promise they deleted the data, but there's no way to verify. A Clawback destruction receipt with TEE attestation is **cryptographic proof** that a specific piece of data was destroyed by a specific version of verified code at a specific time.

### CCPA / CPRA Right to Delete

California's privacy laws grant similar deletion rights. The enforcement challenge is the same: how does a regulator verify deletion actually happened? Clawback receipts provide an auditable answer.

### Biometric Data Regulations (BIPA, EU AI Act)

Illinois BIPA and the EU AI Act impose strict requirements on biometric data lifecycle. Clawback's per-share revocation with provable destruction aligns directly: share biometric data for processing, then cryptographically prove it was destroyed after use.

### Financial Data (SOX, PCI-DSS)

Financial regulations require demonstrable data lifecycle management. Destruction receipts serve as audit artifacts proving data was handled per policy.

---

## Architectural Comparison

```
┌─────────────────────────────────────────────────────────────────┐
│                    Apple PCC                                     │
│                                                                  │
│  Device ──attestation──► PCC Node ──transparency──► Public Log   │
│    │                        │                                    │
│    └── verifies code ───────┘                                    │
│         before sending                                           │
│         any data                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│              Clawback Verified Execution                         │
│                                                                  │
│  Sender ──attestation──► Broker ──transparency──► Public Log     │
│    │                       │                                     │
│    └── verifies code ──────┘                                     │
│         before sharing                                           │
│         any data                                                 │
└─────────────────────────────────────────────────────────────────┘
```

Both follow the same pattern:
1. **Publish** the exact code that will run (transparency log)
2. **Attest** at runtime that the published code is what's actually running (TEE attestation)
3. **Verify** before trusting — the client checks attestation before sending data
4. **Prove** after the fact — signed receipts/logs provide a permanent audit trail

The difference is scope: PCC proves "your data was processed correctly." Clawback proves "your data was destroyed correctly."

---

## References

- [Apple Private Cloud Compute — Security Overview](https://security.apple.com/blog/private-cloud-compute/)
- [AWS Nitro Enclaves — User Guide](https://docs.aws.amazon.com/enclaves/latest/user/)
- [AMD SEV-SNP — Strengthening VM Isolation](https://www.amd.com/en/developer/sev.html)
- [GDPR Article 17 — Right to Erasure](https://gdpr-info.eu/art-17-gdpr/)
- [Clawback Protocol Specification](../spec/SPEC-v0.1.md)
