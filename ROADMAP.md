# Clawback Protocol — Roadmap

## Status: Active Development

---

## ✅ Phase 1 — Foundation (COMPLETE)
- [x] Core concept defined
- [x] Domains secured (clawbackprotocol.org + .com)
- [x] AGPLv3 license selected
- [x] Trademark filed (USPTO Serial No. 99657348, Class 009)
- [x] Python PoC built and running — full lifecycle demo
- [x] Rust production implementation — Axum HTTP services, ChaCha20-Poly1305
- [x] Destruction receipts — HMAC-SHA256, tamper-evident, append-only
- [x] Security audit — 8 findings documented, HIGH items fixed
- [x] PII revocation demo (`demo_pii_signup.py`) — GDPR Article 17 compliance flow
- [x] `clawback-verify` CLI — standalone receipt verification tool

## ✅ Phase 2 — Umbral PRE + Attestation (COMPLETE)
- [x] **Umbral Proxy Re-Encryption** — broker is now zero-knowledge
  - Broker holds kfrags (re-encryption key fragments), NOT encryption keys
  - Even a fully compromised broker cannot decrypt stored payloads
  - Revocation destroys kfrags — decryption becomes mathematically impossible
  - Per-receiver kfrags — wrong receiver cannot decrypt (cryptographically enforced)
- [x] **Cryptographic attestation scaffold** — Nitro-compatible schema
  - Ed25519-signed attestation documents in destruction receipts
  - SHA-384 PCR0 code hash (matches AWS Nitro format)
  - `GET /attestation` transparency log endpoint on broker
  - Signature verification (`verify_attestation_document()`)
  - Tampered attestation correctly rejected
- [x] **Receiver public key exchange** — `GET /public_key` endpoint
- [x] **Multi-share isolation verified** — revoke A, B unaffected (31-point audit)
- [x] **Threshold PRE** — 3-of-5 kfrag splitting tested in Rust
- [x] **Rust implementation updated** — `umbral-pre` crate, 28 tests passing
- [x] **PCC parity documented** — `docs/PCC-INTEGRATION.md` Phase 2 marked complete

## 🔨 Phase 2b — Production Attestation (Next)
- [ ] Deploy broker inside AWS Nitro Enclave
- [ ] Replace simulated attestation with real Nitro attestation documents
- [ ] KMS policy: keys only accessible to enclaves with matching PCR values
- [ ] Publish PCR0 to transparency log (append-only, publicly auditable)
- [ ] Signed share tokens (ECDSA JWT — unforgeable)
- [ ] TTL auto-expiry — shares self-destruct after N seconds

## 🔭 Phase 3 — Multi-Cloud TEE + SDKs (3-6 months)
- [ ] Multi-cloud TEE support (AMD SEV-SNP, Intel TDX, ARM CCA)
- [ ] TEE provider abstraction layer
- [ ] Multi-recipient selective revocation (UI/API)
- [ ] Threshold broker (M-of-N nodes must cooperate)
- [ ] SDK — Python + JavaScript client libraries
- [ ] WASM build — runs in browser
- [ ] On-chain destruction receipts (optional, for public auditability)

## 🌐 Phase 4 — Ecosystem
- [ ] Formal protocol specification (SPEC-v1.0)
- [ ] Whitepaper — peer-reviewed cryptographic analysis
- [ ] Reference integrations (Signal, ProtonMail, enterprise messaging)
- [ ] Consumer application on top of protocol
- [ ] IETF RFC proposal

---

## Why This Matters

Every privacy law (GDPR, CCPA, HIPAA) includes a "right to erasure."
Every company says "we deleted it." None can prove it.

Clawback makes deletion cryptographically provable — not a policy, a mathematical guarantee.

With Phase 2 complete, Clawback implements the same two core properties as Apple's Private Cloud Compute:
1. **Zero-knowledge broker** — broker cannot decrypt data even if fully compromised
2. **Cryptographic attestation** — receipts carry proof of which code ran

> *The internet was built to never forget. Clawback makes forgetting a first-class operation.*
