# Clawback Protocol — Roadmap

## Status: Active Development

---

## ✅ Done
- Core concept defined
- Domains secured (clawbackprotocol.org + .com)
- AGPLv3 license selected
- Trademark filed (USPTO Class 009)
- **PoC built and running** — PRE-based, full lifecycle demo

## 🔨 In Progress (0-3 months)
- [ ] Whitepaper — formal protocol specification
- [ ] Rust core implementation (`ring` crate, X25519/dalek)
- [ ] Replace simulated PRE with Umbral (true proxy re-encryption)
- [ ] Signed share tokens (ECDSA JWT — unforgeable)
- [ ] TTL auto-expiry — shares self-destruct after N seconds

## 🔭 Planned (3-6 months)
- [ ] Multi-recipient selective revocation
- [ ] Threshold broker (M-of-N nodes must cooperate)
- [ ] SDK — Python + JS client libraries
- [ ] WASM build — runs in browser
- [ ] On-chain destruction receipts (optional, for public auditability)

## 🌐 Long Term
- [ ] Reference implementations for Signal, ProtonMail integration
- [ ] Consumer app on top of protocol
- [ ] IETF RFC proposal

---

## Why This Matters

Every privacy law (GDPR, CCPA, HIPAA) includes a "right to erasure."  
Every company says "we deleted it." None can prove it.

Clawback makes deletion cryptographically provable — not a policy, a mathematical guarantee.

> *The internet was built to never forget. Clawback makes forgetting a first-class operation.*
