# Clawback Protocol — Benchmark Results
_Generated: 2026-03-17 | Rust release build | Desktop: Ryzen 5800X + RTX 3080_

## Summary
All 11 stress tests passed in **0.28 seconds** (release mode).
Zero share leaks across 5,000 payloads. All correctness invariants confirmed.

## Release vs Debug Comparison

| Operation | Debug | Release | Speedup |
|-----------|-------|---------|---------|
| Encrypt 64B | 16K ops/s | 694K ops/s | 43× |
| Encrypt 1KB | 4.7K ops/s | 499K ops/s | 106× |
| Encrypt 64KB | 88 ops/s | 30K ops/s | 341× |
| Encrypt 1MB | 6 ops/s | 1.5K ops/s | 253× |
| Broker fetch | 1.7M ops/s | 7.2M ops/s | 4× |
| Broker register | 12K ops/s | 495K ops/s | 40× |
| Broker revoke | 51K ops/s | 628K ops/s | 12× |
| HMAC destruction proof | 71K ops/s | 2.3M ops/s | 32× |
| SHA-256 (64KB) | 750 ops/s | 36K ops/s | 48× |
| Full lifecycle (encrypt→decrypt→revoke) | ~12K ops/s | 348K ops/s | 29× |

## Correctness Verified (5,000 payloads)
- ✅ Zero share leaks on revocation
- ✅ Share isolation: revoking 50% leaves other 50% accessible
- ✅ Double revoke: idempotent (1,000 double-revokes, all REVOKED)
- ✅ Receipt integrity: 2,000 HMAC proofs deterministic and correct
- ✅ Bogus lookups: 10,000 rejected with 403
- ✅ Full lifecycle throughput: 348K ops/s

## Key Numbers for Grant/Partner Presentations
- **628,000 revocations/second** — instant, at scale
- **1,500 ops/s on 1MB documents** — practical for real files
- **2.3M HMAC destruction proofs/second** — verifiable deletion is not a bottleneck
- **7.2M broker fetches/second** — broker is not the bottleneck
- **348K full encrypt→decrypt→revoke cycles/second**

## Test File
`rust/tests/stress_test.rs`
