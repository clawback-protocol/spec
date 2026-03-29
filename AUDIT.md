# Security Audit — Clawback Protocol PoC

Date: 2026-03-29
Auditor: Claude Code
Scope: Python PoC (`broker/app.py`, `sender/app.py`, `receiver/app.py`)

---

## Findings

### [HIGH] Missing input validation on broker POST endpoints

- **File:** `broker/app.py:60-71` (register), `broker/app.py:91-102` (add_share)
- **Issue:** POST endpoints `/register` and `/add_share` accessed `data["field"]` directly without checking if required fields exist. Missing fields caused unhandled `KeyError` (HTTP 500) instead of a proper 400 response.
- **Fix:** Added field presence validation for all required fields before access. Missing fields now return `{"error": "missing required field: <name>"}` with HTTP 400.
- **Status:** FIXED

### [MEDIUM] All shares for same payload receive identical key bytes

- **File:** `sender/app.py:48-63` (`_derive_share_key`)
- **Issue:** The `_derive_share_key()` function returns `enc_key` directly for all shares. This means every share token for the same payload decrypts to the same key bytes. If a receiver caches the key before revocation, they retain decryption capability even after their specific share is revoked.
- **Fix:** This is an acknowledged limitation of the simulated PRE model. In true PRE (Umbral), each receiver gets a unique re-encryption key and revoking kfrags makes re-encryption impossible. Documented in architecture.
- **Status:** ACKNOWLEDGED — will be resolved by Umbral PRE migration (Phase 2)

### [MEDIUM] No authentication on any endpoint

- **File:** All three services
- **Issue:** Any network client can call any endpoint. No API keys, JWTs, mTLS, or other authentication mechanism. An attacker on the local network could register payloads, fetch share keys, or trigger revocations.
- **Fix:** Acceptable for a local PoC demo. Production deployment requires authentication (signed JWTs for share tokens, mTLS between services, API keys for management endpoints).
- **Status:** ACKNOWLEDGED — roadmap item for production hardening

### [MEDIUM] Broker holds plaintext-equivalent share keys

- **File:** `broker/app.py:139` (fetch endpoint returns `share_key`)
- **Issue:** In the simulated PRE model, the broker stores and returns `share_key` which is the actual encryption key. A compromised broker could decrypt all stored payloads. This is the fundamental limitation that true PRE eliminates.
- **Fix:** This is the core motivation for migrating to Umbral PRE, where the broker holds re-encryption keys that cannot be used to decrypt directly.
- **Status:** ACKNOWLEDGED — core design limitation of simulated PRE

### [LOW] No base64 validation on broker registration

- **File:** `broker/app.py:73-76` (register endpoint)
- **Issue:** `encrypted_blob` and `share_key` are stored as-is without validating they are valid base64. Invalid base64 would cause `base64.b64decode()` to raise an exception later in `/revoke` when computing `data_hash`.
- **Fix:** Minimal risk in PoC since the sender service always sends valid base64. Production should validate at the boundary.
- **Status:** ACKNOWLEDGED

### [LOW] Flask development server used for all services

- **File:** `broker/app.py:224`, `sender/app.py:209`, `receiver/app.py:89`
- **Issue:** All services use Flask's built-in development server (`app.run()`). This is single-threaded, not production-hardened, and logs "WARNING: This is a development server" in production environments.
- **Fix:** Production deployment should use gunicorn or uvicorn. Not relevant for PoC demo use.
- **Status:** ACKNOWLEDGED

### [LOW] No rate limiting on any endpoint

- **File:** All three services
- **Issue:** No rate limiting on any endpoint. A malicious client could exhaust broker memory by registering unlimited payloads, or probe for valid share IDs via /fetch.
- **Fix:** Production should add rate limiting (e.g., Flask-Limiter or reverse proxy rate limits).
- **Status:** ACKNOWLEDGED

---

## Security Properties Verified

| Property | Status | Evidence |
|----------|--------|----------|
| Master key never transmitted | PASS | `sender/app.py` stores `master_key` in `_state` dict only; never included in any HTTP response or broker registration |
| Master key never logged | PASS | Flask logger calls only log `payload_id` and `share_id`, never key material |
| Share isolation on revocation | PASS | `broker/app.py:167` — `del entry["shares"][share_id]` only removes the specific share; other shares for the same payload remain active |
| Receipts file opened in append mode | PASS | `broker/app.py:49` — `open(RECEIPTS_FILE, "a")` uses append mode; existing receipts are never overwritten |
| AEAD encryption (not raw cipher) | PASS | `sender/app.py:69` — uses `ChaCha20Poly1305` which provides authenticated encryption |
| Destruction proof is tamper-evident | PASS | `broker/app.py:29-30` — HMAC-SHA256 with broker secret; proof is deterministic and verifiable |
| No ECB mode or deprecated hashes | PASS | Only SHA-256 and HMAC-SHA256 used; no MD5, SHA1, or ECB anywhere in codebase |
| Port migration complete | PASS | No references to old ports (8000/8001/8002) remain in any source file |

---

## Concurrent Revocation Analysis

**Question:** What if two revocations happen simultaneously for the same share?

**Answer:** Flask's built-in server is single-threaded, so requests are serialized. The first revocation succeeds and deletes the share key. The second revocation hits the `share_id not in entry["shares"]` check and returns 404 ("share not found or already revoked"). This is correct behavior. In a multi-worker deployment, a race condition could theoretically cause a double-write to `receipts.jsonl`, but both receipts would be valid and the share key would still be destroyed.
