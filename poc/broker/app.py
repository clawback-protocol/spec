"""
Clawback Protocol — Broker Service (port 8010)

The broker is a zero-knowledge intermediary using Umbral PRE:
  - Stores encrypted payloads (never sees plaintext)
  - Holds per-share re-encryption key fragments (kfrags) — NOT encryption keys
  - Re-encrypts capsule fragments for receivers without accessing plaintext
  - Enforces revocation by destroying kfrags — re-encryption becomes impossible
  - Appends destruction receipts to receipts.jsonl

Zero-knowledge property:
  The broker holds kfrags which can re-encrypt ciphertext from sender→receiver.
  kfrags CANNOT decrypt the data — they can only transform the ciphertext.
  Even if the broker is fully compromised, the data remains encrypted.
"""

import os
import json
import hmac
import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, request, jsonify
from umbral import (
    PublicKey, Capsule, KeyFrag, VerifiedKeyFrag,
    reencrypt,
)
from nitro_attestation import get_attestation_document, verify_attestation_document

app = Flask(__name__)

# ─── State (in-memory; backed by receipts.jsonl on disk) ─────────────────────
payloads = {}
BROKER_SECRET = os.environ.get("BROKER_SECRET", "clawback-broker-secret-changeme")
RECEIPTS_FILE = Path(__file__).parent / "receipts.jsonl"


def _destruction_proof(payload_id: str, revoked_at: str) -> str:
    msg = f"{payload_id}{revoked_at}".encode()
    return hmac.new(BROKER_SECRET.encode(), msg, hashlib.sha256).hexdigest()


def _append_receipt(receipt: dict):
    with open(RECEIPTS_FILE, "a") as f:
        f.write(json.dumps(receipt) + "\n")


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok"}), 200


@app.route("/register", methods=["POST"])
def register():
    """
    Sender registers an encrypted payload with Umbral PRE kfrags.
    Body: {
        payload_id, encrypted_blob (b64), capsule (b64), capsule_ciphertext (b64),
        share_id, kfrags (b64 list),
        receiver_pk (b64), delegating_pk (b64), verifying_pk (b64)
    }
    """
    data = request.json
    if not data:
        return jsonify({"error": "request body required"}), 400
    for field in ("payload_id", "encrypted_blob", "capsule", "capsule_ciphertext",
                  "share_id", "kfrags", "receiver_pk", "delegating_pk", "verifying_pk"):
        if field not in data:
            return jsonify({"error": f"missing required field: {field}"}), 400

    pid = data["payload_id"]
    if pid in payloads:
        return jsonify({"error": "payload already registered"}), 409

    # Deserialize and verify kfrags
    delegating_pk = PublicKey.from_bytes(base64.b64decode(data["delegating_pk"]))
    receiver_pk = PublicKey.from_bytes(base64.b64decode(data["receiver_pk"]))
    verifying_pk = PublicKey.from_bytes(base64.b64decode(data["verifying_pk"]))

    verified_kfrags = []
    for kf_b64 in data["kfrags"]:
        kf = KeyFrag.from_bytes(base64.b64decode(kf_b64))
        vkf = kf.verify(verifying_pk=verifying_pk, delegating_pk=delegating_pk, receiving_pk=receiver_pk)
        verified_kfrags.append(vkf)

    payloads[pid] = {
        "encrypted_blob": data["encrypted_blob"],
        "capsule": data["capsule"],
        "capsule_ciphertext": data["capsule_ciphertext"],
        "delegating_pk": data["delegating_pk"],
        "verifying_pk": data["verifying_pk"],
        "shares": {
            data["share_id"]: {
                "kfrags": verified_kfrags,
                "kfrags_b64": data["kfrags"],
                "receiver_pk": data["receiver_pk"],
            }
        },
    }
    app.logger.info(f"[REGISTER] payload={pid}  share={data['share_id']}  (Umbral PRE — zero-knowledge)")
    return jsonify({"status": "registered", "payload_id": pid}), 201


@app.route("/add_share", methods=["POST"])
def add_share():
    """
    Sender adds a new share (kfrags) for an existing payload.
    Body: { payload_id, share_id, kfrags (b64 list), receiver_pk (b64),
            delegating_pk (b64), verifying_pk (b64) }
    """
    data = request.json
    if not data:
        return jsonify({"error": "request body required"}), 400
    for field in ("payload_id", "share_id", "kfrags", "receiver_pk", "delegating_pk", "verifying_pk"):
        if field not in data:
            return jsonify({"error": f"missing required field: {field}"}), 400

    pid = data["payload_id"]
    if pid not in payloads:
        return jsonify({"error": "unknown payload"}), 404

    delegating_pk = PublicKey.from_bytes(base64.b64decode(data["delegating_pk"]))
    receiver_pk = PublicKey.from_bytes(base64.b64decode(data["receiver_pk"]))
    verifying_pk = PublicKey.from_bytes(base64.b64decode(data["verifying_pk"]))

    verified_kfrags = []
    for kf_b64 in data["kfrags"]:
        kf = KeyFrag.from_bytes(base64.b64decode(kf_b64))
        vkf = kf.verify(verifying_pk=verifying_pk, delegating_pk=delegating_pk, receiving_pk=receiver_pk)
        verified_kfrags.append(vkf)

    payloads[pid]["shares"][data["share_id"]] = {
        "kfrags": verified_kfrags,
        "kfrags_b64": data["kfrags"],
        "receiver_pk": data["receiver_pk"],
    }
    app.logger.info(f"[ADD_SHARE] payload={pid}  share={data['share_id']}  (Umbral PRE)")
    return jsonify({"status": "share_added", "share_id": data["share_id"]}), 200


@app.route("/fetch/<payload_id>", methods=["GET"])
def fetch(payload_id):
    """
    Receiver fetches re-encrypted capsule fragments.
    Query param: share_id
    Returns: { encrypted_blob, capsule, cfrags[], capsule_ciphertext, delegating_pk }

    The broker re-encrypts the capsule using stored kfrags — it never touches
    the plaintext or the encryption key.
    """
    share_id = request.args.get("share_id")
    if not share_id:
        return jsonify({"error": "share_id required"}), 400

    if payload_id not in payloads:
        return jsonify({"error": "unknown payload"}), 404

    entry = payloads[payload_id]
    if share_id not in entry["shares"]:
        return jsonify({"error": "REVOKED", "detail": "This share has been revoked or never existed"}), 403

    share = entry["shares"][share_id]

    # Re-encrypt capsule using kfrags → produce cfrags for receiver
    capsule = Capsule.from_bytes(base64.b64decode(entry["capsule"]))
    cfrags = []
    for vkf in share["kfrags"]:
        cfrag = reencrypt(capsule=capsule, kfrag=vkf)
        cfrags.append(base64.b64encode(bytes(cfrag)).decode())

    app.logger.info(f"[FETCH] payload={payload_id}  share={share_id}  ✓ (re-encrypted, zero-knowledge)")
    return jsonify({
        "payload_id": payload_id,
        "share_id": share_id,
        "encrypted_blob": entry["encrypted_blob"],
        "capsule": entry["capsule"],
        "capsule_ciphertext": entry["capsule_ciphertext"],
        "cfrags": cfrags,
        "delegating_pk": entry["delegating_pk"],
    }), 200


@app.route("/revoke/<payload_id>", methods=["POST"])
def revoke(payload_id):
    """
    Sender revokes a share. The kfrags are destroyed — re-encryption becomes
    mathematically impossible. A receipt is written.
    Body: { share_id }
    """
    data = request.json
    share_id = data.get("share_id")

    if payload_id not in payloads:
        return jsonify({"error": "unknown payload"}), 404

    entry = payloads[payload_id]
    if share_id not in entry["shares"]:
        return jsonify({"error": "share not found or already revoked"}), 404

    # Compute receipt BEFORE destroying the kfrags
    blob_b64 = entry["encrypted_blob"]
    blob_bytes = base64.b64decode(blob_b64)
    data_hash = hashlib.sha256(blob_bytes).hexdigest()
    revoked_at = datetime.now(timezone.utc).isoformat()
    proof = _destruction_proof(payload_id, revoked_at)

    # DESTROY the kfrags — re-encryption is now mathematically impossible
    del entry["shares"][share_id]

    attestation = get_attestation_document(nonce=payload_id.encode())

    receipt = {
        "payload_id": payload_id,
        "share_id": share_id,
        "data_hash": data_hash,
        "revoked_at": revoked_at,
        "destruction_proof": proof,
        "attestation": attestation,
        "status": "DESTROYED",
    }
    _append_receipt(receipt)
    app.logger.info(f"[REVOKE] payload={payload_id}  share={share_id}  proof={proof[:16]}… (kfrags destroyed)")
    return jsonify({"status": "revoked", "receipt": receipt}), 200


@app.route("/receipts/<payload_id>", methods=["GET"])
def receipts(payload_id):
    """Returns all destruction receipts for a given payload."""
    if not RECEIPTS_FILE.exists():
        return jsonify({"receipts": []}), 200

    results = []
    with open(RECEIPTS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("payload_id") == payload_id:
                results.append(rec)

    return jsonify({"payload_id": payload_id, "receipts": results}), 200


@app.route("/attestation", methods=["GET"])
def attestation():
    """
    Returns the broker's current attestation document.
    Equivalent to PCC's transparency log entry for this broker instance.
    """
    doc = get_attestation_document()
    return jsonify({
        "broker_version": "0.2.0",
        "attestation": doc,
        "instructions": (
            "Compare pcrs.pcr0 against the published code hash at "
            "https://github.com/clawback-protocol/spec/releases "
            "to verify this broker is running the expected code."
        ),
    }), 200


if __name__ == "__main__":
    app.run(port=8010, debug=False)
