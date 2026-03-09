"""
Clawback Protocol — Broker Service (port 5000)

The broker is a blind intermediary:
  - Stores encrypted payloads (never sees plaintext)
  - Holds per-share derived keys (only for re-encryption simulation)
  - Enforces revocation instantly — destroyed keys = destroyed access
  - Appends ZK-style destruction receipts to receipts.jsonl
"""

import os
import json
import hmac
import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)

# ─── State (in-memory; backed by receipts.jsonl on disk) ─────────────────────
payloads = {}      # payload_id → { encrypted_blob, shares: { share_id → share_key_b64 } }
BROKER_SECRET = os.environ.get("BROKER_SECRET", "clawback-broker-secret-changeme")
RECEIPTS_FILE = Path(__file__).parent / "receipts.jsonl"


def _destruction_proof(payload_id: str, revoked_at: str) -> str:
    msg = f"{payload_id}{revoked_at}".encode()
    return hmac.new(BROKER_SECRET.encode(), msg, hashlib.sha256).hexdigest()


def _append_receipt(receipt: dict):
    with open(RECEIPTS_FILE, "a") as f:
        f.write(json.dumps(receipt) + "\n")


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.route("/register", methods=["POST"])
def register():
    """
    Sender registers an encrypted payload and its first share key.
    Body: { payload_id, encrypted_blob (b64), share_id, share_key (b64) }
    """
    data = request.json
    pid = data["payload_id"]
    blob = data["encrypted_blob"]   # base64-encoded ciphertext
    share_id = data["share_id"]
    share_key = data["share_key"]   # base64-encoded derived key

    if pid in payloads:
        return jsonify({"error": "payload already registered"}), 409

    payloads[pid] = {
        "encrypted_blob": blob,
        "shares": {
            share_id: share_key
        }
    }
    app.logger.info(f"[REGISTER] payload={pid}  share={share_id}")
    return jsonify({"status": "registered", "payload_id": pid}), 201


@app.route("/add_share", methods=["POST"])
def add_share():
    """
    Sender adds a new share key for an existing payload.
    Body: { payload_id, share_id, share_key (b64) }
    """
    data = request.json
    pid = data["payload_id"]
    share_id = data["share_id"]
    share_key = data["share_key"]

    if pid not in payloads:
        return jsonify({"error": "unknown payload"}), 404

    payloads[pid]["shares"][share_id] = share_key
    app.logger.info(f"[ADD_SHARE] payload={pid}  share={share_id}")
    return jsonify({"status": "share_added", "share_id": share_id}), 200


@app.route("/fetch/<payload_id>", methods=["GET"])
def fetch(payload_id):
    """
    Receiver fetches the encrypted blob + their share key.
    Query param: share_id
    Returns: { encrypted_blob (b64), share_key (b64) }
    """
    share_id = request.args.get("share_id")
    if not share_id:
        return jsonify({"error": "share_id required"}), 400

    if payload_id not in payloads:
        return jsonify({"error": "unknown payload"}), 404

    entry = payloads[payload_id]
    if share_id not in entry["shares"]:
        return jsonify({"error": "REVOKED", "detail": "This share has been revoked or never existed"}), 403

    app.logger.info(f"[FETCH] payload={payload_id}  share={share_id}  ✓")
    return jsonify({
        "payload_id": payload_id,
        "share_id": share_id,
        "encrypted_blob": entry["encrypted_blob"],
        "share_key": entry["shares"][share_id]
    }), 200


@app.route("/revoke/<payload_id>", methods=["POST"])
def revoke(payload_id):
    """
    Sender revokes a share. The share key is destroyed and a receipt is written.
    Body: { share_id }
    """
    data = request.json
    share_id = data.get("share_id")

    if payload_id not in payloads:
        return jsonify({"error": "unknown payload"}), 404

    entry = payloads[payload_id]
    if share_id not in entry["shares"]:
        return jsonify({"error": "share not found or already revoked"}), 404

    # Compute receipt BEFORE destroying the key
    blob_b64 = entry["encrypted_blob"]
    blob_bytes = base64.b64decode(blob_b64)
    data_hash = hashlib.sha256(blob_bytes).hexdigest()
    revoked_at = datetime.now(timezone.utc).isoformat()
    proof = _destruction_proof(payload_id, revoked_at)

    # DESTROY the share key — access is gone instantly
    del entry["shares"][share_id]

    receipt = {
        "payload_id": payload_id,
        "share_id": share_id,
        "data_hash": data_hash,
        "revoked_at": revoked_at,
        "destruction_proof": proof,
        "status": "DESTROYED"
    }
    _append_receipt(receipt)
    app.logger.info(f"[REVOKE] payload={payload_id}  share={share_id}  proof={proof[:16]}…")
    return jsonify({"status": "revoked", "receipt": receipt}), 200


@app.route("/receipts/<payload_id>", methods=["GET"])
def receipts(payload_id):
    """
    Returns all destruction receipts for a given payload.
    """
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


if __name__ == "__main__":
    app.run(port=8000, debug=False)
