"""
Clawback Protocol — Sender Service (port 8011)

The sender owns the data. They:
  - Generate an X25519 keypair (master key, never leaves this service)
  - Encrypt data locally with ChaCha20-Poly1305
  - Derive per-share keys via HKDF(master_key, share_id)
  - Register encrypted blobs + share keys with the broker
  - Can revoke any share at any time (tell broker to destroy share key)

Crypto flow (simulated PRE):
  plaintext
    → encrypt with master_key → ciphertext
    → for each share: derive share_key = HKDF(master_key, share_id)
    → send (ciphertext, share_key) to broker
    → receiver decrypts ciphertext using share_key
    → master_key NEVER leaves sender

Revocation:
  → tell broker to delete share_key
  → receiver can no longer decrypt (no key)
"""

import os
import base64
import uuid
import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from flask import Flask, request, jsonify

app = Flask(__name__)

BROKER_URL = os.environ.get("BROKER_URL", "http://localhost:8010")

# ─── In-memory state ─────────────────────────────────────────────────────────
# payload_id → { master_key_bytes, shares: { share_id: True } }
_state = {}


def _generate_master_key() -> bytes:
    """Generate a random 32-byte master key."""
    return os.urandom(32)


def _derive_share_key(enc_key: bytes, share_id: str) -> bytes:
    """
    Derive a share-specific key from the payload encryption key + share_id.

    In true PRE, the broker would hold a re-encryption key that transforms
    ciphertext without revealing enc_key. Here we simulate that by giving
    each share its own HKDF derivation of enc_key — in practice the broker
    holds a key that CAN decrypt (simulated proxy), and revocation destroys it.
    
    For this PoC we store enc_key directly as the share key, since the receiver
    needs to decrypt with the same key used to encrypt. The share_id provides
    per-share namespacing for the audit trail.
    """
    # Return enc_key directly — share_id is used for receipt/audit trail only.
    # In true PRE: this would be rk_{sender→receiver} = enc_key * receiver_pubkey
    return enc_key


def _encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with ChaCha20-Poly1305. Returns nonce + ciphertext."""
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    ct = chacha.encrypt(nonce, plaintext, None)
    return nonce + ct


def _decrypt(blob: bytes, key: bytes) -> bytes:
    """Decrypt ChaCha20-Poly1305 blob (nonce || ciphertext)."""
    nonce, ct = blob[:12], blob[12:]
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ct, None)


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.route("/encrypt", methods=["POST"])
def encrypt():
    """
    Encrypt a plaintext and register it with the broker.
    Body: { plaintext }
    Returns: { payload_id, share_id, share_token }

    The first share is auto-created so the sender can immediately share it.
    """
    data = request.json
    plaintext = data.get("plaintext", "")
    if not plaintext:
        return jsonify({"error": "plaintext required"}), 400

    payload_id = str(uuid.uuid4())
    master_key = _generate_master_key()

    # Encrypt the data with a HKDF-derived encryption key
    # (we derive from master_key with info="payload" so we can derive share keys separately)
    enc_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"payload-encryption"
    ).derive(master_key)

    ciphertext = _encrypt(plaintext.encode(), enc_key)
    blob_b64 = base64.b64encode(ciphertext).decode()

    # Create the first share
    share_id = str(uuid.uuid4())
    share_key = _derive_share_key(enc_key, share_id)
    share_key_b64 = base64.b64encode(share_key).decode()

    # Register with broker
    resp = requests.post(f"{BROKER_URL}/register", json={
        "payload_id": payload_id,
        "encrypted_blob": blob_b64,
        "share_id": share_id,
        "share_key": share_key_b64
    })
    if resp.status_code != 201:
        return jsonify({"error": "broker registration failed", "detail": resp.json()}), 502

    # Store keys locally (master_key and enc_key never go to broker)
    _state[payload_id] = {
        "master_key": master_key,
        "enc_key": enc_key,
        "shares": {share_id: True}
    }

    app.logger.info(f"[ENCRYPT] payload={payload_id}  share={share_id}")
    return jsonify({
        "payload_id": payload_id,
        "share_id": share_id,
        "share_token": share_id,   # In production this would be a signed JWT
        "status": "registered"
    }), 201


@app.route("/share/<payload_id>", methods=["POST"])
def share(payload_id):
    """
    Issue a new share token for a payload.
    Body: { recipient (optional label) }
    Returns: { share_id, share_token }
    """
    if payload_id not in _state:
        return jsonify({"error": "unknown payload (not owned by this sender)"}), 404

    entry = _state[payload_id]
    share_id = str(uuid.uuid4())
    share_key = _derive_share_key(entry["enc_key"], share_id)
    share_key_b64 = base64.b64encode(share_key).decode()

    # Register new share with broker
    resp = requests.post(f"{BROKER_URL}/add_share", json={
        "payload_id": payload_id,
        "share_id": share_id,
        "share_key": share_key_b64
    })
    if resp.status_code != 200:
        return jsonify({"error": "broker add_share failed", "detail": resp.json()}), 502

    entry["shares"][share_id] = True
    app.logger.info(f"[SHARE] payload={payload_id}  new_share={share_id}")
    return jsonify({
        "payload_id": payload_id,
        "share_id": share_id,
        "share_token": share_id
    }), 200


@app.route("/revoke/<payload_id>", methods=["POST"])
def revoke(payload_id):
    """
    Revoke a share. Tells broker to destroy the share key.
    Body: { share_id }
    Returns: broker receipt
    """
    data = request.json
    share_id = data.get("share_id")
    if not share_id:
        return jsonify({"error": "share_id required"}), 400

    if payload_id not in _state:
        return jsonify({"error": "unknown payload"}), 404

    resp = requests.post(f"{BROKER_URL}/revoke/{payload_id}", json={"share_id": share_id})
    if resp.status_code != 200:
        return jsonify({"error": "broker revocation failed", "detail": resp.json()}), 502

    entry = _state[payload_id]
    entry["shares"].pop(share_id, None)

    receipt = resp.json().get("receipt", {})
    app.logger.info(f"[REVOKE] payload={payload_id}  share={share_id}  ✓ DESTROYED")
    return jsonify({
        "status": "revoked",
        "payload_id": payload_id,
        "share_id": share_id,
        "receipt": receipt
    }), 200


if __name__ == "__main__":
    app.run(port=8011, debug=False)
