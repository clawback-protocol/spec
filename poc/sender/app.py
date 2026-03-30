"""
Clawback Protocol — Sender Service (port 8011)

The sender owns the data. They:
  - Generate an Umbral keypair (sk_sender, pk_sender)
  - Encrypt data locally with ChaCha20-Poly1305 (symmetric data key)
  - Use Umbral to encrypt the data key to sender's public key
  - Generate re-encryption key fragments (kfrags) for each recipient
  - Register encrypted blobs + kfrags with the broker
  - Can revoke any share at any time (tell broker to destroy kfrags)

Crypto flow (Umbral PRE):
  plaintext
    → data_key = random 32 bytes
    → encrypt plaintext with ChaCha20-Poly1305(data_key) → ciphertext
    → capsule, capsule_ct = umbral.encrypt(sender_pk, data_key)
    → kfrags = generate_kfrags(sender_sk, receiver_pk, ...)
    → broker stores: ciphertext, capsule, kfrags
    → broker re-encrypts capsule with kfrag → cfrag
    → receiver decrypts cfrag with receiver_sk → data_key → plaintext
    → master key (sender_sk) NEVER leaves sender

Revocation:
  → tell broker to delete kfrags
  → re-encryption mathematically impossible
"""

import os
import base64
import uuid
import requests
from umbral import SecretKey, Signer, encrypt, generate_kfrags
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from flask import Flask, request, jsonify

app = Flask(__name__)

BROKER_URL = os.environ.get("BROKER_URL", "http://localhost:8010")
RECEIVER_URL = os.environ.get("RECEIVER_URL", "http://localhost:8012")

# ─── Umbral sender keypair (persistent for lifetime of service) ──────────────
_sender_sk = SecretKey.random()
_sender_pk = _sender_sk.public_key()
_sender_signer = Signer(_sender_sk)

# ─── In-memory state ─────────────────────────────────────────────────────────
# payload_id → { capsule, capsule_ciphertext, shares: { share_id: True } }
_state = {}


def _encrypt_plaintext(plaintext: bytes) -> tuple:
    """Encrypt plaintext with a random data key using ChaCha20-Poly1305.
    Returns (data_key, nonce || ciphertext)."""
    data_key = os.urandom(32)
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(data_key)
    ct = chacha.encrypt(nonce, plaintext, None)
    return data_key, nonce + ct


def _serialize_pk(pk) -> str:
    """Serialize an Umbral public key to base64."""
    return base64.b64encode(bytes(pk)).decode()


def _serialize_capsule(capsule) -> str:
    """Serialize an Umbral capsule to base64."""
    return base64.b64encode(bytes(capsule)).decode()


def _serialize_kfrags(kfrags) -> list:
    """Serialize Umbral key fragments to base64 list."""
    return [base64.b64encode(bytes(kf)).decode() for kf in kfrags]


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.route("/encrypt", methods=["POST"])
def encrypt_endpoint():
    """
    Encrypt a plaintext and register it with the broker.
    Body: { plaintext }
    Returns: { payload_id, share_id, share_token }

    1. Generate random data_key, encrypt plaintext with ChaCha20-Poly1305
    2. Use Umbral to encrypt data_key to sender's public key
    3. Fetch receiver's public key
    4. Generate kfrags for receiver
    5. Register with broker: (ciphertext, capsule, kfrags, keys)
    """
    data = request.json
    plaintext = data.get("plaintext", "")
    if not plaintext:
        return jsonify({"error": "plaintext required"}), 400

    payload_id = str(uuid.uuid4())

    # Step 1: Encrypt plaintext with random data key
    data_key, ciphertext = _encrypt_plaintext(plaintext.encode())
    blob_b64 = base64.b64encode(ciphertext).decode()

    # Step 2: Use Umbral to encrypt data_key to sender's public key
    capsule, capsule_ciphertext = encrypt(_sender_pk, data_key)

    # Step 3: Fetch receiver's public key
    try:
        resp = requests.get(f"{RECEIVER_URL}/public_key", timeout=5)
        if resp.status_code != 200:
            return jsonify({"error": "failed to fetch receiver public key"}), 502
        receiver_pk_b64 = resp.json()["public_key"]
        from umbral import PublicKey
        receiver_pk = PublicKey.from_bytes(base64.b64decode(receiver_pk_b64))
    except Exception as e:
        return jsonify({"error": f"receiver key fetch failed: {e}"}), 502

    # Step 4: Generate kfrags for the receiver
    share_id = str(uuid.uuid4())
    kfrags = generate_kfrags(
        delegating_sk=_sender_sk,
        receiving_pk=receiver_pk,
        signer=_sender_signer,
        threshold=1,
        shares=1,
    )

    # Step 5: Register with broker
    resp = requests.post(f"{BROKER_URL}/register", json={
        "payload_id": payload_id,
        "encrypted_blob": blob_b64,
        "capsule": _serialize_capsule(capsule),
        "capsule_ciphertext": base64.b64encode(capsule_ciphertext).decode(),
        "share_id": share_id,
        "kfrags": _serialize_kfrags(kfrags),
        "receiver_pk": receiver_pk_b64,
        "delegating_pk": _serialize_pk(_sender_pk),
        "verifying_pk": _serialize_pk(_sender_signer.verifying_key()),
    })
    if resp.status_code != 201:
        return jsonify({"error": "broker registration failed", "detail": resp.json()}), 502

    # Store state locally
    _state[payload_id] = {
        "capsule": capsule,
        "capsule_ciphertext": capsule_ciphertext,
        "shares": {share_id: True},
    }

    app.logger.info(f"[ENCRYPT] payload={payload_id}  share={share_id}  (Umbral PRE)")
    return jsonify({
        "payload_id": payload_id,
        "share_id": share_id,
        "share_token": share_id,
        "status": "registered",
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

    # Fetch receiver's public key
    try:
        resp = requests.get(f"{RECEIVER_URL}/public_key", timeout=5)
        receiver_pk_b64 = resp.json()["public_key"]
        from umbral import PublicKey
        receiver_pk = PublicKey.from_bytes(base64.b64decode(receiver_pk_b64))
    except Exception as e:
        return jsonify({"error": f"receiver key fetch failed: {e}"}), 502

    share_id = str(uuid.uuid4())
    kfrags = generate_kfrags(
        delegating_sk=_sender_sk,
        receiving_pk=receiver_pk,
        signer=_sender_signer,
        threshold=1,
        shares=1,
    )

    # Register new share with broker
    resp = requests.post(f"{BROKER_URL}/add_share", json={
        "payload_id": payload_id,
        "share_id": share_id,
        "kfrags": _serialize_kfrags(kfrags),
        "receiver_pk": receiver_pk_b64,
        "delegating_pk": _serialize_pk(_sender_pk),
        "verifying_pk": _serialize_pk(_sender_signer.verifying_key()),
    })
    if resp.status_code != 200:
        return jsonify({"error": "broker add_share failed", "detail": resp.json()}), 502

    _state[payload_id]["shares"][share_id] = True
    app.logger.info(f"[SHARE] payload={payload_id}  new_share={share_id}  (Umbral PRE)")
    return jsonify({
        "payload_id": payload_id,
        "share_id": share_id,
        "share_token": share_id,
    }), 200


@app.route("/revoke/<payload_id>", methods=["POST"])
def revoke(payload_id):
    """
    Revoke a share. Tells broker to destroy the kfrags.
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
    app.logger.info(f"[REVOKE] payload={payload_id}  share={share_id}  ✓ DESTROYED (kfrags deleted)")
    return jsonify({
        "status": "revoked",
        "payload_id": payload_id,
        "share_id": share_id,
        "receipt": receipt,
    }), 200


if __name__ == "__main__":
    app.run(port=8011, debug=False)
