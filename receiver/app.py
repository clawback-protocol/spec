"""
Clawback Protocol — Receiver Service (port 8002)

The receiver:
  - Has a share token (share_id) from the sender
  - Asks broker for the encrypted blob + their share key
  - Decrypts locally using the share key
  - Cannot access data if the share has been revoked (broker returns 403)
  - Never has access to the sender's master key

Crypto flow:
  broker returns: { encrypted_blob (b64), share_key (b64) }
  receiver: decrypt(encrypted_blob, share_key) → plaintext

  If revoked: broker returns { error: "REVOKED" } → decryption impossible
"""

import os
import base64
import requests
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from flask import Flask, request, jsonify

app = Flask(__name__)

BROKER_URL = os.environ.get("BROKER_URL", "http://localhost:8000")


def _decrypt(blob: bytes, key: bytes) -> bytes:
    """Decrypt ChaCha20-Poly1305 blob (nonce || ciphertext)."""
    nonce, ct = blob[:12], blob[12:]
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ct, None)


@app.route("/receive", methods=["POST"])
def receive():
    """
    Attempt to receive and decrypt a shared payload.
    Body: { payload_id, share_token }
    Returns: { plaintext } or { error: "REVOKED" }
    """
    data = request.json
    payload_id = data.get("payload_id")
    share_token = data.get("share_token")

    if not payload_id or not share_token:
        return jsonify({"error": "payload_id and share_token required"}), 400

    # Fetch from broker — if revoked, this 403s
    resp = requests.get(
        f"{BROKER_URL}/fetch/{payload_id}",
        params={"share_id": share_token}
    )

    if resp.status_code == 403:
        broker_error = resp.json().get("error", "REVOKED")
        app.logger.warning(f"[RECEIVE] payload={payload_id}  share={share_token}  → REVOKED")
        return jsonify({
            "error": broker_error,
            "detail": "Access denied. This share has been revoked by the sender."
        }), 403

    if resp.status_code != 200:
        return jsonify({"error": "broker fetch failed", "detail": resp.json()}), 502

    result = resp.json()
    encrypted_blob_b64 = result["encrypted_blob"]
    share_key_b64 = result["share_key"]

    encrypted_blob = base64.b64decode(encrypted_blob_b64)
    share_key = base64.b64decode(share_key_b64)

    try:
        plaintext = _decrypt(encrypted_blob, share_key)
        app.logger.info(f"[RECEIVE] payload={payload_id}  share={share_token}  ✓ decrypted")
        return jsonify({
            "payload_id": payload_id,
            "share_id": share_token,
            "plaintext": plaintext.decode("utf-8"),
            "status": "decrypted"
        }), 200
    except Exception as e:
        app.logger.error(f"[RECEIVE] decryption failed: {e}")
        return jsonify({"error": "decryption failed", "detail": str(e)}), 500


if __name__ == "__main__":
    app.run(port=8002, debug=False)
