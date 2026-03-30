"""
Clawback Protocol — Receiver Service (port 8012)

The receiver:
  - Has its own Umbral keypair (sk_receiver, pk_receiver)
  - Exposes its public key via GET /public_key
  - Has a share token (share_id) from the sender
  - Asks broker for the encrypted blob + re-encrypted capsule fragments (cfrags)
  - Uses Umbral to decrypt the data key from the cfrags
  - Decrypts the payload locally with ChaCha20-Poly1305 + data key
  - Cannot access data if the share has been revoked (broker returns 403)
  - Never has access to the sender's private key

Crypto flow (Umbral PRE):
  broker returns: { encrypted_blob, capsule, cfrags[], capsule_ciphertext, sender_pk }
  receiver:
    1. data_key = decrypt_reencrypted(receiver_sk, sender_pk, capsule, cfrags, capsule_ct)
    2. plaintext = ChaCha20.decrypt(encrypted_blob, data_key)

  If revoked: broker returns { error: "REVOKED" } → re-encryption impossible
"""

import os
import base64
from umbral import SecretKey, PublicKey, Capsule, decrypt_reencrypted, VerifiedCapsuleFrag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from flask import Flask, request, jsonify

app = Flask(__name__)

BROKER_URL = os.environ.get("BROKER_URL", "http://localhost:8010")

# ─── Umbral receiver keypair (persistent for lifetime of service) ────────────
_receiver_sk = SecretKey.random()
_receiver_pk = _receiver_sk.public_key()


def _decrypt_payload(blob: bytes, data_key: bytes) -> bytes:
    """Decrypt ChaCha20-Poly1305 blob (nonce || ciphertext) with data_key."""
    nonce, ct = blob[:12], blob[12:]
    chacha = ChaCha20Poly1305(data_key)
    return chacha.decrypt(nonce, ct, None)


@app.route("/public_key", methods=["GET"])
def public_key():
    """Returns the receiver's Umbral public key. Sender needs this to generate kfrags."""
    return jsonify({
        "public_key": base64.b64encode(bytes(_receiver_pk)).decode(),
    }), 200


@app.route("/receive", methods=["POST"])
def receive():
    """
    Attempt to receive and decrypt a shared payload via Umbral PRE.
    Body: { payload_id, share_token }
    Returns: { plaintext } or { error: "REVOKED" }
    """
    data = request.json
    payload_id = data.get("payload_id")
    share_token = data.get("share_token")

    if not payload_id or not share_token:
        return jsonify({"error": "payload_id and share_token required"}), 400

    import requests as req
    # Fetch from broker — if revoked, this 403s
    resp = req.get(
        f"{BROKER_URL}/fetch/{payload_id}",
        params={"share_id": share_token},
    )

    if resp.status_code == 403:
        broker_error = resp.json().get("error", "REVOKED")
        app.logger.warning(f"[RECEIVE] payload={payload_id}  share={share_token}  → REVOKED")
        return jsonify({
            "error": broker_error,
            "detail": "Access denied. This share has been revoked by the sender.",
        }), 403

    if resp.status_code != 200:
        return jsonify({"error": "broker fetch failed", "detail": resp.json()}), 502

    result = resp.json()

    try:
        # Deserialize Umbral objects from broker response
        encrypted_blob = base64.b64decode(result["encrypted_blob"])
        capsule = Capsule.from_bytes(base64.b64decode(result["capsule"]))
        capsule_ciphertext = base64.b64decode(result["capsule_ciphertext"])
        sender_pk = PublicKey.from_bytes(base64.b64decode(result["delegating_pk"]))
        cfrags = [VerifiedCapsuleFrag.from_verified_bytes(base64.b64decode(cf)) for cf in result["cfrags"]]

        # Use Umbral to recover the data key
        data_key = decrypt_reencrypted(
            receiving_sk=_receiver_sk,
            delegating_pk=sender_pk,
            capsule=capsule,
            verified_cfrags=cfrags,
            ciphertext=capsule_ciphertext,
        )

        # Decrypt the payload with the recovered data key
        plaintext = _decrypt_payload(encrypted_blob, data_key)
        app.logger.info(f"[RECEIVE] payload={payload_id}  share={share_token}  ✓ decrypted (Umbral PRE)")
        return jsonify({
            "payload_id": payload_id,
            "share_id": share_token,
            "plaintext": plaintext.decode("utf-8"),
            "status": "decrypted",
        }), 200
    except Exception as e:
        app.logger.error(f"[RECEIVE] decryption failed: {e}")
        return jsonify({"error": "decryption failed", "detail": str(e)}), 500


if __name__ == "__main__":
    app.run(port=8012, debug=False)
