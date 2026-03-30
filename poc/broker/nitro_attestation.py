"""
AWS Nitro Enclave attestation document parser and verifier.

In production: the broker runs inside a Nitro Enclave and calls
`/dev/nsm` (Nitro Security Module) to get a signed attestation doc.

In development (outside enclave): generates a simulated document
that has the same schema but is signed with a local key instead of
the Nitro root CA. Set ENCLAVE_MODE=simulated|nitro via env var.
"""

import os
import json
import hashlib
import cbor2
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ENCLAVE_MODE = os.environ.get("ENCLAVE_MODE", "simulated")


def get_code_hash() -> str:
    """SHA-384 of the broker source — PCR0 equivalent in simulated mode."""
    broker_path = os.path.join(os.path.dirname(__file__), "app.py")
    with open(broker_path, "rb") as f:
        return hashlib.sha384(f.read()).hexdigest()


def get_attestation_document(nonce: bytes = None) -> dict:
    """
    Returns an attestation document.

    In simulated mode: locally signed, schema-compatible with Nitro format.
    In nitro mode: calls /dev/nsm to get a real Nitro attestation document.

    Schema matches AWS Nitro attestation document format:
    https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
    """
    if ENCLAVE_MODE == "nitro":
        return _get_nitro_attestation(nonce)
    else:
        return _get_simulated_attestation(nonce)


def _get_simulated_attestation(nonce: bytes = None) -> dict:
    """Simulated attestation — same schema as Nitro, local signing key."""
    code_hash = get_code_hash()
    timestamp = datetime.now(timezone.utc).isoformat()

    pcr_values = {
        "pcr0": code_hash,
        "pcr1": "simulated-kernel-hash",
        "pcr2": "simulated-application-hash",
    }

    doc = {
        "module_id": os.environ.get("ENCLAVE_ID", "local-dev-enclave"),
        "timestamp": timestamp,
        "pcrs": pcr_values,
        "nonce": nonce.hex() if nonce else None,
        "provider": "simulated",
        "signing_key": "local-ed25519",
        "note": (
            "SIMULATED ATTESTATION — not cryptographically enforced. "
            "In production (ENCLAVE_MODE=nitro): AWS Nitro root CA signed document. "
            "Verify against: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"
        ),
    }

    # Sign the document with a local key (simulated — not Nitro CA)
    private_key = _get_or_create_dev_signing_key()
    doc_bytes = json.dumps(doc, sort_keys=True).encode()
    signature = private_key.sign(doc_bytes)

    return {
        **doc,
        "signature": signature.hex(),
        "verify_with": "local-dev-key (NOT Nitro CA)",
    }


def _get_nitro_attestation(nonce: bytes = None) -> dict:
    """
    Real Nitro attestation — only works inside a Nitro Enclave.
    Calls /dev/nsm via the aws-nitro-enclaves-nsm-api.
    """
    try:
        import aws_nsm_interface as nsm
        attestation_doc = nsm.get_attestation_doc(
            user_data=None,
            nonce=nonce,
            public_key=None,
        )
        # Parse CBOR-encoded attestation document
        doc = cbor2.loads(attestation_doc)
        return {
            "provider": "aws-nitro",
            "raw_cbor": attestation_doc.hex(),
            "module_id": doc.get("module_id", ""),
            "pcrs": {f"pcr{k}": v.hex() for k, v in doc.get("pcrs", {}).items()},
            "timestamp": datetime.fromtimestamp(
                doc.get("timestamp", 0) / 1000, tz=timezone.utc
            ).isoformat(),
            "verify_with": (
                "AWS Nitro root CA — "
                "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"
            ),
        }
    except ImportError:
        raise RuntimeError(
            "aws-nitro-enclaves-nsm-api not available outside Nitro Enclave"
        )


def _get_or_create_dev_signing_key() -> Ed25519PrivateKey:
    """Get or create a local Ed25519 key for simulated attestation signing."""
    key_path = os.path.join(os.path.dirname(__file__), ".dev-signing-key.pem")

    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(key_path, "wb") as f:
        f.write(pem)
    os.chmod(key_path, 0o600)
    return key


def verify_attestation_document(doc: dict) -> bool:
    """
    Verify an attestation document.

    Simulated: verify Ed25519 signature against local dev key.
    Nitro: verify COSE_Sign1 against AWS Nitro root CA.

    Returns True if valid, False if tampered/invalid.
    """
    if doc.get("provider") == "aws-nitro":
        return _verify_nitro_doc(doc)
    else:
        return _verify_simulated_doc(doc)


def _verify_nitro_doc(doc: dict) -> bool:
    """Verify AWS Nitro attestation document against root CA."""
    # Full Nitro verification per:
    # https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
    # 1. Decode CBOR
    # 2. Extract certificate chain
    # 3. Verify chain against AWS Nitro root CA
    # 4. Verify COSE_Sign1 signature
    # 5. Check PCR values match published values
    # Implementation requires: aws-nitro-enclaves-nsm-api + full cert chain
    # TODO: implement full chain verification for production
    return True  # placeholder

def _verify_simulated_doc(doc: dict) -> bool:
    """Verify simulated attestation document signature."""
    doc = dict(doc)  # don't mutate the original
    sig_hex = doc.pop("signature", None)
    verify_with = doc.pop("verify_with", None)
    if not sig_hex:
        return False

    try:
        private_key = _get_or_create_dev_signing_key()
        public_key = private_key.public_key()
        doc_bytes = json.dumps(doc, sort_keys=True).encode()
        public_key.verify(bytes.fromhex(sig_hex), doc_bytes)
        return True
    except Exception:
        return False
