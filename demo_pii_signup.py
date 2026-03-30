#!/usr/bin/env python3
"""
Clawback Protocol — PII Revocation Demo
Scenario: Website Signup Data Sharing

Demonstrates Clawback protecting PII from a realistic website signup scenario.
A user signs up, their PII is shared with a data broker, then the user exercises
their right to revocation. The broker must provably destroy the data.
"""

import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "broker"))

BROKER_PORT = 8010
SENDER_PORT = 8011
RECEIVER_PORT = 8012

BROKER_URL = f"http://localhost:{BROKER_PORT}"
SENDER_URL = f"http://localhost:{SENDER_PORT}"
RECEIVER_URL = f"http://localhost:{RECEIVER_PORT}"

# ── Colors ────────────────────────────────────────────────────────────────────
CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
BOLD = "\033[1m"
RESET = "\033[0m"

processes = []
results = []


def banner(text):
    print(f"\n{CYAN}{BOLD}{'═' * 50}{RESET}")
    print(f"{CYAN}{BOLD}  {text}{RESET}")
    print(f"{CYAN}{BOLD}{'═' * 50}{RESET}")


def step(text):
    print(f"\n{YELLOW}▶ {text}{RESET}")


def ok(text):
    print(f"{GREEN}  ✓ {text}{RESET}")


def fail(text):
    print(f"{RED}  ✗ FAILED: {text}{RESET}")


def check(name, condition, detail=""):
    if condition:
        ok(name)
        results.append((name, True))
    else:
        fail(f"{name} — {detail}" if detail else name)
        results.append((name, False))
    return condition


def cleanup():
    for p in processes:
        try:
            os.kill(p.pid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
    # Clean up receipts files
    for path in [
        os.path.join(ROOT, "broker", "receipts.jsonl"),
        os.path.join(ROOT, "poc", "broker", "receipts.jsonl"),
    ]:
        if os.path.exists(path):
            os.remove(path)


def start_services():
    """Start all three services as subprocesses."""
    step("Starting services...")

    broker = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=os.path.join(ROOT, "broker"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    processes.append(broker)
    ok(f"Broker starting on port {BROKER_PORT}")

    sender = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=os.path.join(ROOT, "sender"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    processes.append(sender)
    ok(f"Sender starting on port {SENDER_PORT}")

    receiver = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=os.path.join(ROOT, "receiver"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    processes.append(receiver)
    ok(f"Receiver starting on port {RECEIVER_PORT}")

    # Wait for all three services to be healthy
    step("Waiting for services to be ready...")
    urls = [
        (BROKER_URL, "Broker"),
        (SENDER_URL, "Sender"),
        (RECEIVER_URL, "Receiver"),
    ]
    for base_url, name in urls:
        ready = False
        # Broker has /health, sender/receiver just need to accept connections
        check_url = f"{base_url}/health" if name == "Broker" else base_url
        for attempt in range(30):
            try:
                r = requests.get(check_url, timeout=1)
                # Any response (even 404) means the service is up
                ready = True
                break
            except (requests.ConnectionError, requests.Timeout):
                pass
            time.sleep(0.5)
        if not ready:
            fail(f"{name} not responding after 15s")
            return False
        ok(f"{name} ready")
    return True


def main():
    banner("Clawback Protocol — PII Revocation Demo")
    print(f"  {CYAN}Scenario: Website Signup Data Sharing{RESET}")

    try:
        if not start_services():
            sys.exit(1)

        # ── Generate fake PII ─────────────────────────────────────────────
        step("Generating fake PII for website signup...")
        pii_payload = {
            "name": "Jordan Riley",
            "email": "jordan.riley.8847@gmail.com",
            "phone": "+1-555-847-2931",
            "dob": "1994-07-15",
            "address": "2847 Maple Street, Austin TX 78701",
            "ssn_last4": "4821",
            "signup_ip": "73.124.88.201",
            "device_fingerprint": "Mozilla/5.0 Chrome/121 ...",
            "signup_timestamp": datetime.now(timezone.utc).isoformat(),
            "consent_given": True,
        }

        print(f"  Name:    {pii_payload['name']}")
        print(f"  Email:   {pii_payload['email']}")
        print(f"  Phone:   {pii_payload['phone']}")
        print(f"  DOB:     {pii_payload['dob']}")
        print(f"  Address: {pii_payload['address']}")
        print(f"  SSN-4:   {pii_payload['ssn_last4']}")

        # ── Encrypt and register ──────────────────────────────────────────
        step("[SENDER] Encrypting PII locally...")
        plaintext = json.dumps(pii_payload)
        resp = requests.post(
            f"{SENDER_URL}/encrypt",
            json={"plaintext": plaintext},
            timeout=5,
        )
        encrypt_ok = check(
            "Payload registered with broker",
            resp.status_code == 201,
            f"HTTP {resp.status_code}: {resp.text}",
        )

        if not encrypt_ok:
            raise SystemExit(1)

        data = resp.json()
        payload_id = data["payload_id"]
        share_token = data["share_token"]
        ok(f"Payload registered: {payload_id}")
        ok(f"Share token issued: {share_token}")

        # ── Platform data broker fetches PII ──────────────────────────────
        step("[PLATFORM BROKER] Fetching user data...")
        resp = requests.post(
            f"{RECEIVER_URL}/receive",
            json={"payload_id": payload_id, "share_token": share_token},
            timeout=5,
        )
        receive_ok = check(
            "PII received and decrypted",
            resp.status_code == 200,
            f"HTTP {resp.status_code}: {resp.text}",
        )

        if receive_ok:
            decrypted = json.loads(resp.json()["plaintext"])
            ok(f"Data: {decrypted['name']}, {decrypted['email']}, {decrypted['phone']}")

        # ── User exercises right to revocation ────────────────────────────
        step("[USER] Exercising right to revocation...")
        resp = requests.post(
            f"{SENDER_URL}/revoke/{payload_id}",
            json={"share_id": share_token},
            timeout=5,
        )
        revoke_ok = check(
            "Kfrags DESTROYED on broker (Umbral PRE)",
            resp.status_code == 200,
            f"HTTP {resp.status_code}: {resp.text}",
        )

        if revoke_ok:
            revoke_data = resp.json()
            receipt = revoke_data.get("receipt", {})
            proof = receipt.get("destruction_proof", "")
            attestation = receipt.get("attestation", {})
            ok(f"Destruction proof: {proof[:16]}...")
            if attestation:
                pcr0 = attestation.get("pcrs", {}).get("pcr0", attestation.get("pcr0", ""))
                ok(f"Attestation: pcr0={pcr0[:16]}... provider={attestation.get('provider', 'unknown')}")

        # ── Platform tries re-access after revocation ─────────────────────
        step("[PLATFORM BROKER] Attempting re-access after revocation...")
        resp = requests.post(
            f"{RECEIVER_URL}/receive",
            json={"payload_id": payload_id, "share_token": share_token},
            timeout=5,
        )
        check(
            "HTTP 403 REVOKED — access correctly denied",
            resp.status_code == 403,
            f"Expected 403, got {resp.status_code}",
        )

        # ── Verify receipt on broker ──────────────────────────────────────
        step("Verifying destruction receipt on broker...")
        resp = requests.get(
            f"{BROKER_URL}/receipts/{payload_id}",
            timeout=5,
        )
        if resp.status_code == 200:
            receipts = resp.json().get("receipts", [])
            found = any(r.get("status") == "DESTROYED" for r in receipts)
            check(
                f"Receipt found: payload_id={payload_id}, status=DESTROYED",
                found,
                "No DESTROYED receipt found",
            )
        else:
            check("Receipt retrieval", False, f"HTTP {resp.status_code}")

        # ── Verify attestation document ──────────────────────────────────
        step("Verifying attestation document...")
        if revoke_ok and attestation:
            from nitro_attestation import verify_attestation_document

            att_valid = verify_attestation_document(attestation)
            pcr0 = attestation.get("pcrs", {}).get(
                "pcr0", attestation.get("pcr0", "")
            )
            provider = attestation.get("provider", "unknown")
            check(
                "Attestation document is verifiable",
                att_valid,
                "Attestation signature verification failed",
            )
            if att_valid:
                ok(f"Attestation verified: code_hash={pcr0[:16]}... provider={provider}")
                ok("In production: verify pcr0 against published release hash")
        else:
            check(
                "Attestation document is verifiable",
                False,
                "No attestation document available (revocation may have failed)",
            )

        # ── Summary ───────────────────────────────────────────────────────
        banner("Results")
        passed = sum(1 for _, p in results if p)
        total = len(results)

        if passed == total:
            print(f"\n  {GREEN}{BOLD}RESULT: ALL {total} CHECKS PASSED{RESET}\n")
        else:
            print(f"\n  {RED}{BOLD}RESULT: {passed}/{total} CHECKS PASSED{RESET}")
            for name, passed in results:
                if not passed:
                    print(f"  {RED}  ✗ {name}{RESET}")
            print()

        sys.exit(0 if passed == total else 1)

    finally:
        cleanup()


if __name__ == "__main__":
    main()
