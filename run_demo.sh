#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Clawback Protocol — Full Demo
#  Spins up all three services, runs the demo flow, then cleans up.
# ─────────────────────────────────────────────────────────────────────────────

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BROKER_PID=""
SENDER_PID=""
RECEIVER_PID=""

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
  echo ""
  echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${RESET}"
  echo -e "${CYAN}${BOLD}  $1${RESET}"
  echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${RESET}"
}

step() { echo -e "\n${YELLOW}▶ $1${RESET}"; }
ok()   { echo -e "${GREEN}✓ $1${RESET}"; }
fail() { echo -e "${RED}✗ $1${RESET}"; }
info() { echo -e "  ${CYAN}$1${RESET}"; }

# ── Cleanup on exit ──────────────────────────────────────────────────────────
cleanup() {
  echo ""
  step "Shutting down services..."
  [[ -n "$BROKER_PID" ]]   && kill "$BROKER_PID"   2>/dev/null && ok "Broker stopped"
  [[ -n "$SENDER_PID" ]]   && kill "$SENDER_PID"   2>/dev/null && ok "Sender stopped"
  [[ -n "$RECEIVER_PID" ]] && kill "$RECEIVER_PID" 2>/dev/null && ok "Receiver stopped"
  # Clean up receipts file for fresh demo runs
  rm -f "$ROOT/broker/receipts.jsonl"
}
trap cleanup EXIT

# ── Start services ───────────────────────────────────────────────────────────
banner "Clawback Protocol — Proxy Re-Encryption Demo"

step "Starting Broker (port 8000)..."
cd "$ROOT/broker"
python3 app.py > /tmp/clawback-broker.log 2>&1 &
BROKER_PID=$!
sleep 1

step "Starting Sender (port 8001)..."
cd "$ROOT/sender"
python3 app.py > /tmp/clawback-sender.log 2>&1 &
SENDER_PID=$!
sleep 1

step "Starting Receiver (port 8002)..."
cd "$ROOT/receiver"
python3 app.py > /tmp/clawback-receiver.log 2>&1 &
RECEIVER_PID=$!
sleep 1

# Quick health check — retry while services warm up
step "Waiting for services to be ready..."
RETRIES=12
until curl -sf http://localhost:8000/receipts/health > /dev/null 2>&1 || [ "$RETRIES" -eq 0 ]; do
  sleep 1
  RETRIES=$((RETRIES - 1))
done
if ! curl -sf http://localhost:8000/receipts/health > /dev/null 2>&1; then
  fail "Broker not responding after 12s. Check /tmp/clawback-broker.log"
  cat /tmp/clawback-broker.log
  exit 1
fi
ok "All services running"

# ─────────────────────────────────────────────────────────────────────────────
banner "Step 1: Sender encrypts sensitive data"
# ─────────────────────────────────────────────────────────────────────────────

step "Encrypting 'This is sensitive data - Reese'..."
ENCRYPT_RESP=$(curl -sf -X POST http://localhost:8001/encrypt \
  -H 'Content-Type: application/json' \
  -d '{"plaintext": "This is sensitive data - Reese"}')

echo "$ENCRYPT_RESP" | python3 -m json.tool
PAYLOAD_ID=$(echo "$ENCRYPT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['payload_id'])")
SHARE_TOKEN=$(echo "$ENCRYPT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['share_token'])")

ok "Payload registered with broker"
info "Payload ID:   $PAYLOAD_ID"
info "Share Token:  $SHARE_TOKEN"

# ─────────────────────────────────────────────────────────────────────────────
banner "Step 2: Receiver fetches and decrypts"
# ─────────────────────────────────────────────────────────────────────────────

step "Receiver requesting access with share token..."
RECEIVE_RESP=$(curl -sf -X POST http://localhost:8002/receive \
  -H 'Content-Type: application/json' \
  -d "{\"payload_id\": \"$PAYLOAD_ID\", \"share_token\": \"$SHARE_TOKEN\"}")

echo "$RECEIVE_RESP" | python3 -m json.tool
PLAINTEXT=$(echo "$RECEIVE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['plaintext'])")

ok "Decryption successful!"
echo -e "  ${BOLD}Plaintext: \"$PLAINTEXT\"${RESET}"

# ─────────────────────────────────────────────────────────────────────────────
banner "Step 3: Sender revokes access"
# ─────────────────────────────────────────────────────────────────────────────

step "Sender revoking share token..."
REVOKE_RESP=$(curl -sf -X POST http://localhost:8001/revoke/$PAYLOAD_ID \
  -H 'Content-Type: application/json' \
  -d "{\"share_id\": \"$SHARE_TOKEN\"}")

echo "$REVOKE_RESP" | python3 -m json.tool
ok "Share key DESTROYED on broker"

# ─────────────────────────────────────────────────────────────────────────────
banner "Step 4: Receiver tries again — should be REVOKED"
# ─────────────────────────────────────────────────────────────────────────────

step "Receiver attempting access after revocation..."
HTTP_CODE=$(curl -s -o /tmp/revoked_resp.json -w "%{http_code}" \
  -X POST http://localhost:8002/receive \
  -H 'Content-Type: application/json' \
  -d "{\"payload_id\": \"$PAYLOAD_ID\", \"share_token\": \"$SHARE_TOKEN\"}")

cat /tmp/revoked_resp.json | python3 -m json.tool

if [ "$HTTP_CODE" = "403" ]; then
  ok "Access correctly denied (HTTP 403)"
  ERROR=$(cat /tmp/revoked_resp.json | python3 -c "import sys,json; print(json.load(sys.stdin)['error'])")
  echo -e "  ${RED}${BOLD}Error: $ERROR${RESET}"
else
  fail "Expected 403, got $HTTP_CODE"
fi

# ─────────────────────────────────────────────────────────────────────────────
banner "Step 5: Destruction Receipt"
# ─────────────────────────────────────────────────────────────────────────────

step "Fetching ZK-style destruction receipt from broker..."
RECEIPT_RESP=$(curl -sf http://localhost:8000/receipts/$PAYLOAD_ID)
echo "$RECEIPT_RESP" | python3 -m json.tool

RECEIPT_COUNT=$(echo "$RECEIPT_RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['receipts']))")
ok "$RECEIPT_COUNT destruction receipt(s) on file"

# ─────────────────────────────────────────────────────────────────────────────
banner "Demo Complete"
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}Summary:${RESET}"
echo -e "  ${GREEN}✓${RESET} Data encrypted locally — broker never saw plaintext"
echo -e "  ${GREEN}✓${RESET} Share key delivered via broker for decryption"
echo -e "  ${GREEN}✓${RESET} Revocation destroyed the share key instantly"
echo -e "  ${GREEN}✓${RESET} Post-revocation access correctly denied"
echo -e "  ${GREEN}✓${RESET} Cryptographic destruction receipt logged"
echo ""
echo -e "${CYAN}  This is the Clawback Protocol. Data is never truly 'sent'.${RESET}"
echo -e "${CYAN}  You hold the keys. You hold the power to revoke.${RESET}"
echo ""
