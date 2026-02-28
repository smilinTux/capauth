#!/usr/bin/env bash
# CapAuth Verification Service — local deploy + smoke test
#
# Usage:
#   ./deploy.sh              # Start the service (builds if needed)
#   ./deploy.sh --test       # Start + run smoke tests
#   ./deploy.sh --stop       # Stop the service
#   ./deploy.sh --status     # Check service status
#
# Requires: docker, docker compose, curl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPAUTH_URL="${CAPAUTH_URL:-http://localhost:8420}"
MODE="${1:-}"

# ── Colour output ─────────────────────────────────────────────────────────────
green() { echo -e "\033[32m$*\033[0m"; }
red()   { echo -e "\033[31m$*\033[0m"; }
blue()  { echo -e "\033[36m$*\033[0m"; }

# ── Generate .env if missing ──────────────────────────────────────────────────
if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
    blue "→ No .env found, generating from .env.example..."
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    # Generate random secrets
    ADMIN_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(24))")
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s/change-me-admin-token-min-32-chars/$ADMIN_TOKEN/" "$SCRIPT_DIR/.env"
    sed -i "s/change-me-jwt-secret-at-least-32-chars/$JWT_SECRET/" "$SCRIPT_DIR/.env"
    green "✓ Generated .env with random secrets"
fi

# ── Handle modes ──────────────────────────────────────────────────────────────
case "$MODE" in
    --stop)
        blue "→ Stopping capauth service..."
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" --env-file "$SCRIPT_DIR/.env" down
        green "✓ Stopped"
        exit 0
        ;;
    --status)
        curl -sf "$CAPAUTH_URL/capauth/v1/status" | python3 -m json.tool
        exit 0
        ;;
    --test)
        DO_TEST=1
        ;;
    "")
        DO_TEST=0
        ;;
    *)
        echo "Unknown option: $MODE"
        echo "Usage: $0 [--test|--stop|--status]"
        exit 1
        ;;
esac

# ── Start service ─────────────────────────────────────────────────────────────
blue "→ Starting CapAuth Verification Service..."
docker compose \
    -f "$SCRIPT_DIR/docker-compose.yml" \
    --env-file "$SCRIPT_DIR/.env" \
    up -d --build

# ── Wait for health ───────────────────────────────────────────────────────────
blue "→ Waiting for service to be healthy..."
MAX_WAIT=60
ELAPSED=0
until curl -sf "$CAPAUTH_URL/capauth/v1/status" >/dev/null 2>&1; do
    if (( ELAPSED >= MAX_WAIT )); then
        red "✗ Service did not become healthy within ${MAX_WAIT}s"
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" logs capauth | tail -20
        exit 1
    fi
    sleep 2
    (( ELAPSED += 2 ))
done

green "✓ CapAuth service is up at $CAPAUTH_URL"

# ── Show status ───────────────────────────────────────────────────────────────
echo ""
blue "── Service Status ──────────────────────────────────────"
curl -sf "$CAPAUTH_URL/capauth/v1/status" | python3 -m json.tool
echo ""

# ── OIDC discovery ────────────────────────────────────────────────────────────
blue "── OIDC Discovery ──────────────────────────────────────"
curl -sf "$CAPAUTH_URL/.well-known/openid-configuration" | python3 -m json.tool 2>/dev/null || \
    echo "(OIDC discovery endpoint not yet configured)"
echo ""

# ── Smoke tests ───────────────────────────────────────────────────────────────
if [[ "${DO_TEST:-0}" == "1" ]]; then
    blue "── Smoke Tests ─────────────────────────────────────────"

    # Test 1: challenge endpoint
    blue "→ Test 1: Issue challenge nonce..."
    CHALLENGE=$(curl -sf -X POST "$CAPAUTH_URL/capauth/v1/challenge" \
        -H "Content-Type: application/json" \
        -d '{"fingerprint": "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF", "client_nonce": "dGVzdA=="}')
    if echo "$CHALLENGE" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'nonce' in d" 2>/dev/null; then
        green "✓ Challenge issued"
    else
        red "✗ Challenge failed: $CHALLENGE"
    fi

    # Test 2: admin key list (requires admin token)
    blue "→ Test 2: Admin key list..."
    ADMIN_TOKEN=$(grep CAPAUTH_ADMIN_TOKEN "$SCRIPT_DIR/.env" | cut -d= -f2)
    KEY_LIST=$(curl -sf "$CAPAUTH_URL/capauth/v1/keys" \
        -H "Authorization: Bearer $ADMIN_TOKEN")
    if echo "$KEY_LIST" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d, list)" 2>/dev/null; then
        green "✓ Admin key list endpoint works"
    else
        red "✗ Admin key list failed: $KEY_LIST"
    fi

    # Test 3: Python e2e tests (if capauth is installed)
    if command -v pytest >/dev/null 2>&1; then
        blue "→ Test 3: Running Python e2e suite..."
        REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
        if cd "$REPO_ROOT" && python -m pytest tests/test_real_pgp_e2e.py -v 2>&1 | tail -15; then
            green "✓ E2E suite passed"
        else
            red "✗ E2E suite had failures (see above)"
        fi
    fi

    echo ""
    green "── All smoke tests complete ────────────────────────────"
fi
