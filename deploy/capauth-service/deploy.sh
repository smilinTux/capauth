#!/usr/bin/env bash
# DEPRECATED (2026-09-26): drives the standalone public verification-service
# container (docker-compose.yml in this directory). Chef decided 2026-09-26
# that capauth runs on localhost as the existing loopback authz PDP (systemd
# --user unit, see SOP.md Scenario A); this standalone mode is deprecated.
# PGP passwordless login for apps is covered by
# ghcr.io/smilintux/authentik-capauth (an Authentik stage, via sksso) instead.
# Kept as-is; not removed, not changed in behavior.
#
# CapAuth Verification Service - local deploy + smoke test
#
# Usage:
#   ./deploy.sh              # Start the service (builds if needed)
#   ./deploy.sh --test       # Start + run smoke tests
#   ./deploy.sh --stop       # Stop the service
#   ./deploy.sh --status     # Check service status
#   ./deploy.sh --provision  # Only generate/reuse the .env secrets, don't start
#
# Requires: docker, docker compose, curl
#
# Secrets: the generated .env is gitignored and is the only on-disk copy of
# CAPAUTH_ADMIN_TOKEN / CAPAUTH_JWT_SECRET. Back it up in skvault. Re-running
# reuses the existing .env (secrets are never rotated). To seed from a vault,
# export CAPAUTH_ADMIN_TOKEN / CAPAUTH_JWT_SECRET before the first run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPAUTH_URL="${CAPAUTH_URL:-http://localhost:8420}"
MODE="${1:-}"

# ── Colour output ─────────────────────────────────────────────────────────────
green() { echo -e "\033[32m$*\033[0m"; }
red()   { echo -e "\033[31m$*\033[0m"; }
blue()  { echo -e "\033[36m$*\033[0m"; }

# ── Provision service secrets into .env (idempotent, vault-friendly) ──────────
# The generated .env is gitignored (see repo .gitignore) so its secrets are
# NEVER committed. It is also the ONLY on-disk copy, so first-run provisioning
# prints a reminder to back it up durably (skvault). Re-running REUSES the
# existing .env verbatim, so restarts/redeploys never silently rotate the live
# CAPAUTH_ADMIN_TOKEN / CAPAUTH_JWT_SECRET.
#
# Vault-backed path: export CAPAUTH_ADMIN_TOKEN / CAPAUTH_JWT_SECRET (e.g. from
# skvault) before the first run and they are adopted verbatim instead of a
# freshly minted random value.
provision_secrets() {
    if [[ -f "$SCRIPT_DIR/.env" ]]; then
        blue "→ Reusing existing $SCRIPT_DIR/.env (secrets preserved, not rotated)"
        return 0
    fi

    blue "→ No .env found, provisioning from .env.example..."
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"

    # A value is "default" if unset/empty or still a committed change-me* placeholder.
    _is_default_secret() {
        case "${1:-}" in
            "" | change-me* | changeme* | CHANGE-ME* | CHANGEME* | change_me* | CHANGE_ME*) return 0 ;;
            *) return 1 ;;
        esac
    }

    local admin_token="${CAPAUTH_ADMIN_TOKEN:-}"
    local jwt_secret="${CAPAUTH_JWT_SECRET:-}"
    local adopted_admin=0 adopted_jwt=0
    if _is_default_secret "$admin_token"; then
        admin_token=$(python3 -c "import secrets; print(secrets.token_hex(24))")
    else
        adopted_admin=1
    fi
    if _is_default_secret "$jwt_secret"; then
        jwt_secret=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    else
        adopted_jwt=1
    fi

    # Rewrite the two keys robustly (no sed delimiter injection: adopted vault
    # secrets may contain / & | etc.). Values are passed via env, never argv.
    ADMIN_TOKEN="$admin_token" JWT_SECRET="$jwt_secret" python3 - "$SCRIPT_DIR/.env" <<'PY'
import os, sys
path = sys.argv[1]
repl = {
    "CAPAUTH_ADMIN_TOKEN": os.environ["ADMIN_TOKEN"],
    "CAPAUTH_JWT_SECRET": os.environ["JWT_SECRET"],
}
out = []
with open(path) as f:
    for line in f:
        key = line.split("=", 1)[0].strip()
        if key in repl:
            out.append(f"{key}={repl[key]}\n")
        else:
            out.append(line)
with open(path, "w") as f:
    f.writelines(out)
PY

    chmod 600 "$SCRIPT_DIR/.env"
    (( adopted_admin )) && blue "  · CAPAUTH_ADMIN_TOKEN adopted from environment (vault)" || blue "  · CAPAUTH_ADMIN_TOKEN generated (random)"
    (( adopted_jwt ))   && blue "  · CAPAUTH_JWT_SECRET adopted from environment (vault)"   || blue "  · CAPAUTH_JWT_SECRET generated (random)"
    green "✓ Provisioned $SCRIPT_DIR/.env (chmod 600, gitignored)"

    red "──────────────────────────────────────────────────────────────"
    red "  BACK UP THESE SECRETS: .env is the ONLY copy and is NOT in git."
    red "  A lost checkout silently rotates every deployed token."
    red "  Store it durably in skvault, e.g.:"
    red "    skvault put capauth-service-env < \"$SCRIPT_DIR/.env\""
    red "  Re-running deploy.sh REUSES this .env (no rotation)."
    red "──────────────────────────────────────────────────────────────"
}

provision_secrets

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
    --provision)
        # Secrets were provisioned above; do not start docker.
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
        echo "Usage: $0 [--test|--stop|--status|--provision]"
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
