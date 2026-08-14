#!/usr/bin/env bash
# CapAuth identity-state backup - scheduled, retained, off-box optional.
#
# Backs up the recoverable identity STATE that has no other automated backup:
#   1. The verification-service keystore (SQLite `keys.db`) - the enrolled
#      consumer public keys / fingerprints (PII-minimal, no private key material).
#   2. The bunker pairing session store (`bunker_sessions.json`) - approved
#      phone<->desktop pairings (session id + opaque join token, NO key material)
#      persisted by the broker, when present.
#   3. The identity PUBLIC key (`identity/public.asc`) - public material only,
#      so `capauth doctor`'s backup_restorable check can PROVE the identity
#      comes back, not just the keystore.
#   4. The Authentik Postgres DB (flows, stages, OAuth providers) - ONLY when a
#      target is configured. This holds the .13 edge SSO wiring for forgejo/sksso.
#
# What it deliberately does NOT touch (see docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md):
#   - The ROOT PRIVATE KEY. Per the DR runbook Step 1, the root key lives in
#     Chef's OFFLINE custody (two independent copies, ROOT_ROTATION_CEREMONY.md
#     Phase 0). It is never written to an automated cron backup. This script will
#     refuse to copy `private.asc` / `.gnupg` private material.
#   - Operator identity.json and per-agent capauth profiles - already covered by
#     the sovereign backup / Syncthing (DR runbook Step 5).
#
# Safety:
#   - Read-only against the live DB (uses sqlite3 online `.backup`; never writes
#     the source). Idempotent: each run creates its own timestamped dir.
#   - NEVER echoes or persists secrets. Postgres password is read from the
#     environment / ~/.pgpass only and is never printed.
#   - Backup dir is created 0700; dumps are 0600.
#
# Restore: scripts/capauth-restore.sh consumes the artifacts this produces
# (confirm-gated round-trip). The ordered cold-machine procedure and the Chef-only
# steps are in docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md. This script only PRODUCES
# the artifacts; it does not restore.
#
# Usage:
#   scripts/capauth-backup.sh            # run a backup now
#   scripts/capauth-backup.sh --dry-run  # show what would happen, touch nothing
#
# Configuration (all via env, sane defaults):
#   CAPAUTH_HOME               capauth home (default: ~/.skcapstone/capauth when it
#                              exists, else legacy ~/.capauth; matches
#                              capauth.resolve_capauth_home())
#   CAPAUTH_DB_PATH            keystore SQLite path (default <home>/service/keys.db)
#   CAPAUTH_BUNKER_STORE       bunker session store path (default
#                              <home>/service/bunker_sessions.json; "" disables)
#   CAPAUTH_DATA_VOLUME        docker volume holding /data/keys.db when the host
#                              path is absent (default: capauth_data)
#   CAPAUTH_BACKUP_DIR         where backups are written (default <home>/backups)
#   CAPAUTH_BACKUP_RETAIN_DAYS prune backups older than N days (default 14)
#   CAPAUTH_BACKUP_REMOTE      optional rsync target for off-box copy
#                              (e.g. user@host:/srv/capauth-backups). Unset = local only.
#   Authentik Postgres (all must be set to enable the pg_dump leg):
#   CAPAUTH_AUTHENTIK_PG_HOST, CAPAUTH_AUTHENTIK_PG_PORT (default 5432),
#   CAPAUTH_AUTHENTIK_PG_DB, CAPAUTH_AUTHENTIK_PG_USER
#   Password: export PGPASSWORD or use ~/.pgpass (never passed on the CLI).

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
# Home resolution MUST match capauth.resolve_capauth_home(): explicit override,
# then the modern ~/.skcapstone/capauth when it exists, then legacy ~/.capauth.
# Defaulting straight to the legacy path meant that on a node using the modern
# home this script exited 0 having backed up NOTHING, warning only that a
# keystore was "not found" when it was simply somewhere else. A backup that
# silently covers nothing is worse than none: doctor's backups_configured check
# goes green on the empty directory it just made.
if [[ -n "${CAPAUTH_HOME:-}" ]]; then
    CAPAUTH_HOME_DIR="$CAPAUTH_HOME"
elif [[ -d "$HOME/.skcapstone/capauth" ]]; then
    CAPAUTH_HOME_DIR="$HOME/.skcapstone/capauth"
else
    CAPAUTH_HOME_DIR="$HOME/.capauth"
fi
DB_PATH="${CAPAUTH_DB_PATH:-$CAPAUTH_HOME_DIR/service/keys.db}"
# Bunker pairing session store (persisted by the broker; see service/bunker.py).
# CAPAUTH_BUNKER_STORE="" disables the leg, matching the service's own override.
if [[ -n "${CAPAUTH_BUNKER_STORE+x}" ]]; then
    BUNKER_STORE="$CAPAUTH_BUNKER_STORE"
else
    BUNKER_STORE="$CAPAUTH_HOME_DIR/service/bunker_sessions.json"
fi
DATA_VOLUME="${CAPAUTH_DATA_VOLUME:-capauth_data}"
BACKUP_ROOT="${CAPAUTH_BACKUP_DIR:-$CAPAUTH_HOME_DIR/backups}"
RETAIN_DAYS="${CAPAUTH_BACKUP_RETAIN_DAYS:-14}"
REMOTE="${CAPAUTH_BACKUP_REMOTE:-}"

PG_HOST="${CAPAUTH_AUTHENTIK_PG_HOST:-}"
PG_PORT="${CAPAUTH_AUTHENTIK_PG_PORT:-5432}"
PG_DB="${CAPAUTH_AUTHENTIK_PG_DB:-}"
PG_USER="${CAPAUTH_AUTHENTIK_PG_USER:-}"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

TS="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$BACKUP_ROOT/capauth-backup-$TS"

# ── Output helpers (status only, never secrets) ───────────────────────────────
log()  { echo "[capauth-backup] $*"; }
warn() { echo "[capauth-backup] WARN: $*" >&2; }
die()  { echo "[capauth-backup] ERROR: $*" >&2; exit 1; }

run() {
    # Echo the action; execute unless --dry-run.
    log "$*"
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    "$@"
}

sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
    elif command -v shasum   >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
    else echo "(sha256 unavailable)"; fi
}

# ── Preflight ─────────────────────────────────────────────────────────────────
log "run $TS  (dry-run=$DRY_RUN)"
log "destination: $DEST"

if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY RUN - no files will be created, no commands with side effects run."
fi

run mkdir -p "$DEST"
[[ "$DRY_RUN" -eq 0 ]] && chmod 700 "$BACKUP_ROOT" "$DEST"

MANIFEST="$DEST/MANIFEST.txt"
manifest() { [[ "$DRY_RUN" -eq 1 ]] && return 0; echo "$*" >> "$MANIFEST"; }

manifest "CapAuth identity-state backup"
manifest "timestamp_utc: $TS"
manifest "host: $(hostname)"
manifest "note: root private key is NOT included (offline custody only)"
manifest "restore: docs/COLD_MACHINE_BOOTSTRAP_AND_DR.md"
manifest ""

BACKED_UP_ANY=0

# ── 1. Keystore (SQLite keys.db) ──────────────────────────────────────────────
backup_keystore() {
    local dst="$DEST/keys.db"

    if [[ -f "$DB_PATH" ]]; then
        # Guard: never let this be a private-key file by mistake.
        case "$(basename "$DB_PATH")" in
            private.asc|*.gpg|*.key) die "refusing to back up private key material: $DB_PATH" ;;
        esac
        log "keystore: host path $DB_PATH -> keys.db (online .backup)"
        if [[ "$DRY_RUN" -eq 0 ]]; then
            if command -v sqlite3 >/dev/null 2>&1; then
                # Online backup: consistent snapshot of a live DB, source untouched.
                sqlite3 "$DB_PATH" ".backup '$dst'"
            else
                warn "sqlite3 not found; falling back to cp (best-effort consistency)"
                cp -p "$DB_PATH" "$dst"
            fi
            chmod 600 "$dst"
            manifest "keys.db: source=$DB_PATH bytes=$(stat -c%s "$dst" 2>/dev/null || stat -f%z "$dst") sha256=$(sha "$dst")"
        fi
        BACKED_UP_ANY=1
        return 0
    fi

    # Host path absent - try the docker volume (container may own /data).
    if command -v docker >/dev/null 2>&1 && docker volume inspect "$DATA_VOLUME" >/dev/null 2>&1; then
        log "keystore: host path absent; pulling keys.db from docker volume $DATA_VOLUME"
        if [[ "$DRY_RUN" -eq 0 ]]; then
            # Copy out via a throwaway read-only mount. cp of a live sqlite is
            # best-effort; for a running service prefer a maintenance window.
            docker run --rm -v "$DATA_VOLUME":/data:ro -v "$DEST":/backup \
                busybox sh -c 'test -f /data/keys.db && cp /data/keys.db /backup/keys.db' \
                || { warn "keys.db not present in volume $DATA_VOLUME"; return 0; }
            chmod 600 "$dst" 2>/dev/null || true
            manifest "keys.db: source=docker-volume:$DATA_VOLUME bytes=$(stat -c%s "$dst" 2>/dev/null || echo '?') sha256=$(sha "$dst")"
        fi
        BACKED_UP_ANY=1
        return 0
    fi

    warn "no keystore found at $DB_PATH and no docker volume $DATA_VOLUME; skipping keystore leg"
}

# ── 2. Bunker pairing sessions (optional) ─────────────────────────────────────
# The broker persists approved phone<->desktop pairings to bunker_sessions.json
# (session id + opaque pairing token + TTL + replay ids; NEVER key material -
# the broker never holds a key). Restoring it lets an in-flight pairing survive a
# machine rebuild instead of forcing every client to re-pair.
backup_bunker() {
    if [[ -z "$BUNKER_STORE" ]]; then
        log "bunker store: disabled (CAPAUTH_BUNKER_STORE=\"\"); skipping"
        return 0
    fi
    if [[ ! -f "$BUNKER_STORE" ]]; then
        log "bunker store: none at $BUNKER_STORE (no live pairings); skipping"
        return 0
    fi
    # Guard: this must be the JSON session store, never a key file.
    case "$(basename "$BUNKER_STORE")" in
        private.asc|*.gpg|*.key|*.asc) die "refusing to back up key-like file as bunker store: $BUNKER_STORE" ;;
    esac
    local dst="$DEST/bunker_sessions.json"
    log "bunker store: $BUNKER_STORE -> bunker_sessions.json"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        cp -p "$BUNKER_STORE" "$dst"
        chmod 600 "$dst"
        manifest "bunker_sessions.json: source=$BUNKER_STORE bytes=$(stat -c%s "$dst" 2>/dev/null || stat -f%z "$dst") sha256=$(sha "$dst")"
    fi
    BACKED_UP_ANY=1
}

# ── 2b. Identity PUBLIC key (public material only) ────────────────────────────
# doctor's backup_restorable check compares the live identity/public.asc against
# the copy in the newest backup: without it, restorability can be asserted but
# never proven, since a keys.db alone says nothing about whether the identity
# itself comes back. Public key material only; the private-half refusal below
# is the invariant and is deliberately belt-and-braces.
backup_identity_pubkey() {
    local src="$CAPAUTH_HOME_DIR/identity/public.asc"
    local dst="$DEST/public.asc"
    [[ -f "$src" ]] || { log "identity public key: none at $src; skipping"; return 0; }
    case "$(basename "$src")" in
        private.asc|*.gpg|*.key) die "refusing to back up private key material: $src" ;;
    esac
    if grep -qi "PRIVATE KEY BLOCK" "$src" 2>/dev/null; then
        die "refusing to back up $src: it contains a PRIVATE key block"
    fi
    log "identity public key: $src -> public.asc"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        cp -p "$src" "$dst"
        chmod 600 "$dst"
        manifest "public.asc: source=$src sha256=$(sha "$dst")"
    fi
    BACKED_UP_ANY=1
}

# ── 3. Authentik Postgres (optional) ──────────────────────────────────────────
backup_authentik_pg() {
    if [[ -z "$PG_HOST" || -z "$PG_DB" || -z "$PG_USER" ]]; then
        log "authentik pg: not configured (CAPAUTH_AUTHENTIK_PG_HOST/DB/USER unset); skipping"
        return 0
    fi
    if ! command -v pg_dump >/dev/null 2>&1; then
        warn "authentik pg configured but pg_dump not found; skipping"
        return 0
    fi

    local dst="$DEST/authentik-${PG_DB}.sql.gz"
    # Password comes from PGPASSWORD/~/.pgpass - never placed on the CLI, never logged.
    log "authentik pg: pg_dump $PG_USER@$PG_HOST:$PG_PORT/$PG_DB -> $(basename "$dst")"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        if pg_dump --host="$PG_HOST" --port="$PG_PORT" --username="$PG_USER" \
                   --dbname="$PG_DB" --no-password --format=plain 2>"$DEST/.pg_dump.err" \
                   | gzip -9 > "$dst"; then
            chmod 600 "$dst"
            rm -f "$DEST/.pg_dump.err"
            manifest "authentik-${PG_DB}.sql.gz: source=pg://$PG_USER@$PG_HOST:$PG_PORT/$PG_DB bytes=$(stat -c%s "$dst" 2>/dev/null || stat -f%z "$dst") sha256=$(sha "$dst")"
            BACKED_UP_ANY=1
        else
            warn "pg_dump failed (see stderr capture); check credentials in ~/.pgpass. Not aborting other legs."
            # Preserve error but ensure no partial dump masquerades as good.
            rm -f "$dst"
        fi
    else
        BACKED_UP_ANY=1
    fi
}

# ── 4. Off-box copy (optional) ────────────────────────────────────────────────
copy_offbox() {
    [[ -z "$REMOTE" ]] && { log "off-box: CAPAUTH_BACKUP_REMOTE unset; local retention only"; return 0; }
    if ! command -v rsync >/dev/null 2>&1; then
        warn "off-box target set but rsync not found; skipping off-box copy"
        return 0
    fi
    log "off-box: rsync $DEST/ -> $REMOTE/"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        rsync -a --chmod=D700,F600 "$DEST" "$REMOTE/" \
            || warn "off-box rsync failed; local backup retained"
    fi
}

# ── 5. Rotation ───────────────────────────────────────────────────────────────
rotate() {
    log "rotation: pruning backups older than $RETAIN_DAYS days under $BACKUP_ROOT"
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    # Only prune our own timestamped dirs; never anything else.
    find "$BACKUP_ROOT" -maxdepth 1 -type d -name 'capauth-backup-*' \
        -mtime +"$RETAIN_DAYS" -print -exec rm -rf {} + 2>/dev/null || true
}

# ── Main ──────────────────────────────────────────────────────────────────────
backup_keystore
backup_bunker
backup_identity_pubkey
backup_authentik_pg

if [[ "$BACKED_UP_ANY" -eq 0 ]]; then
    warn "nothing was backed up - no keystore and no Authentik pg configured"
    # Remove the manifest-only dir so rotation math stays clean.
    [[ "$DRY_RUN" -eq 0 ]] && rm -rf "$DEST" 2>/dev/null || true
    exit 3
fi

copy_offbox
rotate

log "done: $DEST"
[[ "$DRY_RUN" -eq 0 ]] && log "manifest: $MANIFEST"
# Explicit success: the guard above is a no-op on --dry-run and must not become
# the script's (failing) exit status.
exit 0
