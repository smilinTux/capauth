"""Nonce store for CapAuth challenge-response replay protection.

In a production Authentik deployment this module wraps Django's cache
framework (which may be Redis, Memcached, or local memory depending on
the instance configuration).

Each nonce is stored with:
  - The fingerprint that requested it
  - Issue and expiry timestamps
  - A ``used`` flag set to True after the nonce is consumed

A nonce that is expired OR already used is permanently rejected.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

# Authentik runs inside Django, so we use its cache framework.
# When running outside Authentik (tests, CLI), fall back to a simple
# in-process dict — good enough for single-threaded use.
try:
    from django.core.cache import cache as _django_cache

    _USE_DJANGO = True
except ImportError:
    _USE_DJANGO = False
    _MEM_CACHE: dict[str, str] = {}

NONCE_TTL_SECONDS: int = 60
CACHE_KEY_PREFIX: str = "capauth:nonce:"


def _key(nonce_id: str) -> str:
    """Build a cache key for a nonce UUID."""
    return f"{CACHE_KEY_PREFIX}{nonce_id}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def issue(fingerprint: str, client_nonce_echo: str = "") -> dict:
    """Create a new single-use nonce and store it.

    Args:
        fingerprint: The PGP fingerprint of the authenticating client.
        client_nonce_echo: Base64 client nonce to echo back in the challenge.
            Stored so that the canonical payload can be reconstructed at verify time.

    Returns:
        dict: Nonce record with keys ``nonce``, ``issued_at``, ``expires_at``,
            ``client_nonce_echo``.
    """
    nonce_id = str(uuid.uuid4())
    issued_at = _now()
    expires_at = issued_at + timedelta(seconds=NONCE_TTL_SECONDS)

    record = {
        "nonce": nonce_id,
        "fingerprint": fingerprint,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "client_nonce_echo": client_nonce_echo,
        "used": False,
    }
    serialized = json.dumps(record)

    if _USE_DJANGO:
        _django_cache.set(_key(nonce_id), serialized, timeout=NONCE_TTL_SECONDS + 10)
    else:
        _MEM_CACHE[_key(nonce_id)] = serialized

    return record


def consume(nonce_id: str, fingerprint: str) -> tuple[bool, str]:
    """Validate and consume a nonce.

    Marks the nonce as used so it cannot be replayed. Checks:
    1. Nonce exists
    2. Nonce belongs to the claiming fingerprint
    3. Nonce has not expired
    4. Nonce has not already been used

    Args:
        nonce_id: UUID of the nonce to consume.
        fingerprint: Fingerprint claimed in the auth response.

    Returns:
        tuple[bool, str]: (success, error_code). error_code is empty on success.
    """
    cache_key = _key(nonce_id)

    if _USE_DJANGO:
        raw = _django_cache.get(cache_key)
    else:
        raw = _MEM_CACHE.get(cache_key)

    if raw is None:
        return False, "invalid_nonce"

    try:
        record = json.loads(raw)
    except json.JSONDecodeError:
        return False, "invalid_nonce"

    if record.get("fingerprint") != fingerprint:
        # Don't reveal whether the nonce exists for a different fingerprint
        return False, "invalid_nonce"

    expires_at = datetime.fromisoformat(record["expires_at"])
    if _now() > expires_at:
        return False, "expired_nonce"

    if record.get("used"):
        return False, "invalid_nonce"

    # Mark consumed before returning so concurrent requests both fail
    record["used"] = True
    serialized = json.dumps(record)

    if _USE_DJANGO:
        # Keep it briefly so concurrent duplicate requests are rejected
        _django_cache.set(cache_key, serialized, timeout=10)
    else:
        _MEM_CACHE[cache_key] = serialized

    return True, ""


def peek(nonce_id: str) -> Optional[dict]:
    """Read a nonce record without consuming it (for polling / QR flows).

    Args:
        nonce_id: UUID of the nonce to look up.

    Returns:
        Optional[dict]: The nonce record, or None if not found.
    """
    cache_key = _key(nonce_id)

    if _USE_DJANGO:
        raw = _django_cache.get(cache_key)
    else:
        raw = _MEM_CACHE.get(cache_key)

    if raw is None:
        return None

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None
