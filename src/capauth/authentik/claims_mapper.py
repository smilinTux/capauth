"""CapAuth → OIDC claims mapper.

Maps client-asserted CapAuth claims to OIDC standard and custom claims.
This is the layer that translates sovereign profile fields into the token
vocabulary that OIDC-consuming applications understand.

CRITICAL INVARIANT: Claims come FROM the client. They are verified by
cryptographic signature, not by server-side lookup. They are NOT stored.
They flow into the token and disappear when the token expires.
"""

from __future__ import annotations

from typing import Any

# OIDC standard scopes to their constituent claims
SCOPE_CLAIMS: dict[str, list[str]] = {
    "profile": ["name", "preferred_username", "picture", "locale", "zoneinfo", "updated_at", "agent_type", "soul_blueprint_category"],
    "email": ["email", "email_verified"],
    "groups": ["groups"],
}


def map_claims(
    fingerprint: str,
    raw_claims: dict[str, Any],
    requested_scopes: list[str] | None = None,
) -> dict[str, Any]:
    """Map CapAuth client claims to OIDC-compatible token claims.

    The ``sub`` is always the PGP fingerprint — the only persistent
    server-side identifier. All other claims come from the client.

    Args:
        fingerprint: The authenticating client's PGP fingerprint.
        raw_claims: Client-asserted claims from the signed response.
        requested_scopes: OIDC scopes requested (e.g. ["openid", "profile", "email"]).
                          If None, all known claims are included.

    Returns:
        dict: OIDC-compatible claims dict ready to embed in the token.
    """
    oidc: dict[str, Any] = {
        # sub is always the fingerprint — never a name, email, or UUID
        "sub": fingerprint,
        # Custom claim so consuming apps can always recover the fingerprint
        # even if sub is remapped by some middleware
        "capauth_fingerprint": fingerprint,
        # Signals the auth method used — like "pgp" is our amr value
        "amr": ["pgp"],
    }

    # --- profile scope ---
    if _scope_allowed("profile", requested_scopes):
        if name := raw_claims.get("name"):
            oidc["name"] = str(name)
            # preferred_username falls back to a fingerprint-derived handle
            # if the client didn't assert a name
            oidc["preferred_username"] = str(name)

        if avatar_url := raw_claims.get("avatar_url"):
            oidc["picture"] = str(avatar_url)

        if locale := raw_claims.get("locale"):
            oidc["locale"] = str(locale)

        if zoneinfo := raw_claims.get("zoneinfo"):
            oidc["zoneinfo"] = str(zoneinfo)

        if agent_type := raw_claims.get("agent_type"):
            oidc["agent_type"] = str(agent_type)

        if soul_bp := raw_claims.get("soul_blueprint"):
            if isinstance(soul_bp, dict):
                if category := soul_bp.get("category"):
                    oidc["soul_blueprint_category"] = str(category)
            elif isinstance(soul_bp, str):
                oidc["soul_blueprint_category"] = soul_bp

    # --- email scope ---
    if _scope_allowed("email", requested_scopes):
        if email := raw_claims.get("email"):
            oidc["email"] = str(email)
            # Email is self-asserted — we cannot verify ownership
            oidc["email_verified"] = False

    # --- groups scope / custom ---
    if _scope_allowed("groups", requested_scopes):
        if groups := raw_claims.get("groups"):
            if isinstance(groups, list):
                oidc["groups"] = [str(g) for g in groups]
            elif isinstance(groups, str):
                oidc["groups"] = [groups]

    # Pass through any unknown custom claims prefixed with capauth_
    for key, value in raw_claims.items():
        if key not in _KNOWN_CLAIMS and key.startswith("capauth_"):
            oidc[key] = value

    return oidc


def preferred_username_fallback(fingerprint: str) -> str:
    """Generate a stable display handle from a fingerprint when no name is asserted.

    Args:
        fingerprint: Full 40-char PGP fingerprint.

    Returns:
        str: Short handle like ``capauth-8A3FC2D1``.
    """
    return f"capauth-{fingerprint[:8].upper()}"


def _scope_allowed(scope: str, requested_scopes: list[str] | None) -> bool:
    """Return True if the scope is in the requested list, or if no list was given."""
    if requested_scopes is None:
        return True
    return scope in requested_scopes


# Claims we explicitly handle — used to identify passthrough candidates
_KNOWN_CLAIMS = {
    "name",
    "email",
    "avatar_url",
    "groups",
    "locale",
    "zoneinfo",
    "agent_type",
    "soul_blueprint",
}
