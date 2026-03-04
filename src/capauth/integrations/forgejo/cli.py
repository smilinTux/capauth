"""``capauth forgejo`` CLI subcommands.

Provides helpers for operators to configure, test, and manage the
Forgejo CapAuth integration.

Usage
-----
.. code-block:: bash

    # Print app.ini snippet for Forgejo
    capauth forgejo config

    # Verify API connectivity
    capauth forgejo ping

    # Provision a user by fingerprint
    capauth forgejo provision --fingerprint ABCD1234... --username alice

    # Sync admin status
    capauth forgejo set-admin --username alice --admin true

    # List all CapAuth-provisioned users
    capauth forgejo list-users
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Optional

from .config import ForgejoConfig
from .forgejo_api import ForgejoAPIClient, ForgejoAPIError


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------


def cmd_config(config: ForgejoConfig) -> int:
    """Print the app.ini snippet for Forgejo OIDC configuration."""
    base = config.capauth_base_url or "https://auth.yourdomain.com"
    discovery = f"{base}/forgejo/.well-known/openid-configuration"

    snippet = f"""\
; ─── Add to Forgejo app.ini ───────────────────────────────────────────────────
;
; This configures Forgejo to use CapAuth as an OIDC provider for
; passwordless PGP authentication.  Drop this under [oauth2] in app.ini
; or set via the Forgejo Admin UI → Site Administration → Authentication Sources.

[oauth2]
ENABLE = true

[oauth2.source.capauth]
PROVIDER                         = openidConnect
CLIENT_ID                        = {config.client_id}
CLIENT_SECRET                    = {config.client_secret or "any-non-empty-string"}
OPENID_CONNECT_AUTO_DISCOVERY_URL = {discovery}
SCOPES                           = openid profile email groups
USERNAME_CLAIM                   = capauth_fingerprint
REQUIRED_CLAIM_NAME              = capauth_fingerprint
GROUP_CLAIM_NAME                 = groups
ADMIN_GROUP                      = {config.admin_group}
; Optional — restricts login to users in this group:
; REQUIRED_CLAIM_VALUE             = sovereign
"""
    print(snippet)

    errors = config.validate()
    if errors:
        print("⚠  Configuration warnings:")
        for e in errors:
            print(f"   • {e}")
        return 1
    return 0


def cmd_ping(config: ForgejoConfig) -> int:
    """Check Forgejo API connectivity."""
    client = ForgejoAPIClient(config)
    ok = _run(client.ping())
    if ok:
        print(f"✓  Forgejo API reachable at {config.forgejo_base_url}")
        return 0
    else:
        print(f"✗  Could not reach Forgejo API at {config.forgejo_base_url}", file=sys.stderr)
        print("   Check FORGEJO_BASE_URL and FORGEJO_ADMIN_TOKEN.", file=sys.stderr)
        return 1


def cmd_provision(
    config: ForgejoConfig,
    fingerprint: str,
    username: str,
    email: str = "",
    admin: bool = False,
) -> int:
    """Create or update a Forgejo user for a CapAuth fingerprint."""
    client = ForgejoAPIClient(config)
    claims = {
        "preferred_username": username,
        "email": email or f"{username}@capauth.local",
        "groups": [config.admin_group] if admin else [],
    }
    try:
        user = _run(client.get_or_create_user(fingerprint, claims))
        print(json.dumps(user, indent=2))
        return 0
    except ForgejoAPIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_set_admin(config: ForgejoConfig, username: str, is_admin: bool) -> int:
    """Grant or revoke Forgejo admin for a user."""
    client = ForgejoAPIClient(config)
    try:
        user = _run(client.set_user_admin(username, is_admin))
        action = "granted" if is_admin else "revoked"
        print(f"✓  Admin {action} for {username}")
        print(json.dumps({"username": username, "is_admin": user.get("is_admin")}, indent=2))
        return 0
    except ForgejoAPIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_list_users(config: ForgejoConfig, page: int = 1, limit: int = 20) -> int:
    """List Forgejo users."""
    client = ForgejoAPIClient(config)
    try:
        users = _run(client.list_users(limit=limit, page=page))
        for u in users:
            admin_flag = " [admin]" if u.get("is_admin") else ""
            print(f"  {u['login']:<30} {u.get('email', ''):<40}{admin_flag}")
        print(f"\n{len(users)} user(s) on page {page}")
        return 0
    except ForgejoAPIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_create_token(config: ForgejoConfig, username: str, token_name: str = "capauth") -> int:
    """Create a Forgejo API token for a user."""
    client = ForgejoAPIClient(config)
    try:
        token = _run(client.create_api_token(username, token_name))
        print(f"✓  Token created for {username}")
        print(f"   Name : {token.get('name')}")
        print(f"   Token: {token.get('sha1', '(hidden)')}")
        print("   Save this value — Forgejo shows it only once.")
        return 0
    except ForgejoAPIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# CLI entry point (integrate with capauth's click/argparse CLI)
# ---------------------------------------------------------------------------


def main(args: Optional[list[str]] = None) -> int:
    """Minimal argparse CLI for ``capauth forgejo``."""
    import argparse

    config = ForgejoConfig.from_env()

    parser = argparse.ArgumentParser(
        prog="capauth forgejo",
        description="Manage Forgejo CapAuth integration",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("config", help="Print app.ini configuration snippet")
    sub.add_parser("ping", help="Test Forgejo API connectivity")

    prov = sub.add_parser("provision", help="Create or update a Forgejo user")
    prov.add_argument("--fingerprint", required=True, help="40-char PGP fingerprint")
    prov.add_argument("--username", required=True)
    prov.add_argument("--email", default="")
    prov.add_argument("--admin", action="store_true")

    sa = sub.add_parser("set-admin", help="Grant or revoke Forgejo admin")
    sa.add_argument("--username", required=True)
    sa.add_argument("--admin", required=True, choices=["true", "false"])

    lu = sub.add_parser("list-users", help="List Forgejo users")
    lu.add_argument("--page", type=int, default=1)
    lu.add_argument("--limit", type=int, default=20)

    ct = sub.add_parser("create-token", help="Create API token for user")
    ct.add_argument("--username", required=True)
    ct.add_argument("--name", default="capauth")

    ns = parser.parse_args(args)

    if ns.cmd == "config":
        return cmd_config(config)
    if ns.cmd == "ping":
        return cmd_ping(config)
    if ns.cmd == "provision":
        return cmd_provision(config, ns.fingerprint, ns.username, ns.email, ns.admin)
    if ns.cmd == "set-admin":
        return cmd_set_admin(config, ns.username, ns.admin == "true")
    if ns.cmd == "list-users":
        return cmd_list_users(config, ns.page, ns.limit)
    if ns.cmd == "create-token":
        return cmd_create_token(config, ns.username, ns.name)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
