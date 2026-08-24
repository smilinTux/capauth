"""Static OIDC client registry for the CapAuth IdP (spike).

A spike-grade, config-driven client registry. One client = stock Authentik.
There is no dynamic client registration (that's on the TODO list); clients are
declared up front via one of:

1. ``CAPAUTH_OIDC_CLIENTS_FILE`` — path to a JSON file: ``[{...}, {...}]``
2. ``CAPAUTH_OIDC_CLIENTS_JSON`` — the JSON array inline in an env var
3. Programmatic construction (used by tests)

Each client entry:

.. code-block:: json

    {
      "client_id": "authentik",
      "client_secret": "change-me",
      "redirect_uris": ["https://authentik.example/source/oauth/callback/capauth/"],
      "name": "Authentik",
      "scopes": ["openid", "profile", "email", "groups"]
    }

``redirect_uris`` is matched EXACTLY (no wildcard) per OAuth2 security guidance.
"""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DEFAULT_SCOPES = ["openid", "profile", "email", "groups"]


@dataclass
class OIDCClient:
    """A registered OIDC relying party (e.g. Authentik as an OAuth Source)."""

    client_id: str
    client_secret: str
    redirect_uris: list[str]
    name: str = ""
    scopes: list[str] = field(default_factory=lambda: list(DEFAULT_SCOPES))

    def redirect_uri_allowed(self, redirect_uri: str) -> bool:
        """Return True if *redirect_uri* exactly matches a registered URI."""
        return redirect_uri in self.redirect_uris

    def secret_matches(self, candidate: str) -> bool:
        """Require a configured confidential-client secret and compare it safely."""
        if not self.client_secret:
            return False
        return hmac.compare_digest(self.client_secret, candidate or "")


class ClientRegistry:
    """Holds the set of statically-registered OIDC clients.

    Args:
        clients: Optional list of :class:`OIDCClient`. When omitted, the
            registry loads from ``CAPAUTH_OIDC_CLIENTS_FILE`` /
            ``CAPAUTH_OIDC_CLIENTS_JSON`` (see module docstring).
    """

    def __init__(self, clients: Optional[list[OIDCClient]] = None) -> None:
        if clients is None:
            clients = self._load_from_env()
        self._clients: dict[str, OIDCClient] = {c.client_id: c for c in clients}

    @staticmethod
    def _load_from_env() -> list[OIDCClient]:
        raw: Optional[str] = None
        file_path = os.environ.get("CAPAUTH_OIDC_CLIENTS_FILE")
        if file_path and Path(file_path).expanduser().exists():
            raw = Path(file_path).expanduser().read_text(encoding="utf-8")
        elif os.environ.get("CAPAUTH_OIDC_CLIENTS_JSON"):
            raw = os.environ["CAPAUTH_OIDC_CLIENTS_JSON"]

        if not raw:
            return []

        entries = json.loads(raw)
        return [ClientRegistry._client_from_dict(e) for e in entries]

    @staticmethod
    def _client_from_dict(entry: dict) -> OIDCClient:
        return OIDCClient(
            client_id=entry["client_id"],
            client_secret=entry.get("client_secret", ""),
            redirect_uris=list(entry.get("redirect_uris", [])),
            name=entry.get("name", entry["client_id"]),
            scopes=list(entry.get("scopes", DEFAULT_SCOPES)),
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, client_id: str) -> Optional[OIDCClient]:
        """Return the client by id, or None if not registered."""
        return self._clients.get(client_id)

    def __len__(self) -> int:
        return len(self._clients)

    def __contains__(self, client_id: str) -> bool:
        return client_id in self._clients
