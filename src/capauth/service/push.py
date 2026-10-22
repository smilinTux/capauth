"""CapAuth Bunker — Web Push (background approval prompts).

When the phone-signer PWA is backgrounded or closed its WebSocket drops, so it
can't receive a `sign_request`. Web Push wakes it: the phone subscribes (keyed by
its PGP fingerprint), and when a desktop wants that key to sign it asks the
service to push a notification carrying the pairing URI. Tapping the notification
opens the PWA pre-filled, ready to pair + approve.

Pieces:
  * **VAPID** keypair (P-256), generated once and persisted so the
    application-server key the browser subscribed with stays stable across
    restarts. `application_server_key()` is what the PWA passes to
    `pushManager.subscribe`.
  * **Subscription registry** keyed by uppercase fingerprint, persisted to JSON
    so subscriptions survive restarts.
  * **notify()** sends a VAPID-signed Web Push (via ``pywebpush``) to every
    subscription for a fingerprint, pruning ones the push service has expired
    (404/410).

``pywebpush`` is an optional dependency (capauth[service]); if it's unavailable
the endpoints degrade gracefully (subscribe still stores; notify reports the
gap) rather than crashing the service.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Optional

from .. import resolve_capauth_home

logger = logging.getLogger("capauth.push")

_VAPID_SUBJECT = os.environ.get("CAPAUTH_VAPID_SUBJECT", "mailto:admin@skworld.io")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def default_data_dir() -> Path:
    """Resolve the service-owned durable data root for push state."""
    configured = os.environ.get("CAPAUTH_DATA_DIR")
    if configured:
        return Path(configured)
    return resolve_capauth_home() / "service"


class PushRegistry:
    """VAPID keypair + fingerprint→subscriptions registry + push sender.

    State is persisted under ``data_dir`` (VAPID private key PEM + subscriptions
    JSON) so the application-server key and subscriptions survive restarts.
    """

    def __init__(self, data_dir: str | os.PathLike[str] | None = None) -> None:
        self._dir = Path(data_dir) if data_dir is not None else default_data_dir()
        self._lock = threading.Lock()
        self._subs_path = self._dir / "push_subs.json"
        self._vapid_path = self._dir / "vapid_private.pem"
        self._subs: dict[str, list[dict]] = self._load_subs()
        self._app_server_key: Optional[str] = None
        self._vapid_pem: Optional[str] = None
        self._ensure_vapid()

    # -- VAPID ------------------------------------------------------------

    def _ensure_vapid(self) -> None:
        """Load or generate the VAPID keypair; cache the app-server key + PEM."""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
        except Exception:  # pragma: no cover - cryptography is a hard dep
            return
        priv = None
        if self._vapid_path.exists():
            try:
                priv = serialization.load_pem_private_key(
                    self._vapid_path.read_bytes(), password=None
                )
            except Exception:
                logger.warning("push: bad VAPID key on disk; regenerating")
        if priv is None:
            priv = ec.generate_private_key(ec.SECP256R1())
            try:
                self._dir.mkdir(parents=True, exist_ok=True)
                self._vapid_path.write_bytes(
                    priv.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                )
            except Exception as exc:  # pragma: no cover
                logger.warning("push: could not persist VAPID key: %s", exc)
        self._vapid_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
        raw_pub = priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self._app_server_key = _b64url(raw_pub)

    def application_server_key(self) -> str:
        """Base64url of the raw P-256 public key — for pushManager.subscribe."""
        return self._app_server_key or ""

    # -- subscriptions ----------------------------------------------------

    def _load_subs(self) -> dict[str, list[dict]]:
        try:
            return json.loads(self._subs_path.read_text())
        except Exception:
            return {}

    def _save_subs(self) -> None:
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            self._subs_path.write_text(json.dumps(self._subs))
        except Exception as exc:  # pragma: no cover
            logger.warning("push: could not persist subscriptions: %s", exc)

    def subscribe(self, fingerprint: str, subscription: dict) -> None:
        fp = (fingerprint or "").upper()
        endpoint = subscription.get("endpoint")
        if not fp or not endpoint:
            raise ValueError("fingerprint + subscription.endpoint required")
        with self._lock:
            subs = self._subs.setdefault(fp, [])
            # De-dup by endpoint (a phone re-subscribing updates its keys).
            subs = [s for s in subs if s.get("endpoint") != endpoint]
            subs.append(subscription)
            self._subs[fp] = subs
            self._save_subs()

    def subscription_count(self, fingerprint: str) -> int:
        return len(self._subs.get((fingerprint or "").upper(), []))

    # -- send -------------------------------------------------------------

    def notify(self, fingerprint: str, payload: dict) -> dict[str, Any]:
        """Send a Web Push to every subscription for ``fingerprint``.

        Returns ``{"sent": n, "pruned": m, "error": str|None}``. Dead
        subscriptions (404/410) are pruned.
        """
        fp = (fingerprint or "").upper()
        subs = list(self._subs.get(fp, []))
        if not subs:
            return {"sent": 0, "pruned": 0, "error": "no_subscriptions"}
        try:
            from pywebpush import WebPushException, webpush
        except Exception:
            return {"sent": 0, "pruned": 0, "error": "pywebpush_unavailable"}

        sent, dead = 0, []
        for sub in subs:
            try:
                webpush(
                    subscription_info=sub,
                    data=json.dumps(payload),
                    vapid_private_key=self._vapid_pem,
                    vapid_claims={"sub": _VAPID_SUBJECT},
                )
                sent += 1
            except WebPushException as exc:
                status = getattr(getattr(exc, "response", None), "status_code", None)
                if status in (404, 410):
                    dead.append(sub.get("endpoint"))
                else:  # pragma: no cover - transient push-service error
                    logger.warning("push: send failed (%s): %s", status, exc)
        if dead:
            with self._lock:
                self._subs[fp] = [
                    s for s in self._subs.get(fp, []) if s.get("endpoint") not in dead
                ]
                self._save_subs()
        return {"sent": sent, "pruned": len(dead), "error": None}
