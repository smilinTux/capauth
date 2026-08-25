"""WebAuthn passkey front-door for the CapAuth OIDC IdP.

A passkey is a **convenience authenticator bound to an existing sovereign PGP
fingerprint — NOT a new identity.** You may only register a passkey *after*
proving ownership of the fingerprint with your PGP key; logging in with the
passkey then mints the SAME OIDC identity (``sub`` = fingerprint) but with
``amr=["webauthn"]`` instead of ``["pgp"]`` so a relying party can tell which
tier was used. This keeps the sovereign PGP credential as the root of trust and
the passkey as an additive, phishing-resistant easy-mode.

Credentials are persisted (``passkeys.json``) keyed by credential ID; the
WebAuthn challenges (registration tickets + login challenges) live in memory and
expire. The exact origin and explicit named RP ID are validated before use.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import secrets
import stat
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

logger = logging.getLogger("capauth.service.oidc.passkey")

RP_NAME = "CapAuth"
_CHALLENGE_TTL = 300  # seconds for a pending reg/auth ceremony


class PasskeyStoreUnavailableError(RuntimeError):
    """Durable passkey state cannot be read or written safely."""


class PasskeyRPUnavailableError(RuntimeError):
    """The WebAuthn relying-party configuration is unavailable or unsafe."""


def _named_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise PasskeyRPUnavailableError("passkey RP must be a DNS name")
    if (
        len(host) > 253
        or "." not in host
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        )
    ):
        raise PasskeyRPUnavailableError("passkey RP must be a DNS name")
    return host


def rp_origin_and_id() -> tuple[str, str]:
    """Return the exact HTTPS origin and configured named RP ID.

    The RP ID must equal the issuer host or be its DNS suffix, as WebAuthn
    requires. IP literals and implicit RP IDs fail closed.
    """
    issuer = (os.environ.get("CAPAUTH_OIDC_ISSUER") or "").strip().rstrip("/")
    configured_rp_id = (os.environ.get("CAPAUTH_WEBAUTHN_RP_ID") or "").strip()
    try:
        parsed = urlsplit(issuer)
        port = parsed.port
    except ValueError as exc:
        raise PasskeyRPUnavailableError("invalid passkey issuer") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise PasskeyRPUnavailableError("passkey issuer must be named HTTPS")
    host = _named_host(parsed.hostname)
    rp_id = _named_host(configured_rp_id)
    if host != rp_id and not host.endswith(f".{rp_id}"):
        raise PasskeyRPUnavailableError("passkey RP ID does not match issuer")
    origin = f"https://{host}{f':{port}' if port is not None else ''}"
    return origin, rp_id


class PasskeyStore:
    """Persisted passkey credentials + in-memory ceremony challenges."""

    def __init__(self, data_dir: str | None = None) -> None:
        configured = Path(data_dir).expanduser() if data_dir else None
        if configured is not None and not configured.is_absolute():
            configured = None
        self._dir = configured
        self._path = configured / "passkeys.json" if configured is not None else None
        self._lock = threading.Lock()
        # cred_id(b64url) -> {fingerprint, public_key(b64url), sign_count}
        self._creds: dict[str, dict] = self._load()
        self._reg: dict[str, dict] = {}  # ticket -> {fingerprint, challenge, exp}
        self._auth: dict[str, dict] = {}  # request_id -> {challenge, exp}

    # -- persistence ------------------------------------------------------

    def _storage_preflight(self) -> None:
        if self._dir is None or self._path is None:
            raise PasskeyStoreUnavailableError("passkey data directory is not configured")
        if self._dir.is_symlink():
            raise PasskeyStoreUnavailableError("passkey data directory is unavailable")
        if self._dir.exists():
            if not self._dir.is_dir() or stat.S_IMODE(self._dir.stat().st_mode) & 0o077:
                raise PasskeyStoreUnavailableError("passkey data directory is unavailable")
        if self._path.is_symlink():
            raise PasskeyStoreUnavailableError("passkey state is unavailable")
        if self._path.exists():
            if not self._path.is_file() or stat.S_IMODE(self._path.stat().st_mode) != 0o600:
                raise PasskeyStoreUnavailableError("passkey state is unavailable")

    def preflight(self) -> tuple[str, str]:
        """Validate isolated storage and WebAuthn configuration without mutation."""
        relying_party = rp_origin_and_id()
        self._storage_preflight()
        return relying_party

    def _load(self) -> dict[str, dict]:
        if self._path is None:
            return {}
        self._storage_preflight()
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise PasskeyStoreUnavailableError("passkey state unavailable") from exc
        if not isinstance(data, dict):
            raise PasskeyStoreUnavailableError("passkey state is not an object")
        return data

    def _save(self) -> None:
        if self._dir is None or self._path is None:
            raise PasskeyStoreUnavailableError("passkey data directory is not configured")
        tmp = self._path.with_name(f".{self._path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}")
        try:
            self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._storage_preflight()
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                payload = json.dumps(self._creds, sort_keys=True).encode("utf-8")
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, self._path)
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise PasskeyStoreUnavailableError("passkey state unavailable") from exc

    def credentials_for(self, fingerprint: str) -> list[str]:
        fp = (fingerprint or "").upper()
        return [cid for cid, c in self._creds.items() if c.get("fingerprint") == fp]

    def has_any(self, fingerprint: str) -> bool:
        return bool(self.credentials_for(fingerprint))

    # -- registration (gated: caller must already be PGP-verified) --------

    def begin_registration(self, fingerprint: str) -> tuple[str, dict[str, Any]]:
        """Create registration options for a PGP-proven fingerprint.

        Returns ``(ticket, options_dict)``. The ticket binds the subsequent
        ``complete_registration`` to this fingerprint + challenge.
        """
        fp = fingerprint.upper()
        _origin, rp_id = self.preflight()
        exclude = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
            for cid in self.credentials_for(fp)
        ]
        opts = generate_registration_options(
            rp_id=rp_id,
            rp_name=RP_NAME,
            user_id=fp.encode("ascii"),
            user_name=f"capauth-{fp[:8]}",
            user_display_name=f"CapAuth {fp[:8]}",
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            exclude_credentials=exclude,
        )
        ticket = secrets.token_urlsafe(24)
        self._reg[ticket] = {
            "fingerprint": fp,
            "challenge": bytes_to_base64url(opts.challenge),
            "exp": time.time() + _CHALLENGE_TTL,
        }
        return ticket, json.loads(options_to_json(opts))

    def complete_registration(self, ticket: str, credential: Any) -> tuple[str, str]:
        """Verify the attestation and store the credential. Returns (fp, cred_id)."""
        rec = self._reg.pop(ticket, None)
        if rec is None or rec["exp"] < time.time():
            raise ValueError("expired or unknown registration ticket")
        origin, rp_id = self.preflight()
        verification = verify_registration_response(
            credential=credential if isinstance(credential, str) else json.dumps(credential),
            expected_challenge=base64url_to_bytes(rec["challenge"]),
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=False,
        )
        cid = bytes_to_base64url(verification.credential_id)
        with self._lock:
            new_credential = {
                "fingerprint": rec["fingerprint"],
                "public_key": bytes_to_base64url(verification.credential_public_key),
                "sign_count": verification.sign_count,
            }
            previous = self._creds.get(cid)
            self._creds[cid] = new_credential
            try:
                self._save()
            except PasskeyStoreUnavailableError:
                if previous is None:
                    self._creds.pop(cid, None)
                else:
                    self._creds[cid] = previous
                raise
        logger.info("passkey registered for fp=%s", rec["fingerprint"][:8])
        return rec["fingerprint"], cid

    # -- authentication ---------------------------------------------------

    def begin_authentication(self, request_id: str, fingerprint_hint: str = "") -> dict[str, Any]:
        """Create authentication options for an OIDC login request.

        ``fingerprint_hint`` narrows ``allowCredentials``; omit it for a
        discoverable (resident-key) login where the authenticator picks.
        """
        _origin, rp_id = self.preflight()
        allow = (
            [
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
                for cid in self.credentials_for(fingerprint_hint)
            ]
            if fingerprint_hint
            else []
        )
        opts = generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=allow or None,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        self._auth[request_id] = {
            "challenge": bytes_to_base64url(opts.challenge),
            "exp": time.time() + _CHALLENGE_TTL,
        }
        return json.loads(options_to_json(opts))

    def complete_authentication(self, request_id: str, credential: Any) -> str:
        """Verify the assertion against a stored credential. Returns fingerprint."""
        rec = self._auth.pop(request_id, None)
        if rec is None or rec["exp"] < time.time():
            raise ValueError("expired or unknown authentication challenge")
        cred = credential if isinstance(credential, dict) else json.loads(credential)
        cid = cred.get("id") or cred.get("rawId")
        stored = self._creds.get(cid)
        if not stored:
            raise ValueError("unknown credential")
        origin, rp_id = self.preflight()
        verification = verify_authentication_response(
            credential=credential if isinstance(credential, str) else json.dumps(credential),
            expected_challenge=base64url_to_bytes(rec["challenge"]),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(stored["public_key"]),
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=False,
        )
        with self._lock:
            previous_count = stored["sign_count"]
            stored["sign_count"] = verification.new_sign_count
            try:
                self._save()
            except PasskeyStoreUnavailableError:
                stored["sign_count"] = previous_count
                raise
        logger.info("passkey login for fp=%s", stored["fingerprint"][:8])
        return stored["fingerprint"]
