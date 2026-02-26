"""CapAuth service login implementation.

Implements ``capauth login <service-url>`` — the full client-side flow:

1. Load fingerprint from ~/.capauth/profile.yml (or system GPG keyring)
2. Load profile claims from ~/.capauth/profile.yml (service-specific override supported)
3. Fetch challenge nonce from the service's CapAuth endpoint
4. Verify the server's nonce signature (if server provides one)
5. Sign the nonce — via system GPG (subprocess) if available, otherwise PGPy
6. Sign the claims bundle bound to this nonce
7. POST the signed response to /capauth/v1/verify
8. Cache received OIDC tokens at ~/.capauth/tokens/<service_host>/tokens.json
9. Return a summary dict for the CLI to display

GPG signing priority:
  1. System GPG keyring (``gpg --detach-sign``) if fingerprint is in keyring
  2. PGPy backend with private key loaded from the capauth profile

Works for both humans and AI agents — agents can call this as a library
without user interaction if the fingerprint is in the system keyring.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
import yaml

from .authentik.verifier import (
    canonical_claims_payload,
    canonical_nonce_payload,
    verify_nonce_signature,
)
from .exceptions import CapAuthError
from .profile import DEFAULT_CAPAUTH_DIR, load_profile

TOKEN_DIR_NAME = "tokens"
PROFILE_YAML_NAME = "profile.yml"


# ---------------------------------------------------------------------------
# GPG subprocess signing
# ---------------------------------------------------------------------------


def _gpg_sign(data: bytes, fingerprint: str) -> str:
    """Sign bytes using the system GPG keyring via subprocess.

    Uses ``gpg --detach-sign --armor`` so the returned signature can be
    verified against the matching public key without the original data being
    embedded.  This is the recommended signing path for the CLI login command
    because it works with hardware tokens (YubiKey, OpenPGP card) and
    system-managed keys without importing private keys into CapAuth.

    Args:
        data: Raw bytes to sign.
        fingerprint: PGP fingerprint of the key to sign with.

    Returns:
        str: ASCII-armored PGP detach-sig (BEGIN PGP SIGNATURE block).

    Raises:
        CapAuthError: If gpg is unavailable or signing fails.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_in:
        tmp_in.write(data)
        tmp_path = tmp_in.name

    sig_path = tmp_path + ".asc"
    try:
        result = subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--detach-sign",
                "--armor",
                "-u", fingerprint,
                tmp_path,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise CapAuthError(
                f"gpg signing failed (code {result.returncode}): {result.stderr.strip()}"
            )
        if not Path(sig_path).exists():
            raise CapAuthError("gpg produced no signature file.")
        return Path(sig_path).read_text(encoding="utf-8")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
        Path(sig_path).unlink(missing_ok=True)


def _gpg_export_pubkey(fingerprint: str) -> str:
    """Export a public key from the system GPG keyring.

    Args:
        fingerprint: 40-char PGP fingerprint.

    Returns:
        str: ASCII-armored public key.

    Raises:
        CapAuthError: If the key is not found or gpg fails.
    """
    result = subprocess.run(
        ["gpg", "--export", "--armor", fingerprint],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise CapAuthError(
            f"gpg export failed for {fingerprint[:8]}: {result.stderr.strip()}"
        )
    return result.stdout


def _fingerprint_in_gpg_keyring(fingerprint: str) -> bool:
    """Check if a fingerprint has a secret key in the system GPG keyring.

    Args:
        fingerprint: 40-char PGP fingerprint.

    Returns:
        bool: True if the key exists and can sign.
    """
    try:
        result = subprocess.run(
            ["gpg", "--list-secret-keys", "--with-colons", fingerprint],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def do_login(
    service_url: str,
    passphrase: str = "",
    no_claims: bool = False,
    service_profile_name: Optional[str] = None,
    output_token_path: Optional[Path] = None,
    base_dir: Optional[Path] = None,
    use_gpg_keyring: bool = True,
) -> dict[str, Any]:
    """Perform a full CapAuth login to a service.

    Signs the challenge nonce using the system GPG keyring (``gpg --detach-sign``)
    if the fingerprint is found there, otherwise falls back to the PGPy backend
    with the private key stored in the CapAuth profile.

    Args:
        service_url: Service URL or hostname, e.g. ``nextcloud.penguin.kingdom``
                     or ``https://nextcloud.penguin.kingdom``.
        passphrase: Passphrase to unlock the local private key (PGPy backend only).
                    Not needed when using the system GPG keyring.
        no_claims: If True, authenticate anonymously (fingerprint only, no profile claims).
        service_profile_name: Name of a service-specific claims override in profile.yml.
        output_token_path: If set, write tokens here instead of the default cache.
        base_dir: CapAuth home directory. Defaults to ``~/.capauth/``.
        use_gpg_keyring: If True (default), prefer system GPG keyring for signing.

    Returns:
        dict: Summary with keys ``service``, ``fingerprint``, ``name``, ``token_path``,
              ``access_token``.

    Raises:
        CapAuthError: On any authentication failure.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR

    # --- Load fingerprint and public key ---
    fingerprint, public_key_armor, _sign_fn = _load_identity(
        base=base,
        passphrase=passphrase,
        use_gpg_keyring=use_gpg_keyring,
    )

    # --- Resolve service URL ---
    service_id, challenge_url, verify_url = _resolve_urls(service_url)

    # --- Build client nonce ---
    client_nonce_raw = os.urandom(16)
    client_nonce_b64 = base64.b64encode(client_nonce_raw).decode("ascii")

    # --- Step 1: Fetch challenge from server ---
    challenge = _fetch_challenge(
        challenge_url=challenge_url,
        fingerprint=fingerprint,
        client_nonce_b64=client_nonce_b64,
    )

    # --- Step 2: Verify server's nonce signature (if server key is available) ---
    if server_pubkey := challenge.get("server_public_key"):
        nonce_payload = canonical_nonce_payload(
            nonce=challenge["nonce"],
            client_nonce_echo=challenge["client_nonce_echo"],
            timestamp=challenge["timestamp"],
            service=challenge["service"],
            expires=challenge["expires"],
        )
        if not verify_nonce_signature(
            payload=nonce_payload,
            signature_armor=challenge.get("server_signature", ""),
            public_key_armor=server_pubkey,
        ):
            raise CapAuthError("Server nonce signature verification failed. Possible MITM.")

    # Verify the echoed client nonce to prevent precomputed challenges
    echoed = challenge.get("client_nonce_echo", "")
    if echoed != client_nonce_b64:
        raise CapAuthError("Server did not echo our client nonce correctly.")

    # --- Step 3: Sign the nonce ---
    nonce_canonical = canonical_nonce_payload(
        nonce=challenge["nonce"],
        client_nonce_echo=challenge["client_nonce_echo"],
        timestamp=challenge["timestamp"],
        service=challenge["service"],
        expires=challenge["expires"],
    )
    try:
        nonce_signature = _sign_fn(nonce_canonical)
    except CapAuthError:
        raise
    except Exception as exc:
        raise CapAuthError(f"Failed to sign nonce: {exc}") from exc

    # --- Step 4: Load claims ---
    claims: dict[str, Any] = {}
    claims_signature: str = ""

    if not no_claims:
        claims = _load_claims(
            base=base,
            service_id=service_id,
            service_profile_name=service_profile_name,
        )

        if claims:
            claims_canonical = canonical_claims_payload(
                fingerprint=fingerprint,
                nonce=challenge["nonce"],
                claims=claims,
            )
            try:
                claims_signature = _sign_fn(claims_canonical)
            except CapAuthError:
                raise
            except Exception as exc:
                raise CapAuthError(f"Failed to sign claims: {exc}") from exc

    # --- Step 5: POST signed response ---
    response_body = {
        "capauth_version": "1.0",
        "fingerprint": fingerprint,
        "nonce": challenge["nonce"],
        "nonce_signature": nonce_signature,
        "claims": claims,
        "claims_signature": claims_signature,
        "public_key": public_key_armor,
    }

    token_response = _post_response(verify_url=verify_url, body=response_body)

    # --- Step 6: Cache tokens ---
    token_path = _cache_tokens(
        tokens=token_response,
        service_id=service_id,
        base=base,
        output_path=output_token_path,
    )

    return {
        "service": service_id,
        "fingerprint": fingerprint,
        "name": claims.get("name"),
        "token_path": str(token_path),
        "access_token": token_response.get("access_token"),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_identity(
    base: Path,
    passphrase: str,
    use_gpg_keyring: bool,
) -> tuple[str, str, Any]:
    """Resolve fingerprint, public key, and a signing callable.

    Prefers the system GPG keyring if ``use_gpg_keyring`` is True and the
    fingerprint is present there.  Falls back to the PGPy-based profile key.

    Args:
        base: CapAuth home directory.
        passphrase: Passphrase for PGPy signing (ignored when using GPG keyring).
        use_gpg_keyring: Whether to check the system GPG keyring first.

    Returns:
        tuple: (fingerprint, public_key_armor, sign_callable)
               where sign_callable accepts ``bytes`` and returns ``str`` (armor).

    Raises:
        CapAuthError: If neither signing method is available.
    """
    # Try to get fingerprint from profile.yml first, then profile.json
    profile_yml = base / PROFILE_YAML_NAME
    yml_fingerprint: Optional[str] = None
    if profile_yml.exists():
        try:
            data = yaml.safe_load(profile_yml.read_text(encoding="utf-8")) or {}
            yml_fingerprint = data.get("fingerprint") or data.get("claims", {}).get("fingerprint")
        except Exception:
            pass

    if not yml_fingerprint:
        # Check identity/profile.json (capauth native format)
        profile_json = base / "identity" / "profile.json"
        if profile_json.exists():
            try:
                import json as _json
                pdata = _json.loads(profile_json.read_text(encoding="utf-8"))
                yml_fingerprint = pdata.get("key_info", {}).get("fingerprint")
            except Exception:
                pass

    import capauth.login as _self  # module-level ref so mocks work in tests

    # Try system GPG keyring first
    if use_gpg_keyring and yml_fingerprint:
        if _self._fingerprint_in_gpg_keyring(yml_fingerprint):
            try:
                pub_armor = _self._gpg_export_pubkey(yml_fingerprint)
                _fp = yml_fingerprint
                def sign_fn(data: bytes, _fp=_fp) -> str:  # noqa: E306
                    return _self._gpg_sign(data, _fp)
                return yml_fingerprint, pub_armor, sign_fn
            except CapAuthError:
                pass  # fall through to PGPy

    # Fall back: load full capauth profile (PGPy private key)
    try:
        profile = load_profile(base)
        fingerprint = profile.key_info.fingerprint

        # Also check GPG keyring against profile fingerprint (if yml_fingerprint didn't match)
        if use_gpg_keyring and _self._fingerprint_in_gpg_keyring(fingerprint):
            try:
                pub_armor = _self._gpg_export_pubkey(fingerprint)
                _fp = fingerprint
                def sign_fn(data: bytes, _fp=_fp) -> str:  # noqa: E306
                    return _self._gpg_sign(data, _fp)
                return fingerprint, pub_armor, sign_fn
            except CapAuthError:
                pass

        # PGPy path
        from .crypto import get_backend
        private_key_armor = Path(profile.key_info.private_key_path).read_text(encoding="utf-8")
        public_key_armor = Path(profile.key_info.public_key_path).read_text(encoding="utf-8")
        backend = get_backend(profile.crypto_backend)

        def sign_fn_pgpy(data: bytes) -> str:
            return backend.sign(data, private_key_armor, passphrase)

        return fingerprint, public_key_armor, sign_fn_pgpy

    except Exception as exc:
        raise CapAuthError(
            f"Could not load identity. Run 'capauth init' or check your GPG keyring. ({exc})"
        ) from exc


def _resolve_urls(service_url: str) -> tuple[str, str, str]:
    """Resolve a service URL or hostname into CapAuth API endpoint URLs.

    Accepts:
    - ``nextcloud.penguin.kingdom`` (bare hostname, HTTPS assumed)
    - ``https://nextcloud.penguin.kingdom``
    - ``https://nextcloud.penguin.kingdom/custom/path``

    Args:
        service_url: Raw service URL or hostname from the user.

    Returns:
        tuple: (service_id, challenge_url, verify_url)
    """
    if not service_url.startswith("http"):
        service_url = f"https://{service_url}"

    parsed = urlparse(service_url)
    service_id = parsed.hostname or service_url
    base_path = parsed.path.rstrip("/") or ""

    challenge_url = f"{parsed.scheme}://{parsed.netloc}{base_path}/capauth/v1/challenge"
    verify_url = f"{parsed.scheme}://{parsed.netloc}{base_path}/capauth/v1/verify"

    return service_id, challenge_url, verify_url


def _fetch_challenge(
    challenge_url: str,
    fingerprint: str,
    client_nonce_b64: str,
) -> dict[str, Any]:
    """Request a challenge nonce from the service.

    Args:
        challenge_url: Full URL for the challenge endpoint.
        fingerprint: Client's PGP fingerprint.
        client_nonce_b64: Base64-encoded random client nonce.

    Returns:
        dict: Challenge response from the server.

    Raises:
        CapAuthError: On network failure or unexpected server response.
    """
    payload = {
        "capauth_version": "1.0",
        "fingerprint": fingerprint,
        "client_nonce": client_nonce_b64,
        "requested_service": urlparse(challenge_url).hostname,
    }

    try:
        resp = httpx.post(challenge_url, json=payload, timeout=10.0)
    except httpx.RequestError as exc:
        raise CapAuthError(f"Network error reaching {challenge_url}: {exc}") from exc

    if resp.status_code == 403:
        data = resp.json()
        if data.get("status") == "enrollment_pending":
            raise CapAuthError(
                "Your key requires administrator approval before first login. "
                "Contact the service admin."
            )
        raise CapAuthError(f"Auth denied by server: {data.get('error_description', 'forbidden')}")

    if not resp.is_success:
        raise CapAuthError(
            f"Challenge request failed (HTTP {resp.status_code}): {resp.text[:200]}"
        )

    try:
        data = resp.json()
    except Exception as exc:
        raise CapAuthError(f"Server returned invalid JSON: {exc}") from exc

    for required in ("nonce", "client_nonce_echo", "timestamp", "service", "expires"):
        if required not in data:
            raise CapAuthError(f"Challenge response missing required field: {required}")

    return data


def _post_response(verify_url: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST the signed authentication response to the service.

    Args:
        verify_url: Full URL for the verify endpoint.
        body: Signed response body.

    Returns:
        dict: OIDC token response from the server.

    Raises:
        CapAuthError: On network failure, signature rejection, or server error.
    """
    try:
        resp = httpx.post(verify_url, json=body, timeout=15.0)
    except httpx.RequestError as exc:
        raise CapAuthError(f"Network error posting response to {verify_url}: {exc}") from exc

    if resp.status_code == 401:
        try:
            data = resp.json()
            error_code = data.get("error", "authentication_failed")
            description = data.get("error_description", "Signature verification failed.")
        except Exception:
            error_code, description = "authentication_failed", resp.text[:200]
        raise CapAuthError(f"Authentication rejected ({error_code}): {description}")

    if resp.status_code == 403:
        raise CapAuthError("Access forbidden. Your key may not be enrolled on this service.")

    if not resp.is_success:
        raise CapAuthError(f"Verify request failed (HTTP {resp.status_code}): {resp.text[:200]}")

    try:
        return resp.json()
    except Exception as exc:
        raise CapAuthError(f"Server returned invalid JSON in token response: {exc}") from exc


def _load_claims(
    base: Path,
    service_id: str,
    service_profile_name: Optional[str],
) -> dict[str, Any]:
    """Load profile claims from ~/.capauth/profile.yml.

    Checks for a service-specific override first, then falls back to the
    default ``claims`` block. Returns an empty dict if no profile.yml exists.

    Args:
        base: CapAuth home directory.
        service_id: Hostname of the target service (for service profile lookup).
        service_profile_name: Explicit service profile name override.

    Returns:
        dict: Claims to assert in the auth response.
    """
    profile_yml = base / PROFILE_YAML_NAME
    if not profile_yml.exists():
        return {}

    try:
        data = yaml.safe_load(profile_yml.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}

    service_profiles: dict = data.get("service_profiles", {})

    # Prefer explicitly named profile, then service hostname match, then default
    lookup_key = service_profile_name or service_id
    if lookup_key in service_profiles:
        return dict(service_profiles[lookup_key])

    return dict(data.get("claims", {}))


def _cache_tokens(
    tokens: dict[str, Any],
    service_id: str,
    base: Path,
    output_path: Optional[Path],
) -> Path:
    """Write token response to disk.

    Default cache location: ``~/.capauth/tokens/<service>/tokens.json``

    Args:
        tokens: OIDC token response dict.
        service_id: Service hostname (used for directory naming).
        base: CapAuth home directory.
        output_path: Override the default cache location.

    Returns:
        Path: Where the tokens were written.
    """
    # Sanitize service_id to a safe directory name
    safe_name = re.sub(r"[^\w.\-]", "_", service_id)

    if output_path:
        dest = output_path
    else:
        token_dir = base / TOKEN_DIR_NAME / safe_name
        token_dir.mkdir(parents=True, exist_ok=True)
        dest = token_dir / "tokens.json"

    # Add cached_at timestamp for expiry management
    tokens["cached_at"] = datetime.now(timezone.utc).isoformat()

    dest.write_text(json.dumps(tokens, indent=2), encoding="utf-8")
    dest.chmod(0o600)  # tokens are secrets

    return dest


def load_cached_token(
    service_url: str,
    base_dir: Optional[Path] = None,
) -> Optional[dict[str, Any]]:
    """Load a previously cached token for a service, if it exists and hasn't expired.

    Args:
        service_url: Service URL or hostname.
        base_dir: CapAuth home directory. Defaults to ``~/.capauth/``.

    Returns:
        Optional[dict]: Token dict, or None if not found / expired.
    """
    base = base_dir or DEFAULT_CAPAUTH_DIR
    service_id, _, _ = _resolve_urls(service_url)
    safe_name = re.sub(r"[^\w.\-]", "_", service_id)
    token_path = base / TOKEN_DIR_NAME / safe_name / "tokens.json"

    if not token_path.exists():
        return None

    try:
        data = json.loads(token_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    # Simple expiry check based on expires_in + cached_at
    cached_at_str = data.get("cached_at")
    expires_in = data.get("expires_in")

    if cached_at_str and expires_in:
        from datetime import timedelta

        cached_at = datetime.fromisoformat(cached_at_str)
        expires_at = cached_at + timedelta(seconds=int(expires_in))
        if datetime.now(timezone.utc) >= expires_at:
            return None

    return data
