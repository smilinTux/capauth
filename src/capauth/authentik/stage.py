"""CapAuth Authentik Custom Stage.

Implements a Django-based Authentik custom authentication stage that:

1. Presents a "Login with CapAuth" challenge to the user
2. Issues a time-limited challenge nonce
3. Displays the challenge as QR code (mobile), copyable string (CLI),
   or auto-detects a browser extension
4. Polls for / accepts a signed response
5. Verifies PGP signatures
6. Enrolls new keys on first login (or queues for admin approval)
7. Populates an ephemeral Authentik user session from client-asserted claims
8. Issues OIDC tokens with client-sourced claims

Installation in Authentik:
  1. Drop this file (and siblings) into the Authentik custom stages path
  2. Create a ``CapAuthStage`` model instance in the admin UI
  3. Add the stage to a Flow as the first or only authentication stage
  4. Configure CAPAUTH_* settings in your Authentik environment

The Authentik user record created here contains ONLY the fingerprint.
All display fields are populated from client claims at login time and
are never written to the database.

Reference: https://docs.goauthentik.io/developer-docs/api/flow-executor
"""

from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .claims_mapper import map_claims, preferred_username_fallback
from .nonce_store import consume, issue, peek
from .verifier import (
    canonical_claims_payload,
    canonical_nonce_payload,
    fingerprint_from_armor,
    verify_claims_signature,
    verify_nonce_signature,
)

logger = logging.getLogger("capauth.authentik.stage")

# --- Django / Authentik imports (optional at module level so the file
#     is importable in test environments without a full Authentik stack) ---
try:
    from django.db import models
    from django.http import HttpResponse
    from django.utils.translation import gettext_lazy as _
    from rest_framework.fields import BooleanField, CharField, DictField

    from authentik.flows.challenge import (
        Challenge,
        ChallengeResponse,
        HttpChallengeResponse,
    )
    from authentik.flows.models import Stage
    from authentik.flows.planner import PLAN_CONTEXT_PENDING_USER
    from authentik.flows.stage import ChallengeStageView

    _AUTHENTIK_AVAILABLE = True
except ImportError:
    _AUTHENTIK_AVAILABLE = False
    # Provide stubs so the module is importable in isolation
    models = None  # type: ignore[assignment]
    Stage = object  # type: ignore[assignment,misc]
    ChallengeStageView = object  # type: ignore[assignment,misc]

# Service identifier — must match what clients put in their auth requests
CAPAUTH_SERVICE_ID: str = os.environ.get("CAPAUTH_SERVICE_ID", "authentik.local")
# Server's own PGP key armor (signs challenge nonces so clients can verify them)
CAPAUTH_SERVER_KEY_ARMOR: str = os.environ.get("CAPAUTH_SERVER_KEY_ARMOR", "")
CAPAUTH_SERVER_KEY_PASSPHRASE: str = os.environ.get("CAPAUTH_SERVER_KEY_PASSPHRASE", "")
# Whether to require admin approval for new key enrollments
CAPAUTH_REQUIRE_APPROVAL: bool = os.environ.get("CAPAUTH_REQUIRE_APPROVAL", "false").lower() == "true"


# ---------------------------------------------------------------------------
# Django Model (Authentik stage configuration)
# ---------------------------------------------------------------------------

def _default_capauth_stage_name() -> str:
    """Generate a unique default name for CapAuthStage (Stage.name is unique)."""
    return f"CapAuth Stage {uuid.uuid4().hex[:8]}"


if _AUTHENTIK_AVAILABLE:
    class CapAuthStage(Stage):
        """Authentik stage that authenticates users via CapAuth PGP challenge-response.

        A single instance of this model represents a configured CapAuth stage.
        Multiple flows can reference the same stage configuration.
        """

        # Service identifier shown in the challenge nonce
        service_id = models.CharField(
            max_length=255,
            default=CAPAUTH_SERVICE_ID,
            help_text="Hostname/identifier clients must use in their auth requests.",
        )

        # Whether new keys auto-enroll or require admin approval
        require_enrollment_approval = models.BooleanField(
            default=CAPAUTH_REQUIRE_APPROVAL,
            help_text="If True, new PGP keys require admin approval before first login.",
        )

        # Nonce TTL in seconds
        nonce_ttl_seconds = models.IntegerField(
            default=60,
            help_text="How long (seconds) a challenge nonce remains valid.",
        )

        # Override Stage.name with a unique default (Stage requires unique name)
        name = models.TextField(unique=True, default=_default_capauth_stage_name)

        class Meta:
            app_label = "capauth"
            verbose_name = "CapAuth Stage"
            verbose_name_plural = "CapAuth Stages"

        def __str__(self) -> str:
            return f"CapAuth Stage ({self.service_id})"

        @property
        def serializer(self):
            from .api import CapAuthStageSerializer
            return CapAuthStageSerializer

        @property
        def view(self):
            return CapAuthStageView  # defined below in same module

        @property
        def component(self) -> str:
            return "ak-stage-capauth"


# ---------------------------------------------------------------------------
# Authentik Key Registry (Django model)
# ---------------------------------------------------------------------------

if _AUTHENTIK_AVAILABLE:
    class CapAuthKeyRegistry(models.Model):
        """Stores enrolled PGP public keys for authentication.

        This is the ENTIRE user database for CapAuth. One row per enrolled key.
        No names. No emails. No avatars. The fingerprint IS the identity.

        Multiple fingerprints may map to the same logical user via the
        ``linked_to`` field (multi-device enrollment).
        """

        fingerprint = models.CharField(
            max_length=40,
            primary_key=True,
            help_text="Full 40-character uppercase PGP fingerprint.",
        )
        public_key_armor = models.TextField(
            help_text="ASCII-armored PGP public key. Needed for signature verification.",
        )
        enrolled_at = models.DateTimeField(auto_now_add=True)
        last_auth = models.DateTimeField(null=True, blank=True)
        approved = models.BooleanField(
            default=True,
            help_text="Set to False when require_enrollment_approval is active.",
        )
        # Link multiple fingerprints to one identity (multi-device)
        linked_to = models.CharField(
            max_length=40,
            null=True,
            blank=True,
            help_text="Primary fingerprint for multi-device identities.",
        )

        class Meta:
            app_label = "capauth"
            verbose_name = "CapAuth Key"
            verbose_name_plural = "CapAuth Keys"

        def __str__(self) -> str:
            return f"CapAuth Key {self.fingerprint[:8]}..."

        @property
        def effective_fingerprint(self) -> str:
            """Return primary fingerprint for linked keys."""
            return self.linked_to or self.fingerprint


# ---------------------------------------------------------------------------
# Challenge / Response logic (framework-independent)
# ---------------------------------------------------------------------------

def build_challenge(
    fingerprint: str,
    client_nonce_b64: str,
    service_id: str,
    server_key_armor: str,
    server_key_passphrase: str,
) -> dict[str, Any]:
    """Issue a signed challenge nonce for a client auth request.

    Args:
        fingerprint: Client's claimed PGP fingerprint.
        client_nonce_b64: Base64 client nonce to include in the challenge.
        service_id: This server's service identifier.
        server_key_armor: Server's ASCII-armored private key for signing.
        server_key_passphrase: Passphrase for the server's private key.

    Returns:
        dict: Challenge nonce payload ready to serialize and send to the client.
    """
    from ..crypto import get_backend

    nonce_record = issue(fingerprint, client_nonce_echo=client_nonce_b64)
    nonce_id = nonce_record["nonce"]
    timestamp = nonce_record["issued_at"]
    expires = nonce_record["expires_at"]

    payload = canonical_nonce_payload(
        nonce=nonce_id,
        client_nonce_echo=client_nonce_b64,
        timestamp=timestamp,
        service=service_id,
        expires=expires,
    )

    server_signature = ""
    if server_key_armor:
        try:
            backend = get_backend()
            server_signature = backend.sign(payload, server_key_armor, server_key_passphrase)
        except Exception as exc:
            logger.warning("Failed to sign nonce with server key: %s", exc)

    return {
        "capauth_version": "1.0",
        "nonce": nonce_id,
        "client_nonce_echo": client_nonce_b64,
        "timestamp": timestamp,
        "service": service_id,
        "expires": expires,
        "server_signature": server_signature,
    }


def verify_auth_response(
    fingerprint: str,
    nonce_id: str,
    nonce_signature_armor: str,
    claims: dict[str, Any],
    claims_signature_armor: str,
    public_key_armor: str,
    challenge_context: dict[str, Any],
) -> tuple[bool, str, dict[str, Any]]:
    """Verify a complete CapAuth authentication response.

    Steps:
    1. Consume the nonce (replay-protection)
    2. Verify the nonce signature against the client's public key
    3. Verify the claims signature against the client's public key
    4. Return the verified OIDC claims

    Args:
        fingerprint: Client's claimed PGP fingerprint.
        nonce_id: UUID of the challenge nonce.
        nonce_signature_armor: Client's PGP signature over the canonical nonce payload.
        claims: Dict of client-asserted profile claims.
        claims_signature_armor: Client's PGP signature over the canonical claims payload.
        public_key_armor: Client's ASCII-armored PGP public key.
        challenge_context: The challenge dict returned by ``build_challenge``.

    Returns:
        tuple[bool, str, dict]: (success, error_code, verified_oidc_claims).
        On failure, error_code is set and claims dict is empty.
    """
    # Step 1: Consume nonce (single-use, expiry check)
    ok, err = consume(nonce_id, fingerprint)
    if not ok:
        logger.warning("Nonce check failed for %s: %s", fingerprint[:8], err)
        return False, err, {}

    # Step 2: Verify nonce signature
    nonce_payload = canonical_nonce_payload(
        nonce=challenge_context["nonce"],
        client_nonce_echo=challenge_context["client_nonce_echo"],
        timestamp=challenge_context["timestamp"],
        service=challenge_context["service"],
        expires=challenge_context["expires"],
    )
    if not verify_nonce_signature(nonce_payload, nonce_signature_armor, public_key_armor):
        logger.warning("Nonce signature verification failed for fingerprint %s", fingerprint[:8])
        return False, "invalid_nonce_signature", {}

    # Step 3: Verify claims signature (skip if no claims submitted — anonymous auth)
    if claims and claims_signature_armor:
        claims_payload = canonical_claims_payload(
            fingerprint=fingerprint,
            nonce=nonce_id,
            claims=claims,
        )
        if not verify_claims_signature(claims_payload, claims_signature_armor, public_key_armor):
            logger.warning("Claims signature verification failed for fingerprint %s", fingerprint[:8])
            return False, "invalid_claims_signature", {}
    elif claims_signature_armor and not claims:
        # Signature present but no claims — treat as anonymous
        claims = {}
    elif claims and not claims_signature_armor:
        # Claims present but no signature — reject
        logger.warning("Claims present but no signature for fingerprint %s", fingerprint[:8])
        return False, "invalid_claims_signature", {}

    # Step 4: Map to OIDC
    oidc_claims = map_claims(fingerprint=fingerprint, raw_claims=claims)
    logger.info("CapAuth authentication successful for fingerprint %s", fingerprint[:8])
    return True, "", oidc_claims


# ---------------------------------------------------------------------------
# Authentik Challenge / ChallengeResponse (flow executor contract)
# ---------------------------------------------------------------------------

if _AUTHENTIK_AVAILABLE:
    class CapAuthChallenge(Challenge):
        """Challenge sent to the frontend: either request fingerprint or show nonce/QR."""

        need_fingerprint = BooleanField(required=False, default=False)
        fingerprint = CharField(required=False, allow_blank=True)
        nonce = CharField(required=False, allow_blank=True)
        client_nonce_echo = CharField(required=False, allow_blank=True)
        timestamp = CharField(required=False, allow_blank=True)
        service = CharField(required=False, allow_blank=True)
        expires = CharField(required=False, allow_blank=True)
        server_signature = CharField(required=False, allow_blank=True)
        presentation = CharField(required=False, allow_blank=True)
        qr_payload = CharField(required=False, allow_blank=True)
        component = CharField(default="ak-stage-capauth")

    class CapAuthChallengeResponse(ChallengeResponse):
        """Response from the frontend: fingerprint only (step 1) or full signed response (step 2)."""

        fingerprint = CharField(required=False, allow_blank=True)
        nonce = CharField(required=False, allow_blank=True)
        nonce_signature = CharField(required=False, allow_blank=True)
        claims = DictField(required=False, allow_null=True)
        claims_signature = CharField(required=False, allow_blank=True)
        public_key = CharField(required=False, allow_blank=True)
        component = CharField(default="ak-stage-capauth")


# ---------------------------------------------------------------------------
# Authentik StageView (ChallengeStageView)
# ---------------------------------------------------------------------------

if _AUTHENTIK_AVAILABLE:
    class CapAuthStageView(ChallengeStageView):
        """Authentik stage view implementing the CapAuth challenge-response flow.

        GET returns a challenge: either need_fingerprint (user must enter fingerprint)
        or full challenge (nonce, QR, etc.). POST accepts either fingerprint-only
        (we return a new challenge with nonce) or full signed response (we verify and stage_ok).
        """

        response_class = CapAuthChallengeResponse

        def get_challenge(self, *args, **kwargs) -> Challenge:
            """Return challenge: need_fingerprint or full nonce challenge from request.GET."""
            request = self.request
            fingerprint = (request.GET.get("fingerprint") or "").strip()
            if not fingerprint or len(fingerprint) != 40:
                return CapAuthChallenge(
                    data={
                        "need_fingerprint": True,
                        "component": "ak-stage-capauth",
                    }
                )

            client_nonce_raw = os.urandom(16)
            client_nonce_b64 = base64.b64encode(client_nonce_raw).decode("ascii")
            stage: CapAuthStage = self.executor.current_stage
            challenge = build_challenge(
                fingerprint=fingerprint,
                client_nonce_b64=client_nonce_b64,
                service_id=stage.service_id,
                server_key_armor=CAPAUTH_SERVER_KEY_ARMOR,
                server_key_passphrase=CAPAUTH_SERVER_KEY_PASSPHRASE,
            )
            self.executor.plan.context["capauth_challenge"] = challenge
            self.executor.plan.context["capauth_fingerprint"] = fingerprint

            is_extension = request.headers.get("X-CapAuth-Extension") == "true"
            is_qr = "application/qr+capauth" in (request.headers.get("Accept") or "")
            presentation = "extension" if is_extension else ("qr" if is_qr else "string")
            data = {
                "need_fingerprint": False,
                "fingerprint": fingerprint,
                "nonce": challenge["nonce"],
                "client_nonce_echo": challenge["client_nonce_echo"],
                "timestamp": challenge["timestamp"],
                "service": challenge["service"],
                "expires": challenge["expires"],
                "server_signature": challenge.get("server_signature", ""),
                "presentation": presentation,
                "qr_payload": "",
                "component": "ak-stage-capauth",
            }
            if is_qr:
                data["qr_payload"] = json.dumps({
                    "capauth_qr": "1.0",
                    "nonce": challenge["nonce"],
                    "service": challenge["service"],
                    "callback": request.build_absolute_uri(f"/capauth/v1/qr-verify/{challenge['nonce']}"),
                    "expires": challenge["expires"],
                }, separators=(",", ":"))
            return CapAuthChallenge(data=data)

        def challenge_valid(self, response: CapAuthChallengeResponse) -> HttpResponse:
            """Handle POST: fingerprint-only (return new challenge with nonce) or full signed response (verify and stage_ok)."""
            # Response data may be in validated_data (after is_valid()) or initial_data
            data = getattr(response, "validated_data", None) or getattr(response, "data", None) or {}
            if not data and hasattr(response, "initial_data"):
                data = response.initial_data or {}
            fingerprint = (data.get("fingerprint") or "").strip()
            nonce_id = (data.get("nonce") or "").strip()
            nonce_sig = (data.get("nonce_signature") or data.get("nonce_sig") or "").strip()
            claims = data.get("claims") or {}
            claims_sig = (data.get("claims_signature") or "").strip()
            public_key_armor = (data.get("public_key") or "").strip()

            # Step 1: Only fingerprint submitted — issue challenge with nonce and return new challenge
            if fingerprint and not nonce_sig:
                if len(fingerprint) != 40:
                    return self.challenge_invalid(response)
                client_nonce_raw = os.urandom(16)
                client_nonce_b64 = base64.b64encode(client_nonce_raw).decode("ascii")
                stage = self.executor.current_stage
                challenge = build_challenge(
                    fingerprint=fingerprint,
                    client_nonce_b64=client_nonce_b64,
                    service_id=stage.service_id,
                    server_key_armor=CAPAUTH_SERVER_KEY_ARMOR,
                    server_key_passphrase=CAPAUTH_SERVER_KEY_PASSPHRASE,
                )
                self.executor.plan.context["capauth_challenge"] = challenge
                self.executor.plan.context["capauth_fingerprint"] = fingerprint
                request = self.request
                is_extension = request.headers.get("X-CapAuth-Extension") == "true"
                is_qr = "application/qr+capauth" in (request.headers.get("Accept") or "")
                presentation = "extension" if is_extension else ("qr" if is_qr else "string")
                new_challenge_data = {
                    "need_fingerprint": False,
                    "fingerprint": fingerprint,
                    "nonce": challenge["nonce"],
                    "client_nonce_echo": challenge["client_nonce_echo"],
                    "timestamp": challenge["timestamp"],
                    "service": challenge["service"],
                    "expires": challenge["expires"],
                    "server_signature": challenge.get("server_signature", ""),
                    "presentation": presentation,
                    "qr_payload": "",
                    "component": "ak-stage-capauth",
                }
                if is_qr:
                    new_challenge_data["qr_payload"] = json.dumps({
                        "capauth_qr": "1.0",
                        "nonce": challenge["nonce"],
                        "service": challenge["service"],
                        "callback": request.build_absolute_uri(f"/capauth/v1/qr-verify/{challenge['nonce']}"),
                        "expires": challenge["expires"],
                    }, separators=(",", ":"))
                return HttpChallengeResponse(CapAuthChallenge(data=new_challenge_data))

            # Step 2: Full signed response
            if not all([fingerprint, nonce_id, nonce_sig]):
                return self.challenge_invalid(response)

            challenge_ctx = self.executor.plan.context.get("capauth_challenge", {})
            stored_fp = self.executor.plan.context.get("capauth_fingerprint", "")
            if fingerprint != stored_fp:
                return self.challenge_invalid(response)

            if not public_key_armor:
                try:
                    registry_entry = CapAuthKeyRegistry.objects.get(fingerprint=fingerprint)
                    public_key_armor = registry_entry.public_key_armor
                except CapAuthKeyRegistry.DoesNotExist:
                    return self.challenge_invalid(response)

            derived_fp = fingerprint_from_armor(public_key_armor)
            if derived_fp and derived_fp.upper() != fingerprint.upper():
                return self.challenge_invalid(response)

            stage = self.executor.current_stage
            is_new = not CapAuthKeyRegistry.objects.filter(fingerprint=fingerprint).exists()
            if is_new:
                if stage.require_enrollment_approval:
                    return self.challenge_invalid(response)
                CapAuthKeyRegistry.objects.create(
                    fingerprint=fingerprint,
                    public_key_armor=public_key_armor,
                    approved=True,
                )
                logger.info("New CapAuth key enrolled: %s", fingerprint[:8])

            try:
                key_record = CapAuthKeyRegistry.objects.get(fingerprint=fingerprint)
            except CapAuthKeyRegistry.DoesNotExist:
                return self.challenge_invalid(response)
            if not key_record.approved:
                return self.challenge_invalid(response)

            success, error_code, oidc_claims = verify_auth_response(
                fingerprint=fingerprint,
                nonce_id=nonce_id,
                nonce_signature_armor=nonce_sig,
                claims=claims,
                claims_signature_armor=claims_sig,
                public_key_armor=public_key_armor,
                challenge_context=challenge_ctx,
            )
            if not success:
                return self.challenge_invalid(response)

            CapAuthKeyRegistry.objects.filter(fingerprint=fingerprint).update(
                last_auth=datetime.now(timezone.utc)
            )

            from django.contrib.auth import get_user_model
            User = get_user_model()
            effective_fp = key_record.effective_fingerprint
            user, created = User.objects.get_or_create(username=effective_fp)
            display_name = oidc_claims.get("name", preferred_username_fallback(effective_fp))
            user.name = display_name
            if email := oidc_claims.get("email"):
                user.email = email
            self.executor.plan.context[PLAN_CONTEXT_PENDING_USER] = user
            self.executor.plan.context["capauth_oidc_claims"] = oidc_claims
            self.executor.plan.context["capauth_fingerprint_verified"] = effective_fp
            logger.info("CapAuth authentication completed for fingerprint %s (new=%s)", effective_fp[:8], created)
            return self.executor.stage_ok()
