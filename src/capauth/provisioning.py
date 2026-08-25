"""Operator provisioning: enroll + tokenize a subject so the authz PDP allows it.

``capauth.authz.decide`` allows a subject only when it has an enrolled
``DeviceRecord`` of sufficient mode AND an active token granting the capability.
This helper provisions BOTH in one call, so an operator can enroll the live
subjects (agents, operators) that skchat's PEP decides on. That turns the authz
shadow measurement from a uniform deny-all into meaningful data: provisioned
subjects agree with the legacy allow, and the divergence log shows exactly which
subjects still need provisioning.

Pure orchestration over the shipped pairing + token surfaces; storage root is
injectable so tests never touch the real ``~/.skcapstone``.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Optional

from .crypto import get_backend
from .identity_class import IdentityClassError, IdentityClassName, assign_identity_class
from .models import Algorithm
from .pairing import (
    EnrollmentMode,
    PairingError,
    approve,
    attested_challenge,
    enroll_device,
    fingerprint_for,
    verified_challenge,
)
from .pairing.store import default_base_dir
from .subject import canonical_subject
from .tokens import issue_token

#: The default scopes a skchat subject is provisioned with (send/inbox/prekey).
SKCHAT_SCOPES = ["skchat.send", "skchat.inbox", "skchat.prekey"]

#: Identity the ephemeral operator-minted keypair carries (never persisted
#: beyond one provision_subject call; see :func:`_mint_operator_credential`).
_MINT_UID_NAME = "capauth-operator-provision"
_MINT_UID_EMAIL = "provision@capauth.local"


def _mint_operator_credential(mode: "EnrollmentMode | str", subject: str) -> tuple[str, dict]:
    """Generate a real, throwaway keypair + valid mode-appropriate proof.

    Card N10 (09a6d6f3) fix, item 4: this function used to not exist, and
    ``provision_subject`` passed ``pubkey or subject`` straight through --
    the bare subject STRING stood in for a public key whenever no real device
    key was to hand, which is both nonsensical key material and, now that
    :func:`capauth.pairing.enroll_device` actually checks proof for
    ``verified``/``attested``, would never verify.

    ``provision_subject`` is invoked BY the operator to grant trust directly
    (it is not a caller-asserted device enrollment from an untrusted party),
    so minting a real keypair here and immediately proving it to
    ``enroll_device`` is not a security downgrade: the operator already IS the
    authority the resulting proof establishes. The private half is discarded
    the moment this call returns; only the public half and the signature(s)
    over it are ever persisted.

    Args:
        mode: The enrollment mode ``provision_subject`` was called with.
        subject: The (not yet canonicalized) subject being provisioned.

    Returns:
        A ``(pubkey_armor, extra_kwargs)`` pair. ``extra_kwargs`` carries
        ``proof`` (verified), or ``operator_pubkey`` + ``attestation``
        (attested), matching exactly what ``enroll_device`` will re-derive
        and check for the SAME canonicalized subject.
    """
    if isinstance(mode, EnrollmentMode):
        resolved_mode = mode
    else:
        try:
            resolved_mode = EnrollmentMode(mode)
        except ValueError as exc:
            # Match enroll_device's own _coerce_mode wording so an unknown
            # mode fails the same way regardless of which path caught it.
            raise PairingError(f"unknown enrollment mode: {mode!r}") from exc

    backend = get_backend()
    passphrase = secrets.token_hex(16)
    bundle = backend.generate_keypair(
        _MINT_UID_NAME, _MINT_UID_EMAIL, passphrase, Algorithm.ED25519
    )

    # Mirrors enroll_device's own subject resolution for a non-bare-fingerprint
    # string (the only shape provision_subject's callers ever pass): strip +
    # canonicalize. Must match byte-for-byte or enroll_device would re-derive a
    # different challenge than the one just signed here and reject its own
    # operator-minted proof.
    canonical = canonical_subject(subject.strip())
    fingerprint = fingerprint_for(bundle.public_armor)

    extra: dict = {}
    if resolved_mode is EnrollmentMode.VERIFIED:
        challenge = verified_challenge(fingerprint, canonical)
        extra["proof"] = backend.sign(challenge, bundle.private_armor, passphrase)
    elif resolved_mode is EnrollmentMode.ATTESTED:
        challenge = attested_challenge(fingerprint, canonical)
        extra["operator_pubkey"] = bundle.public_armor
        extra["attestation"] = backend.sign(challenge, bundle.private_armor, passphrase)
    # tofu needs no proof; the real keypair alone is still an improvement over
    # a bare subject string standing in for key material.

    return bundle.public_armor, extra


def provision_subject(
    subject: str,
    scopes: Optional[list[str]] = None,
    *,
    identity_class: "IdentityClassName | str",
    mode: str = "verified",
    pubkey: Optional[str] = None,
    proof: Optional[str] = None,
    operator_pubkey: Optional[str] = None,
    attestation: Optional[str] = None,
    ttl_hours: int = 720,
    approver: str = "operator",
    sign: bool = True,
    base_dir: Optional[Path] = None,
) -> dict:
    """Provision one explicitly classed subject for PDP decisions.

    Enrolls a ``DeviceRecord`` at ``mode`` (default verified, the strongest, which
    satisfies every seeded skchat rule) and issues a capability token granting
    ``scopes`` (default the three skchat capabilities). It also persists the
    required capability-ceiling assignment. All three land under the same
    ``base_dir`` the PDP reads. The class ceiling and enrollment floor can still
    deny a granted scope.

    Args:
        subject: The subject identity the PDP will see (e.g. an fqid).
            Canonicalized at enrollment (card N3, ``capauth.pairing.enroll_device``);
            a translatable legacy shape is normalized, a non-conforming one is
            refused (:class:`capauth.exceptions.SubjectNamingError`).
        scopes: Capabilities to grant; defaults to the skchat scopes.
        identity_class: Required capability-ceiling role. It is explicit because
            fqid spelling alone cannot safely distinguish an operator, agent,
            service, connector, or node.
        mode: Enrollment mode for the device (verified | attested | tofu).
        pubkey: The subject's real public key, when a specific device key is
            to hand. When omitted (the common operator-provisioning case), a
            fresh throwaway keypair is minted and self-proven for you (card
            N10, 09a6d6f3: this used to fall back to ``pubkey or subject``,
            substituting the bare SUBJECT STRING as if it were key material --
            that placeholder never verifies now that ``enroll_device`` checks
            proof, so it is gone, not merely deprioritized).
        proof: A real device signature for ``verified`` mode, if ``pubkey`` is
            also given (see :func:`capauth.pairing.verified_challenge` for the
            exact bytes to sign). Ignored when ``pubkey`` is omitted (the
            minted credential supplies its own).
        operator_pubkey: A real vouching-operator key for ``attested`` mode, if
            ``pubkey`` is also given. Ignored when ``pubkey`` is omitted.
        attestation: A real operator signature for ``attested`` mode, pairing
            with ``operator_pubkey`` (see
            :func:`capauth.pairing.attested_challenge`). Ignored when
            ``pubkey`` is omitted.
        ttl_hours: Token lifetime (default 30 days).
        approver: Recorded as the device's approver.
        sign: PGP-sign the capability token. Signing failures RAISE
            (:class:`capauth.tokens.TokenSigningError`) rather than degrading to
            an unsigned token. Passing ``sign=False`` provisions a subject whose
            token the PDP will REJECT, since :func:`capauth.authz.decide`
            requires a verifying signature; it is for tests, not for real
            provisioning.
        base_dir: Injectable storage root (defaults to ~/.skcapstone).

    Returns:
        A summary dict: subject (the CANONICAL form actually enrolled/granted,
        which may differ from the ``subject`` argument if it was a translatable
        legacy shape), device_id, token_id, mode, identity_class, scopes.
    """
    granted = list(scopes) if scopes is not None else list(SKCHAT_SCOPES)
    base = Path(base_dir).expanduser() if base_dir is not None else default_base_dir()
    try:
        resolved_identity_class = (
            identity_class
            if isinstance(identity_class, IdentityClassName)
            else IdentityClassName(str(identity_class).strip())
        )
    except ValueError as exc:
        raise IdentityClassError(f"unknown identity class {identity_class!r}") from exc

    if pubkey is None:
        # No real device key presented: mint one + prove it ourselves rather
        # than substitute the subject string (card N10, item 4).
        pubkey, proof_kwargs = _mint_operator_credential(mode, subject)
    else:
        # A real device key WAS presented: pass through whatever real proof
        # the caller supplied (or none, for tofu / a caller that will supply
        # it separately). enroll_device is the one place that validates it;
        # we do not second-guess it here.
        proof_kwargs = {
            k: v
            for k, v in {
                "proof": proof,
                "operator_pubkey": operator_pubkey,
                "attestation": attestation,
            }.items()
            if v is not None
        }

    enrollment = enroll_device(
        pubkey, granted, mode=mode, subject=subject, base_dir=base, **proof_kwargs
    )
    # enroll_device canonicalizes subject (card N3); the token MUST be issued
    # under the same canonical spelling the device was enrolled under, or
    # decide() (an exact string match over both facts) can never correlate
    # them. Falls back to the caller's raw subject only in the degenerate case
    # enroll_device itself had nothing to canonicalize (see its docstring).
    # (named canonical_subj, not canonical_subject, so it does not shadow the
    # module-level capauth.subject.canonical_subject imported above)
    canonical_subj = enrollment.subject or subject
    device = approve(enrollment.enrollment_id, approver, base_dir=base)
    stored_class = assign_identity_class(canonical_subj, resolved_identity_class, base_dir=base)
    token = issue_token(base, canonical_subj, granted, ttl_hours=ttl_hours, sign=sign)

    return {
        "subject": canonical_subj,
        "device_id": device.device_id,
        "token_id": token.payload.token_id,
        "mode": device.mode.value,
        "identity_class": stored_class,
        "scopes": granted,
    }


__all__ = ["provision_subject", "SKCHAT_SCOPES"]
