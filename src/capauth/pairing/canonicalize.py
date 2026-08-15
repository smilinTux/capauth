"""One-shot rewrite of the live pairing store to canonical subjects.

Coord card N5 (`754265a7`), the migration companion to card N2's normalizer
(``capauth.subject.canonical_subject``, ``sk-standards/standards/
IDENTITY_NAMING_STANDARD.md``) and card N3's write-path enforcement
(``capauth.pairing.enroll_device`` refuses a non-canonical subject as of
commit ``a1fab497``). N3 only guards NEW enrollments; this module fixes the
records that predate it -- the live store this deployment actually runs on
was accumulating non-canonical subjects long before either card existed.

Two, deliberately different, rewrite strategies
------------------------------------------------
**Device records** (``<base_dir>/peers/*.json``, the ``pairing`` sidecar's
``devices[].subject`` field) are rewritten IN PLACE. A device record carries
no cryptographic signature over its own bytes -- it is trusted because it
lives in the local pairing store, not because anything signs it -- so
correcting its ``subject`` spelling is a plain, reversible edit. Exactly one
field is ever touched: the sidecar's own per-device ``subject`` (added when
missing, corrected when present-but-legacy). The surrounding v1 peer record
(``identity``, ``name``, ``capauth_uri``, ``handle``, ``fqid``, ...) is never
touched: ``capauth.pairing.store`` documents that shape as staying VERBATIM
("the M2 rule is absolute"), and this migration does not get a carve-out from
that rule just because it has a good reason.

**Capability tokens** (``<base_dir>/security/tokens/*.json``,
``payload.subject``) are handled completely differently, and NEVER edited in
place. :func:`capauth.tokens.signature_verifies` verifies a PGP signature over
``token.payload.model_dump_json()`` -- the WHOLE payload, subject included.
Rewriting ``payload.subject`` on a signed token would silently invalidate the
one signature that makes the token worth anything, while leaving a
plausible-looking, still-``verified: true``-tagged JSON file behind: exactly
the kind of quietly-broken artifact this migration exists to eliminate, not
create. So a non-canonical, still-active, non-revoked token is instead
RE-ISSUED: a brand-new payload is built (fresh ``token_id``, fresh
``issued_at``, the ORIGINAL ``expires_at`` preserved verbatim so re-issuance
never silently extends a grant's lifetime), freshly signed by
:func:`capauth.tokens._apply_signature`, and stored under its own new id. The
old token is then revoked via :func:`capauth.tokens.revoke_token` -- a state
transition, matching capauth's never-delete philosophy (:func:`capauth.
pairing.kernel.revoke` marks a device revoked rather than removing it; this
does the same for a superseded token). A revoked or already-expired token's
subject is left untouched: it can never grant anything via
:func:`capauth.authz.decide` regardless of spelling (revocation / expiry gate
that first), and re-issuing a FRESH, validly-signed token for a subject whose
grant was deliberately revoked or has lapsed would perversely restore it.

Both scans are idempotent: :func:`capauth.subject.canonical_subject` is
idempotent on an already-canonical string, so a record already rewritten (or
never non-canonical) never appears in a subsequent plan, and re-running
:func:`apply_canonical_rewrite` after a first application is a no-op (the
migration's own smoke test, run it twice).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from capauth.exceptions import SubjectNamingError
from capauth.subject import canonical_subject
from capauth.tokens import (
    SignedToken,
    TokenPayload,
    _apply_signature,
    _compute_token_id,
    _get_issuer_fingerprint,
    _store_token,
    is_revoked,
    list_tokens,
    revoke_token,
)

from .store import SIDECAR_KEY, PairingStore, default_base_dir

logger = logging.getLogger("capauth.pairing.canonicalize")

#: Metadata keys stamped onto a rewritten device sidecar entry (additive,
#: never overwrites an existing stamp -- see :func:`_rewrite_device_entry`).
_MIGRATED_FROM_KEY = "subject_migrated_from"
_MIGRATED_AT_KEY = "subject_migrated_at"

#: Metadata keys stamped onto a re-issued token's payload, so the new token
#: carries a durable pointer back to what it superseded.
_TOKEN_MIGRATED_FROM_ID_KEY = "migrated_from_token_id"
_TOKEN_MIGRATED_FROM_SUBJECT_KEY = "migrated_from_subject"


@dataclass(frozen=True)
class DeviceRewrite:
    """One planned (or applied) device sidecar subject rewrite."""

    peer_path: Path
    device_id: str
    old_subject: str
    new_subject: str


@dataclass(frozen=True)
class TokenRewrite:
    """One planned (or applied) token re-issuance."""

    token_path: Path
    old_token_id: str
    old_subject: str
    new_subject: str
    #: None until :func:`apply_canonical_rewrite` actually mints the
    #: replacement (a dry-run plan cannot know the new token's id: it depends
    #: on ``issued_at``, which is set at apply time).
    new_token_id: Optional[str] = None


@dataclass(frozen=True)
class TokenSkip:
    """A non-canonical token subject deliberately left untouched, and why."""

    token_path: Path
    token_id: str
    subject: str
    reason: str


@dataclass
class RewritePlan:
    """Everything :func:`scan_canonical_rewrite` found, before any writes."""

    base_dir: Path
    devices: list[DeviceRewrite] = field(default_factory=list)
    tokens: list[TokenRewrite] = field(default_factory=list)
    token_skips: list[TokenSkip] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """True iff there is nothing left to rewrite (the migration is done)."""
        return not self.devices and not self.tokens


def _safe_canonicalize(subject: str) -> Optional[str]:
    """:func:`canonical_subject`, returning None on a subject it refuses.

    A subject that cannot be canonicalized at all (malformed past what the
    alias table repairs) is not this migration's problem to invent a mapping
    for; :func:`skcapstone.doctor._scan_pairing_subjects` already surfaces
    those separately as ``"rejected: ..."`` findings for a human to look at.
    """
    try:
        return canonical_subject(subject)
    except SubjectNamingError:
        return None


def _peer_level_subject(record: dict) -> str:
    """The v1 peer record's own identity-ish fields, as a last-resort subject.

    Mirrors :meth:`capauth.pairing.store.PairingStore._subject_of` exactly
    (same field priority), since that is what a sidecar device entry WITHOUT
    its own ``subject`` key falls back to at read time
    (:meth:`PairingStore._device_from_entry`). Used here only to compute what
    an entry's EFFECTIVE current subject is, never written back to the v1
    record itself.
    """
    return record.get("identity") or record.get("name") or record.get("capauth_uri") or ""


def scan_canonical_rewrite(base_dir: Optional[Path] = None) -> RewritePlan:
    """Build the full rewrite plan without touching the store.

    Walks every peer file's ``pairing.devices[]`` sidecar entries and every
    stored token's payload, comparing each subject against
    :func:`capauth.subject.canonical_subject`. Safe to call against the real
    ``~/.skcapstone`` store: this function never writes.

    Args:
        base_dir: Storage root (defaults to ``~/.skcapstone``, the same root
            :func:`capauth.pairing.store.default_base_dir` and the token
            store both use).

    Returns:
        RewritePlan: every device and token that needs rewriting, plus the
        tokens deliberately skipped (revoked / expired) and why.
    """
    home = Path(base_dir).expanduser() if base_dir is not None else default_base_dir()
    store = PairingStore(base_dir=home)
    plan = RewritePlan(base_dir=home)

    if store.peers_dir.exists():
        for path in sorted(store.peers_dir.glob("*.json")):
            record = store._load_peer_raw(path)  # noqa: SLF001 - same package family
            if not isinstance(record, dict):
                continue
            sidecar = record.get(SIDECAR_KEY)
            if not isinstance(sidecar, dict):
                continue
            devices = sidecar.get("devices")
            if not isinstance(devices, list):
                continue
            peer_level = _peer_level_subject(record)
            for entry in devices:
                if not isinstance(entry, dict):
                    continue
                current = entry.get("subject") or peer_level
                if not current:
                    continue
                canonical = _safe_canonicalize(current)
                if canonical is None or canonical == current:
                    continue
                plan.devices.append(
                    DeviceRewrite(
                        peer_path=path,
                        device_id=str(entry.get("device_id") or ""),
                        old_subject=current,
                        new_subject=canonical,
                    )
                )

    for token in list_tokens(home):
        subject = token.payload.subject or ""
        canonical = _safe_canonicalize(subject)
        if canonical is None or canonical == subject:
            continue
        token_id = token.payload.token_id
        token_path = home / "security" / "tokens" / f"{token_id[:16]}.json"
        if is_revoked(home, token_id):
            plan.token_skips.append(
                TokenSkip(
                    token_path=token_path,
                    token_id=token_id,
                    subject=subject,
                    reason="already revoked: re-issuing would perversely restore a "
                    "deliberately-revoked grant",
                )
            )
            continue
        if not token.payload.is_active:
            plan.token_skips.append(
                TokenSkip(
                    token_path=token_path,
                    token_id=token_id,
                    subject=subject,
                    reason="expired / not-yet-valid: re-issuing would silently revive "
                    "a lapsed grant",
                )
            )
            continue
        plan.tokens.append(
            TokenRewrite(
                token_path=token_path,
                old_token_id=token_id,
                old_subject=subject,
                new_subject=canonical,
            )
        )

    return plan


def format_rewrite_plan(plan: RewritePlan) -> str:
    """Render ``plan`` as the human-readable dry-run report."""
    lines: list[str] = []
    lines.append(f"CapAuth canonical-subject rewrite plan -- store: {plan.base_dir}")
    lines.append("")

    lines.append(
        f"== Device records (peers/*.json pairing.devices[].subject): {len(plan.devices)} =="
    )
    for rewrite in plan.devices:
        rel = _relative(rewrite.peer_path, plan.base_dir)
        did = rewrite.device_id[:8] or "?"
        lines.append(f"  {rel} device {did}: {rewrite.old_subject!r} -> {rewrite.new_subject!r}")
    if not plan.devices:
        lines.append("  (none -- every device record is already canonical)")
    lines.append("")

    lines.append(
        f"== Capability tokens to re-issue (security/tokens/*.json payload.subject): {len(plan.tokens)} =="
    )
    for rewrite in plan.tokens:
        rel = _relative(rewrite.token_path, plan.base_dir)
        lines.append(
            f"  {rel} token {rewrite.old_token_id[:12]}: {rewrite.old_subject!r} -> "
            f"{rewrite.new_subject!r} (mint new signed token, revoke {rewrite.old_token_id[:12]})"
        )
    if not plan.tokens:
        lines.append("  (none -- every active, non-revoked token is already canonical)")
    lines.append("")

    if plan.token_skips:
        lines.append(
            f"== Non-canonical tokens deliberately left untouched: {len(plan.token_skips)} =="
        )
        for skip in plan.token_skips:
            rel = _relative(skip.token_path, plan.base_dir)
            lines.append(f"  {rel} token {skip.token_id[:12]} ({skip.subject!r}): {skip.reason}")
        lines.append("")

    total = len(plan.devices) + len(plan.tokens)
    lines.append(
        f"TOTAL: {total} rewrite(s) planned ({len(plan.devices)} device, {len(plan.tokens)} token)."
        + (" Store is already fully canonical." if plan.is_empty else "")
    )
    return "\n".join(lines)


def _relative(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


@dataclass
class RewriteReport:
    """What :func:`apply_canonical_rewrite` actually did."""

    devices_rewritten: list[DeviceRewrite] = field(default_factory=list)
    tokens_reissued: list[TokenRewrite] = field(default_factory=list)
    tokens_revoked: list[str] = field(default_factory=list)


def _rewrite_device_entry(entry: dict, new_subject: str, old_subject: str) -> None:
    """Mutate one sidecar device entry's ``subject`` in place, additively.

    Stamps ``subject_migrated_from`` / ``subject_migrated_at`` the FIRST time
    an entry is touched only (never overwritten on a later run), so the
    record keeps one honest paper trail of its original spelling rather than
    a moving target -- the same "state transition, not erasure" posture
    :func:`capauth.pairing.kernel.revoke` uses for devices.
    """
    entry["subject"] = new_subject
    if _MIGRATED_FROM_KEY not in entry:
        entry[_MIGRATED_FROM_KEY] = old_subject
        entry[_MIGRATED_AT_KEY] = datetime.now(timezone.utc).isoformat()


def _reissue_token(home: Path, old: SignedToken, new_subject: str, *, sign: bool) -> SignedToken:
    """Mint a brand-new, canonically-subjected, freshly-signed token.

    Preserves ``capabilities``, ``token_type``, ``not_before``, ``audience``,
    and -- critically -- the ORIGINAL ``expires_at`` verbatim (not a fresh
    TTL computed from now), so re-issuance can never silently extend how long
    a grant is good for. ``issued_at`` and ``token_id`` are fresh: this is a
    genuinely new, independently-verifiable token, not an edited copy of the
    old one wearing a new signature.
    """
    issuer_fp = _get_issuer_fingerprint(home)
    metadata = dict(old.payload.metadata)
    metadata[_TOKEN_MIGRATED_FROM_ID_KEY] = old.payload.token_id
    metadata[_TOKEN_MIGRATED_FROM_SUBJECT_KEY] = old.payload.subject

    payload = TokenPayload(
        token_id="",
        token_type=old.payload.token_type,
        issuer=issuer_fp,
        subject=new_subject,
        capabilities=list(old.payload.capabilities),
        issued_at=datetime.now(timezone.utc),
        expires_at=old.payload.expires_at,
        not_before=old.payload.not_before,
        metadata=metadata,
        audience=old.payload.audience,
    )
    payload.token_id = _compute_token_id(payload)

    token = SignedToken(payload=payload)
    _apply_signature(token, home, sign=sign)
    _store_token(home, token)
    return token


def apply_canonical_rewrite(
    plan: RewritePlan,
    *,
    sign_reissued_tokens: bool = True,
) -> RewriteReport:
    """Apply a previously-built :class:`RewritePlan` to the store.

    Re-runnable and idempotent: call :func:`scan_canonical_rewrite` again
    after this returns and the new plan's ``devices``/``tokens`` lists are
    empty (every rewritten record is now, by construction, exactly the
    canonical string ``canonical_subject`` returns for it, and that function
    is idempotent on its own output).

    Args:
        plan: The plan to apply, from :func:`scan_canonical_rewrite`. Passing
            a stale plan (built against a store that has since changed) is
            safe but pointless -- re-scan first.
        sign_reissued_tokens: Whether re-issued tokens should be PGP-signed
            (the production default). Tests that inject a hermetic identity
            with no real signing key pass ``False``, matching
            ``capauth.tokens.issue_token``'s own ``sign`` parameter.

    Returns:
        RewriteReport: exactly what was changed.
    """
    store = PairingStore(base_dir=plan.base_dir)
    report = RewriteReport()

    by_path: dict[Path, list[DeviceRewrite]] = {}
    for rewrite in plan.devices:
        by_path.setdefault(rewrite.peer_path, []).append(rewrite)

    for path, rewrites in by_path.items():
        record = store._load_peer_raw(path)  # noqa: SLF001 - same package family
        if not isinstance(record, dict):
            logger.warning("skipping %s: no longer a valid peer record", path)
            continue
        sidecar = record.get(SIDECAR_KEY)
        if not isinstance(sidecar, dict):
            continue
        devices = sidecar.get("devices")
        if not isinstance(devices, list):
            continue
        wanted = {(r.device_id, r.old_subject) for r in rewrites}
        touched = False
        for entry in devices:
            if not isinstance(entry, dict):
                continue
            key = (
                str(entry.get("device_id") or ""),
                entry.get("subject") or _peer_level_subject(record),
            )
            if key not in wanted:
                continue
            new_subject = next(
                r.new_subject for r in rewrites if (r.device_id, r.old_subject) == key
            )
            _rewrite_device_entry(entry, new_subject, key[1])
            touched = True
            report.devices_rewritten.append(
                DeviceRewrite(
                    peer_path=path,
                    device_id=key[0],
                    old_subject=key[1],
                    new_subject=new_subject,
                )
            )
        if touched:
            store._write_peer_raw(path, record)  # noqa: SLF001 - same package family

    for rewrite in plan.tokens:
        matching = [
            t for t in list_tokens(plan.base_dir) if t.payload.token_id == rewrite.old_token_id
        ]
        if not matching:
            logger.warning("skipping token %s: no longer present", rewrite.old_token_id[:12])
            continue
        old_token = matching[0]
        new_token = _reissue_token(
            plan.base_dir, old_token, rewrite.new_subject, sign=sign_reissued_tokens
        )
        revoke_token(plan.base_dir, rewrite.old_token_id)
        report.tokens_reissued.append(
            TokenRewrite(
                token_path=rewrite.token_path,
                old_token_id=rewrite.old_token_id,
                old_subject=rewrite.old_subject,
                new_subject=rewrite.new_subject,
                new_token_id=new_token.payload.token_id,
            )
        )
        report.tokens_revoked.append(rewrite.old_token_id)

    return report


__all__ = [
    "DeviceRewrite",
    "TokenRewrite",
    "TokenSkip",
    "RewritePlan",
    "RewriteReport",
    "scan_canonical_rewrite",
    "format_rewrite_plan",
    "apply_canonical_rewrite",
]
