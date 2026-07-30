"""capauth ⇄ skcapstone — optional integration adapter.

capauth runs fully standalone.  When the ``skcapstone`` package is installed
(and the operator has not forced standalone mode with ``SK_STANDALONE=1``),
this adapter routes alerts through skcapstone's shared **sk-alert** bus and
registers a periodic key-rotation check with the fleet **skscheduler**, so
the whole sk* mesh sees auth events in one alert stream.  When skcapstone is
absent, every call degrades to capauth's native behaviour (structured logging
only — capauth has no native alerting path today).

This is the *default-on-by-presence* pattern from
``skcapstone/docs/ADR-optional-integration-backbone.md`` — nothing here is a
hard dependency; ``skcapstone`` lives in the optional ``[skcapstone]`` extra.

Public API:
    is_present()                       -> bool
    alert(event, payload, level)       -> bool   (True iff sent via sk-alert)
    ensure_schedule(interval_hours)    -> bool   (True iff registered with skscheduler)
    unregister_schedule()              -> bool
    register_self(pid_file)            -> bool

Topic convention: ``capauth.<severity>`` (severity ∈ info|warn|error|critical).
The semantic *event* name is carried in the payload ``event`` field — not the
topic suffix — so ``skcapstone alerts``' ``*.error``/``*.critical``/``*.warn``
wildcards match by severity while detail is preserved.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("capauth.integration")

#: This service's name — used as the alert topic prefix and registry key.
SERVICE = "capauth"

#: Fleet-scheduler job name for the key-rotation health check.
#: The scheduled job is a stub until a capauth signing daemon ships — it
#: simply runs ``capauth profile verify`` so the fleet knows keys are valid.
ROTATION_JOB = "capauth_key_rotation_check"

# Optional dependency, never a hard one, and never imported at module load time.
# ``skcapstone`` is an OPTIONAL, HIGHER-layer subapp; capauth is the L0 core and
# must import without it.  This adapter legitimately BRIDGES to skcapstone (that
# is its whole purpose), so we keep it optional-by-presence but resolve the
# import LAZILY on first use.  Importing ``capauth.integration`` (let alone
# ``import capauth``) therefore never pulls skcapstone into ``sys.modules``.
#
# ``_sdk`` is a cache with a sentinel: ``_UNSET`` means "not yet resolved", while
# ``None`` means "resolved and absent".  Tests set ``_sdk = None`` to force the
# absent path, and the sentinel keeps that monkeypatch from being re-resolved.
_UNSET: Any = object()
_sdk: Any = _UNSET


def _get_sdk() -> Any:
    """Resolve ``skcapstone.sdk`` lazily, caching the result (module or ``None``).

    The import is deferred to first call so that merely importing this module
    never triggers a subapp import.  Any failure (package absent or a broken
    partial install) caches ``None`` so callers transparently take the native
    fallback path.
    """
    global _sdk
    if _sdk is _UNSET:
        try:
            from skcapstone import sdk as sdk_mod  # type: ignore

            _sdk = sdk_mod
        except Exception:  # ImportError, or a broken partial install
            _sdk = None
    return _sdk


#: severity → logging method name (native fallback)
_LOG_METHOD = {
    "info": "info",
    "warn": "warning",
    "error": "error",
    "critical": "critical",
}
_NOTIFY_LEVELS = frozenset({"warn", "error", "critical"})


def is_present() -> bool:
    """Return whether skcapstone integration should be used from this process.

    ``True`` only when the package imported, the operator has not set
    ``SK_STANDALONE``, and the SDK reports itself available.  Any failure is
    treated as "not present" so callers transparently use their native path.
    """
    if os.environ.get("SK_STANDALONE"):
        return False
    sdk = _get_sdk()
    if sdk is None:
        return False
    try:
        return bool(sdk.is_available())
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("skcapstone present-check failed: %s", exc)
        return False


def alert(event: str, payload: dict[str, Any], level: str = "info") -> bool:
    """Emit an alert: via skcapstone sk-alert when present, else local log.

    The published topic follows the ecosystem convention ``capauth.<severity>``
    (so ``skcapstone alerts`` — which subscribes to ``*.error`` / ``*.critical``
    / ``*.warn`` — surfaces it).  The semantic *event* name is carried in the
    payload's ``event`` field rather than the topic, so routing stays
    severity-based while detail is preserved.

    Typical events: ``"verify_failed"``, ``"enrollment_error"``,
    ``"key_rotation_due"``, ``"auth_denied"``.

    Args:
        event: Semantic event name.  Stored in the payload as ``event``.
        payload: JSON-serialisable event body.
        level: ``info | warn | error | critical``.

    Returns:
        ``True`` if published to the shared bus, ``False`` if it fell back to
        local logging (which always also happens at the matching level).
    """
    body = {"event": event, **dict(payload)}
    if is_present():
        try:
            return bool(
                _get_sdk().alert(
                    f"{SERVICE}.{level}",
                    body,
                    level=level,
                    notify=level in _NOTIFY_LEVELS,
                )
            )
        except Exception as exc:
            logger.warning("sk-alert publish failed, logging locally: %s", exc)

    # native fallback — structured log at the matching level
    method = getattr(logger, _LOG_METHOD.get(level, "info"))
    method("[%s.%s] %s", SERVICE, level, body)
    return False


def ensure_schedule(interval_hours: float = 24.0) -> bool:
    """Register a key-rotation check with the fleet scheduler, if present.

    Writes a ``jobs.d/capauth_key_rotation_check.yaml`` drop-in that runs
    ``capauth profile verify`` every *interval_hours*, confirming that the
    PGP key is intact and the profile signature is valid.  This is a stub
    for the capauth signing-daemon cadence that will replace it once
    ``capauth rotate`` is implemented.  Idempotent — safe to call on every
    startup.

    Args:
        interval_hours: Check cadence in hours (default 24h).

    Returns:
        ``True`` if registered with skscheduler; ``False`` when skcapstone is
        absent and the caller should rely on its native mechanisms.
    """
    if not is_present():
        return False
    try:
        _get_sdk().register_job(
            {
                "name": ROTATION_JOB,
                "type": "shell",
                "command": "capauth profile verify",
                "every": f"{int(interval_hours * 3600)}s",
                "timeout": 60,
                "notify": "on_failure",
                "notify_level": "warn",
            }
        )
        logger.info(
            "Registered '%s' with skcapstone scheduler (every %.1fh).",
            ROTATION_JOB,
            interval_hours,
        )
        return True
    except Exception as exc:
        logger.warning("ensure_schedule failed (using native): %s", exc)
        return False


def unregister_schedule() -> bool:
    """Remove the key-rotation check drop-in from the fleet scheduler."""
    sdk = _get_sdk()
    if sdk is None:
        return False
    try:
        return bool(sdk.unregister_job(ROTATION_JOB))
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("unregister_schedule failed: %s", exc)
        return False


def register_self(pid_file: Optional[str] = None) -> bool:
    """Advertise capauth to skcapstone's discovery registry, if present.

    Args:
        pid_file: Optional pid-file path used as a liveness signal.

    Returns:
        ``True`` if registered, ``False`` otherwise.
    """
    if not is_present():
        return False
    try:
        _get_sdk().register_service(
            SERVICE,
            pid_file=pid_file or str(Path("~/.capauth/service.pid").expanduser()),
        )
        return True
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("register_self failed: %s", exc)
        return False
