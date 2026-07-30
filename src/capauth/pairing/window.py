"""The operator pairing window: PairingGate semantics promoted into capauth.

This is skchat ``pairing_gate.PairingGate`` lifted verbatim in behavior into the
kernel, with a stable id and a clean record shape. The three controls are
unchanged:

1. **Operator-opened, time-boxed window.** Enrollment through a window is
   rejected unless the operator has opened one (a short TTL during which they
   *intend* to pair a device). No always-on public pairing.
2. **One-time-ish nonce.** Each window carries a nonce the enroll must present;
   the window auto-closes after ``max_accepts`` successful pairings.
3. **Rate limit.** Attempts are throttled (per rolling window) to blunt
   brute-force / DoS.

``now`` is injectable so tests drive time deterministically (expiry, throttle).
"""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Callable


class PairingWindow:
    """In-memory operator pairing window: time-boxed nonce + accept cap + rate limit.

    Faithful to ``skchat.pairing_gate.PairingGate``: same TTL / nonce /
    ``max_accepts`` / rolling-throttle semantics, promoted with a window id and
    ``check``/``consume`` returning the same ``(ok, reason)`` contract.
    """

    def __init__(
        self,
        *,
        window_ttl: float = 300.0,
        max_accepts: int = 3,
        throttle_window: float = 60.0,
        max_attempts_per_throttle: int = 10,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.window_id: str = str(uuid.uuid4())
        self._window_ttl = window_ttl
        self._max_accepts = max_accepts
        self._throttle_window = throttle_window
        self._max_attempts = max_attempts_per_throttle
        self._now = now
        self._nonce: str | None = None
        self._expires: float = 0.0
        self._accepts: int = 0
        self._attempts: list[float] = []
        # Open the window immediately on construction (open_window is the factory).
        self.open()

    # -- operator side --------------------------------------------------------
    def open(self) -> dict:
        """(Re)open a time-boxed pairing window; returns the nonce + expiry."""
        self._nonce = secrets.token_urlsafe(16)
        self._expires = self._now() + self._window_ttl
        self._accepts = 0
        return {
            "window_id": self.window_id,
            "nonce": self._nonce,
            "expires_at": self._expires,
            "ttl": self._window_ttl,
            "max_accepts": self._max_accepts,
        }

    def close(self) -> None:
        """Close the window: no further enrollments accepted until reopened."""
        self._nonce = None
        self._expires = 0.0

    def is_open(self) -> bool:
        """True while the window has a live nonce and has not expired."""
        return self._nonce is not None and self._now() < self._expires

    @property
    def nonce(self) -> str | None:
        return self._nonce

    @property
    def accepts(self) -> int:
        return self._accepts

    @property
    def max_accepts(self) -> int:
        return self._max_accepts

    @property
    def expires_at(self) -> float:
        return self._expires

    # -- accept side ----------------------------------------------------------
    def check(self, nonce: str | None) -> tuple[bool, str]:
        """Validate an enroll attempt: rate-limit -> window -> nonce -> accept-cap.

        Returns ``(ok, reason)`` and records the attempt for throttling either
        way, exactly as the shipped gate does.
        """
        if self._throttled():
            return False, "rate limited: too many pairing attempts"
        if not self.is_open():
            return False, "pairing window not open"
        if not nonce or nonce != self._nonce:
            return False, "invalid or missing pairing nonce"
        if self._accepts >= self._max_accepts:
            return False, "pairing window accept limit reached"
        return True, "ok"

    def consume(self) -> None:
        """Record a successful pairing; auto-close once the accept cap is hit."""
        self._accepts += 1
        if self._accepts >= self._max_accepts:
            self.close()

    # -- internals ------------------------------------------------------------
    def _throttled(self) -> bool:
        t = self._now()
        self._attempts = [a for a in self._attempts if a > t - self._throttle_window]
        self._attempts.append(t)
        return len(self._attempts) > self._max_attempts


def open_window(
    *,
    window_ttl: float = 300.0,
    max_accepts: int = 3,
    throttle_window: float = 60.0,
    max_attempts_per_throttle: int = 10,
    now: Callable[[], float] = time.time,
) -> PairingWindow:
    """Open an operator pairing window (the promoted ``PairingGate.open_window``).

    Args:
        window_ttl: Seconds the window stays open.
        max_accepts: Successful pairings before the window auto-closes.
        throttle_window: Rolling seconds over which attempts are counted.
        max_attempts_per_throttle: Max attempts allowed in the rolling window.
        now: Injectable clock (tests drive expiry/throttle deterministically).

    Returns:
        PairingWindow: An opened window; read ``.nonce`` / ``.window_id`` to
        gate enrollments (pass them to :func:`capauth.pairing.enroll_device`).
    """
    return PairingWindow(
        window_ttl=window_ttl,
        max_accepts=max_accepts,
        throttle_window=throttle_window,
        max_attempts_per_throttle=max_attempts_per_throttle,
        now=now,
    )


__all__ = ["PairingWindow", "open_window"]
