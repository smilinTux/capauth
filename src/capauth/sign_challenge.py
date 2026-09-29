"""Sign a CapAuth login challenge from the clipboard: ``capauth sign-challenge``.

The login page shows the exact message to sign (``CAPAUTH_NONCE_V1`` or
``V2``) with a copy button. This module takes that text from the clipboard
(or stdin), checks that it really is a complete CapAuth challenge, signs it
with ``gpg --detach-sign`` and puts the ASCII-armored signature back on the
clipboard (or stdout) for the page's paste box.

The passphrase never passes through this tool: gpg asks gpg-agent, and
gpg-agent asks the human with its own pinentry dialog.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Field order of the canonical payload (capauth.authentik.verifier
# canonical_nonce_payload); the signature covers these exact bytes.
_FIELDS = {
    "CAPAUTH_NONCE_V1": ("nonce", "client_nonce", "timestamp", "service", "expires"),
    "CAPAUTH_NONCE_V2": ("nonce", "client_nonce", "origin", "timestamp", "service", "expires"),
}
_FP_RE = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$")


class ChallengeError(Exception):
    """The input is not something this tool will sign, or signing failed."""


def normalize_challenge(text: str) -> bytes:
    """Return the canonical payload bytes, or raise ChallengeError.

    Copy and paste may add CRLF line ends and blank lines around the text;
    those are removed. Anything else (a missing, renamed, reordered or
    extra line) is refused: this tool signs CapAuth login challenges only,
    never arbitrary clipboard content.

    Args:
        text: The copied challenge text.

    Returns:
        bytes: The exact UTF-8 payload the server verifies.
    """
    lines = [
        ln.strip() for ln in text.replace("\r\n", "\n").replace("\r", "\n").strip().split("\n")
    ]
    fields = _FIELDS.get(lines[0] if lines else "")
    if fields is None or len(lines) != len(fields) + 1:
        raise ChallengeError("the clipboard does not hold a CapAuth login challenge")
    for line, name in zip(lines[1:], fields):
        key, sep, value = line.partition("=")
        if key != name or not sep or not value:
            raise ChallengeError("the clipboard does not hold a complete CapAuth login challenge")
    return "\n".join(lines).encode("utf-8")


def _load_profile(home: Optional[Path]):
    from .profile import load_profile

    return load_profile(home)


def resolve_key(key: Optional[str], home: Optional[Path]) -> str:
    """Pick the signing key: --key, else $CAPAUTH_SIGN_KEY, else the CapAuth profile.

    Args:
        key: Fingerprint from the command line, if any.
        home: CapAuth home (for the profile fallback).

    Returns:
        str: Upper-case fingerprint without spaces.
    """
    chosen = key or os.environ.get("CAPAUTH_SIGN_KEY")
    if not chosen:
        try:
            chosen = _load_profile(home).key_info.fingerprint
        except Exception as exc:
            raise ChallengeError(
                "no signing key: pass --key <fingerprint>, set CAPAUTH_SIGN_KEY, "
                f"or create a CapAuth profile ({exc})"
            ) from exc
    fp = re.sub(r"\s", "", chosen).upper()
    if not _FP_RE.match(fp):
        raise ChallengeError("the signing key must be a 40 or 64 hex digit fingerprint")
    return fp


def _clipboard_tools() -> tuple[list[str], list[str]]:
    """Return (paste argv, copy argv) for the first clipboard tool available."""
    candidates = []
    if os.environ.get("WAYLAND_DISPLAY"):
        candidates.append((["wl-paste", "--no-newline"], ["wl-copy"]))
    if os.environ.get("DISPLAY"):
        candidates.append(
            (
                ["xclip", "-selection", "clipboard", "-o"],
                ["xclip", "-selection", "clipboard", "-i"],
            )
        )
        candidates.append(
            (["xsel", "--clipboard", "--output"], ["xsel", "--clipboard", "--input"])
        )
    if sys.platform == "darwin":
        candidates.append((["pbpaste"], ["pbcopy"]))
    for paste, copy in candidates:
        if shutil.which(paste[0]) and shutil.which(copy[0]):
            return paste, copy
    raise ChallengeError(
        "no clipboard tool found: install wl-clipboard (Wayland) or xclip (X11), "
        "or use --stdin and --stdout"
    )


def read_clipboard() -> str:
    paste, _copy = _clipboard_tools()
    res = subprocess.run(paste, capture_output=True, text=True, timeout=10)
    if res.returncode != 0:
        raise ChallengeError(f"reading the clipboard failed ({paste[0]})")
    return res.stdout


def write_clipboard(text: str) -> None:
    _paste, copy = _clipboard_tools()
    # wl-copy and xclip fork to keep serving the selection: their output must
    # not be a pipe we wait on
    res = subprocess.run(
        copy,
        input=text,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    if res.returncode != 0:
        raise ChallengeError(f"writing the clipboard failed ({copy[0]})")


def _gpg_env() -> dict:
    env = dict(os.environ)
    # a terminal pinentry needs to know the terminal; stdin is our pipe
    if "GPG_TTY" not in env:
        for stream in (sys.stderr, sys.stdout):
            try:
                env["GPG_TTY"] = os.ttyname(stream.fileno())
                break
            except (OSError, ValueError, AttributeError):
                continue
    return env


def sign(payload: bytes, fingerprint: str) -> str:
    """Detach-sign ``payload`` with ``fingerprint`` through gpg (and gpg-agent).

    Args:
        payload: Canonical challenge bytes.
        fingerprint: Key to sign with; gpg must hold its secret key.

    Returns:
        str: ASCII-armored detached signature.
    """
    gpg = shutil.which("gpg")
    if gpg is None:
        raise ChallengeError("gpg is not installed")
    env = _gpg_env()
    held = subprocess.run(
        [gpg, "--batch", "--with-colons", "--list-secret-keys", fingerprint],
        capture_output=True,
        text=True,
        env=env,
    )
    if held.returncode != 0:
        raise ChallengeError(
            f"gpg holds no secret key {fingerprint}. Import it once "
            "(gpg asks for its passphrase): gpg --import <CapAuth home>/identity/private.asc"
        )
    res = subprocess.run(
        [gpg, "--armor", "--detach-sign", "--local-user", fingerprint, "--output", "-"],
        input=payload,
        capture_output=True,
        env=env,
        timeout=300,
    )
    sig = res.stdout.decode("utf-8", "replace")
    if res.returncode != 0 or "BEGIN PGP SIGNATURE" not in sig:
        raise ChallengeError("gpg did not sign (passphrase dialog cancelled or key unusable)")
    return sig
