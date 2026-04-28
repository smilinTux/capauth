"""CapAuth -- Capability-based Authentication.

Decentralized, PGP-based identity and authorization.
OAuth is dead. Long live sovereignty.
"""

from __future__ import annotations

import os
from pathlib import Path

__version__ = "0.1.6"

SKCAPSTONE_HOME = Path.home() / ".skcapstone"
DEFAULT_CAPAUTH_DIR = SKCAPSTONE_HOME / "capauth"
LEGACY_CAPAUTH_DIR = Path.home() / ".capauth"


def resolve_capauth_home(base_dir: Path | None = None) -> Path:
    """Resolve the CapAuth home directory.

    Priority:
    1. Explicit ``base_dir``
    2. ``CAPAUTH_HOME`` environment override
    3. New default under ``~/.skcapstone/capauth`` when present
    4. Legacy ``~/.capauth`` when it already exists
    5. New default under ``~/.skcapstone/capauth``
    """
    if base_dir is not None:
        return Path(base_dir).expanduser()

    env_home = os.environ.get("CAPAUTH_HOME")
    if env_home:
        return Path(env_home).expanduser()

    if DEFAULT_CAPAUTH_DIR.exists():
        return DEFAULT_CAPAUTH_DIR
    if LEGACY_CAPAUTH_DIR.exists():
        return LEGACY_CAPAUTH_DIR
    return DEFAULT_CAPAUTH_DIR
