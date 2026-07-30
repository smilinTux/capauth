"""CapAuth -- Capability-based Authentication.

Decentralized, PGP-based identity and authorization.
OAuth is dead. Long live sovereignty.
"""

from __future__ import annotations

import os
from pathlib import Path

from .agent_identity import AgentIdentity, resolve_agent_identity
from .authz import (
    DEFAULT_RULES,
    OBLIGATION_AUDIT,
    CapabilityRule,
    Decision,
    Obligation,
    decide,
)
from .pairing import (
    DeviceRecord,
    Enrollment,
    EnrollmentMode,
    PairingError,
    PairingStore,
    PairingWindow,
    approve,
    enroll_device,
    list_devices,
    mode_satisfies,
    open_window,
    revoke,
)
from .provisioning import SKCHAT_SCOPES, provision_subject
from .tokens import (
    Capability,
    SignedToken,
    TokenPayload,
    TokenType,
    export_token,
    has_scope,
    import_token,
    is_revoked,
    issue_token,
    list_tokens,
    mint_audience_token,
    revoke_token,
    verify_audience_token,
    verify_token,
)
from .trust import (
    CALIBRATION_FILENAME,
    DEFAULT_THRESHOLDS,
    FORMATTERS,
    TrustEdge,
    TrustGraph,
    TrustNode,
    TrustThresholds,
    apply_setting,
    build_trust_graph,
    format_dot,
    format_json,
    format_table,
    load_calibration,
    recommend_thresholds,
    save_calibration,
)

__all__ = [
    "AgentIdentity",
    "resolve_agent_identity",
    "resolve_capauth_home",
    # authz kernel (spine M3: deterministic decide() PDP)
    "decide",
    "Decision",
    "Obligation",
    "CapabilityRule",
    "DEFAULT_RULES",
    "OBLIGATION_AUDIT",
    # pairing kernel (spine M2: enrollment modes + operator window)
    "enroll_device",
    "approve",
    "revoke",
    "list_devices",
    "open_window",
    "mode_satisfies",
    "PairingError",
    "EnrollmentMode",
    "Enrollment",
    "DeviceRecord",
    "PairingWindow",
    "PairingStore",
    # tokens (kernel track M1: moved verbatim from skcapstone)
    "Capability",
    "SignedToken",
    "TokenPayload",
    "TokenType",
    "export_token",
    "import_token",
    "is_revoked",
    "issue_token",
    "list_tokens",
    "revoke_token",
    "verify_token",
    # audience-scoped token minting (audience-mint, M1+/R4.2)
    "mint_audience_token",
    "verify_audience_token",
    "has_scope",
    # trust (kernel track M1: moved verbatim from skcapstone)
    "FORMATTERS",
    "CALIBRATION_FILENAME",
    "DEFAULT_THRESHOLDS",
    "TrustEdge",
    "TrustGraph",
    "TrustNode",
    "TrustThresholds",
    "apply_setting",
    "build_trust_graph",
    "format_dot",
    "format_json",
    "format_table",
    "load_calibration",
    "recommend_thresholds",
    "save_calibration",
]

__version__ = "0.2.10"

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
