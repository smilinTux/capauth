"""CapAuth trust domain: trust-web graph + Cloud 9 trust calibration.

Kernel track M1: the trust graph and calibration modules moved verbatim from
``skcapstone`` into the CapAuth L0 identity/authz core. The public surface is
re-exported here so callers can ``from capauth.trust import ...`` while the
submodules (``capauth.trust.graph``, ``capauth.trust.calibration``) keep the
original implementations byte-identical.

On-disk formats, JSON keys, and file paths (``~/.skcapstone/trust/...``) are
unchanged so existing data still loads.
"""

from __future__ import annotations

from capauth.trust.calibration import (
    CALIBRATION_FILENAME,
    DEFAULT_THRESHOLDS,
    TrustThresholds,
    apply_setting,
    load_calibration,
    recommend_thresholds,
    save_calibration,
)
from capauth.trust.graph import (
    FORMATTERS,
    TrustEdge,
    TrustGraph,
    TrustNode,
    build_trust_graph,
    format_dot,
    format_json,
    format_table,
)

__all__ = [
    # graph
    "FORMATTERS",
    "TrustEdge",
    "TrustGraph",
    "TrustNode",
    "build_trust_graph",
    "format_dot",
    "format_json",
    "format_table",
    # calibration
    "CALIBRATION_FILENAME",
    "DEFAULT_THRESHOLDS",
    "TrustThresholds",
    "apply_setting",
    "load_calibration",
    "recommend_thresholds",
    "save_calibration",
]
