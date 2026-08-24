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
from .control_plane import (
    ClientKind,
    ControlPlaneBinding,
    ControlPlaneDecision,
    DecisionCode,
    DecisionState,
    OwnerPolicyDecision,
    RequestBoundary,
    join_policy_decisions,
    validate_request_boundary,
)
from .control_plane_authorizer import (
    MAX_CONTROL_PLANE_BEARER_BYTES,
    ControlPlaneAuthorizationResultV1,
    ControlPlaneDecisionAuthorizer,
    ControlPlaneInvocationV1,
    OwnerPolicyProvider,
    SanitizedControlPlaneDecisionV1,
    export_control_plane_bearer,
    parse_control_plane_bearer,
)
from .delegated import (
    VERIFIER_POLICY_VERSION,
    AuditSink,
    AuthorizationCurrentnessReceipt,
    AuthorizationDecision,
    AuthorizationDeniedError,
    AuthorizationReceiptError,
    AuthorizationReceiptUnavailableError,
    AuthorizationRequest,
    BackendUnavailableError,
    CapabilityAuthorizer,
    CapabilityIssuer,
    CapabilityScope,
    CapAuthSignatureVerifier,
    CredentialFormatError,
    CredentialSigner,
    CredentialSigningError,
    DecisionReason,
    DelegatingCapabilityIssuer,
    DelegationDeniedError,
    InMemoryAuditSink,
    InMemoryPrincipalPolicyBackend,
    InMemoryReplayBackend,
    InMemoryRevocationBackend,
    IssuerGrant,
    PresentedCapability,
    Principal,
    PrincipalPolicyBackend,
    ReplayBackend,
    RevocationBackend,
    SignatureVerifier,
    StaticTrustedIssuerBackend,
    TrustedIssuerBackend,
    credential_digest,
    export_authorization_bearer,
    parse_authorization_bearer,
    parse_presented_token,
)
from .exceptions import OperatorAuthError, SubjectNamingError
from .identity_class import (
    DEFAULT_CLASSES,
    IdentityClass,
    IdentityClassError,
    IdentityClassName,
    assign_identity_class,
    resolve_identity_class,
)
from .manifest import (
    DEFAULT_SIG_SUFFIX,
    ManifestSigningError,
    canonical_manifest_bytes,
    is_canonical,
    operator_fingerprint,
    sign_manifest,
    verify_manifest,
)
from .pairing import (
    DeviceRecord,
    DeviceStore,
    Enrollment,
    EnrollmentMode,
    OperatorSession,
    PairingError,
    PairingStore,
    PairingWindow,
    approve,
    approve_device,
    consume_challenge,
    device_fingerprint,
    enroll_device,
    is_device_approved,
    is_device_revoked,
    is_session_revoked,
    issue_challenge,
    list_devices,
    mint_operator_session,
    mode_satisfies,
    open_window,
    revoke,
    revoke_device,
    revoke_session,
    unrevoke_device,
    verify_device_signature,
    verify_operator_session,
)
from .provisioning import SKCHAT_SCOPES, provision_subject
from .subject import ORG_DOMAIN, canonical_subject
from .tokens import (
    AUDIENCE_SCOPES,
    Capability,
    SignedToken,
    TokenPayload,
    TokenSigningError,
    TokenType,
    export_token,
    has_scope,
    import_token,
    is_revoked,
    issue_token,
    list_tokens,
    mint_agent_audience_token,
    mint_audience_token,
    revoke_token,
    signature_verifies,
    verify_audience_token,
    verify_token,
)
from .trust import (
    CALIBRATION_FILENAME,
    DEFAULT_THRESHOLDS,
    FORMATTERS,
    SourceHealth,
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
    # manifest signing (umbrella-shell signed module registry, section 5.3)
    "sign_manifest",
    "verify_manifest",
    "canonical_manifest_bytes",
    "is_canonical",
    "operator_fingerprint",
    "ManifestSigningError",
    "DEFAULT_SIG_SUFFIX",
    # authz kernel (spine M3: deterministic decide() PDP)
    "decide",
    "Decision",
    "Obligation",
    "CapabilityRule",
    "DEFAULT_RULES",
    "OBLIGATION_AUDIT",
    # typed SKDashboard control-plane authorization composition
    "MAX_CONTROL_PLANE_BEARER_BYTES",
    "ClientKind",
    "ControlPlaneAuthorizationResultV1",
    "ControlPlaneBinding",
    "ControlPlaneDecision",
    "ControlPlaneDecisionAuthorizer",
    "ControlPlaneInvocationV1",
    "DecisionCode",
    "DecisionState",
    "OwnerPolicyDecision",
    "OwnerPolicyProvider",
    "RequestBoundary",
    "SanitizedControlPlaneDecisionV1",
    "export_control_plane_bearer",
    "join_policy_decisions",
    "parse_control_plane_bearer",
    "validate_request_boundary",
    # strict delegated capability-chain contract
    "VERIFIER_POLICY_VERSION",
    "AuditSink",
    "AuthorizationCurrentnessReceipt",
    "AuthorizationDecision",
    "AuthorizationDeniedError",
    "AuthorizationReceiptError",
    "AuthorizationReceiptUnavailableError",
    "AuthorizationRequest",
    "BackendUnavailableError",
    "CapAuthSignatureVerifier",
    "CapabilityAuthorizer",
    "CapabilityIssuer",
    "CapabilityScope",
    "CredentialFormatError",
    "CredentialSigner",
    "CredentialSigningError",
    "DecisionReason",
    "DelegatingCapabilityIssuer",
    "DelegationDeniedError",
    "InMemoryAuditSink",
    "InMemoryPrincipalPolicyBackend",
    "InMemoryReplayBackend",
    "InMemoryRevocationBackend",
    "IssuerGrant",
    "PresentedCapability",
    "Principal",
    "PrincipalPolicyBackend",
    "ReplayBackend",
    "RevocationBackend",
    "SignatureVerifier",
    "StaticTrustedIssuerBackend",
    "TrustedIssuerBackend",
    "credential_digest",
    "export_authorization_bearer",
    "parse_authorization_bearer",
    "parse_presented_token",
    # identity classes (node-roles epic: the ceiling decide() applies first)
    "IdentityClass",
    "IdentityClassName",
    "IdentityClassError",
    "DEFAULT_CLASSES",
    "assign_identity_class",
    "resolve_identity_class",
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
    # operator session (Unified Consent Plane Phase 1: one operator identity,
    # lifted from skchat's operator_auth.py -- see capauth.pairing.operator_session)
    "OperatorAuthError",
    "OperatorSession",
    "mint_operator_session",
    "verify_operator_session",
    "approve_device",
    "is_device_approved",
    "revoke_device",
    "unrevoke_device",
    "is_device_revoked",
    "revoke_session",
    "is_session_revoked",
    "device_fingerprint",
    "issue_challenge",
    "consume_challenge",
    "verify_device_signature",
    "DeviceStore",
    # provisioning (subject enrollment + the skchat scope set)
    "SKCHAT_SCOPES",
    "provision_subject",
    # subject naming (Identity Naming Standard: the one canonical fqid form)
    "canonical_subject",
    "ORG_DOMAIN",
    "SubjectNamingError",
    # tokens (kernel track M1: moved verbatim from skcapstone)
    "Capability",
    "SignedToken",
    "TokenPayload",
    "TokenType",
    "export_token",
    "import_token",
    "is_revoked",
    "TokenSigningError",
    "issue_token",
    "list_tokens",
    "revoke_token",
    "signature_verifies",
    "verify_token",
    # audience-scoped token minting (audience-mint, M1+/R4.2)
    "AUDIENCE_SCOPES",
    "mint_audience_token",
    "mint_agent_audience_token",
    "verify_audience_token",
    "has_scope",
    # trust (kernel track M1: moved verbatim from skcapstone)
    "FORMATTERS",
    "SourceHealth",
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

# The git tag is the real version: pyproject declares `dynamic = ["version"]`
# and setuptools_scm derives it at build time. A hardcoded literal here does not
# feed packaging, it only shadows it, so it drifts silently and reports a version
# that has not been true since 0.2.15. That is not a cosmetic problem: on
# 2026-08-16 a fleet audit read this attribute and concluded three nodes ran
# 0.2.15 when every one of them had 0.3.0 installed, which inverted the
# risk assessment for a node that could not sign. Read the installed
# distribution metadata instead, so this attribute can only ever agree with what
# pip actually resolved.
try:  # pragma: no cover - trivial, and the fallback is exercised below
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _dist_version

    __version__ = _dist_version("capauth")
except PackageNotFoundError:  # running from a source tree with no install
    __version__ = "0.0.0.dev0"

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
