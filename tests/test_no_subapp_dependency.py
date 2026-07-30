"""Gate: capauth CORE must import free of every higher-layer subapp.

capauth is the L0 identity/authz core.  It may be composed WITH the higher
subapps (skcapstone, skchat, skcomms, skmemory, skos, skharness), but importing
the core surface must never PULL one in.  Each L0 -> subapp coupling is either
inverted, lazily guarded, or degrades gracefully; this test locks that in.

The proof runs in a CLEAN interpreter subprocess (not the pytest process, which
has already imported plenty), imports the core surface, and asserts NONE of the
subapps entered ``sys.modules``.  The subapps ARE installed in this venv, so a
green result means the core genuinely does not touch them, not merely that they
are absent.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

# The subapps that capauth L0 must never import as a side effect of core import.
SUBAPPS = ("skcapstone", "skchat", "skcomms", "skmemory", "skos", "skharness")

# The capauth CORE surface (identity/authz kernel), each imported explicitly.
CORE_MODULES = (
    "capauth",
    "capauth.agent_identity",
    "capauth.tokens",
    "capauth.pairing",
    "capauth.authz",
    "capauth.trust",
    "capauth.pqc_identity",
)


def _clean_import_leaks(modules: tuple[str, ...]) -> list[str]:
    """Import ``modules`` in a fresh interpreter; return any leaked subapps.

    Returns the sorted list of subapp names that entered ``sys.modules`` as a
    side effect of importing the given modules.  An empty list is the pass
    condition.
    """
    script = textwrap.dedent(
        f"""
        import sys
        for _m in {modules!r}:
            __import__(_m)
        _subapps = {SUBAPPS!r}
        _leaked = sorted(
            s for s in _subapps
            if any(k == s or k.startswith(s + ".") for k in sys.modules)
        )
        print(",".join(_leaked))
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    out = proc.stdout.strip()
    return out.split(",") if out else []


def test_core_import_pulls_no_subapp():
    """Importing the whole capauth core surface leaks zero subapps."""
    leaked = _clean_import_leaks(CORE_MODULES)
    assert leaked == [], (
        f"capauth core import pulled in subapps: {leaked}. "
        "The L0 core must not depend on any higher-layer subapp."
    )


def test_bare_capauth_import_pulls_no_subapp():
    """Even a bare ``import capauth`` (package __init__) leaks zero subapps."""
    leaked = _clean_import_leaks(("capauth",))
    assert leaked == [], f"`import capauth` pulled in subapps: {leaked}"


def test_integration_module_import_is_lazy():
    """Importing the skcapstone bridge module must not eagerly load skcapstone.

    ``capauth.integration`` legitimately bridges to skcapstone, but the import
    is resolved lazily on first use, so merely importing the module never pulls
    skcapstone into ``sys.modules``.
    """
    leaked = _clean_import_leaks(("capauth.integration",))
    assert leaked == [], (
        f"`import capauth.integration` eagerly pulled in subapps: {leaked}. "
        "The skcapstone import must be lazy (deferred to first use)."
    )


def _hide(monkeypatch, *names: str) -> None:
    """Make ``import <name>`` raise ImportError in-process.

    A ``None`` entry in ``sys.modules`` forces the import machinery to raise
    ImportError for that name (and any ``from <name>.sub import ...``), which
    simulates the subapp being absent without uninstalling it.
    """
    for name in names:
        monkeypatch.setitem(sys.modules, name, None)


def test_agent_identity_falls_back_to_env_without_skmemory(monkeypatch):
    """#1 agent_identity: skmemory absent -> env precedence still resolves."""
    from capauth import agent_identity

    _hide(monkeypatch, "skmemory", "skmemory.agents")
    for var in ("SKAGENT", "SKCAPSTONE_AGENT", "SKMEMORY_AGENT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SKAGENT", "jarvis")
    # Env is the documented primary source; resolves with no skmemory at all.
    assert agent_identity._resolve_active_agent_name() == "jarvis"


def test_agent_identity_default_when_no_env_no_skmemory(monkeypatch):
    """#1 agent_identity: no env AND no skmemory -> None (caller floors to local)."""
    from capauth import agent_identity

    _hide(monkeypatch, "skmemory", "skmemory.agents")
    for var in ("SKAGENT", "SKCAPSTONE_AGENT", "SKMEMORY_AGENT"):
        monkeypatch.delenv(var, raising=False)
    # No env and skmemory import raises: graceful None (never an exception).
    assert agent_identity._resolve_active_agent_name() is None
    assert agent_identity.resolve_agent_identity(None).agent == "local"


def test_pqc_identity_raises_clear_error_without_skcomms(monkeypatch):
    """#2 pqc_identity: skcomms absent -> clear HybridSigUnavailable, no crash."""
    from capauth import pqc_identity

    _hide(monkeypatch, "skcomms", "skcomms.pqsig")
    with pytest.raises(pqc_identity.HybridSigUnavailable):
        pqc_identity._pqsig()
    with pytest.raises(pqc_identity.HybridSigUnavailable):
        pqc_identity.hybrid_keypair_for("lumina")
