"""Tri-mode tests for the capauth ⇄ skcapstone integration adapter.

Contract per skcapstone/docs/ADR-optional-integration-backbone.md:
  * standalone  (SK_STANDALONE=1)         → native fallback (log only)
  * absent      (_sdk = None)             → native fallback (log only)
  * integrated  (skcapstone present,
                 SKCAPSTONE_HOME sandboxed) → sk-alert / skscheduler / registry

skcapstone is installed in the dev venv, so "integrated" mode is exercised
against a sandboxed temp SKCAPSTONE_HOME — writes never leak to
~/.skcapstone/config/jobs.d/ or ~/.skcapstone/registry/.
"""

from __future__ import annotations

import json

import pytest

from capauth import integration


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Sandbox skcapstone's shared home at a temp dir for each test.

    Both SKCAPSTONE_HOME (used by the scheduler_jobs writer) and the
    skcapstone.AGENT_HOME module attribute (captured at import-time) are
    redirected to tmp_path so no fragment ever escapes to the real home.
    """
    monkeypatch.setenv("SKCAPSTONE_HOME", str(tmp_path))
    monkeypatch.delenv("SK_STANDALONE", raising=False)
    import skcapstone

    monkeypatch.setattr(skcapstone, "AGENT_HOME", str(tmp_path))
    return tmp_path


# ---------------------------------------------------------------------------
# Standalone mode — SK_STANDALONE=1
# ---------------------------------------------------------------------------


def test_standalone_flag_disables_integration(monkeypatch):
    """SK_STANDALONE=1 forces native mode regardless of skcapstone presence."""
    monkeypatch.setenv("SK_STANDALONE", "1")
    assert integration.is_present() is False
    assert integration.alert("verify_failed", {"fingerprint": "abcd1234"}, level="warn") is False
    assert integration.ensure_schedule() is False
    assert integration.register_self() is False
    assert integration.unregister_schedule() is False


def test_standalone_unregister_never_resolves_scheduler(monkeypatch, tmp_path):
    """Standalone unregister leaves an out-of-sandbox scheduler job untouched."""
    injected_home = tmp_path / "injected-home"
    sentinel = tmp_path / "outside-injected-home" / "jobs.d" / "capauth_key_rotation_check.yaml"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text("sentinel scheduler job\n", encoding="utf-8")
    expected = sentinel.read_bytes()

    monkeypatch.setenv("SK_STANDALONE", "1")
    monkeypatch.setenv("SKCAPSTONE_HOME", str(injected_home))

    def destructive_sdk_resolver():
        sentinel.unlink()
        raise AssertionError("standalone unregister must not resolve the scheduler SDK")

    monkeypatch.setattr(integration, "_get_sdk", destructive_sdk_resolver)

    assert integration.unregister_schedule() is False
    assert sentinel.read_bytes() == expected
    assert not injected_home.exists()


# ---------------------------------------------------------------------------
# Absent mode — skcapstone package not importable
# ---------------------------------------------------------------------------


def test_absent_skcapstone_falls_back_to_log(monkeypatch):
    """When _sdk is None (skcapstone absent), every call returns False gracefully."""
    monkeypatch.delenv("SK_STANDALONE", raising=False)
    monkeypatch.setattr(integration, "_sdk", None)
    assert integration.is_present() is False
    assert integration.alert("auth_denied", {"fingerprint": "abcd1234"}) is False
    assert integration.ensure_schedule() is False
    assert integration.register_self() is False
    assert integration.unregister_schedule() is False


def test_absent_sdk_alert_returns_false_for_all_levels(monkeypatch):
    """Native fallback: alert() always returns False for any level."""
    monkeypatch.setattr(integration, "_sdk", None)
    for level in ("info", "warn", "error", "critical"):
        assert integration.alert("enrollment_error", {"fp": "x"}, level=level) is False


# ---------------------------------------------------------------------------
# Integrated mode — skcapstone present, SKCAPSTONE_HOME sandboxed
# ---------------------------------------------------------------------------


def test_is_present_true_when_skcapstone_available(home):
    """With skcapstone installed and no SK_STANDALONE, is_present() is True."""
    assert integration.is_present() is True


def test_alert_publishes_to_correct_severity_topic(home):
    """alert() writes a pubsub message at topic capauth.<level>."""
    assert (
        integration.alert(
            "verify_failed",
            {"fingerprint": "abcd1234", "error_code": "sig_mismatch"},
            level="warn",
        )
        is True
    )
    topic_dir = home / "pubsub" / "topics" / "capauth.warn"
    assert topic_dir.is_dir(), f"expected topic dir {topic_dir} to exist"
    msg_files = list(topic_dir.glob("msg-*.json"))
    assert msg_files, "expected at least one pubsub message file"
    data = json.loads(msg_files[0].read_text())
    assert data["topic"] == "capauth.warn"
    # CRITICAL: event name must be in payload, NOT in topic suffix
    assert data["payload"]["event"] == "verify_failed"
    assert data["payload"]["fingerprint"] == "abcd1234"


def test_alert_error_level_publishes(home):
    """error-level alert lands on capauth.error topic."""
    assert integration.alert("enrollment_error", {"fp": "deadbeef"}, level="error") is True
    topic_dir = home / "pubsub" / "topics" / "capauth.error"
    assert topic_dir.is_dir()
    data = json.loads(next(topic_dir.glob("msg-*.json")).read_text())
    assert data["payload"]["event"] == "enrollment_error"


def test_alert_critical_level_publishes(home):
    """critical-level alert lands on capauth.critical topic."""
    assert integration.alert("key_rotation_due", {"fp": "cafebabe"}, level="critical") is True
    topic_dir = home / "pubsub" / "topics" / "capauth.critical"
    assert topic_dir.is_dir()
    data = json.loads(next(topic_dir.glob("msg-*.json")).read_text())
    assert data["payload"]["event"] == "key_rotation_due"


def test_ensure_schedule_registers_rotation_check(home):
    """ensure_schedule() writes a jobs.d drop-in for capauth_key_rotation_check."""
    assert integration.ensure_schedule(interval_hours=24) is True
    from skcapstone.scheduler_jobs import load_jobs_with_dropins

    jobs = {j.name: j for j in load_jobs_with_dropins(home / "config" / "jobs.yaml")}
    assert integration.ROTATION_JOB in jobs, f"expected {integration.ROTATION_JOB} in {list(jobs)}"
    assert jobs[integration.ROTATION_JOB].command == "capauth profile verify"
    assert jobs[integration.ROTATION_JOB].every_seconds == 24 * 3600


def test_ensure_schedule_idempotent(home):
    """Calling ensure_schedule() twice does not raise or duplicate."""
    assert integration.ensure_schedule() is True
    assert integration.ensure_schedule() is True


def test_unregister_schedule_removes_job(home):
    """unregister_schedule() removes the rotation-check drop-in."""
    integration.ensure_schedule()
    assert integration.unregister_schedule() is True
    assert integration.unregister_schedule() is False
    from skcapstone.scheduler_jobs import load_jobs_with_dropins

    jobs = {j.name: j for j in load_jobs_with_dropins(home / "config" / "jobs.yaml")}
    assert integration.ROTATION_JOB not in jobs


def test_register_self_writes_registry_entry(home):
    """register_self() writes a service registry JSON file."""
    assert integration.register_self(pid_file="/tmp/capauth-test.pid") is True
    registry_file = home / "registry" / "capauth.json"
    assert registry_file.exists(), f"expected registry file {registry_file}"
    entry = json.loads(registry_file.read_text())
    assert entry["name"] == "capauth"


def test_no_leak_to_real_home(home):
    """All integrated operations use the sandboxed home, not ~/.skcapstone."""
    import os
    from pathlib import Path

    integration.ensure_schedule()
    integration.register_self(pid_file="/tmp/capauth-leak-test.pid")

    # Verify writes went to sandboxed home
    assert (home / "registry" / "capauth.json").exists()

    # Verify real home is clean (if it exists at all, the job file must not be there)
    real_jobs_d = Path(os.path.expanduser("~/.skcapstone/config/jobs.d"))
    if real_jobs_d.exists():
        assert not (real_jobs_d / f"{integration.ROTATION_JOB}.yaml").exists()


# ---------------------------------------------------------------------------
# Wiring smoke: app and service modules import without error
# ---------------------------------------------------------------------------


def test_service_app_imports_integration_without_error():
    """capauth.service.app can be imported without errors."""
    import capauth.service.app  # noqa: F401


def test_integration_module_constants():
    """Check module-level constants are correct."""
    assert integration.SERVICE == "capauth"
    assert integration.ROTATION_JOB == "capauth_key_rotation_check"
