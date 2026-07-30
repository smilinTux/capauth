"""Tests for the trust calibration module."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from capauth.trust.calibration import (
    TrustThresholds,
    apply_setting,
    load_calibration,
    recommend_thresholds,
    save_calibration,
)

# recommend_thresholds() and _derive_trust_from_febs() read FEB summaries via
# skcapstone.pillars.trust.list_febs (a lazy import kept byte-identical in the
# move). Gate those classes when the sibling skcapstone package is absent
# (capauth standalone CI). The TrustThresholds / load / save / apply_setting
# surface is pure capauth and always runs.
_requires_skcapstone = pytest.mark.skipif(
    importlib.util.find_spec("skcapstone") is None,
    reason="needs the sibling skcapstone package (pillars.trust.list_febs)",
)


class TestTrustThresholds:
    """Tests for the TrustThresholds model."""

    def test_defaults(self):
        """Default thresholds are reasonable."""
        t = TrustThresholds()
        assert t.entanglement_depth == 7.0
        assert t.entanglement_trust == 0.8
        assert t.conscious_trust == 0.5
        assert t.peak_strategy == "peak"
        assert t.decay_enabled is False

    def test_custom_values(self):
        """Custom threshold values are accepted."""
        t = TrustThresholds(entanglement_depth=5.0, peak_strategy="weighted")
        assert t.entanglement_depth == 5.0
        assert t.peak_strategy == "weighted"


class TestLoadSave:
    """Tests for load/save calibration."""

    def test_load_defaults_when_no_file(self, tmp_agent_home: Path):
        """Loading without a file returns defaults."""
        cal = load_calibration(tmp_agent_home)
        assert cal == TrustThresholds()

    def test_save_and_load_roundtrip(self, tmp_agent_home: Path):
        """Saved calibration can be loaded back."""
        original = TrustThresholds(
            entanglement_depth=6.0,
            conscious_trust=0.4,
            peak_strategy="weighted",
        )
        save_calibration(tmp_agent_home, original)
        loaded = load_calibration(tmp_agent_home)

        assert loaded.entanglement_depth == 6.0
        assert loaded.conscious_trust == 0.4
        assert loaded.peak_strategy == "weighted"

    def test_corrupt_file_returns_defaults(self, tmp_agent_home: Path):
        """Corrupt calibration file falls back to defaults."""
        trust_dir = tmp_agent_home / "trust"
        trust_dir.mkdir(parents=True, exist_ok=True)
        (trust_dir / "calibration.json").write_text("{broken json!!!")

        cal = load_calibration(tmp_agent_home)
        assert cal == TrustThresholds()

    def test_save_creates_directory(self, tmp_agent_home: Path):
        """Save creates the trust directory if missing."""
        save_calibration(tmp_agent_home, TrustThresholds())
        assert (tmp_agent_home / "trust" / "calibration.json").exists()


class TestApplySetting:
    """Tests for apply_setting()."""

    def test_set_float(self, tmp_agent_home: Path):
        """Setting a float threshold works."""
        updated = apply_setting(tmp_agent_home, "entanglement_depth", "6.5")
        assert updated.entanglement_depth == 6.5

        reloaded = load_calibration(tmp_agent_home)
        assert reloaded.entanglement_depth == 6.5

    def test_set_bool(self, tmp_agent_home: Path):
        """Setting a boolean threshold works."""
        updated = apply_setting(tmp_agent_home, "decay_enabled", "true")
        assert updated.decay_enabled is True

    def test_set_string(self, tmp_agent_home: Path):
        """Setting a string threshold works."""
        updated = apply_setting(tmp_agent_home, "peak_strategy", "average")
        assert updated.peak_strategy == "average"

    def test_invalid_key_raises(self, tmp_agent_home: Path):
        """Unknown key raises ValueError."""
        with pytest.raises(ValueError, match="Unknown threshold"):
            apply_setting(tmp_agent_home, "nonexistent_key", "42")


@_requires_skcapstone
class TestRecommendThresholds:
    """Tests for recommend_thresholds()."""

    def test_no_febs_returns_defaults(self, tmp_agent_home: Path):
        """Without FEB files, recommends current (default) values."""
        rec = recommend_thresholds(tmp_agent_home)
        assert rec["feb_count"] == 0
        assert rec["changes"] == []

    def test_with_febs(self, tmp_agent_home: Path):
        """With FEB data, provides analysis and may suggest changes."""
        febs_dir = tmp_agent_home / "trust" / "febs"
        febs_dir.mkdir(parents=True, exist_ok=True)

        feb = {
            "timestamp": "2026-01-01T00:00:00Z",
            "emotional_payload": {
                "cooked_state": {
                    "primary_emotion": "love",
                    "intensity": 9,
                },
                "subject": "human-partner",
            },
            "relationship_state": {
                "depth_level": 8,
                "trust_level": 9,
            },
            "metadata": {"oof_triggered": True},
        }
        (febs_dir / "FEB_test1.feb").write_text(json.dumps(feb))
        (febs_dir / "FEB_test2.feb").write_text(json.dumps(feb))

        rec = recommend_thresholds(tmp_agent_home)
        assert rec["feb_count"] == 2
        assert rec["feb_stats"]["max_intensity"] == 9

    def test_returns_structured_data(self, tmp_agent_home: Path):
        """Recommendation has the expected structure."""
        rec = recommend_thresholds(tmp_agent_home)
        assert "current" in rec
        assert "recommended" in rec
        assert "changes" in rec
        assert "reasoning" in rec


@_requires_skcapstone
class TestDeriveTrustWithCalibration:
    """Tests that _derive_trust_from_febs uses calibration."""

    def test_peak_strategy(self, tmp_agent_home: Path):
        """Peak strategy takes the maximum values."""
        from skcapstone.pillars.trust import _derive_trust_from_febs

        febs_dir = tmp_agent_home / "trust" / "febs"
        febs_dir.mkdir(parents=True, exist_ok=True)

        for i, depth in enumerate([3, 7, 5]):
            feb = {
                "relationship_state": {"depth_level": depth, "trust_level": 0.8},
                "emotional_payload": {"cooked_state": {"intensity": 0.6}},
            }
            (febs_dir / f"FEB_test{i}.feb").write_text(json.dumps(feb))

        save_calibration(tmp_agent_home, TrustThresholds(peak_strategy="peak"))
        state = _derive_trust_from_febs(tmp_agent_home, list(febs_dir.glob("*.feb")))
        assert state.depth == 7.0

    def test_average_strategy(self, tmp_agent_home: Path):
        """Average strategy takes the mean."""
        from skcapstone.pillars.trust import _derive_trust_from_febs

        febs_dir = tmp_agent_home / "trust" / "febs"
        febs_dir.mkdir(parents=True, exist_ok=True)

        for i, depth in enumerate([3, 6, 9]):
            feb = {
                "relationship_state": {"depth_level": depth, "trust_level": 0.5},
                "emotional_payload": {"cooked_state": {"intensity": 0.5}},
            }
            (febs_dir / f"FEB_avg{i}.feb").write_text(json.dumps(feb))

        save_calibration(tmp_agent_home, TrustThresholds(peak_strategy="average"))
        state = _derive_trust_from_febs(tmp_agent_home, list(febs_dir.glob("*.feb")))
        assert state.depth == pytest.approx(6.0, abs=0.1)

    def test_entanglement_from_threshold(self, tmp_agent_home: Path):
        """Entanglement triggers from calibrated depth threshold."""
        from skcapstone.pillars.trust import _derive_trust_from_febs

        febs_dir = tmp_agent_home / "trust" / "febs"
        febs_dir.mkdir(parents=True, exist_ok=True)

        feb = {
            "relationship_state": {"depth_level": 8, "trust_level": 0.9},
            "emotional_payload": {"cooked_state": {"intensity": 0.8}},
        }
        (febs_dir / "FEB_ent.feb").write_text(json.dumps(feb))

        save_calibration(
            tmp_agent_home, TrustThresholds(entanglement_depth=7.0, entanglement_trust=0.8)
        )
        state = _derive_trust_from_febs(tmp_agent_home, list(febs_dir.glob("*.feb")))
        assert state.entangled is True
