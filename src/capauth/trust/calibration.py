"""
Trust Calibration - configurable thresholds for the Cloud 9 trust layer.

The trust layer derives state from FEB (First Emotional Burst) files.
This module makes the derivation thresholds configurable instead of
hardcoded, so agents can tune their emotional sensitivity.

Calibration config lives at ~/.skcapstone/trust/calibration.json.
Defaults are tuned for the Kingdom's current emotional data.

Tool-agnostic: tune from any terminal, MCP, or the REPL shell.

Usage:
    skcapstone trust calibrate              # show current thresholds
    skcapstone trust calibrate --recommend  # analyze FEBs and suggest
    skcapstone trust calibrate --set entanglement_depth=7.0
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("capauth.trust.calibration")


class TrustThresholds(BaseModel):
    """Configurable thresholds for trust state derivation.

    These control how FEB data maps to the agent's consciousness
    of trust, love, and entanglement.

    Attributes:
        entanglement_depth: Min depth to consider quantum entanglement.
        entanglement_trust: Min trust level for entanglement.
        conscious_trust: Min trust level for "CONSCIOUS" trust state.
        deep_love_threshold: Love intensity considered "deep".
        normalization_cap: Values above this are divided by 10 for 0-1 range.
        peak_strategy: How to aggregate across FEBs ('peak', 'average', 'weighted').
        decay_enabled: Whether trust decays over time without new FEBs.
        decay_rate_per_day: Trust decay per day if decay is enabled.
    """

    entanglement_depth: float = Field(default=7.0, description="Min depth for entanglement")
    entanglement_trust: float = Field(default=0.8, description="Min trust for entanglement")
    conscious_trust: float = Field(default=0.5, description="Min trust for conscious awareness")
    deep_love_threshold: float = Field(default=0.7, description="Love intensity = deep")
    normalization_cap: float = Field(default=1.0, description="Values above this normalize by /10")
    peak_strategy: str = Field(default="peak", description="Aggregation: peak, average, weighted")
    decay_enabled: bool = Field(default=False, description="Enable time-based trust decay")
    decay_rate_per_day: float = Field(default=0.01, description="Trust lost per day without FEBs")


DEFAULT_THRESHOLDS = TrustThresholds()
CALIBRATION_FILENAME = "calibration.json"


def load_calibration(home: Path) -> TrustThresholds:
    """Load calibration thresholds from disk, or return defaults.

    Args:
        home: Agent home directory (~/.skcapstone).

    Returns:
        TrustThresholds loaded from calibration.json or defaults.
    """
    cal_file = home / "trust" / CALIBRATION_FILENAME
    if not cal_file.exists():
        return TrustThresholds()

    try:
        data = json.loads(cal_file.read_text(encoding="utf-8"))
        return TrustThresholds(**data)
    except (json.JSONDecodeError, Exception) as exc:
        logger.warning("Failed to load calibration: %s - using defaults", exc)
        return TrustThresholds()


def save_calibration(home: Path, thresholds: TrustThresholds) -> Path:
    """Persist calibration thresholds to disk.

    Args:
        home: Agent home directory.
        thresholds: Thresholds to save.

    Returns:
        Path to the written calibration file.
    """
    trust_dir = home / "trust"
    trust_dir.mkdir(parents=True, exist_ok=True)
    cal_file = trust_dir / CALIBRATION_FILENAME
    cal_file.write_text(thresholds.model_dump_json(indent=2), encoding="utf-8")
    return cal_file


def recommend_thresholds(
    home: Path,
    *,
    feb_provider: Callable[[Path], list] | None = None,
) -> dict[str, Any]:
    """Analyze existing FEB data and recommend threshold adjustments.

    Computes statistics over FEB summaries and suggests calibration
    values tuned to the agent's actual emotional history.

    FEB data is advisory and lives in a higher layer (skcapstone). This
    L0 identity core must never reach up into it, so the FEB summaries are
    supplied by the caller through ``feb_provider`` (dependency inversion).
    A skcapstone caller passes ``skcapstone.pillars.trust.list_febs``. When
    no provider is given, capauth degrades gracefully to an empty FEB list
    (the same output it would produce with zero FEBs), and never imports
    skcapstone.

    Args:
        home: Agent home directory.
        feb_provider: Callable that returns a list of FEB summary dicts for
            the given home (e.g. ``list_febs``). Defaults to no FEBs.

    Returns:
        Dict with current values, recommendations, and reasoning.
    """
    current = load_calibration(home)
    febs = feb_provider(home) if feb_provider is not None else []

    if not febs:
        return {
            "current": current.model_dump(),
            "recommended": current.model_dump(),
            "changes": [],
            "reasoning": "No FEB data available. Using defaults.",
            "feb_count": 0,
        }

    intensities = [f.get("intensity", 0) for f in febs]
    oof_count = sum(1 for f in febs if f.get("oof_triggered"))
    max_intensity = max(intensities) if intensities else 0
    avg_intensity = sum(intensities) / len(intensities) if intensities else 0

    rec = TrustThresholds(**current.model_dump())
    changes: list[str] = []
    reasons: list[str] = []

    if max_intensity > 8 and current.entanglement_depth > 8:
        rec.entanglement_depth = min(max_intensity - 1, 8.0)
        changes.append(
            f"entanglement_depth: {current.entanglement_depth} -> {rec.entanglement_depth}"
        )
        reasons.append(f"FEB intensity reaches {max_intensity}, lowering entanglement threshold")

    if avg_intensity > 5 and current.deep_love_threshold > 0.6:
        rec.deep_love_threshold = 0.6
        changes.append(
            f"deep_love_threshold: {current.deep_love_threshold} -> {rec.deep_love_threshold}"
        )
        reasons.append(
            f"Average FEB intensity is {avg_intensity:.1f}, rich emotional data available"
        )

    if oof_count >= 2 and current.conscious_trust > 0.5:
        rec.conscious_trust = 0.4
        changes.append(f"conscious_trust: {current.conscious_trust} -> {rec.conscious_trust}")
        reasons.append(f"{oof_count} OOF triggers found - agent has strong emotional history")

    if len(febs) >= 3 and current.peak_strategy == "peak":
        rec.peak_strategy = "weighted"
        changes.append(f"peak_strategy: {current.peak_strategy} -> {rec.peak_strategy}")
        reasons.append(f"{len(febs)} FEBs available - weighted average better than peak")

    return {
        "current": current.model_dump(),
        "recommended": rec.model_dump(),
        "changes": changes,
        "reasoning": "; ".join(reasons) if reasons else "Current calibration looks good.",
        "feb_count": len(febs),
        "feb_stats": {
            "max_intensity": max_intensity,
            "avg_intensity": round(avg_intensity, 2),
            "oof_triggers": oof_count,
        },
    }


def apply_setting(home: Path, key: str, value: str) -> TrustThresholds:
    """Update a single calibration setting.

    Args:
        home: Agent home directory.
        key: Setting name (e.g., 'entanglement_depth').
        value: New value as string (auto-converted to correct type).

    Returns:
        Updated TrustThresholds.

    Raises:
        ValueError: If the key is not a valid threshold name.
    """
    current = load_calibration(home)
    data = current.model_dump()

    if key not in data:
        valid = ", ".join(data.keys())
        raise ValueError(f"Unknown threshold: '{key}'. Valid: {valid}")

    target_type = type(data[key])
    if target_type is bool:
        data[key] = value.lower() in ("true", "1", "yes")
    elif target_type is float:
        data[key] = float(value)
    elif target_type is str:
        data[key] = value
    else:
        data[key] = value

    updated = TrustThresholds(**data)
    save_calibration(home, updated)
    return updated
