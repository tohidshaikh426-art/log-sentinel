"""Explainable rule-based risk scoring and severity mapping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from log_sentinel.detection.models import Severity


@dataclass(frozen=True, slots=True)
class RiskScoreResult:
    """Transparent score breakdown showing why an incident received its severity."""

    risk_score: int
    severity: Severity
    breakdown: dict[str, Any]


def map_score_to_severity(score: int) -> Severity:
    """Map a 0-100 risk score to Low, Medium, High, or Critical."""
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def calculate_risk_score(
    *,
    failed_attempts: int,
    unique_usernames: int,
    duration_seconds: float,
    success_after_failures: bool,
    is_repeat_offender: bool,
    scoring_cfg: dict[str, Any],
) -> RiskScoreResult:
    """Compute an explainable 0-100 risk score from behavioral indicators."""
    per_attempt = int(scoring_cfg.get("failure_points_per_attempt", 7))
    failure_cap = int(scoring_cfg.get("failure_points_cap", 40))
    per_user = int(scoring_cfg.get("spread_points_per_user", 6))
    spread_cap = int(scoring_cfg.get("spread_points_cap", 25))
    saf_bonus_val = int(scoring_cfg.get("success_after_failure_bonus", 30))
    velocity_threshold = float(scoring_cfg.get("velocity_attempts_per_min_threshold", 3.0))
    velocity_bonus_val = int(scoring_cfg.get("velocity_bonus", 10))
    repeat_bonus_val = int(scoring_cfg.get("repeat_offender_bonus", 20))

    failure_points = min(failure_cap, max(0, failed_attempts) * per_attempt)
    target_spread_points = min(spread_cap, max(0, unique_usernames) * per_user)
    success_after_failure_bonus = saf_bonus_val if success_after_failures else 0

    # Calculate attempts/min using at least a 1-minute denominator so short bursts don't divide by zero
    minutes = max(1.0, duration_seconds / 60.0)
    attempts_per_min = round(max(0, failed_attempts) / minutes, 2)
    velocity_bonus = (
        velocity_bonus_val
        if failed_attempts >= 3 and attempts_per_min >= velocity_threshold
        else 0
    )

    repeat_offender_bonus = repeat_bonus_val if is_repeat_offender else 0

    total = min(
        100,
        failure_points
        + target_spread_points
        + success_after_failure_bonus
        + velocity_bonus
        + repeat_offender_bonus,
    )
    severity = map_score_to_severity(total)

    return RiskScoreResult(
        risk_score=total,
        severity=severity,
        breakdown={
            "failure_points": failure_points,
            "target_spread_points": target_spread_points,
            "success_after_failure_bonus": success_after_failure_bonus,
            "velocity_bonus": velocity_bonus,
            "repeat_offender_bonus": repeat_offender_bonus,
            "attempts_per_minute": attempts_per_min,
            "total_score": total,
        },
    )
