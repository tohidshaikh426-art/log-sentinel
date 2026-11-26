"""Data models and configuration loader for Log Sentinel detection engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any, Literal

Severity = Literal["low", "medium", "high", "critical"]

DEFAULT_RULES_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "rules_config.json"
)


def load_rules_config(config_path: Path | str | None = None) -> dict[str, Any]:
    """Load detection thresholds and scoring weights from JSON configuration."""
    path = Path(config_path) if config_path else DEFAULT_RULES_CONFIG_PATH
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


@dataclass(slots=True)
class DetectedIncident:
    """Explainable security incident generated or updated by the detection engine."""

    device_id: str
    rule_id: str
    incident_title: str
    description: str
    source_ip: str | None
    username: str | None
    severity: Severity
    risk_score: int
    dedup_key: str
    first_observed: str
    last_observed: str
    event_count: int
    evidence: dict[str, Any] = field(default_factory=dict)
    supporting_fingerprints: list[str] = field(default_factory=list)
    is_simulated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize incident to JSON-ready dictionary for cloud ingestion."""
        return asdict(self)
