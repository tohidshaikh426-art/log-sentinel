"""Normalized event data models and deterministic fingerprinting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from typing import Any, Literal

AuthResult = Literal["success", "failure", "unknown"]
ParseStatus = Literal["valid", "malformed", "ignored"]


def compute_event_fingerprint(
    *,
    device_id: str,
    event_timestamp: str,
    username: str | None,
    source_ip: str | None,
    event_type: str,
    raw_event: str,
    position_hint: str | int | None = None,
) -> str:
    """Return a deterministic 64-char SHA-256 hex fingerprint for event deduplication."""
    parts = [
        device_id or "",
        event_timestamp or "",
        username or "",
        source_ip or "",
        event_type or "",
        raw_event or "",
        "" if position_hint is None else str(position_hint),
    ]
    payload = "|".join(parts).encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


@dataclass(slots=True)
class NormalizedEvent:
    """Standardized authentication event shared by collector, rules, and cloud ingestion."""

    device_id: str
    event_timestamp: str
    username: str | None
    source_ip: str | None
    event_type: str
    auth_result: AuthResult
    auth_method: str | None
    service: str | None
    raw_event: str
    event_fingerprint: str
    is_simulated: bool = False
    parse_status: ParseStatus = "valid"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-ready dictionary matching the ingestion API schema."""
        return asdict(self)


@dataclass(slots=True)
class MalformedRecord:
    """Details about an unparseable or invalid log record."""

    line_number: int
    reason: str
    raw_snippet: str


@dataclass(slots=True)
class ParseReport:
    """Summary and outputs from parsing a batch of log lines or an uploaded file."""

    source_format: str
    total_lines: int = 0
    events: list[NormalizedEvent] = field(default_factory=list)
    ignored_count: int = 0
    malformed_records: list[MalformedRecord] = field(default_factory=list)

    @property
    def parsed_count(self) -> int:
        return len(self.events)

    @property
    def malformed_count(self) -> int:
        return len(self.malformed_records)
