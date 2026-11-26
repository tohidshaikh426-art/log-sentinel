"""Authentication log parsers and event normalizers."""

from __future__ import annotations

from datetime import datetime, tzinfo
from typing import Iterable

from log_sentinel.parser.csv_parser import REQUIRED_CSV_COLUMNS, parse_csv_lines, parse_csv_text
from log_sentinel.parser.models import (
    MalformedRecord,
    NormalizedEvent,
    ParseReport,
    compute_event_fingerprint,
)
from log_sentinel.parser.sanitizer import sanitize_text, sanitize_username, validate_ip
from log_sentinel.parser.syslog_auth import parse_auth_log_line, parse_auth_log_lines
from log_sentinel.parser.timestamps import parse_timestamp_to_utc


def parse_log_lines(
    lines: Iterable[str],
    *,
    device_id: str,
    source_format: str = "auth_log",
    local_tz: tzinfo | None = None,
    reference_now: datetime | None = None,
    is_simulated: bool = False,
) -> ParseReport:
    """Dispatch log lines to the appropriate supported parser ('auth_log', 'journal', or 'csv')."""
    if source_format in {"auth_log", "journal"}:
        return parse_auth_log_lines(
            lines,
            device_id=device_id,
            source_format=source_format,
            local_tz=local_tz,
            reference_now=reference_now,
            is_simulated=is_simulated,
        )
    if source_format == "csv":
        return parse_csv_lines(
            lines,
            device_id=device_id,
            local_tz=local_tz,
            is_simulated=is_simulated,
        )
    raise ValueError(f"Unsupported log format: {source_format!r}")


__all__ = [
    "MalformedRecord",
    "NormalizedEvent",
    "ParseReport",
    "REQUIRED_CSV_COLUMNS",
    "compute_event_fingerprint",
    "parse_auth_log_line",
    "parse_auth_log_lines",
    "parse_csv_lines",
    "parse_csv_text",
    "parse_log_lines",
    "parse_timestamp_to_utc",
    "sanitize_text",
    "sanitize_username",
    "validate_ip",
]
