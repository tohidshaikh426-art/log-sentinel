"""Documented CSV authentication log parser."""

from __future__ import annotations

import csv
from datetime import tzinfo
import io
from typing import Iterable

from log_sentinel.parser.models import (
    MalformedRecord,
    NormalizedEvent,
    ParseReport,
    compute_event_fingerprint,
)
from log_sentinel.parser.sanitizer import (
    sanitize_optional,
    sanitize_text,
    sanitize_username,
    validate_ip,
)
from log_sentinel.parser.timestamps import parse_timestamp_to_utc

REQUIRED_CSV_COLUMNS = ("event_timestamp", "event_type", "auth_result")
OPTIONAL_CSV_COLUMNS = ("username", "source_ip", "auth_method", "service", "raw_event")
ALLOWED_AUTH_RESULTS = {"success", "failure", "unknown"}


def parse_csv_lines(
    lines: Iterable[str],
    *,
    device_id: str,
    local_tz: tzinfo | None = None,
    is_simulated: bool = False,
) -> ParseReport:
    """
    Parse CSV authentication events using documented columns.

    Required headers: event_timestamp, event_type, auth_result
    Optional headers: username, source_ip, auth_method, service, raw_event
    """
    report = ParseReport(source_format="csv")
    raw_lines = [line for line in lines if line.strip()]
    if not raw_lines:
        return report

    reader = csv.DictReader(raw_lines)
    if not reader.fieldnames:
        report.total_lines = len(raw_lines)
        report.malformed_records.append(
            MalformedRecord(line_number=1, reason="Missing CSV header row", raw_snippet="")
        )
        return report

    normalized_headers = [h.strip() for h in reader.fieldnames if h is not None]
    reader.fieldnames = normalized_headers
    missing = [col for col in REQUIRED_CSV_COLUMNS if col not in normalized_headers]
    if missing:
        report.total_lines = len(raw_lines)
        report.malformed_records.append(
            MalformedRecord(
                line_number=1,
                reason=f"Missing required CSV columns: {', '.join(missing)}",
                raw_snippet=sanitize_text(raw_lines[0], max_length=160),
            )
        )
        return report

    for row_index, row in enumerate(reader, start=2):
        report.total_lines += 1

        if None in row and row[None]:
            report.malformed_records.append(
                MalformedRecord(
                    line_number=row_index,
                    reason="CSV row has more columns than header",
                    raw_snippet=sanitize_text(str(row), max_length=160),
                )
            )
            continue

        raw_ts = (row.get("event_timestamp") or "").strip()
        try:
            event_timestamp = parse_timestamp_to_utc(raw_ts, local_tz=local_tz)
        except ValueError as exc:
            report.malformed_records.append(
                MalformedRecord(
                    line_number=row_index,
                    reason=str(exc),
                    raw_snippet=sanitize_text(str(row), max_length=160),
                )
            )
            continue

        event_type = sanitize_optional(row.get("event_type"), max_length=64)
        if not event_type:
            report.malformed_records.append(
                MalformedRecord(
                    line_number=row_index,
                    reason="Missing event_type",
                    raw_snippet=sanitize_text(str(row), max_length=160),
                )
            )
            continue

        auth_result = (row.get("auth_result") or "").strip().lower()
        if auth_result not in ALLOWED_AUTH_RESULTS:
            report.malformed_records.append(
                MalformedRecord(
                    line_number=row_index,
                    reason=f"Invalid auth_result {auth_result!r}; expected success, failure, or unknown",
                    raw_snippet=sanitize_text(str(row), max_length=160),
                )
            )
            continue

        raw_ip = (row.get("source_ip") or "").strip()
        source_ip: str | None = None
        if raw_ip:
            source_ip = validate_ip(raw_ip)
            if source_ip is None:
                report.malformed_records.append(
                    MalformedRecord(
                        line_number=row_index,
                        reason=f"Invalid source_ip {raw_ip!r}",
                        raw_snippet=sanitize_text(str(row), max_length=160),
                    )
                )
                continue

        username = sanitize_username(row.get("username"))
        auth_method = sanitize_optional(row.get("auth_method"), max_length=40)
        service = sanitize_optional(row.get("service"), max_length=40) or "csv_import"
        raw_event = sanitize_text(
            row.get("raw_event")
            or f"csv event_type={event_type} user={username or '-'} ip={source_ip or '-'} result={auth_result}",
            max_length=512,
        )

        fingerprint = compute_event_fingerprint(
            device_id=device_id,
            event_timestamp=event_timestamp,
            username=username,
            source_ip=source_ip,
            event_type=event_type,
            raw_event=raw_event,
            position_hint=f"csv:{row_index}",
        )

        report.events.append(
            NormalizedEvent(
                device_id=device_id,
                event_timestamp=event_timestamp,
                username=username,
                source_ip=source_ip,
                event_type=event_type,
                auth_result=auth_result,  # type: ignore[arg-type]
                auth_method=auth_method,
                service=service,
                raw_event=raw_event,
                event_fingerprint=fingerprint,
                is_simulated=is_simulated,
                parse_status="valid",
            )
        )

    return report


def parse_csv_text(
    csv_text: str,
    *,
    device_id: str,
    local_tz: tzinfo | None = None,
    is_simulated: bool = False,
) -> ParseReport:
    """Convenience wrapper parsing CSV text content."""
    return parse_csv_lines(
        io.StringIO(csv_text),
        device_id=device_id,
        local_tz=local_tz,
        is_simulated=is_simulated,
    )
