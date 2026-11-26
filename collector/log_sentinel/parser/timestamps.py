"""Timestamp parsing and UTC ISO-8601 normalization."""

from __future__ import annotations

from datetime import datetime, timezone, tzinfo
import re

# RFC 3164 syslog timestamp without year: "Nov 26 21:42:38" or "Jan  5 04:01:02"
_RFC3164_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})$"
)

# Compact timezone offset without colon from journalctl short-iso, e.g. "+0530"
_COMPACT_OFFSET_RE = re.compile(r"([+-]\d{2})(\d{2})$")

_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def format_utc_iso(dt: datetime) -> str:
    """Format a timezone-aware datetime in canonical UTC ISO-8601 ('Z') format."""
    utc_dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp_to_utc(
    raw_ts: str,
    *,
    local_tz: tzinfo | None = None,
    reference_now: datetime | None = None,
) -> str:
    """
    Parse RFC 3164 syslog, journalctl short-iso, or ISO-8601 timestamps into UTC ISO-8601.

    Raises ValueError if the timestamp cannot be parsed safely.
    """
    if not raw_ts or not raw_ts.strip():
        raise ValueError("Empty timestamp")

    ts = raw_ts.strip()
    tz = local_tz or timezone.utc
    now_ref = reference_now or datetime.now(timezone.utc)
    if now_ref.tzinfo is None:
        now_ref = now_ref.replace(tzinfo=timezone.utc)

    # 1. Try RFC 3164 syslog format ("Nov 26 21:42:38")
    rfc_match = _RFC3164_RE.match(ts)
    if rfc_match:
        month = _MONTHS.get(rfc_match.group("month"))
        if month is None:
            raise ValueError(f"Unknown syslog month: {rfc_match.group('month')}")
        day = int(rfc_match.group("day"))
        hour, minute, second = (int(part) for part in rfc_match.group("time").split(":"))

        ref_in_tz = now_ref.astimezone(tz)
        year = ref_in_tz.year
        try:
            candidate = datetime(year, month, day, hour, minute, second, tzinfo=tz)
        except ValueError as exc:
            # Handle Feb 29 leap-year rollover safely
            if month == 2 and day == 29:
                candidate = datetime(year - 1, month, day, hour, minute, second, tzinfo=tz)
            else:
                raise ValueError(f"Invalid syslog date: {ts}") from exc

        # Year-rollover correction: e.g. Dec 31 log parsed on Jan 1 is previous year
        if (candidate - ref_in_tz).total_seconds() > 86400 * 7:
            candidate = candidate.replace(year=year - 1)

        return format_utc_iso(candidate)

    # 2. Try ISO-8601 / journalctl short-iso (normalize trailing Z and +HHMM)
    normalized = ts
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    elif _COMPACT_OFFSET_RE.search(normalized):
        normalized = _COMPACT_OFFSET_RE.sub(r"\1:\2", normalized)

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"Unrecognized timestamp format: {raw_ts}") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz)

    return format_utc_iso(parsed)
