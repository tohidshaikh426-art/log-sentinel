"""Parsers for Ubuntu/Debian /var/log/auth.log and systemd journal (short-iso) records."""

from __future__ import annotations

from datetime import datetime, tzinfo
import re
from typing import Iterable

from log_sentinel.parser.models import (
    MalformedRecord,
    NormalizedEvent,
    ParseReport,
    compute_event_fingerprint,
)
from log_sentinel.parser.sanitizer import sanitize_optional, sanitize_text, sanitize_username, validate_ip
from log_sentinel.parser.timestamps import parse_timestamp_to_utc

# Matches RFC 3164 ("Nov 26 21:42:38 host proc[pid]: msg") or ISO/journalctl ("2026-11-26T21:42:38+0530 host proc[pid]: msg")
_SYSLOG_HEADER_RE = re.compile(
    r"^(?P<ts>"
    r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"|(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r")\s+(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9_.\-/]+(?:\([^)]+\))?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)$"
)

_AUTH_PROCESS_PREFIXES = ("sshd", "sudo", "su", "login", "pam_unix", "passwd", "chsh")

_SSH_ACCEPTED_RE = re.compile(
    r"^Accepted\s+(?P<method>password|publickey|keyboard-interactive/pam|keyboard-interactive)\s+"
    r"for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+"
)
_SSH_FAILED_INVALID_RE = re.compile(
    r"^Failed\s+(?P<method>password|publickey|keyboard-interactive/pam|none)\s+"
    r"for\s+invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+"
)
_SSH_FAILED_VALID_RE = re.compile(
    r"^Failed\s+(?P<method>password|publickey|keyboard-interactive/pam|none)\s+"
    r"for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+"
)
_SSH_INVALID_USER_RE = re.compile(
    r"^Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+\d+)?"
)
_SSH_MAX_AUTH_RE = re.compile(
    r"^error:\s+maximum\s+authentication\s+attempts\s+exceeded\s+for\s+"
    r"(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+"
)
_SSH_DISCONNECT_AUTH_RE = re.compile(
    r"^(?:Disconnected\s+from|Connection\s+closed\s+by)\s+"
    r"(?P<kind>authenticating|invalid)\s+user\s+(?P<user>\S+)\s+(?P<ip>\S+)\s+port\s+\d+"
)

_PAM_RHOST_RE = re.compile(r"\brhost=([^\s;]+)")
_PAM_USER_RE = re.compile(r"\buser=([^\s;]+)")

_SUDO_FAILED_RE = re.compile(r"^(?P<user>\S+)\s*:\s*\d+\s+incorrect\s+password\s+attempts\b")
_SUDO_SUCCESS_RE = re.compile(r"^(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=.*;\s*USER=\S+\s*;\s*COMMAND=")
_LOGIN_FAILED_RE = re.compile(
    r"^FAILED\s+LOGIN\s+\(\d+\)\s+on\s+.+?\s+FOR\s+['\"]?(?P<user>[^'\",\s]+)['\"]?,\s+Authentication\s+failure"
)
_SU_FAILED_RE = re.compile(r"^FAILED\s+su\s+for\s+(?P<target>\S+)\s+by\s+(?P<actor>\S+)")

# Known benign operational syslog messages inside auth services (not security errors/malformed)
_BENIGN_AUTH_MSG_PREFIXES = (
    "Server listening on ",
    "Received signal ",
    "pam_unix(",
    "session opened for user ",
    "session closed for user ",
    "Connection closed by ",
    "Disconnected from ",
    "Connection reset by ",
    "Accepted none for ",
    "Did not receive identification string",
    "banner exchange:",
    "Unable to negotiate with ",
)


def _normalize_proc_name(proc: str) -> str:
    base = proc.split("(", 1)[0].lower()
    if base.startswith("sshd"):
        return "sshd"
    return base


def _is_auth_process(proc: str) -> bool:
    lowered = proc.lower()
    return any(lowered.startswith(prefix) for prefix in _AUTH_PROCESS_PREFIXES)


def _is_benign_auth_noise(msg: str) -> bool:
    if msg.startswith("pam_unix(") and "authentication failure;" in msg:
        return False
    return msg.startswith(_BENIGN_AUTH_MSG_PREFIXES)


def parse_auth_log_line(
    line: str,
    *,
    device_id: str,
    local_tz: tzinfo | None = None,
    reference_now: datetime | None = None,
    is_simulated: bool = False,
    position_hint: str | int | None = None,
) -> tuple[NormalizedEvent | None, str | None]:
    """
    Parse one line from /var/log/auth.log or journalctl -o short-iso.

    Returns:
      - (NormalizedEvent, None) when a supported authentication event was parsed.
      - (None, None) when the line is blank or benign non-auth syslog noise (ignored).
      - (None, reason) when the line is malformed or an unrecognized auth record.
    """
    if line is None:
        return None, None

    stripped = line.strip()
    if not stripped:
        return None, None

    header = _SYSLOG_HEADER_RE.match(stripped)
    if not header:
        return None, "Line does not match supported syslog or journald header format"

    raw_ts = header.group("ts")
    proc_raw = header.group("proc")
    msg = header.group("msg").strip()

    try:
        event_timestamp = parse_timestamp_to_utc(
            raw_ts, local_tz=local_tz, reference_now=reference_now
        )
    except ValueError as exc:
        return None, str(exc)

    if not _is_auth_process(proc_raw):
        return None, None

    service = sanitize_optional(_normalize_proc_name(proc_raw), max_length=40)
    raw_event = sanitize_text(stripped, max_length=512)

    username: str | None = None
    source_ip: str | None = None
    event_type: str | None = None
    auth_result: str | None = None
    auth_method: str | None = None

    # 1. SSH patterns
    if m := _SSH_ACCEPTED_RE.match(msg):
        method = m.group("method")
        username = sanitize_username(m.group("user"))
        source_ip = validate_ip(m.group("ip"))
        if source_ip is None:
            return None, f"Invalid IP address in SSH accepted log: {m.group('ip')!r}"
        event_type = "ssh_accepted_login"
        auth_result = "success"
        auth_method = "keyboard-interactive" if method.startswith("keyboard-interactive") else method

    elif m := _SSH_FAILED_INVALID_RE.match(msg):
        username = sanitize_username(m.group("user"))
        source_ip = validate_ip(m.group("ip"))
        if source_ip is None:
            return None, f"Invalid IP address in SSH invalid user log: {m.group('ip')!r}"
        event_type = "ssh_invalid_user"
        auth_result = "failure"
        auth_method = m.group("method")

    elif m := _SSH_FAILED_VALID_RE.match(msg):
        method = m.group("method")
        username = sanitize_username(m.group("user"))
        source_ip = validate_ip(m.group("ip"))
        if source_ip is None:
            return None, f"Invalid IP address in SSH failed log: {m.group('ip')!r}"
        event_type = "ssh_failed_password" if method == "password" else "ssh_auth_failure"
        auth_result = "failure"
        auth_method = method

    elif m := _SSH_INVALID_USER_RE.match(msg):
        username = sanitize_username(m.group("user"))
        source_ip = validate_ip(m.group("ip"))
        if source_ip is None:
            return None, f"Invalid IP address in invalid user log: {m.group('ip')!r}"
        event_type = "ssh_invalid_user"
        auth_result = "failure"
        auth_method = "ssh"

    elif m := _SSH_MAX_AUTH_RE.match(msg):
        username = sanitize_username(m.group("user"))
        source_ip = validate_ip(m.group("ip"))
        if source_ip is None:
            return None, f"Invalid IP address in max auth log: {m.group('ip')!r}"
        event_type = "ssh_auth_failure"
        auth_result = "failure"
        auth_method = "ssh"

    elif m := _SSH_DISCONNECT_AUTH_RE.match(msg):
        username = sanitize_username(m.group("user"))
        source_ip = validate_ip(m.group("ip"))
        if source_ip is None:
            return None, f"Invalid IP address in disconnect auth log: {m.group('ip')!r}"
        event_type = "ssh_invalid_user" if m.group("kind") == "invalid" else "ssh_auth_failure"
        auth_result = "failure"
        auth_method = "ssh"

    # 2. PAM authentication failure (can appear under sshd, sudo, su, login, or directly as pam_unix)
    elif "authentication failure;" in msg:
        rhost_match = _PAM_RHOST_RE.search(msg)
        user_match = _PAM_USER_RE.search(msg)
        if rhost_match:
            source_ip = validate_ip(rhost_match.group(1))
        if user_match:
            username = sanitize_username(user_match.group(1))
        event_type = "pam_auth_failure"
        auth_result = "failure"
        auth_method = "pam"

    # 3. Sudo events
    elif service == "sudo" and (m := _SUDO_FAILED_RE.match(msg)):
        username = sanitize_username(m.group("user"))
        event_type = "sudo_auth_failure"
        auth_result = "failure"
        auth_method = "sudo"

    elif service == "sudo" and (m := _SUDO_SUCCESS_RE.match(msg)):
        username = sanitize_username(m.group("user"))
        event_type = "sudo_auth_success"
        auth_result = "success"
        auth_method = "sudo"

    # 4. Local login / su failures
    elif m := _LOGIN_FAILED_RE.match(msg):
        username = sanitize_username(m.group("user"))
        event_type = "local_auth_failure"
        auth_result = "failure"
        auth_method = "password"

    elif m := _SU_FAILED_RE.match(msg):
        username = sanitize_username(m.group("target"))
        event_type = "su_auth_failure"
        auth_result = "failure"
        auth_method = "su"

    else:
        if _is_benign_auth_noise(msg):
            return None, None
        return None, f"Unrecognized authentication message format for service '{service}'"

    fingerprint = compute_event_fingerprint(
        device_id=device_id,
        event_timestamp=event_timestamp,
        username=username,
        source_ip=source_ip,
        event_type=event_type,
        raw_event=raw_event,
        position_hint=position_hint,
    )

    event = NormalizedEvent(
        device_id=device_id,
        event_timestamp=event_timestamp,
        username=username,
        source_ip=source_ip,
        event_type=event_type,
        auth_result=auth_result,  # type: ignore[arg-type]
        auth_method=sanitize_optional(auth_method, max_length=40),
        service=service,
        raw_event=raw_event,
        event_fingerprint=fingerprint,
        is_simulated=is_simulated,
        parse_status="valid",
    )
    return event, None


def parse_auth_log_lines(
    lines: Iterable[str],
    *,
    device_id: str,
    source_format: str = "auth_log",
    local_tz: tzinfo | None = None,
    reference_now: datetime | None = None,
    is_simulated: bool = False,
) -> ParseReport:
    """Parse multiple auth.log or journald lines and produce a complete ParseReport."""
    report = ParseReport(source_format=source_format)

    for line_no, line in enumerate(lines, start=1):
        report.total_lines += 1
        event, error_reason = parse_auth_log_line(
            line,
            device_id=device_id,
            local_tz=local_tz,
            reference_now=reference_now,
            is_simulated=is_simulated,
            position_hint=f"{source_format}:{line_no}",
        )
        if event is not None:
            report.events.append(event)
        elif error_reason is not None:
            report.malformed_records.append(
                MalformedRecord(
                    line_number=line_no,
                    reason=error_reason,
                    raw_snippet=sanitize_text(line, max_length=160),
                )
            )
        else:
            report.ignored_count += 1

    return report
