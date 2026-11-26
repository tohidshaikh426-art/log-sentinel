"""Comprehensive unit tests for Log Sentinel Phase 3 parsers and normalizers."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from log_sentinel.parser import (
    parse_auth_log_line,
    parse_csv_text,
    parse_log_lines,
    parse_timestamp_to_utc,
)

DEVICE_ID = "00000000-0000-0000-0000-000000000001"
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_timestamp_rfc3164_year_rollover_and_timezone():
    ist = timezone(timedelta(hours=5, minutes=30))
    ref_jan1 = datetime(2026, 1, 1, 0, 10, 0, tzinfo=ist)
    # Dec 31 23:55 IST parsed on Jan 1 2026 must resolve to Dec 31 2025 -> 18:25 UTC
    utc_ts = parse_timestamp_to_utc("Dec 31 23:55:00", local_tz=ist, reference_now=ref_jan1)
    assert utc_ts == "2025-12-31T18:25:00Z"


def test_timestamp_journal_compact_offset():
    utc_ts = parse_timestamp_to_utc("2026-11-26T21:45:05+0530")
    assert utc_ts == "2026-11-26T16:15:05Z"


def test_parse_ssh_accepted_and_failed_lines():
    ref = datetime(2026, 11, 26, 22, 0, 0, tzinfo=timezone.utc)

    accepted, err = parse_auth_log_line(
        "Nov 26 21:40:12 ubuntu sshd[2101]: Accepted publickey for deploy from 198.51.100.10 port 51200 ssh2: ED25519 SHA256:abc",
        device_id=DEVICE_ID,
        reference_now=ref,
    )
    assert err is None
    assert accepted is not None
    assert accepted.event_type == "ssh_accepted_login"
    assert accepted.auth_result == "success"
    assert accepted.auth_method == "publickey"
    assert accepted.username == "deploy"
    assert accepted.source_ip == "198.51.100.10"
    assert accepted.event_timestamp == "2026-11-26T21:40:12Z"

    failed_v6, err_v6 = parse_auth_log_line(
        "2026-11-26T21:45:05+0530 ubuntu sshd-session[3301]: Failed password for root from 2001:db8::42 port 55100 ssh2",
        device_id=DEVICE_ID,
    )
    assert err_v6 is None
    assert failed_v6 is not None
    assert failed_v6.event_type == "ssh_failed_password"
    assert failed_v6.auth_result == "failure"
    assert failed_v6.source_ip == "2001:db8::42"
    assert failed_v6.service == "sshd"
    assert failed_v6.event_timestamp == "2026-11-26T16:15:05Z"


def test_parse_invalid_user_and_pam_missing_fields():
    ref = datetime(2026, 11, 26, 22, 0, 0, tzinfo=timezone.utc)

    inv, err = parse_auth_log_line(
        "Nov 26 21:42:04 ubuntu sshd[2125]: Failed password for invalid user guest from 192.0.2.88 port 53112 ssh2",
        device_id=DEVICE_ID,
        reference_now=ref,
    )
    assert err is None
    assert inv is not None
    assert inv.event_type == "ssh_invalid_user"
    assert inv.auth_result == "failure"
    assert inv.username == "guest"

    pam, err_pam = parse_auth_log_line(
        "Nov 26 21:43:00 ubuntu sudo: pam_unix(sudo:auth): authentication failure; logname=deploy uid=1001 euid=0 tty=/dev/pts/0 ruser=deploy rhost=  user=deploy",
        device_id=DEVICE_ID,
        reference_now=ref,
    )
    assert err_pam is None
    assert pam is not None
    assert pam.event_type == "pam_auth_failure"
    assert pam.auth_result == "failure"
    assert pam.source_ip is None
    assert pam.username == "deploy"


def test_sanitization_strips_ansi_and_control_chars():
    ref = datetime(2026, 11, 26, 22, 0, 0, tzinfo=timezone.utc)
    malicious_line = "Nov 26 21:42:02 ubuntu sshd[99]: Invalid user \x1b[31m<script>alert(1)</script>\x07 from 192.0.2.5 port 1234"
    ev, err = parse_auth_log_line(malicious_line, device_id=DEVICE_ID, reference_now=ref)
    assert err is None
    assert ev is not None
    assert "\x1b" not in (ev.username or "")
    assert "\x07" not in ev.raw_event
    assert ev.username == "<script>alert(1)</script>"


def test_ignored_vs_malformed_lines():
    lines = [
        "",
        "Nov 26 21:40:01 ubuntu CRON[1001]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        "Nov 26 21:40:45 ubuntu sshd[2105]: Server listening on 0.0.0.0 port 22.",
        "corrupted line with no syslog header",
        "Nov 99 21:40:00 ubuntu sshd[10]: Failed password for admin from 203.0.113.55 port 22 ssh2",
        "Nov 26 21:40:10 ubuntu sshd[10]: Failed password for admin from 999.999.999.999 port 22 ssh2",
        "Nov 26 21:40:15 ubuntu sshd[10]: Completely unknown sshd auth event payload",
    ]
    report = parse_log_lines(
        lines,
        device_id=DEVICE_ID,
        source_format="auth_log",
        reference_now=datetime(2026, 11, 26, 22, 0, 0, tzinfo=timezone.utc),
    )
    assert report.total_lines == 7
    assert report.parsed_count == 0
    assert report.ignored_count == 3
    assert report.malformed_count == 4
    assert [m.line_number for m in report.malformed_records] == [4, 5, 6, 7]


def test_deterministic_fingerprint_for_same_second_events():
    lines = [
        "Nov 26 21:41:01 ubuntu sshd[2110]: Failed password for admin from 203.0.113.55 port 40001 ssh2",
        "Nov 26 21:41:01 ubuntu sshd[2110]: Failed password for admin from 203.0.113.55 port 40001 ssh2",
    ]
    ref = datetime(2026, 11, 26, 22, 0, 0, tzinfo=timezone.utc)
    r1 = parse_log_lines(lines, device_id=DEVICE_ID, reference_now=ref)
    r2 = parse_log_lines(lines, device_id=DEVICE_ID, reference_now=ref)
    assert r1.parsed_count == 2
    assert r1.events[0].event_fingerprint != r1.events[1].event_fingerprint
    assert r1.events[0].event_fingerprint == r2.events[0].event_fingerprint


def test_sample_auth_and_journal_files_parse_cleanly():
    ref = datetime(2026, 11, 26, 22, 0, 0, tzinfo=timezone.utc)
    auth_lines = (SAMPLES_DIR / "sample_auth.log").read_text(encoding="utf-8").splitlines()
    auth_report = parse_log_lines(auth_lines, device_id=DEVICE_ID, source_format="auth_log", reference_now=ref)
    assert auth_report.malformed_count == 0
    assert auth_report.ignored_count == 2  # CRON + Server listening
    assert auth_report.parsed_count == 14

    journal_lines = (SAMPLES_DIR / "sample_journal.log").read_text(encoding="utf-8").splitlines()
    journal_report = parse_log_lines(journal_lines, device_id=DEVICE_ID, source_format="journal")
    assert journal_report.malformed_count == 0
    assert journal_report.ignored_count == 1  # systemd Started Session
    assert journal_report.parsed_count == 3


def test_csv_parser_valid_and_invalid_rows():
    csv_text = (SAMPLES_DIR / "sample_events.csv").read_text(encoding="utf-8")
    report = parse_log_lines(csv_text.splitlines(), device_id=DEVICE_ID, source_format="csv")
    assert report.parsed_count == 3
    assert report.malformed_count == 0
    assert report.events[2].username is None
    assert report.events[2].auth_method is None

    bad_csv = (
        "event_timestamp,username,source_ip,event_type,auth_result\n"
        "not-a-timestamp,admin,192.0.2.1,ssh_failed_password,failure\n"
        "2026-11-26T16:10:00Z,admin,bad-ip,ssh_failed_password,failure\n"
        "2026-11-26T16:10:00Z,admin,192.0.2.1,ssh_failed_password,maybe\n"
    )
    bad_report = parse_csv_text(bad_csv, device_id=DEVICE_ID)
    assert bad_report.parsed_count == 0
    assert bad_report.malformed_count == 3

    missing_header_csv = "timestamp,user\n2026-11-26T16:10:00Z,admin\n"
    missing_report = parse_csv_text(missing_header_csv, device_id=DEVICE_ID)
    assert missing_report.malformed_count == 1
    assert "Missing required CSV columns" in missing_report.malformed_records[0].reason
