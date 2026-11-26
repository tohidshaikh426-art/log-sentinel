"""Comprehensive unit tests for Log Sentinel Phase 4 detection engine and risk scoring."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from log_sentinel.detection import (
    DetectionEngine,
    calculate_risk_score,
    load_rules_config,
    map_score_to_severity,
)
from log_sentinel.parser import NormalizedEvent, compute_event_fingerprint, parse_log_lines

DEVICE_ID = "00000000-0000-0000-0000-000000000001"
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def _make_event(
    *,
    offset_seconds: int,
    username: str | None = "admin",
    source_ip: str | None = "203.0.113.50",
    auth_result: str = "failure",
    event_type: str | None = None,
    is_simulated: bool = False,
    idx: int = 0,
) -> NormalizedEvent:
    base = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
    ts = (base + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    etype = event_type or ("ssh_accepted_login" if auth_result == "success" else "ssh_failed_password")
    raw = f"sample {etype} user={username} ip={source_ip} idx={idx}"
    fp = compute_event_fingerprint(
        device_id=DEVICE_ID,
        event_timestamp=ts,
        username=username,
        source_ip=source_ip,
        event_type=etype,
        raw_event=raw,
        position_hint=idx,
    )
    return NormalizedEvent(
        device_id=DEVICE_ID,
        event_timestamp=ts,
        username=username,
        source_ip=source_ip,
        event_type=etype,
        auth_result=auth_result,  # type: ignore[arg-type]
        auth_method="password",
        service="sshd",
        raw_event=raw,
        event_fingerprint=fp,
        is_simulated=is_simulated,
        parse_status="valid",
    )


def test_risk_scoring_formula_and_severity_thresholds():
    cfg = load_rules_config()["scoring"]

    low = calculate_risk_score(
        failed_attempts=1,
        unique_usernames=1,
        duration_seconds=30,
        success_after_failures=False,
        is_repeat_offender=False,
        scoring_cfg=cfg,
    )
    assert low.risk_score == 13
    assert low.severity == "low"

    high = calculate_risk_score(
        failed_attempts=5,
        unique_usernames=1,
        duration_seconds=20,
        success_after_failures=False,
        is_repeat_offender=False,
        scoring_cfg=cfg,
    )
    assert high.risk_score == 51
    assert high.severity == "high"
    assert high.breakdown["velocity_bonus"] == 10

    critical = calculate_risk_score(
        failed_attempts=5,
        unique_usernames=1,
        duration_seconds=30,
        success_after_failures=True,
        is_repeat_offender=True,
        scoring_cfg=cfg,
    )
    assert critical.risk_score == 100
    assert critical.severity == "critical"
    assert map_score_to_severity(24) == "low"
    assert map_score_to_severity(25) == "medium"
    assert map_score_to_severity(50) == "high"
    assert map_score_to_severity(75) == "critical"


def test_normal_activity_produces_no_incidents():
    engine = DetectionEngine()
    events = [
        _make_event(offset_seconds=0, username="deploy", source_ip="198.51.100.10", auth_result="success", idx=1),
        _make_event(offset_seconds=30, username="deploy", source_ip="198.51.100.10", auth_result="failure", idx=2),
        _make_event(offset_seconds=45, username="deploy", source_ip="198.51.100.10", auth_result="success", idx=3),
        _make_event(offset_seconds=300, username="ops", source_ip="198.51.100.11", auth_result="failure", idx=4),
        _make_event(offset_seconds=320, username="ops", source_ip="198.51.100.11", auth_result="success", idx=5),
    ]
    incidents = engine.process_events(events)
    assert incidents == []


def test_rule_001_brute_force_and_deduplication():
    engine = DetectionEngine()
    events = [
        _make_event(offset_seconds=i * 5, username="admin", source_ip="203.0.113.55", idx=i)
        for i in range(8)
    ]
    incidents = engine.process_events(events)
    rule1 = [inc for inc in incidents if inc.rule_id == "RULE_001"]
    # 8 failures in same burst must correlate into 1 single incident with event_count=8
    assert len(rule1) == 1
    assert rule1[0].event_count == 8
    assert rule1[0].severity == "high"
    assert rule1[0].risk_score >= 50
    assert len(rule1[0].supporting_fingerprints) == 8
    assert "score_breakdown" in rule1[0].evidence


def test_rule_001_respects_sliding_time_window():
    engine = DetectionEngine()
    # 4 failures at t=0..15s, then 2 failures 4 minutes later (outside 120s window) -> max 4 in window (<5)
    events = [
        _make_event(offset_seconds=0, idx=1),
        _make_event(offset_seconds=5, idx=2),
        _make_event(offset_seconds=10, idx=3),
        _make_event(offset_seconds=15, idx=4),
        _make_event(offset_seconds=240, idx=5),
        _make_event(offset_seconds=245, idx=6),
    ]
    incidents = engine.process_events(events)
    assert [inc for inc in incidents if inc.rule_id == "RULE_001"] == []


def test_rule_002_multiple_target_accounts():
    engine = DetectionEngine()
    users = ["alice", "bob", "charlie", "david"]
    events = [
        _make_event(offset_seconds=i * 10, username=u, source_ip="192.0.2.88", idx=i)
        for i, u in enumerate(users)
    ]
    incidents = engine.process_events(events)
    rule2 = [inc for inc in incidents if inc.rule_id == "RULE_002"]
    assert len(rule2) == 1
    assert rule2[0].severity == "high"
    assert rule2[0].evidence["unique_username_count"] == 4
    assert "Potential password spraying" in rule2[0].incident_title


def test_rule_003_suspicious_success_after_failures():
    engine = DetectionEngine()
    events = [
        _make_event(offset_seconds=0, username="admin", source_ip="203.0.113.99", auth_result="failure", idx=1),
        _make_event(offset_seconds=10, username="admin", source_ip="203.0.113.99", auth_result="failure", idx=2),
        _make_event(offset_seconds=20, username="admin", source_ip="203.0.113.99", auth_result="failure", idx=3),
        _make_event(offset_seconds=30, username="admin", source_ip="203.0.113.99", auth_result="success", idx=4),
    ]
    incidents = engine.process_events(events)
    rule3 = [inc for inc in incidents if inc.rule_id == "RULE_003"]
    assert len(rule3) == 1
    assert rule3[0].severity in {"high", "critical"}
    assert rule3[0].event_count == 4
    assert "does not prove compromise" in rule3[0].description


def test_rule_004_high_volume_device_failures():
    engine = DetectionEngine()
    # 20 failures across 10 different IPs (2 per IP -> no single IP hits RULE_001, but device hits RULE_004)
    events = [
        _make_event(
            offset_seconds=i * 5,
            username="root",
            source_ip=f"198.51.100.{(i % 10) + 1}",
            idx=i,
        )
        for i in range(20)
    ]
    incidents = engine.process_events(events)
    rule4 = [inc for inc in incidents if inc.rule_id == "RULE_004"]
    assert len(rule4) == 1
    assert rule4[0].event_count == 20
    assert rule4[0].severity in {"medium", "high"}


def test_rule_005_repeat_offender_after_cooldown():
    engine = DetectionEngine()
    # First burst at t=0..20s triggers RULE_001 (should NOT trigger RULE_005 immediately)
    first_burst = [
        _make_event(offset_seconds=i * 5, username="admin", source_ip="203.0.113.77", idx=i)
        for i in range(5)
    ]
    first_incidents = engine.process_events(first_burst)
    assert [i.rule_id for i in first_incidents] == ["RULE_001"]

    # Second burst 10 minutes later (600s >= 300s cooldown) with 3 new failures -> triggers RULE_005
    second_burst = [
        _make_event(offset_seconds=600 + i * 5, username="admin", source_ip="203.0.113.77", idx=10 + i)
        for i in range(3)
    ]
    second_incidents = engine.process_events(second_burst)
    rule5 = [inc for inc in second_incidents if inc.rule_id == "RULE_005"]
    assert len(rule5) == 1
    assert rule5[0].evidence["score_breakdown"]["repeat_offender_bonus"] == 20


def test_end_to_end_sample_auth_log_detection():
    ref = datetime(2026, 11, 26, 22, 0, 0, tzinfo=timezone.utc)
    lines = (SAMPLES_DIR / "sample_auth.log").read_text(encoding="utf-8").splitlines()
    report = parse_log_lines(lines, device_id=DEVICE_ID, source_format="auth_log", reference_now=ref)
    incidents = DetectionEngine().process_events(report.events)

    rule_ids = {(inc.rule_id, inc.source_ip) for inc in incidents}
    assert ("RULE_001", "203.0.113.55") in rule_ids
    assert ("RULE_003", "203.0.113.55") in rule_ids
    assert ("RULE_002", "192.0.2.88") in rule_ids
