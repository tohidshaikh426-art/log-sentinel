"""Stateful sliding-window rule engine for Log Sentinel authentication events."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from log_sentinel.detection.models import DetectedIncident, load_rules_config
from log_sentinel.detection.scoring import calculate_risk_score
from log_sentinel.parser.models import NormalizedEvent
from log_sentinel.parser.timestamps import format_utc_iso


def _parse_iso_utc(ts: str) -> datetime:
    normalized = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _prune_window(
    dq: deque[tuple[datetime, NormalizedEvent]],
    current_dt: datetime,
    window_seconds: int,
) -> list[NormalizedEvent]:
    cutoff = current_dt.timestamp() - window_seconds
    while dq and dq[0][0].timestamp() < cutoff:
        dq.popleft()
    return [item[1] for item in dq]


class DetectionEngine:
    """
    Evaluates normalized authentication events against Version 1.0 rules (RULE_001–RULE_005).

    Supports both incremental streaming (live collector) and batch evaluation (historical uploads).
    Repeated events in the same attack sequence update existing active incidents via dedup_key.
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        config_path: Path | str | None = None,
        known_offender_ips: dict[str, datetime] | None = None,
    ) -> None:
        self.config = config if config is not None else load_rules_config(config_path)
        self.rules_cfg: dict[str, Any] = self.config.get("rules", {})
        self.scoring_cfg: dict[str, Any] = self.config.get("scoring", {})

        # Sliding event windows keyed by (device_id, is_simulated, scope_key)
        self._failures_by_ip: dict[tuple[str, bool, str], deque[tuple[datetime, NormalizedEvent]]] = defaultdict(deque)
        self._failures_by_device: dict[tuple[str, bool], deque[tuple[datetime, NormalizedEvent]]] = defaultdict(deque)
        self._failures_by_ip_user: dict[tuple[str, bool, str, str], deque[tuple[datetime, NormalizedEvent]]] = defaultdict(deque)

        # Prior offender IP timestamps keyed by (device_id, is_simulated, source_ip) -> last_flagged_dt
        self._prior_offenders: dict[tuple[str, bool, str], datetime] = {}
        if known_offender_ips:
            for ip, dt in known_offender_ips.items():
                self._prior_offenders[("*", False, ip)] = dt

        # Active deduplicated incidents by dedup_key
        self._active_incidents: dict[str, DetectedIncident] = {}

    def _rule(self, rule_id: str) -> dict[str, Any]:
        return self.rules_cfg.get(rule_id, {})

    def _is_prior_offender(
        self,
        device_id: str,
        is_simulated: bool,
        source_ip: str,
        current_dt: datetime,
        lookback_seconds: int,
        cooldown_seconds: int,
    ) -> bool:
        for key in ((device_id, is_simulated, source_ip), ("*", False, source_ip)):
            flagged_at = self._prior_offenders.get(key)
            if flagged_at is not None:
                age = (current_dt - flagged_at).total_seconds()
                min_age = 0 if key[0] == "*" else cooldown_seconds
                if min_age <= age <= lookback_seconds and age > 0:
                    return True
        return False

    def _mark_offender(
        self,
        device_id: str,
        is_simulated: bool,
        source_ip: str,
        flagged_dt: datetime,
    ) -> None:
        key = (device_id, is_simulated, source_ip)
        prev = self._prior_offenders.get(key)
        if prev is None or flagged_dt > prev:
            self._prior_offenders[key] = flagged_dt

    def _upsert_incident(
        self,
        *,
        dedup_key: str,
        device_id: str,
        rule_id: str,
        incident_title: str,
        description: str,
        source_ip: str | None,
        username: str | None,
        risk_score: int,
        severity: str,
        first_observed: str,
        last_observed: str,
        supporting_events: list[NormalizedEvent],
        evidence: dict[str, Any],
        is_simulated: bool,
    ) -> DetectedIncident:
        fingerprints = [ev.event_fingerprint for ev in supporting_events]
        existing = self._active_incidents.get(dedup_key)

        if existing is None:
            incident = DetectedIncident(
                device_id=device_id,
                rule_id=rule_id,
                incident_title=incident_title,
                description=description,
                source_ip=source_ip,
                username=username,
                severity=severity,  # type: ignore[arg-type]
                risk_score=risk_score,
                dedup_key=dedup_key,
                first_observed=first_observed,
                last_observed=last_observed,
                event_count=len(supporting_events),
                evidence=evidence,
                supporting_fingerprints=list(dict.fromkeys(fingerprints)),
                is_simulated=is_simulated,
            )
            self._active_incidents[dedup_key] = incident
            return incident

        merged_fps = list(dict.fromkeys([*existing.supporting_fingerprints, *fingerprints]))
        existing.incident_title = incident_title
        existing.description = description
        if username and not existing.username:
            existing.username = username
        if risk_score >= existing.risk_score:
            existing.risk_score = risk_score
            existing.severity = severity  # type: ignore[arg-type]
        existing.first_observed = min(existing.first_observed, first_observed)
        existing.last_observed = max(existing.last_observed, last_observed)
        existing.event_count = max(existing.event_count, len(merged_fps))
        existing.evidence = evidence
        existing.supporting_fingerprints = merged_fps
        return existing

    def process_event(self, event: NormalizedEvent) -> list[DetectedIncident]:
        """Evaluate one normalized event and return any newly created or updated incidents."""
        if event.parse_status != "valid":
            return []

        event_dt = _parse_iso_utc(event.event_timestamp)
        prefix = "sim" if event.is_simulated else "live"
        touched: list[DetectedIncident] = []

        if event.auth_result == "failure":
            # Track device-wide failure window (RULE_004)
            dev_key = (event.device_id, event.is_simulated)
            self._failures_by_device[dev_key].append((event_dt, event))

            if event.source_ip:
                ip_key = (event.device_id, event.is_simulated, event.source_ip)
                self._failures_by_ip[ip_key].append((event_dt, event))

                if event.username:
                    ip_user_key = (event.device_id, event.is_simulated, event.source_ip, event.username)
                    self._failures_by_ip_user[ip_user_key].append((event_dt, event))

                # Check RULE_005 (Repeat Offender) BEFORE marking this IP from current batch
                r5 = self._rule("RULE_005")
                r5_window = int(r5.get("window_seconds", 300))
                r5_threshold = int(r5.get("threshold", 3))
                r5_cooldown = int(r5.get("repeat_cooldown_seconds", 300))
                r5_lookback = int(r5.get("prior_lookback_seconds", 86400))
                is_repeat = self._is_prior_offender(
                    event.device_id,
                    event.is_simulated,
                    event.source_ip,
                    event_dt,
                    r5_lookback,
                    r5_cooldown,
                )

                # RULE_001: Repeated Failed Authentication from one IP
                r1 = self._rule("RULE_001")
                if r1.get("enabled", True):
                    w1 = int(r1.get("window_seconds", 120))
                    t1 = int(r1.get("threshold", 5))
                    evs1 = _prune_window(self._failures_by_ip[ip_key], event_dt, w1)
                    if len(evs1) >= t1:
                        users1 = sorted({e.username for e in evs1 if e.username})
                        first_ts = evs1[0].event_timestamp
                        last_ts = evs1[-1].event_timestamp
                        dur = (_parse_iso_utc(last_ts) - _parse_iso_utc(first_ts)).total_seconds()
                        score = calculate_risk_score(
                            failed_attempts=len(evs1),
                            unique_usernames=max(1, len(users1)),
                            duration_seconds=dur,
                            success_after_failures=False,
                            is_repeat_offender=is_repeat,
                            scoring_cfg=self.scoring_cfg,
                        )
                        dedup_key = f"{prefix}:{event.device_id}:RULE_001:{event.source_ip}"
                        evidence = {
                            "rule_id": "RULE_001",
                            "rule_name": r1.get("name", "Repeated Failed Authentication"),
                            "threshold": t1,
                            "window_seconds": w1,
                            "observed_count": len(evs1),
                            "source_ip": event.source_ip,
                            "sample_usernames": users1[:10],
                            "trigger_reason": (
                                f"Observed {len(evs1)} failed authentication attempts from {event.source_ip} "
                                f"within {w1}s (threshold: {t1}). Possible brute-force activity."
                            ),
                            "score_breakdown": score.breakdown,
                        }
                        inc = self._upsert_incident(
                            dedup_key=dedup_key,
                            device_id=event.device_id,
                            rule_id="RULE_001",
                            incident_title=f"Possible brute-force attempts from {event.source_ip}",
                            description=evidence["trigger_reason"],
                            source_ip=event.source_ip,
                            username=users1[0] if len(users1) == 1 else None,
                            risk_score=score.risk_score,
                            severity=score.severity,
                            first_observed=first_ts,
                            last_observed=last_ts,
                            supporting_events=evs1,
                            evidence=evidence,
                            is_simulated=event.is_simulated,
                        )
                        touched.append(inc)
                        self._mark_offender(event.device_id, event.is_simulated, event.source_ip, event_dt)

                # RULE_002: Multiple Target Accounts (Password Spraying / Enumeration)
                r2 = self._rule("RULE_002")
                if r2.get("enabled", True):
                    w2 = int(r2.get("window_seconds", 300))
                    t2 = int(r2.get("threshold", 4))
                    evs2 = _prune_window(self._failures_by_ip[ip_key], event_dt, w2)
                    users2 = sorted({e.username for e in evs2 if e.username})
                    if len(users2) >= t2:
                        first_ts = evs2[0].event_timestamp
                        last_ts = evs2[-1].event_timestamp
                        dur = (_parse_iso_utc(last_ts) - _parse_iso_utc(first_ts)).total_seconds()
                        score = calculate_risk_score(
                            failed_attempts=len(evs2),
                            unique_usernames=len(users2),
                            duration_seconds=dur,
                            success_after_failures=False,
                            is_repeat_offender=is_repeat,
                            scoring_cfg=self.scoring_cfg,
                        )
                        dedup_key = f"{prefix}:{event.device_id}:RULE_002:{event.source_ip}"
                        evidence = {
                            "rule_id": "RULE_002",
                            "rule_name": r2.get("name", "Multiple Target Accounts"),
                            "threshold": t2,
                            "window_seconds": w2,
                            "observed_count": len(evs2),
                            "unique_username_count": len(users2),
                            "source_ip": event.source_ip,
                            "sample_usernames": users2[:15],
                            "trigger_reason": (
                                f"Source IP {event.source_ip} failed authentication against {len(users2)} distinct "
                                f"usernames within {w2}s (threshold: {t2}). Potential password spraying or account enumeration."
                            ),
                            "score_breakdown": score.breakdown,
                        }
                        inc = self._upsert_incident(
                            dedup_key=dedup_key,
                            device_id=event.device_id,
                            rule_id="RULE_002",
                            incident_title=f"Potential password spraying from {event.source_ip}",
                            description=evidence["trigger_reason"],
                            source_ip=event.source_ip,
                            username=None,
                            risk_score=score.risk_score,
                            severity=score.severity,
                            first_observed=first_ts,
                            last_observed=last_ts,
                            supporting_events=evs2,
                            evidence=evidence,
                            is_simulated=event.is_simulated,
                        )
                        touched.append(inc)
                        self._mark_offender(event.device_id, event.is_simulated, event.source_ip, event_dt)

                # RULE_005: Repeat Offender Activity
                if r5.get("enabled", True) and is_repeat:
                    evs5 = _prune_window(self._failures_by_ip[ip_key], event_dt, r5_window)
                    if len(evs5) >= r5_threshold:
                        users5 = sorted({e.username for e in evs5 if e.username})
                        first_ts = evs5[0].event_timestamp
                        last_ts = evs5[-1].event_timestamp
                        dur = (_parse_iso_utc(last_ts) - _parse_iso_utc(first_ts)).total_seconds()
                        score = calculate_risk_score(
                            failed_attempts=len(evs5),
                            unique_usernames=max(1, len(users5)),
                            duration_seconds=dur,
                            success_after_failures=False,
                            is_repeat_offender=True,
                            scoring_cfg=self.scoring_cfg,
                        )
                        dedup_key = f"{prefix}:{event.device_id}:RULE_005:{event.source_ip}"
                        evidence = {
                            "rule_id": "RULE_005",
                            "rule_name": r5.get("name", "Repeat Offender Activity"),
                            "threshold": r5_threshold,
                            "window_seconds": r5_window,
                            "prior_lookback_seconds": r5_lookback,
                            "observed_count": len(evs5),
                            "source_ip": event.source_ip,
                            "sample_usernames": users5[:10],
                            "trigger_reason": (
                                f"Previously flagged source IP {event.source_ip} generated {len(evs5)} additional "
                                f"failed attempts within {r5_window}s."
                            ),
                            "score_breakdown": score.breakdown,
                        }
                        inc = self._upsert_incident(
                            dedup_key=dedup_key,
                            device_id=event.device_id,
                            rule_id="RULE_005",
                            incident_title=f"Repeat offender activity from {event.source_ip}",
                            description=evidence["trigger_reason"],
                            source_ip=event.source_ip,
                            username=users5[0] if len(users5) == 1 else None,
                            risk_score=score.risk_score,
                            severity=score.severity,
                            first_observed=first_ts,
                            last_observed=last_ts,
                            supporting_events=evs5,
                            evidence=evidence,
                            is_simulated=event.is_simulated,
                        )
                        touched.append(inc)

            # RULE_004: High-Volume Authentication Failures across entire device
            r4 = self._rule("RULE_004")
            if r4.get("enabled", True):
                w4 = int(r4.get("window_seconds", 300))
                t4 = int(r4.get("threshold", 20))
                evs4 = _prune_window(self._failures_by_device[dev_key], event_dt, w4)
                if len(evs4) >= t4:
                    ips4 = sorted({e.source_ip for e in evs4 if e.source_ip})
                    users4 = sorted({e.username for e in evs4 if e.username})
                    first_ts = evs4[0].event_timestamp
                    last_ts = evs4[-1].event_timestamp
                    dur = (_parse_iso_utc(last_ts) - _parse_iso_utc(first_ts)).total_seconds()
                    score = calculate_risk_score(
                        failed_attempts=len(evs4),
                        unique_usernames=max(1, len(users4)),
                        duration_seconds=dur,
                        success_after_failures=False,
                        is_repeat_offender=False,
                        scoring_cfg=self.scoring_cfg,
                    )
                    dedup_key = f"{prefix}:{event.device_id}:RULE_004:{event.device_id}"
                    evidence = {
                        "rule_id": "RULE_004",
                        "rule_name": r4.get("name", "High-Volume Authentication Failures"),
                        "threshold": t4,
                        "window_seconds": w4,
                        "observed_count": len(evs4),
                        "distinct_source_ips": ips4[:15],
                        "sample_usernames": users4[:15],
                        "trigger_reason": (
                            f"Device recorded {len(evs4)} failed authentication events across "
                            f"{len(ips4)} source IP(s) within {w4}s (threshold: {t4})."
                        ),
                        "score_breakdown": score.breakdown,
                    }
                    inc = self._upsert_incident(
                        dedup_key=dedup_key,
                        device_id=event.device_id,
                        rule_id="RULE_004",
                        incident_title="High-volume authentication failures detected",
                        description=evidence["trigger_reason"],
                        source_ip=ips4[0] if len(ips4) == 1 else None,
                        username=None,
                        risk_score=score.risk_score,
                        severity=score.severity,
                        first_observed=first_ts,
                        last_observed=last_ts,
                        supporting_events=evs4,
                        evidence=evidence,
                        is_simulated=event.is_simulated,
                    )
                    touched.append(inc)

        elif event.auth_result == "success" and event.source_ip and event.username:
            # RULE_003: Suspicious Success After Failures
            r3 = self._rule("RULE_003")
            if r3.get("enabled", True):
                w3 = int(r3.get("window_seconds", 600))
                t3 = int(r3.get("threshold", 3))
                ip_user_key = (event.device_id, event.is_simulated, event.source_ip, event.username)
                prior_failures = _prune_window(self._failures_by_ip_user[ip_user_key], event_dt, w3)
                if len(prior_failures) >= t3:
                    supporting = [*prior_failures, event]
                    first_ts = supporting[0].event_timestamp
                    last_ts = format_utc_iso(event_dt)
                    dur = (_parse_iso_utc(last_ts) - _parse_iso_utc(first_ts)).total_seconds()
                    r5_cfg = self._rule("RULE_005")
                    r5_lookback = int(r5_cfg.get("prior_lookback_seconds", 86400))
                    r5_cooldown = int(r5_cfg.get("repeat_cooldown_seconds", 300))
                    is_repeat = self._is_prior_offender(
                        event.device_id,
                        event.is_simulated,
                        event.source_ip,
                        event_dt,
                        r5_lookback,
                        r5_cooldown,
                    )
                    score = calculate_risk_score(
                        failed_attempts=len(prior_failures),
                        unique_usernames=1,
                        duration_seconds=dur,
                        success_after_failures=True,
                        is_repeat_offender=is_repeat,
                        scoring_cfg=self.scoring_cfg,
                    )
                    dedup_key = f"{prefix}:{event.device_id}:RULE_003:{event.source_ip}:{event.username}"
                    evidence = {
                        "rule_id": "RULE_003",
                        "rule_name": r3.get("name", "Suspicious Success After Failures"),
                        "threshold": t3,
                        "window_seconds": w3,
                        "prior_failures_count": len(prior_failures),
                        "source_ip": event.source_ip,
                        "username": event.username,
                        "trigger_reason": (
                            f"Successful login for '{event.username}' from {event.source_ip} followed "
                            f"{len(prior_failures)} failed attempts within {w3}s. "
                            "This pattern may indicate a compromised account, though it does not prove compromise."
                        ),
                        "score_breakdown": score.breakdown,
                    }
                    inc = self._upsert_incident(
                        dedup_key=dedup_key,
                        device_id=event.device_id,
                        rule_id="RULE_003",
                        incident_title=f"Suspicious login after failures for '{event.username}' from {event.source_ip}",
                        description=evidence["trigger_reason"],
                        source_ip=event.source_ip,
                        username=event.username,
                        risk_score=score.risk_score,
                        severity=score.severity,
                        first_observed=first_ts,
                        last_observed=last_ts,
                        supporting_events=supporting,
                        evidence=evidence,
                        is_simulated=event.is_simulated,
                    )
                    touched.append(inc)
                    self._mark_offender(event.device_id, event.is_simulated, event.source_ip, event_dt)

        return touched

    def process_events(self, events: Iterable[NormalizedEvent]) -> list[DetectedIncident]:
        """Evaluate a sequence of events in chronological order and return unique affected incidents."""
        ordered = sorted(events, key=lambda e: e.event_timestamp)
        touched_by_key: dict[str, DetectedIncident] = {}
        for ev in ordered:
            for inc in self.process_event(ev):
                touched_by_key[inc.dedup_key] = inc
        return list(touched_by_key.values())
