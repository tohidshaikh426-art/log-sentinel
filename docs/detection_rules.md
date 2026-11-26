# Log Sentinel — Detection Rules & Risk Scoring Specification

All detection rules in Version 1.0 are **deterministic, explainable, and configurable** via `collector/log_sentinel/config/rules_config.json`. Detections indicate *suspicious activity* requiring review—never proof of compromise.

## 1. Version 1.0 Rules

| Rule ID | Rule Name | Trigger Condition (Defaults) | Window | Base Severity Range | Correlation Key |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `RULE_001` | Repeated Failed Authentication (Possible Brute Force) | `>= 5` failed auth events from the same `source_ip` | 120s (2m) | Medium–Critical | `(prefix, device_id, RULE_001, source_ip)` |
| `RULE_002` | Multiple Target Accounts (Potential Password Spraying) | `1` `source_ip` fails auth against `>= 4` distinct usernames | 300s (5m) | High–Critical | `(prefix, device_id, RULE_002, source_ip)` |
| `RULE_003` | Suspicious Success After Failures | `1` `success` event for `(source_ip, username)` preceded by `>= 3` `failure` events | 600s (10m) | High–Critical | `(prefix, device_id, RULE_003, source_ip, username)` |
| `RULE_004` | High-Volume Authentication Failures | `>= 20` total failed auth events on a single device across any IPs | 300s (5m) | Medium–High | `(prefix, device_id, RULE_004, device_id)` |
| `RULE_005` | Repeat Offender Activity | A previously flagged `source_ip` triggers `>= 3` new failures within window | 300s (5m) / 24h lookback | Medium–Critical | `(prefix, device_id, RULE_005, source_ip)` |

## 2. Explainable Risk Scoring (0–100)

```text
risk_score = min(
  100,
  failure_points
  + target_spread_points
  + success_after_failure_bonus
  + velocity_bonus
  + repeat_offender_bonus
)
```

- **Failure Points:** `min(40, failed_attempts * 7)`
- **Target Spread Points:** `min(25, unique_usernames * 6)`
- **Success-After-Failure Bonus:** `+30` when a valid login follows repeated failures from the same IP/username
- **Velocity Bonus:** `+10` when `failed_attempts >= 3` and failure rate is `>= 3.0 attempts/minute`
- **Repeat Offender Bonus:** `+20` when the `source_ip` was flagged within the prior 24 hours

### Severity Mapping

- `0–24`: **Low**
- `25–49`: **Medium**
- `50–74`: **High**
- `75–100`: **Critical**

## 3. Incident Deduplication & Evidence

Repeated events matching an active incident within its correlation key update `last_observed`, increment `event_count`, recalculate `risk_score`/`severity`, and append supporting fingerprints rather than generating duplicate incidents per event.

Every incident stores an `evidence` JSON object recording:
- `rule_id`, `rule_name`, `threshold`, `window_seconds`
- `trigger_reason` (human-readable explanation)
- `score_breakdown` (each factor's exact point contribution)
- `sample_usernames`, `source_ip`, `observed_count`
