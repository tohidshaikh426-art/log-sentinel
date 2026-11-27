# Log Sentinel — Testing & Verification Guide

## 1. Automated Test Suites

### A. Python Collector, Parsers & Detection Engine (`pytest`)
Run from `collector/`:
```bash
# Activate virtual environment first (Linux: source .venv/bin/activate)
.\.venv\Scripts\python.exe -m pytest
```
Covers:
- `tests/test_foundation.py` — Package imports and version checks.
- `tests/test_parser.py` — RFC 3164 year-rollover, `journalctl -o short-iso` offsets, IPv4/IPv6 SSH accepted/failed/invalid-user/PAM/sudo logs, ANSI/control-character sanitization, ignored vs. malformed line reporting, deterministic fingerprints, and CSV header/row validation.
- `tests/test_detection.py` — Risk scoring math, severity thresholds, normal activity (zero false alerts), `RULE_001`–`RULE_005`, sliding time-window expiration, burst deduplication, repeat-offender cooldown, and `sample_auth.log` integration.
- `tests/test_collector.py` — HTTPS config validation, incremental tailing with `(inode, byte_offset)` restart persistence, `logrotate` recovery, SQLite backoff & queue bounds, offline buffering + recovery flush, non-retryable `401` handling, and CLI `--dry-run`.

### B. Supabase Edge Functions (`node --test`)
Run from repository root:
```bash
node --experimental-strip-types --test supabase/functions/tests/edge_functions_test.ts
```
Covers (with mocked Supabase clients):
- `ingest-events` — invalid/missing collector tokens (`401`), paused device blocking (`403`), invalid IP rejection (`400`), duplicate fingerprint deduplication, and `upsert_security_incident` correlation.
- `collector-heartbeat` — device online status and `last_heartbeat` update.
- `analyze-upload` — admin JWT enforcement (`401`), binary/null-byte rejection (`400`), and `auth_log` brute-force detection.
- `run-simulation` — admin JWT enforcement, `normal` (0 incidents), `brute_force` (`RULE_001` with `is_simulated=true`), and `collector_offline` (`status='offline'`).

### C. Database Schema & Row Level Security (`verify_phase2_rls.sql`)
Run inside Supabase Dashboard → **SQL Editor** (executes inside `BEGIN; ... ROLLBACK;`):
- Verifies profile auto-creation trigger, incident deduplication partial index, `anon` privilege blocking, `device_credentials` isolation, forensic column immutability (`guard_incident_update()`), 90s offline status view, and `reset_demo_data()` preserving live records.

### D. Frontend React & Vitest Suite (`vitest`)
Run from `frontend/`:
```bash
npx vitest run
npm run build
```
Covers:
- `src/App.test.jsx` — Unauthenticated redirect to `/login`, email validation, 8 sidebar routes, honest collector status, and `ConfirmModal` `Esc` dismissal.
- `src/Phase8.test.jsx` — Overview KPIs/charts, `Live Only` toggle, error/retry banner, Events pagination/filters, XSS `<script>` safe plain-text rendering, Inspect modal, and IP Analysis filtering/links.
- `src/Phase9.test.jsx` — Incidents evidence breakdown + triage update, Log Analyzer extension validation + upload summary, formula-safe CSV export (`=CMD()` neutralization), and Settings device registration + token rotation confirmation.
- `src/Phase10.test.jsx` — 90s stale-heartbeat offline math, `useRealtimeFeed` single-channel stability + reconnect sync + unmount cleanup, and `LiveMonitoringPage` live deduplicated stream + pause toggle.
- `src/Phase11.test.jsx` — All 6 Demo scenarios, rate selector, confirmation modal before `reset_demo_data()`, and offline local presentation fallback.
