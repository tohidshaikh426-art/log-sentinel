# Log Sentinel — Architecture & Viva Explanation Guide (MCA Mini Project 1)

## Core Concepts Quick Reference

- **What are Security Logs?** Chronological OS records capturing system and authentication events (logins, password failures, `sudo` usage). In Ubuntu/Debian, authentication logs reside in `/var/log/auth.log` or `systemd` journal.
- **Why Log Monitoring Matters:** Without monitoring, repeated SSH password guessing or compromised credentials go unnoticed until damage occurs.
- **Brute Force vs. Password Spraying:**
  - *Brute Force (`RULE_001`):* Many failed attempts from one IP against one or a few accounts in a short window.
  - *Password Spraying / Enumeration (`RULE_002`):* One IP tries common passwords across many different usernames (`alice`, `bob`, `oracle`, `postgres`) to evade per-account lockouts.
- **Rule-Based Detection & False Positives:** Rules use transparent, configurable thresholds (`rules_config.json`) rather than opaque ML. Detections report *suspicious patterns* (not proof of compromise), because legitimate users mistyping passwords or shared office NAT IPs can trigger false positives.
- **Explainable Risk Scoring:** Every incident computes `0–100` from documented factors (failure count, target spread, success-after-failure, velocity, repeat offender) and stores `score_breakdown` in JSONB.
- **Log Parsing & Event Normalization:** Raw lines from RFC 3164 (`auth.log`), ISO-8601 (`journalctl`), and CSV are sanitized (ANSI/control chars stripped), converted to UTC timestamps, mapped to one `NormalizedEvent` schema, and hashed into a SHA-256 `event_fingerprint` for deduplication.
- **Collector Resilience:** Tracks `(inode, byte_offset)` in SQLite to avoid rereading logs on restart and to recover across `logrotate`; buffers batches offline with exponential backoff; runs without `root` via `adm` / `systemd-journal` group membership.
- **Cloud Security (RLS + Edge Functions):** Frontend uses only the public anon/publishable key + Supabase Auth; `SUPABASE_SERVICE_ROLE_KEY` stays exclusively inside Deno Edge Functions; collectors authenticate with per-device SHA-256 tokens (`device_credentials` has zero client RLS policies); `guard_incident_update()` prevents UI users from altering forensic scores/evidence.
- **Real-Time Delivery:** Uses Supabase Realtime (`postgres_changes`) over WebSockets rather than polling loops, combined with a 90-second heartbeat staleness check for offline collector detection.
