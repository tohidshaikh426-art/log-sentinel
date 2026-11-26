# Log Sentinel — System Architecture (Version 1.0)

## 1. Design Principles

- **Zero-Cost Operation (₹0):** Runs strictly within free-tier quotas of Vercel, Supabase, and GitHub, with a Python 3 collector running on user-controlled Linux machines.
- **Defensive Only:** Read-only log monitoring and alert generation. Version 1.0 never performs automatic IP blocking, remote command execution, or active scanning.
- **Least Privilege & Secret Isolation:** `SUPABASE_SERVICE_ROLE_KEY` never leaves Supabase Edge Function secrets. The frontend uses Supabase Auth + anon key + RLS. The collector uses a per-device hashed bearer token (`X-Collector-Token`).
- **Explainable Detection:** Every incident records the exact rule ID, threshold, time window, supporting event IDs, and risk score breakdown.

## 2. Five-Component Architecture

1. **Component A — Web Dashboard (`frontend/`)**
   - Built with React, JavaScript, Vite, CSS, and Chart.js.
   - Authenticates administrators via Supabase Auth.
   - Displays live KPIs, charts, paginated events, incidents, IP analytics, historical log uploads, reports, and Demo Mode controls.
   - Receives real-time updates via Supabase Realtime (`postgres_changes`).

2. **Component B — Python Log Collector (`collector/`)**
   - Runs as a standalone non-root agent on the monitored Linux host (e.g., member of `adm` group to read `/var/log/auth.log`).
   - Tracks `(inode, byte_offset)` to avoid reprocessing and to survive `logrotate` and restarts.
   - Normalizes raw log lines, runs local detection rules, sends periodic heartbeats, and buffers failed uploads in a local SQLite retry queue.

3. **Component C — Cloud Ingestion (`supabase/functions/`)**
   - `ingest-events`: Authenticates `X-Collector-Token`, validates event schemas and payload sizes, deduplicates via `event_fingerprint`, and persists events + correlated incidents.
   - `collector-heartbeat`: Updates `monitored_devices.last_heartbeat`, collector version, and received counts.
   - `analyze-upload`: Authenticated admin endpoint that parses uploaded `.log`/`.csv` files using the same rule specification and saves results.

4. **Component D — Database (`supabase/migrations/`)**
   - PostgreSQL with foreign keys, constraints, indexes, and strict Row Level Security.
   - Supports `is_simulated` isolation so Demo Mode scenarios run through the real pipeline without mixing with live logs.

5. **Component E — Rule-Based Detection Engine**
   - Evaluates sliding time windows over normalized authentication events using configurable thresholds (`rules_config.json`).
   - Computes transparent `0–100` risk scores and deduplicates repeated bursts into correlated incidents.

## 3. Normalized Event Contract

```json
{
  "device_id": "uuid",
  "event_timestamp": "2026-11-26T16:12:38Z",
  "username": "admin",
  "source_ip": "192.168.1.50",
  "event_type": "ssh_failed_password",
  "auth_result": "failure",
  "auth_method": "password",
  "service": "sshd",
  "raw_event": "sanitized log line (max 512 chars)",
  "event_fingerprint": "sha256-hex",
  "is_simulated": false,
  "parse_status": "valid"
}
```

## 4. Free-Tier Constraints & Mitigations

- **Database Storage (500 MB) & Edge Function Invocations (500K/mo):** Mitigated by batching collector events (up to 25 events or 3–5s window), updating heartbeat timestamps in place on `monitored_devices` rather than inserting unbounded heartbeat rows, and capping `raw_event` length.
- **Project Inactivity Pause:** Supabase Free projects pause after 7 days of inactivity. Demo Mode and documented wake-up steps ensure reliable academic demonstrations.
