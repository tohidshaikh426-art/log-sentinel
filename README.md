# Log Sentinel — Real-Time Security Log Monitoring & Threat Detection System

**Log Sentinel** is a lightweight, defensive Security Operations Center (SOC) web application and log-monitoring pipeline built as an MCA Mini Project (Version 1.0) on a **₹0 free-tier architecture**.

## Problem Statement

Server administrators and small teams need visibility into who is attempting to authenticate against their Linux hosts—to spot repeated failed logins, brute-force bursts, password spraying, and suspicious post-failure logins—without paying for commercial SIEM tools or exposing servers directly to the internet.

## Key Features

- **Real-Time SOC Dashboard:** Overview KPIs, 4 Chart.js visualizations, Live Monitoring feed, and 90-second stale-heartbeat offline collector detection via Supabase Realtime.
- **Resilient Python Collector (`collector/`):** Continuous non-root tailing of `/var/log/auth.log` or `systemd` journal with `(inode, byte_offset)` cursor persistence, `logrotate` recovery, SQLite offline retry spool, and 30s heartbeats.
- **Explainable Rule-Based Detection (`RULE_001`–`RULE_005`):** Detects brute force, multi-account password spraying, suspicious success after failures, high-volume device failures, and repeat offenders with transparent `0–100` risk score breakdowns and burst deduplication.
- **Incident Investigation & Triage:** Search/filter incidents, inspect supporting events and risk score math, update statuses (`open` → `investigating` → `resolved`), and record investigation notes.
- **IP Analysis & Historical Log Analyzer:** Server-side per-IP threat summaries (no paid IP APIs) plus `.log`/`.csv` file upload scanning using the exact same detection rules.
- **CSV & Print-to-PDF Reports:** Formula-safe CSV export and clean `@media print` PDF reports.
- **Controlled Demo / Simulation Mode:** 6 synthetic scenarios (Normal, Brute Force, Password Spraying, Suspicious Success, Repeat Offender, Collector Offline) with unmistakable `SIMULATION MODE` indicators, safe `reset_demo_data()`, and an Offline Local Preview fallback.

## Technology Stack (₹0 Free Tier)

- **Frontend:** React, JavaScript, Vite, CSS, Chart.js (`vercel` Free Tier)
- **Cloud Backend & Database:** Supabase (PostgreSQL, Auth, Row Level Security, Realtime, Deno Edge Functions — Free Tier)
- **Collector & Detection:** Python 3, `requests`, `python-dotenv`, `sqlite3`, `pytest`
- **Version Control:** Git & GitHub

## Project Structure

```text
Log Sentinel/
├── frontend/     # React + Vite SOC web dashboard & Vitest suite
├── collector/    # Python 3 log collector, parsers, detection engine & pytest suite
├── supabase/     # SQL migrations, RLS policies, Deno Edge Functions & tests
├── docs/         # Architecture, schema, detection rules, testing & viva docs
├── .env.example  # Placeholder environment variables (never commit real secrets)
└── .gitignore
```

## Quick Setup & Deployment

### 1. Supabase Database & Edge Functions
See [supabase/README.md](supabase/README.md) for full instructions:
1. Run `supabase/migrations/202611260001_initial_schema.sql`, `0002`, and `0003` in order in the Supabase SQL Editor.
2. Verify RLS with `supabase/seed/verify_phase2_rls.sql`.
3. Create an admin user in **Authentication → Users** (check **Auto Confirm User**).
4. Deploy Edge Functions (`ingest-events`, `collector-heartbeat`, `analyze-upload`, `run-simulation`).

### 2. Frontend Local Development & Vercel Deployment
1. Copy `.env.example` values into `frontend/.env.local` (`VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` or `VITE_SUPABASE_PUBLISHABLE_KEY`).
2. Run locally:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
3. **Deploy to Vercel (Free):** Import this GitHub repository in Vercel, set **Root Directory** to `frontend`, add `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` (or `VITE_SUPABASE_ANON_KEY`) in Environment Variables, and deploy (`frontend/vercel.json` handles SPA routing and security headers).

### 3. Python Collector on Linux
See [collector/README.md](collector/README.md) for least-privilege (`adm` group, non-root) installation, `systemd` service setup, `--dry-run` testing, and troubleshooting.

## Testing

See [docs/testing.md](docs/testing.md) for complete commands across Python (`pytest`), Edge Functions (`node --experimental-strip-types --test`), Database RLS (`verify_phase2_rls.sql`), and Frontend (`npx vitest run` & `npm run build`).

## Honest Limitations (Version 1.0)

- Rule-based detection is not equivalent to a commercial SIEM and can produce false positives.
- Detection depends on supported log formats (`auth.log`, `journalctl -o short-iso`, documented CSV) and available fields; missing or unsupported log sources cannot be analyzed.
- IP addresses alone do not reliably identify an attacker, and detections indicate suspicious patterns—never proof of compromise.
- Version 1.0 does not automatically block IP addresses or execute remote commands.
- Free-tier cloud hosting does not guarantee 24/7 SLA availability (Supabase Free pauses after 7 days of inactivity).
- Demo Mode data is synthetic and isolated via `is_simulated = true`.

## Future Scope

- Additional log parsers (Nginx/Apache access logs, Windows Security Event Logs).
- Configurable email/webhook alerting and rule threshold editor UI.
- Multi-role RBAC (Read-only Auditor vs. SOC Admin).
