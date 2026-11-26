# Log Sentinel — Real-Time Security Log Monitoring & Threat Detection System

Log Sentinel is a lightweight, defensive Security Operations Center (SOC) web application designed for monitoring Linux authentication logs, detecting suspicious activity with explainable rules, storing incidents in PostgreSQL, and streaming real-time updates to a web dashboard.

## Architecture Overview

- **Frontend (`frontend/`)**: React + Vite + Chart.js dashboard hosted on Vercel (Free Tier).
- **Cloud Backend (`supabase/`)**: Supabase PostgreSQL, Auth, Row Level Security (RLS), Realtime, and Edge Functions (Free Tier).
- **Collector & Detection (`collector/`)**: Standalone Python 3 log collector, normalizer, and rule-based detection engine.
- **Documentation (`docs/`)**: System architecture, database schema, detection rules, and testing specs.

## Project Structure

```text
Log Sentinel/
├── frontend/     # React + Vite SOC web dashboard
├── collector/    # Python 3 log collector, parser, detection engine & tests
├── supabase/     # SQL migrations, RLS policies, Edge Functions & seeds
├── docs/         # Architecture, schema, detection rules & testing docs
├── .env.example  # Placeholder environment variables
└── .gitignore
```

## Phase Status

Currently completing **Phase 1 — Architecture Lock & Project Foundation**.
See [docs/architecture.md](docs/architecture.md), [docs/database_schema.md](docs/database_schema.md), and [docs/detection_rules.md](docs/detection_rules.md) for the locked design specifications.
