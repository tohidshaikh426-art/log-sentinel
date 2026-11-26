# Log Sentinel — Database Schema Specification

All tables reside in PostgreSQL (Supabase) with Row Level Security (RLS) enabled. Migrations are stored in [supabase/migrations/](../supabase/migrations/).

## 1. Tables

### `profiles`
- `id` (`UUID`, PK, FK -> `auth.users(id)` ON DELETE CASCADE)
- `full_name` (`TEXT`, max 120 chars)
- `email` (`TEXT`, NOT NULL)
- `created_at` (`TIMESTAMPTZ`, DEFAULT `NOW()`)
- Automatically populated on user signup via trigger `on_auth_user_created`.

### `monitored_devices`
- `id` (`UUID`, PK, DEFAULT `gen_random_uuid()`)
- `device_name` (`TEXT`, NOT NULL)
- `host_identifier` (`TEXT`, UNIQUE, NOT NULL)
- `os_info` (`TEXT`)
- `collector_version` (`TEXT`)
- `is_simulated` (`BOOLEAN`, NOT NULL, DEFAULT `false`)
- `status` (`TEXT`, CHECK `status IN ('online', 'offline', 'paused')`, DEFAULT `'offline'`)
- `last_heartbeat` (`TIMESTAMPTZ`)
- `last_event_at` (`TIMESTAMPTZ`)
- `events_received_count` (`BIGINT`, NOT NULL, DEFAULT `0`)
- `created_at` (`TIMESTAMPTZ`, NOT NULL, DEFAULT `NOW()`)

*Note on Offline Detection:* View `monitored_devices_status` computes `effective_status = 'offline'` whenever `last_heartbeat IS NULL` or `NOW() - last_heartbeat > INTERVAL '90 seconds'`.

### `device_credentials`
- `device_id` (`UUID`, PK, FK -> `monitored_devices(id)` ON DELETE CASCADE)
- `token_hash` (`TEXT`, NOT NULL, 64-char SHA-256 hex)
- `created_at` (`TIMESTAMPTZ`, NOT NULL, DEFAULT `NOW()`)
- `updated_at` (`TIMESTAMPTZ`, NOT NULL, DEFAULT `NOW()`)
- *Security:* RLS enabled with **zero client policies** (`anon`/`authenticated` cannot query token hashes; only Edge Functions using `service_role` verify tokens).

### `authentication_events`
- `id` (`UUID`, PK, DEFAULT `gen_random_uuid()`)
- `device_id` (`UUID`, NOT NULL, FK -> `monitored_devices(id)` ON DELETE CASCADE)
- `event_timestamp` (`TIMESTAMPTZ`, NOT NULL)
- `ingestion_timestamp` (`TIMESTAMPTZ`, NOT NULL, DEFAULT `NOW()`)
- `username` (`TEXT`, max 128 chars)
- `source_ip` (`INET`)
- `event_type` (`TEXT`, NOT NULL)
- `auth_result` (`TEXT`, NOT NULL, CHECK `auth_result IN ('success', 'failure', 'unknown')`)
- `auth_method` (`TEXT`)
- `service` (`TEXT`)
- `raw_event` (`TEXT`, max 512 chars, control chars stripped)
- `event_fingerprint` (`TEXT`, UNIQUE, NOT NULL, 64-char SHA-256 hex)
- `is_simulated` (`BOOLEAN`, NOT NULL, DEFAULT `false`)

### `security_incidents`
- `id` (`UUID`, PK, DEFAULT `gen_random_uuid()`)
- `device_id` (`UUID`, NOT NULL, FK -> `monitored_devices(id)` ON DELETE CASCADE)
- `rule_id` (`TEXT`, NOT NULL)
- `incident_title` (`TEXT`, NOT NULL)
- `description` (`TEXT`, NOT NULL)
- `source_ip` (`INET`)
- `username` (`TEXT`)
- `severity` (`TEXT`, NOT NULL, CHECK `severity IN ('low', 'medium', 'high', 'critical')`)
- `risk_score` (`INTEGER`, NOT NULL, CHECK `risk_score BETWEEN 0 AND 100`)
- `status` (`TEXT`, NOT NULL, CHECK `status IN ('open', 'investigating', 'resolved')`, DEFAULT `'open'`)
- `dedup_key` (`TEXT`, NOT NULL) — partial unique index `WHERE status <> 'resolved'`
- `first_observed` (`TIMESTAMPTZ`, NOT NULL)
- `last_observed` (`TIMESTAMPTZ`, NOT NULL)
- `event_count` (`INTEGER`, NOT NULL, DEFAULT `1`, CHECK `event_count >= 1`)
- `evidence` (`JSONB`, NOT NULL, DEFAULT `'{}'::jsonb`)
- `investigation_notes` (`TEXT`, max 2000 chars)
- `is_simulated` (`BOOLEAN`, NOT NULL, DEFAULT `false`)
- `created_at` (`TIMESTAMPTZ`, NOT NULL, DEFAULT `NOW()`)
- `updated_at` (`TIMESTAMPTZ`, NOT NULL, DEFAULT `NOW()`)
- `resolved_at` (`TIMESTAMPTZ`)

### `incident_events`
- `incident_id` (`UUID`, FK -> `security_incidents(id)` ON DELETE CASCADE)
- `event_id` (`UUID`, FK -> `authentication_events(id)` ON DELETE CASCADE)
- `PRIMARY KEY (incident_id, event_id)`

### `analysis_uploads`
- `id` (`UUID`, PK, DEFAULT `gen_random_uuid()`)
- `uploaded_by` (`UUID`, FK -> `auth.users(id)` ON DELETE SET NULL)
- `filename` (`TEXT`, NOT NULL)
- `file_format` (`TEXT`, NOT NULL, CHECK `file_format IN ('auth_log', 'journal', 'csv')`)
- `total_lines` (`INTEGER`, NOT NULL)
- `parsed_count` (`INTEGER`, NOT NULL)
- `malformed_count` (`INTEGER`, NOT NULL)
- `incidents_created` (`INTEGER`, NOT NULL)
- `summary` (`JSONB`, NOT NULL, DEFAULT `'{}'::jsonb`)
- `created_at` (`TIMESTAMPTZ`, NOT NULL, DEFAULT `NOW()`)

## 2. RPCs, Security Policies & Realtime

- **RLS:** Zero `anon` privileges on all tables. Authenticated admins can `SELECT` monitoring data, update their own `profiles`, pause/rename `monitored_devices`, and triage `security_incidents` (`status` and `investigation_notes` only — forensic columns are locked by `guard_incident_update()`).
- **RPCs:**
  - `register_monitored_device(...)` & `rotate_device_token(...)` — generates 256-bit collector tokens and stores only SHA-256 hashes.
  - `get_ip_summary(...)` — server-side IP aggregation.
  - `reset_demo_data()` — deletes only `is_simulated = TRUE` records.
  - `upsert_security_incident(...)` — `service_role`-only atomic deduplication & `incident_events` linking.
- **Realtime:** `monitored_devices`, `authentication_events`, and `security_incidents` are published to `supabase_realtime`.
