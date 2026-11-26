# Log Sentinel — Database Schema Specification

All tables reside in PostgreSQL (Supabase) with Row Level Security (RLS) enabled.

## 1. Tables

### `profiles`
- `id` (`UUID`, PK, FK -> `auth.users(id)` ON DELETE CASCADE)
- `full_name` (`TEXT`)
- `email` (`TEXT`, NOT NULL)
- `created_at` (`TIMESTAMPTZ`, DEFAULT `NOW()`)

### `monitored_devices`
- `id` (`UUID`, PK, DEFAULT `gen_random_uuid()`)
- `device_name` (`TEXT`, NOT NULL)
- `host_identifier` (`TEXT`, UNIQUE, NOT NULL)
- `os_info` (`TEXT`)
- `collector_version` (`TEXT`)
- `token_hash` (`TEXT`, NOT NULL) — SHA-256 hash of per-device collector secret (never returned to frontend)
- `is_simulated` (`BOOLEAN`, NOT NULL, DEFAULT `false`)
- `status` (`TEXT`, CHECK `status IN ('online', 'offline', 'paused')`, DEFAULT `'offline'`)
- `last_heartbeat` (`TIMESTAMPTZ`)
- `last_event_at` (`TIMESTAMPTZ`)
- `events_received_count` (`BIGINT`, NOT NULL, DEFAULT `0`)
- `created_at` (`TIMESTAMPTZ`, NOT NULL, DEFAULT `NOW()`)

*Note on Offline Detection:* A device is treated as offline whenever `last_heartbeat IS NULL` or `NOW() - last_heartbeat > INTERVAL '90 seconds'`.

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
- `event_fingerprint` (`TEXT`, UNIQUE, NOT NULL) — prevents duplicate insertion across retries
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
- `dedup_key` (`TEXT`, NOT NULL)
- `first_observed` (`TIMESTAMPTZ`, NOT NULL)
- `last_observed` (`TIMESTAMPTZ`, NOT NULL)
- `event_count` (`INTEGER`, NOT NULL, DEFAULT `1`, CHECK `event_count >= 1`)
- `evidence` (`JSONB`, NOT NULL, DEFAULT `'{}'::jsonb`)
- `investigation_notes` (`TEXT`)
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

## 2. Security & Realtime Policies

- **RLS:** No anonymous `SELECT`, `INSERT`, `UPDATE`, or `DELETE` on any table. Authenticated admins can `SELECT` all monitoring data and `UPDATE` incident `status`, `investigation_notes`, and `resolved_at`. Collectors only write through Edge Functions using `SERVICE_ROLE_KEY`.
- **Realtime:** `authentication_events`, `security_incidents`, and `monitored_devices` are published to `supabase_realtime`.
