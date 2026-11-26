-- ============================================================================
-- Log Sentinel — Phase 2 Migration 001: Initial Relational Schema
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Administrator profiles linked 1:1 with Supabase Auth users
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name TEXT CHECK (full_name IS NULL OR char_length(full_name) <= 120),
  email TEXT NOT NULL CHECK (char_length(trim(email)) BETWEEN 3 AND 254),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name, email)
  VALUES (
    NEW.id,
    NULLIF(trim(COALESCE(NEW.raw_user_meta_data ->> 'full_name', '')), ''),
    COALESCE(NEW.email, 'admin@logsentinel.local')
  )
  ON CONFLICT (id) DO UPDATE
    SET email = EXCLUDED.email;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- 2. Monitored machines (publicly visible metadata only; secrets live separately)
CREATE TABLE IF NOT EXISTS public.monitored_devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_name TEXT NOT NULL CHECK (char_length(trim(device_name)) BETWEEN 1 AND 120),
  host_identifier TEXT NOT NULL UNIQUE CHECK (char_length(trim(host_identifier)) BETWEEN 1 AND 128),
  os_info TEXT CHECK (os_info IS NULL OR char_length(os_info) <= 160),
  collector_version TEXT CHECK (collector_version IS NULL OR char_length(collector_version) <= 40),
  is_simulated BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL DEFAULT 'offline' CHECK (status IN ('online', 'offline', 'paused')),
  last_heartbeat TIMESTAMPTZ,
  last_event_at TIMESTAMPTZ,
  events_received_count BIGINT NOT NULL DEFAULT 0 CHECK (events_received_count >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Private per-device collector credential hashes (never exposed to browser clients)
CREATE TABLE IF NOT EXISTS public.device_credentials (
  device_id UUID PRIMARY KEY REFERENCES public.monitored_devices(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL CHECK (char_length(token_hash) = 64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Normalized authentication events
CREATE TABLE IF NOT EXISTS public.authentication_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES public.monitored_devices(id) ON DELETE CASCADE,
  event_timestamp TIMESTAMPTZ NOT NULL,
  ingestion_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  username TEXT CHECK (username IS NULL OR char_length(username) <= 128),
  source_ip INET,
  event_type TEXT NOT NULL CHECK (char_length(trim(event_type)) BETWEEN 1 AND 64),
  auth_result TEXT NOT NULL CHECK (auth_result IN ('success', 'failure', 'unknown')),
  auth_method TEXT CHECK (auth_method IS NULL OR char_length(auth_method) <= 40),
  service TEXT CHECK (service IS NULL OR char_length(service) <= 40),
  raw_event TEXT CHECK (raw_event IS NULL OR char_length(raw_event) <= 512),
  event_fingerprint TEXT NOT NULL UNIQUE CHECK (char_length(event_fingerprint) = 64),
  is_simulated BOOLEAN NOT NULL DEFAULT FALSE
);

-- 5. Correlated security incidents
CREATE TABLE IF NOT EXISTS public.security_incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES public.monitored_devices(id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL CHECK (char_length(trim(rule_id)) BETWEEN 1 AND 32),
  incident_title TEXT NOT NULL CHECK (char_length(trim(incident_title)) BETWEEN 1 AND 200),
  description TEXT NOT NULL CHECK (char_length(trim(description)) BETWEEN 1 AND 2000),
  source_ip INET,
  username TEXT CHECK (username IS NULL OR char_length(username) <= 128),
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved')),
  dedup_key TEXT NOT NULL CHECK (char_length(trim(dedup_key)) BETWEEN 1 AND 255),
  first_observed TIMESTAMPTZ NOT NULL,
  last_observed TIMESTAMPTZ NOT NULL,
  event_count INTEGER NOT NULL DEFAULT 1 CHECK (event_count >= 1),
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  investigation_notes TEXT CHECK (investigation_notes IS NULL OR char_length(investigation_notes) <= 2000),
  is_simulated BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ,
  CHECK (last_observed >= first_observed)
);

-- Enforce single active (unresolved) incident per correlation key
CREATE UNIQUE INDEX IF NOT EXISTS idx_security_incidents_active_dedup
  ON public.security_incidents (dedup_key)
  WHERE status <> 'resolved';

-- 6. Join table linking incidents to supporting authentication events
CREATE TABLE IF NOT EXISTS public.incident_events (
  incident_id UUID NOT NULL REFERENCES public.security_incidents(id) ON DELETE CASCADE,
  event_id UUID NOT NULL REFERENCES public.authentication_events(id) ON DELETE CASCADE,
  PRIMARY KEY (incident_id, event_id)
);

-- 7. Historical log analysis upload summaries
CREATE TABLE IF NOT EXISTS public.analysis_uploads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  uploaded_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  filename TEXT NOT NULL CHECK (char_length(trim(filename)) BETWEEN 1 AND 255),
  file_format TEXT NOT NULL CHECK (file_format IN ('auth_log', 'journal', 'csv')),
  total_lines INTEGER NOT NULL CHECK (total_lines >= 0),
  parsed_count INTEGER NOT NULL CHECK (parsed_count >= 0),
  malformed_count INTEGER NOT NULL CHECK (malformed_count >= 0),
  incidents_created INTEGER NOT NULL CHECK (incidents_created >= 0),
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Query & dashboard performance indexes
CREATE INDEX IF NOT EXISTS idx_monitored_devices_heartbeat
  ON public.monitored_devices (last_heartbeat DESC);

CREATE INDEX IF NOT EXISTS idx_auth_events_device_ts
  ON public.authentication_events (device_id, event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_auth_events_ip_ts
  ON public.authentication_events (source_ip, event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_auth_events_result_ts
  ON public.authentication_events (auth_result, event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_auth_events_sim_ts
  ON public.authentication_events (is_simulated, event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_status_sev_obs
  ON public.security_incidents (status, severity, last_observed DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_ip
  ON public.security_incidents (source_ip);

CREATE INDEX IF NOT EXISTS idx_incidents_sim_obs
  ON public.security_incidents (is_simulated, last_observed DESC);

CREATE INDEX IF NOT EXISTS idx_incident_events_event_id
  ON public.incident_events (event_id);

CREATE INDEX IF NOT EXISTS idx_analysis_uploads_created
  ON public.analysis_uploads (created_at DESC);
