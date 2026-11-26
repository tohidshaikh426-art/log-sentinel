-- ============================================================================
-- Log Sentinel — Phase 2 Migration 003: Triggers, Views, RPCs & Realtime
-- ============================================================================

-- 1. Protect immutable forensic fields when authenticated admins triage incidents
CREATE OR REPLACE FUNCTION public.guard_incident_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  v_claims JSONB := COALESCE(NULLIF(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb);
  jwt_role TEXT := COALESCE(
    NULLIF(current_setting('request.jwt.claim.role', true), ''),
    v_claims ->> 'role',
    ''
  );
BEGIN
  -- Always refresh updated_at
  NEW.updated_at := NOW();

  -- Automatically maintain resolved_at based on status transitions
  IF NEW.status = 'resolved' AND OLD.status IS DISTINCT FROM 'resolved' THEN
    NEW.resolved_at := COALESCE(NEW.resolved_at, NOW());
  ELSIF NEW.status IN ('open', 'investigating') AND OLD.status = 'resolved' THEN
    NEW.resolved_at := NULL;
  END IF;

  -- Restrict dashboard users (authenticated role) to triage columns only
  IF jwt_role = 'authenticated' OR current_user = 'authenticated' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.device_id IS DISTINCT FROM OLD.device_id
       OR NEW.rule_id IS DISTINCT FROM OLD.rule_id
       OR NEW.incident_title IS DISTINCT FROM OLD.incident_title
       OR NEW.description IS DISTINCT FROM OLD.description
       OR NEW.source_ip IS DISTINCT FROM OLD.source_ip
       OR NEW.username IS DISTINCT FROM OLD.username
       OR NEW.severity IS DISTINCT FROM OLD.severity
       OR NEW.risk_score IS DISTINCT FROM OLD.risk_score
       OR NEW.dedup_key IS DISTINCT FROM OLD.dedup_key
       OR NEW.first_observed IS DISTINCT FROM OLD.first_observed
       OR NEW.last_observed IS DISTINCT FROM OLD.last_observed
       OR NEW.event_count IS DISTINCT FROM OLD.event_count
       OR NEW.evidence IS DISTINCT FROM OLD.evidence
       OR NEW.is_simulated IS DISTINCT FROM OLD.is_simulated
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'Authenticated users may only update status and investigation_notes on security_incidents.';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_guard_incident_update ON public.security_incidents;
CREATE TRIGGER trg_guard_incident_update
  BEFORE UPDATE ON public.security_incidents
  FOR EACH ROW
  EXECUTE FUNCTION public.guard_incident_update();

-- 2. View computing true online/offline status using 90-second heartbeat threshold
CREATE OR REPLACE VIEW public.monitored_devices_status
WITH (security_invoker = true) AS
SELECT
  d.id,
  d.device_name,
  d.host_identifier,
  d.os_info,
  d.collector_version,
  d.is_simulated,
  d.status,
  d.last_heartbeat,
  d.last_event_at,
  d.events_received_count,
  d.created_at,
  CASE
    WHEN d.status = 'paused' THEN 'paused'
    WHEN d.last_heartbeat IS NULL THEN 'offline'
    WHEN d.last_heartbeat < NOW() - INTERVAL '90 seconds' THEN 'offline'
    ELSE 'online'
  END AS effective_status
FROM public.monitored_devices d;

GRANT SELECT ON public.monitored_devices_status TO authenticated;

-- 3. Server-side per-IP threat aggregation (prevents loading whole DB into browser)
CREATE OR REPLACE FUNCTION public.get_ip_summary(
  p_include_simulated BOOLEAN DEFAULT TRUE,
  p_limit INTEGER DEFAULT 100
)
RETURNS TABLE (
  source_ip INET,
  total_events BIGINT,
  failed_attempts BIGINT,
  successful_logins BIGINT,
  incident_count BIGINT,
  max_risk_score INTEGER,
  first_observed TIMESTAMPTZ,
  last_observed TIMESTAMPTZ
)
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
  WITH event_stats AS (
    SELECT
      e.source_ip,
      COUNT(*) AS total_events,
      COUNT(*) FILTER (WHERE e.auth_result = 'failure') AS failed_attempts,
      COUNT(*) FILTER (WHERE e.auth_result = 'success') AS successful_logins,
      MIN(e.event_timestamp) AS first_observed,
      MAX(e.event_timestamp) AS last_observed
    FROM public.authentication_events e
    WHERE e.source_ip IS NOT NULL
      AND (p_include_simulated OR e.is_simulated = FALSE)
    GROUP BY e.source_ip
  ),
  incident_stats AS (
    SELECT
      i.source_ip,
      COUNT(*) AS incident_count,
      COALESCE(MAX(i.risk_score), 0)::INTEGER AS max_risk_score
    FROM public.security_incidents i
    WHERE i.source_ip IS NOT NULL
      AND (p_include_simulated OR i.is_simulated = FALSE)
    GROUP BY i.source_ip
  )
  SELECT
    es.source_ip,
    es.total_events,
    es.failed_attempts,
    es.successful_logins,
    COALESCE(ist.incident_count, 0) AS incident_count,
    COALESCE(ist.max_risk_score, 0) AS max_risk_score,
    es.first_observed,
    es.last_observed
  FROM event_stats es
  LEFT JOIN incident_stats ist ON ist.source_ip = es.source_ip
  ORDER BY COALESCE(ist.max_risk_score, 0) DESC, es.failed_attempts DESC, es.last_observed DESC
  LIMIT GREATEST(1, LEAST(COALESCE(p_limit, 100), 500));
$$;

REVOKE ALL ON FUNCTION public.get_ip_summary(BOOLEAN, INTEGER) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_ip_summary(BOOLEAN, INTEGER) TO authenticated;

-- 4. Register a monitored device and return a one-time collector bearer token
CREATE OR REPLACE FUNCTION public.register_monitored_device(
  p_device_name TEXT,
  p_host_identifier TEXT,
  p_os_info TEXT DEFAULT NULL,
  p_is_simulated BOOLEAN DEFAULT FALSE
)
RETURNS TABLE (
  device_id UUID,
  collector_token TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_device_id UUID;
  v_raw_token TEXT;
  v_token_hash TEXT;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Authentication required to register a monitored device.';
  END IF;

  v_raw_token := encode(gen_random_bytes(32), 'hex');
  v_token_hash := encode(digest(convert_to(v_raw_token, 'UTF8'), 'sha256'), 'hex');

  INSERT INTO public.monitored_devices (
    device_name,
    host_identifier,
    os_info,
    is_simulated,
    status
  )
  VALUES (
    trim(p_device_name),
    trim(p_host_identifier),
    NULLIF(trim(COALESCE(p_os_info, '')), ''),
    COALESCE(p_is_simulated, FALSE),
    'offline'
  )
  RETURNING id INTO v_device_id;

  INSERT INTO public.device_credentials (device_id, token_hash)
  VALUES (v_device_id, v_token_hash);

  RETURN QUERY SELECT v_device_id, v_raw_token;
END;
$$;

REVOKE ALL ON FUNCTION public.register_monitored_device(TEXT, TEXT, TEXT, BOOLEAN) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.register_monitored_device(TEXT, TEXT, TEXT, BOOLEAN) TO authenticated;

-- 5. Rotate a device collector token without exposing previous tokens
CREATE OR REPLACE FUNCTION public.rotate_device_token(p_device_id UUID)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_raw_token TEXT;
  v_token_hash TEXT;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Authentication required to rotate device token.';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM public.monitored_devices WHERE id = p_device_id) THEN
    RAISE EXCEPTION 'Monitored device not found.';
  END IF;

  v_raw_token := encode(gen_random_bytes(32), 'hex');
  v_token_hash := encode(digest(convert_to(v_raw_token, 'UTF8'), 'sha256'), 'hex');

  INSERT INTO public.device_credentials (device_id, token_hash, updated_at)
  VALUES (p_device_id, v_token_hash, NOW())
  ON CONFLICT (device_id) DO UPDATE
    SET token_hash = EXCLUDED.token_hash,
        updated_at = NOW();

  RETURN v_raw_token;
END;
$$;

REVOKE ALL ON FUNCTION public.rotate_device_token(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.rotate_device_token(UUID) TO authenticated;

-- 6. Safe Demo Mode reset: deletes ONLY is_simulated = TRUE records
CREATE OR REPLACE FUNCTION public.reset_demo_data()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_incidents_deleted INTEGER := 0;
  v_events_deleted INTEGER := 0;
  v_devices_deleted INTEGER := 0;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Authentication required to reset demo data.';
  END IF;

  DELETE FROM public.security_incidents WHERE is_simulated = TRUE;
  GET DIAGNOSTICS v_incidents_deleted = ROW_COUNT;

  DELETE FROM public.authentication_events WHERE is_simulated = TRUE;
  GET DIAGNOSTICS v_events_deleted = ROW_COUNT;

  DELETE FROM public.monitored_devices WHERE is_simulated = TRUE;
  GET DIAGNOSTICS v_devices_deleted = ROW_COUNT;

  RETURN jsonb_build_object(
    'incidents_deleted', v_incidents_deleted,
    'events_deleted', v_events_deleted,
    'devices_deleted', v_devices_deleted
  );
END;
$$;

REVOKE ALL ON FUNCTION public.reset_demo_data() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.reset_demo_data() TO authenticated;

-- 7. Atomic incident upsert/deduplication helper (service_role / Edge Functions only)
CREATE OR REPLACE FUNCTION public.upsert_security_incident(
  p_device_id UUID,
  p_rule_id TEXT,
  p_incident_title TEXT,
  p_description TEXT,
  p_source_ip INET,
  p_username TEXT,
  p_severity TEXT,
  p_risk_score INTEGER,
  p_dedup_key TEXT,
  p_first_observed TIMESTAMPTZ,
  p_last_observed TIMESTAMPTZ,
  p_event_count INTEGER,
  p_evidence JSONB,
  p_is_simulated BOOLEAN DEFAULT FALSE,
  p_event_ids UUID[] DEFAULT ARRAY[]::UUID[]
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_incident_id UUID;
BEGIN
  INSERT INTO public.security_incidents (
    device_id,
    rule_id,
    incident_title,
    description,
    source_ip,
    username,
    severity,
    risk_score,
    status,
    dedup_key,
    first_observed,
    last_observed,
    event_count,
    evidence,
    is_simulated
  )
  VALUES (
    p_device_id,
    p_rule_id,
    p_incident_title,
    p_description,
    p_source_ip,
    p_username,
    p_severity,
    p_risk_score,
    'open',
    p_dedup_key,
    p_first_observed,
    p_last_observed,
    GREATEST(1, COALESCE(p_event_count, 1)),
    COALESCE(p_evidence, '{}'::jsonb),
    COALESCE(p_is_simulated, FALSE)
  )
  ON CONFLICT (dedup_key) WHERE status <> 'resolved'
  DO UPDATE SET
    incident_title = EXCLUDED.incident_title,
    description = EXCLUDED.description,
    username = COALESCE(EXCLUDED.username, public.security_incidents.username),
    severity = CASE
      WHEN EXCLUDED.risk_score >= public.security_incidents.risk_score THEN EXCLUDED.severity
      ELSE public.security_incidents.severity
    END,
    risk_score = GREATEST(public.security_incidents.risk_score, EXCLUDED.risk_score),
    first_observed = LEAST(public.security_incidents.first_observed, EXCLUDED.first_observed),
    last_observed = GREATEST(public.security_incidents.last_observed, EXCLUDED.last_observed),
    event_count = GREATEST(public.security_incidents.event_count, EXCLUDED.event_count),
    evidence = EXCLUDED.evidence,
    updated_at = NOW()
  RETURNING id INTO v_incident_id;

  IF COALESCE(array_length(p_event_ids, 1), 0) > 0 THEN
    INSERT INTO public.incident_events (incident_id, event_id)
    SELECT v_incident_id, eid
    FROM unnest(p_event_ids) AS eid
    ON CONFLICT DO NOTHING;
  END IF;

  RETURN v_incident_id;
END;
$$;

REVOKE ALL ON FUNCTION public.upsert_security_incident(
  UUID, TEXT, TEXT, TEXT, INET, TEXT, TEXT, INTEGER, TEXT,
  TIMESTAMPTZ, TIMESTAMPTZ, INTEGER, JSONB, BOOLEAN, UUID[]
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.upsert_security_incident(
  UUID, TEXT, TEXT, TEXT, INET, TEXT, TEXT, INTEGER, TEXT,
  TIMESTAMPTZ, TIMESTAMPTZ, INTEGER, JSONB, BOOLEAN, UUID[]
) TO service_role;

-- 8. Enable Supabase Realtime publication idempotently for live dashboard tables
DO $$
DECLARE
  tbl TEXT;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    FOREACH tbl IN ARRAY ARRAY['monitored_devices', 'authentication_events', 'security_incidents']
    LOOP
      IF NOT EXISTS (
        SELECT 1
        FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime'
          AND schemaname = 'public'
          AND tablename = tbl
      ) THEN
        EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE public.%I', tbl);
      END IF;
    END LOOP;
  END IF;
END;
$$;
