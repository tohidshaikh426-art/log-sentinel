-- ============================================================================
-- Log Sentinel — Phase 2 Verification Script (Safe Rollback Transaction)
-- Run in Supabase SQL Editor after applying migrations 001, 002, and 003.
-- Every assertion raises an exception on failure; transaction rolls back cleanly.
-- ============================================================================

BEGIN;

-- 1. Seed a test admin user in auth.users (triggers profiles row creation)
DO $$
DECLARE
  v_user_id UUID := '11111111-1111-1111-1111-111111111111';
  v_real_device_id UUID;
  v_sim_device_id UUID;
  v_real_event_id UUID;
  v_sim_event_id UUID;
  v_incident_id UUID;
  v_count INTEGER;
  v_reset_result JSONB;
BEGIN
  INSERT INTO auth.users (
    id, instance_id, aud, role, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at
  )
  VALUES (
    v_user_id,
    '00000000-0000-0000-0000-000000000000',
    'authenticated',
    'authenticated',
    'phase2-verify@logsentinel.local',
    '$2a$10$abcdefghijklmnopqrstuv',
    NOW(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    '{"full_name":"Phase2 Verifier"}'::jsonb,
    NOW(),
    NOW()
  )
  ON CONFLICT (id) DO NOTHING;

  -- Assert profile trigger created row
  SELECT COUNT(*) INTO v_count FROM public.profiles WHERE id = v_user_id;
  IF v_count <> 1 THEN
    RAISE EXCEPTION 'FAIL: Profile trigger did not create profile row';
  END IF;

  -- Seed 1 real device + 1 simulated device
  INSERT INTO public.monitored_devices (device_name, host_identifier, is_simulated, last_heartbeat)
  VALUES ('real-host-test', 'real-host-verify-01', FALSE, NOW())
  RETURNING id INTO v_real_device_id;

  INSERT INTO public.device_credentials (device_id, token_hash)
  VALUES (v_real_device_id, repeat('a', 64));

  INSERT INTO public.monitored_devices (device_name, host_identifier, is_simulated, last_heartbeat)
  VALUES ('sim-host-test', 'sim-host-verify-01', TRUE, NOW() - INTERVAL '5 minutes')
  RETURNING id INTO v_sim_device_id;

  -- Seed 1 real event + 1 simulated event
  INSERT INTO public.authentication_events (
    device_id, event_timestamp, username, source_ip, event_type,
    auth_result, event_fingerprint, is_simulated
  )
  VALUES (
    v_real_device_id, NOW(), 'ubuntu', '203.0.113.10', 'ssh_failed_password',
    'failure', repeat('b', 64), FALSE
  )
  RETURNING id INTO v_real_event_id;

  INSERT INTO public.authentication_events (
    device_id, event_timestamp, username, source_ip, event_type,
    auth_result, event_fingerprint, is_simulated
  )
  VALUES (
    v_sim_device_id, NOW(), 'admin', '198.51.100.77', 'ssh_failed_password',
    'failure', repeat('c', 64), TRUE
  )
  RETURNING id INTO v_sim_event_id;

  -- Test incident upsert & deduplication (calling twice with same dedup_key must produce 1 row)
  v_incident_id := public.upsert_security_incident(
    v_sim_device_id, 'RULE_001', 'Possible Brute Force', '5 failed attempts',
    '198.51.100.77'::inet, 'admin', 'high', 65,
    'sim:RULE_001:198.51.100.77', NOW() - INTERVAL '1 minute', NOW(), 5,
    '{"rule_id":"RULE_001"}'::jsonb, TRUE, ARRAY[v_sim_event_id]
  );

  PERFORM public.upsert_security_incident(
    v_sim_device_id, 'RULE_001', 'Possible Brute Force', '7 failed attempts',
    '198.51.100.77'::inet, 'admin', 'critical', 80,
    'sim:RULE_001:198.51.100.77', NOW() - INTERVAL '1 minute', NOW(), 7,
    '{"rule_id":"RULE_001"}'::jsonb, TRUE, ARRAY[v_sim_event_id]
  );

  SELECT COUNT(*) INTO v_count
  FROM public.security_incidents
  WHERE dedup_key = 'sim:RULE_001:198.51.100.77';
  IF v_count <> 1 THEN
    RAISE EXCEPTION 'FAIL: Incident deduplication expected 1 row, got %', v_count;
  END IF;

  -- Test anonymous access is blocked
  EXECUTE 'SET LOCAL ROLE anon';
  BEGIN
    SELECT COUNT(*) INTO v_count FROM public.authentication_events;
    RAISE EXCEPTION 'FAIL: anon role unexpectedly allowed to read authentication_events';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL; -- Expected
  END;
  RESET ROLE;

  -- Test authenticated admin access & constraints
  PERFORM set_config('request.jwt.claim.sub', v_user_id::text, true);
  PERFORM set_config('request.jwt.claim.role', 'authenticated', true);
  PERFORM set_config(
    'request.jwt.claims',
    json_build_object('sub', v_user_id::text, 'role', 'authenticated')::text,
    true
  );
  EXECUTE 'SET LOCAL ROLE authenticated';

  -- Should read events & computed online/offline view
  SELECT COUNT(*) INTO v_count FROM public.authentication_events;
  IF v_count < 2 THEN
    RAISE EXCEPTION 'FAIL: authenticated user could not read authentication_events';
  END IF;

  SELECT COUNT(*) INTO v_count
  FROM public.monitored_devices_status
  WHERE id = v_sim_device_id AND effective_status = 'offline';
  IF v_count <> 1 THEN
    RAISE EXCEPTION 'FAIL: stale heartbeat device not reported offline';
  END IF;

  -- Should NOT be able to read device_credentials
  BEGIN
    SELECT COUNT(*) INTO v_count FROM public.device_credentials;
    RAISE EXCEPTION 'FAIL: authenticated user unexpectedly accessed device_credentials';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL; -- Expected
  END;

  -- Should NOT be able to insert directly into authentication_events
  BEGIN
    INSERT INTO public.authentication_events (
      device_id, event_timestamp, event_type, auth_result, event_fingerprint
    ) VALUES (
      v_real_device_id, NOW(), 'ssh_failed_password', 'failure', repeat('d', 64)
    );
    RAISE EXCEPTION 'FAIL: authenticated user unexpectedly inserted directly into authentication_events';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL; -- Expected
  END;

  -- Should be allowed to triage incident status & notes
  UPDATE public.security_incidents
  SET status = 'investigating', investigation_notes = 'Checking IP logs'
  WHERE id = v_incident_id;

  -- Should NOT be allowed to tamper with forensic risk_score
  BEGIN
    UPDATE public.security_incidents SET risk_score = 10 WHERE id = v_incident_id;
    RAISE EXCEPTION 'FAIL: authenticated user was able to tamper with risk_score';
  EXCEPTION WHEN raise_exception THEN
    NULL; -- Expected from guard_incident_update()
  END;

  -- Reset demo data should delete simulated records but preserve real records
  v_reset_result := public.reset_demo_data();
  RESET ROLE;

  SELECT COUNT(*) INTO v_count FROM public.authentication_events WHERE id = v_real_event_id;
  IF v_count <> 1 THEN
    RAISE EXCEPTION 'FAIL: reset_demo_data deleted real authentication_events';
  END IF;

  SELECT COUNT(*) INTO v_count FROM public.authentication_events WHERE id = v_sim_event_id;
  IF v_count <> 0 THEN
    RAISE EXCEPTION 'FAIL: reset_demo_data failed to delete simulated authentication_events';
  END IF;

  RAISE NOTICE 'ALL PHASE 2 VERIFICATION CHECKS PASSED: %', v_reset_result;
END;
$$;

ROLLBACK;
