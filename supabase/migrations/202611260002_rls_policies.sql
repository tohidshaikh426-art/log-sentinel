-- ============================================================================
-- Log Sentinel — Phase 2 Migration 002: Row Level Security (RLS) Policies
-- ============================================================================

-- Enable RLS on every public table
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.monitored_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authentication_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.analysis_uploads ENABLE ROW LEVEL SECURITY;

-- Belt-and-suspenders: revoke all table privileges from anonymous role
REVOKE ALL ON
  public.profiles,
  public.monitored_devices,
  public.device_credentials,
  public.authentication_events,
  public.security_incidents,
  public.incident_events,
  public.analysis_uploads
FROM anon;

-- Grant minimal required privileges to authenticated dashboard admins (enforced by RLS)
REVOKE ALL ON
  public.profiles,
  public.monitored_devices,
  public.device_credentials,
  public.authentication_events,
  public.security_incidents,
  public.incident_events,
  public.analysis_uploads
FROM authenticated;

GRANT SELECT, UPDATE ON public.profiles TO authenticated;
GRANT SELECT, UPDATE ON public.monitored_devices TO authenticated;
GRANT SELECT ON public.authentication_events TO authenticated;
GRANT SELECT, UPDATE ON public.security_incidents TO authenticated;
GRANT SELECT ON public.incident_events TO authenticated;
GRANT SELECT ON public.analysis_uploads TO authenticated;

-- 1. profiles: admins can only read/update their own profile
DROP POLICY IF EXISTS "profiles_select_own" ON public.profiles;
CREATE POLICY "profiles_select_own"
  ON public.profiles
  FOR SELECT
  TO authenticated
  USING (auth.uid() = id);

DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;
CREATE POLICY "profiles_update_own"
  ON public.profiles
  FOR UPDATE
  TO authenticated
  USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);

-- 2. monitored_devices: authenticated admins can read and pause/rename devices
--    Device creation happens via register_monitored_device() RPC so credentials are hashed server-side.
DROP POLICY IF EXISTS "devices_select_authenticated" ON public.monitored_devices;
CREATE POLICY "devices_select_authenticated"
  ON public.monitored_devices
  FOR SELECT
  TO authenticated
  USING (auth.uid() IS NOT NULL);

DROP POLICY IF EXISTS "devices_update_authenticated" ON public.monitored_devices;
CREATE POLICY "devices_update_authenticated"
  ON public.monitored_devices
  FOR UPDATE
  TO authenticated
  USING (auth.uid() IS NOT NULL)
  WITH CHECK (auth.uid() IS NOT NULL);

-- 3. device_credentials: intentionally ZERO policies for anon/authenticated (service_role only)

-- 4. authentication_events: read-only for authenticated admins (writes via Edge Functions only)
DROP POLICY IF EXISTS "events_select_authenticated" ON public.authentication_events;
CREATE POLICY "events_select_authenticated"
  ON public.authentication_events
  FOR SELECT
  TO authenticated
  USING (auth.uid() IS NOT NULL);

-- 5. security_incidents: authenticated admins can read and triage status/notes
DROP POLICY IF EXISTS "incidents_select_authenticated" ON public.security_incidents;
CREATE POLICY "incidents_select_authenticated"
  ON public.security_incidents
  FOR SELECT
  TO authenticated
  USING (auth.uid() IS NOT NULL);

DROP POLICY IF EXISTS "incidents_update_authenticated" ON public.security_incidents;
CREATE POLICY "incidents_update_authenticated"
  ON public.security_incidents
  FOR UPDATE
  TO authenticated
  USING (auth.uid() IS NOT NULL)
  WITH CHECK (auth.uid() IS NOT NULL);

-- 6. incident_events: read-only for authenticated admins
DROP POLICY IF EXISTS "incident_events_select_authenticated" ON public.incident_events;
CREATE POLICY "incident_events_select_authenticated"
  ON public.incident_events
  FOR SELECT
  TO authenticated
  USING (auth.uid() IS NOT NULL);

-- 7. analysis_uploads: read-only for authenticated admins (inserts via analyze-upload Edge Function)
DROP POLICY IF EXISTS "uploads_select_authenticated" ON public.analysis_uploads;
CREATE POLICY "uploads_select_authenticated"
  ON public.analysis_uploads
  FOR SELECT
  TO authenticated
  USING (auth.uid() IS NOT NULL);
