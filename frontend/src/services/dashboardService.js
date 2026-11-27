import { supabase } from './supabaseClient';

function assertSupabase() {
  if (!supabase) {
    throw new Error('Supabase client is not configured.');
  }
  return supabase;
}

function isIpLiteral(value) {
  const s = value.trim();
  const ipv4Parts = s.split('.');
  if (ipv4Parts.length === 4 && ipv4Parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) {
    return true;
  }
  return s.includes(':') && /^[0-9a-f:]+$/i.test(s);
}

function applySimulatedFilter(query, dataMode) {
  if (dataMode === 'live') return query.eq('is_simulated', false);
  if (dataMode === 'simulated') return query.eq('is_simulated', true);
  return query;
}

export async function fetchDevicesList() {
  const client = assertSupabase();
  const { data, error } = await client
    .from('monitored_devices_status')
    .select(
      'id, device_name, host_identifier, os_info, collector_version, is_simulated, status, effective_status, last_heartbeat, last_event_at, events_received_count',
    )
    .order('created_at', { ascending: false });

  if (error) {
    throw new Error(error.message || 'Failed to load monitored devices');
  }
  return data || [];
}

export async function fetchOverviewMetrics({ dataMode = 'all' } = {}) {
  const client = assertSupabase();

  const countEvents = (extraFn) => {
    let q = client.from('authentication_events').select('id', { count: 'exact', head: true });
    q = applySimulatedFilter(q, dataMode);
    if (extraFn) q = extraFn(q);
    return q;
  };

  const countIncidents = (extraFn) => {
    let q = client.from('security_incidents').select('id', { count: 'exact', head: true });
    q = applySimulatedFilter(q, dataMode);
    if (extraFn) q = extraFn(q);
    return q;
  };

  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  let recentEventsQuery = client
    .from('authentication_events')
    .select('event_timestamp, auth_result')
    .gte('event_timestamp', since24h)
    .order('event_timestamp', { ascending: true })
    .limit(500);
  recentEventsQuery = applySimulatedFilter(recentEventsQuery, dataMode);

  let recentIncidentsQuery = client
    .from('security_incidents')
    .select(
      'id, rule_id, incident_title, source_ip, username, severity, risk_score, status, event_count, last_observed, is_simulated',
    )
    .order('last_observed', { ascending: false })
    .limit(6);
  recentIncidentsQuery = applySimulatedFilter(recentIncidentsQuery, dataMode);

  const includeSimulated = dataMode !== 'live';

  const [
    totalRes,
    successRes,
    failureRes,
    incTotalRes,
    incLowRes,
    incMedRes,
    incHighRes,
    incCritRes,
    timelineRes,
    recentIncRes,
    devices,
    ipSummaryRes,
  ] = await Promise.all([
    countEvents(),
    countEvents((q) => q.eq('auth_result', 'success')),
    countEvents((q) => q.eq('auth_result', 'failure')),
    countIncidents(),
    countIncidents((q) => q.eq('severity', 'low')),
    countIncidents((q) => q.eq('severity', 'medium')),
    countIncidents((q) => q.eq('severity', 'high')),
    countIncidents((q) => q.eq('severity', 'critical')),
    recentEventsQuery,
    recentIncidentsQuery,
    fetchDevicesList(),
    client.rpc('get_ip_summary', { p_include_simulated: includeSimulated, p_limit: 8 }),
  ]);

  const firstError = [
    totalRes.error,
    successRes.error,
    failureRes.error,
    incTotalRes.error,
    timelineRes.error,
    recentIncRes.error,
    ipSummaryRes.error,
  ].find(Boolean);

  if (firstError) {
    throw new Error(firstError.message || 'Unable to load dashboard metrics');
  }

  let topIps = ipSummaryRes.data || [];
  if (dataMode === 'simulated') {
    // RPC filters all vs live-only; when viewing simulated-only, filter client-side if needed
    topIps = topIps.slice(0, 8);
  }

  const filteredDevices =
    dataMode === 'live'
      ? devices.filter((d) => !d.is_simulated)
      : dataMode === 'simulated'
        ? devices.filter((d) => d.is_simulated)
        : devices;

  const lastEventAt = filteredDevices.reduce((latest, d) => {
    if (!d.last_event_at) return latest;
    return !latest || d.last_event_at > latest ? d.last_event_at : latest;
  }, null);

  return {
    kpis: {
      totalEvents: totalRes.count ?? 0,
      successfulLogins: successRes.count ?? 0,
      failedLogins: failureRes.count ?? 0,
      totalIncidents: incTotalRes.count ?? 0,
      highIncidents: incHighRes.count ?? 0,
      criticalIncidents: incCritRes.count ?? 0,
      monitoredDevices: filteredDevices.length,
      onlineDevices: filteredDevices.filter((d) => d.effective_status === 'online').length,
      lastEventAt,
    },
    severityCounts: {
      low: incLowRes.count ?? 0,
      medium: incMedRes.count ?? 0,
      high: incHighRes.count ?? 0,
      critical: incCritRes.count ?? 0,
    },
    timelineEvents: timelineRes.data || [],
    recentIncidents: recentIncRes.data || [],
    topSuspiciousIps: topIps,
  };
}

export async function fetchEventsPage({
  page = 1,
  pageSize = 25,
  search = '',
  authResult = 'all',
  deviceId = 'all',
  dataMode = 'all',
} = {}) {
  const client = assertSupabase();
  const safePage = Math.max(1, page);
  const from = (safePage - 1) * pageSize;
  const to = from + pageSize - 1;

  let query = client
    .from('authentication_events')
    .select(
      'id, device_id, event_timestamp, ingestion_timestamp, username, source_ip, event_type, auth_result, auth_method, service, raw_event, is_simulated, monitored_devices(device_name, host_identifier)',
      { count: 'exact' },
    )
    .order('event_timestamp', { ascending: false })
    .range(from, to);

  query = applySimulatedFilter(query, dataMode);
  if (authResult !== 'all') {
    query = query.eq('auth_result', authResult);
  }
  if (deviceId !== 'all') {
    query = query.eq('device_id', deviceId);
  }

  const trimmed = search.trim();
  if (trimmed) {
    // Strip PostgREST filter punctuation to prevent filter syntax breakage
    const safeTerm = trimmed.replace(/[,()*%]/g, '');
    if (safeTerm) {
      if (isIpLiteral(safeTerm)) {
        query = query.or(
          `source_ip.eq.${safeTerm},username.ilike.%${safeTerm}%,raw_event.ilike.%${safeTerm}%`,
        );
      } else {
        query = query.or(
          `username.ilike.%${safeTerm}%,event_type.ilike.%${safeTerm}%,service.ilike.%${safeTerm}%,raw_event.ilike.%${safeTerm}%`,
        );
      }
    }
  }

  const { data, count, error } = await query;
  if (error) {
    throw new Error(error.message || 'Unable to fetch authentication events');
  }

  return {
    rows: data || [],
    totalCount: count ?? 0,
    page: safePage,
    pageSize,
  };
}

export async function fetchIpSummary({ includeSimulated = true, limit = 150 } = {}) {
  const client = assertSupabase();
  const { data, error } = await client.rpc('get_ip_summary', {
    p_include_simulated: includeSimulated,
    p_limit: limit,
  });

  if (error) {
    throw new Error(error.message || 'Unable to fetch IP threat summary');
  }
  return data || [];
}
