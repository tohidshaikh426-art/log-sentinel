import { isSupabaseConfigured, supabase } from './supabaseClient';

const MAX_UPLOAD_CHARS = 1_800_000;

function assertSupabase() {
  if (!supabase || !isSupabaseConfigured) {
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

export async function fetchIncidentsPage({
  page = 1,
  pageSize = 20,
  search = '',
  severity = 'all',
  status = 'all',
  dataMode = 'all',
} = {}) {
  const client = assertSupabase();
  const safePage = Math.max(1, page);
  const from = (safePage - 1) * pageSize;
  const to = from + pageSize - 1;

  let query = client
    .from('security_incidents')
    .select(
      'id, device_id, rule_id, incident_title, description, source_ip, username, severity, risk_score, status, first_observed, last_observed, event_count, evidence, investigation_notes, is_simulated, resolved_at, monitored_devices(device_name, host_identifier)',
      { count: 'exact' },
    )
    .order('last_observed', { ascending: false })
    .range(from, to);

  query = applySimulatedFilter(query, dataMode);
  if (severity !== 'all') query = query.eq('severity', severity);
  if (status !== 'all') query = query.eq('status', status);

  const trimmed = search.trim();
  if (trimmed) {
    const safeTerm = trimmed.replace(/[,()*%]/g, '');
    if (safeTerm) {
      if (isIpLiteral(safeTerm)) {
        query = query.or(
          `source_ip.eq.${safeTerm},incident_title.ilike.%${safeTerm}%,username.ilike.%${safeTerm}%`,
        );
      } else {
        query = query.or(
          `incident_title.ilike.%${safeTerm}%,rule_id.ilike.%${safeTerm}%,username.ilike.%${safeTerm}%,description.ilike.%${safeTerm}%`,
        );
      }
    }
  }

  const { data, count, error } = await query;
  if (error) {
    throw new Error(error.message || 'Unable to load security incidents');
  }

  return {
    rows: data || [],
    totalCount: count ?? 0,
    page: safePage,
    pageSize,
  };
}

export async function fetchIncidentLinkedEvents(incidentId) {
  const client = assertSupabase();
  const { data, error } = await client
    .from('incident_events')
    .select(
      'event_id, authentication_events(id, event_timestamp, username, source_ip, event_type, auth_result, auth_method, raw_event)',
    )
    .eq('incident_id', incidentId)
    .limit(50);

  if (error) {
    throw new Error(error.message || 'Unable to fetch supporting events');
  }

  return (data || [])
    .map((row) => row.authentication_events)
    .filter(Boolean)
    .sort((a, b) => Date.parse(b.event_timestamp) - Date.parse(a.event_timestamp));
}

export async function updateIncidentTriage(incidentId, { status, investigationNotes }) {
  const client = assertSupabase();
  const { data, error } = await client
    .from('security_incidents')
    .update({
      status,
      investigation_notes: investigationNotes ? investigationNotes.trim() : null,
    })
    .eq('id', incidentId)
    .select(
      'id, device_id, rule_id, incident_title, description, source_ip, username, severity, risk_score, status, first_observed, last_observed, event_count, evidence, investigation_notes, is_simulated, resolved_at, monitored_devices(device_name, host_identifier)',
    )
    .single();

  if (error) {
    throw new Error(error.message || 'Failed to update incident');
  }
  return data;
}

export async function analyzeUploadedLogFile({ filename, fileFormat, content }) {
  const client = assertSupabase();

  if (!content || !content.trim()) {
    throw new Error('The selected file is empty.');
  }
  if (content.includes('\u0000')) {
    throw new Error('Rejected unsafe binary file content.');
  }
  if (content.length > MAX_UPLOAD_CHARS) {
    throw new Error('File exceeds the 1.8 MB safe upload limit.');
  }

  const { data: sessionData, error: sessionErr } = await client.auth.getSession();
  const accessToken = sessionData?.session?.access_token;
  if (sessionErr || !accessToken) {
    throw new Error('Your administrator session expired. Please sign in again.');
  }

  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL?.trim();
  const anonKey = (
    import.meta.env.VITE_SUPABASE_ANON_KEY ||
    import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY ||
    ''
  ).trim();

  const response = await fetch(`${supabaseUrl}/functions/v1/analyze-upload`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
      apikey: anonKey,
    },
    body: JSON.stringify({
      filename,
      file_format: fileFormat,
      content,
    }),
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload?.error || `Upload analysis failed (HTTP ${response.status})`);
  }
  return payload;
}

export async function fetchUploadHistory(limit = 15) {
  const client = assertSupabase();
  const { data, error } = await client
    .from('analysis_uploads')
    .select(
      'id, filename, file_format, total_lines, parsed_count, malformed_count, incidents_created, summary, created_at',
    )
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) {
    throw new Error(error.message || 'Unable to load upload history');
  }
  return data || [];
}

export async function fetchReportDataset({ dataMode = 'all', dateFrom = '', dateTo = '' } = {}) {
  const client = assertSupabase();

  const applyEventBounds = (q) => {
    let next = applySimulatedFilter(q, dataMode);
    if (dateFrom) next = next.gte('event_timestamp', new Date(`${dateFrom}T00:00:00Z`).toISOString());
    if (dateTo) next = next.lte('event_timestamp', new Date(`${dateTo}T23:59:59Z`).toISOString());
    return next;
  };

  const applyIncidentBounds = (q) => {
    let next = applySimulatedFilter(q, dataMode);
    if (dateFrom) next = next.gte('last_observed', new Date(`${dateFrom}T00:00:00Z`).toISOString());
    if (dateTo) next = next.lte('last_observed', new Date(`${dateTo}T23:59:59Z`).toISOString());
    return next;
  };

  const [totalEvRes, successEvRes, failEvRes, incidentsRes, ipsRes] = await Promise.all([
    applyEventBounds(client.from('authentication_events').select('id', { count: 'exact', head: true })),
    applyEventBounds(
      client.from('authentication_events').select('id', { count: 'exact', head: true }).eq('auth_result', 'success'),
    ),
    applyEventBounds(
      client.from('authentication_events').select('id', { count: 'exact', head: true }).eq('auth_result', 'failure'),
    ),
    applyIncidentBounds(
      client
        .from('security_incidents')
        .select(
          'id, rule_id, incident_title, source_ip, username, severity, risk_score, status, event_count, first_observed, last_observed, is_simulated',
          { count: 'exact' },
        )
        .order('last_observed', { ascending: false })
        .limit(200),
    ),
    client.rpc('get_ip_summary', { p_include_simulated: dataMode !== 'live', p_limit: 50 }),
  ]);

  const err = [
    totalEvRes.error,
    successEvRes.error,
    failEvRes.error,
    incidentsRes.error,
    ipsRes.error,
  ].find(Boolean);
  if (err) {
    throw new Error(err.message || 'Unable to generate report dataset');
  }

  const incidents = incidentsRes.data || [];
  const severitySummary = { low: 0, medium: 0, high: 0, critical: 0 };
  const ruleMap = new Map();

  for (const inc of incidents) {
    if (severitySummary[inc.severity] !== undefined) {
      severitySummary[inc.severity] += 1;
    }
    const prev = ruleMap.get(inc.rule_id) || { rule_id: inc.rule_id, count: 0, max_score: 0 };
    prev.count += 1;
    prev.max_score = Math.max(prev.max_score, inc.risk_score || 0);
    ruleMap.set(inc.rule_id, prev);
  }

  return {
    generatedAt: new Date().toISOString(),
    dataMode,
    dateFrom,
    dateTo,
    totals: {
      totalEvents: totalEvRes.count ?? 0,
      successfulLogins: successEvRes.count ?? 0,
      failedLogins: failEvRes.count ?? 0,
      detectedIncidents: incidentsRes.count ?? incidents.length,
    },
    severitySummary,
    ruleSummary: Array.from(ruleMap.values()).sort((a, b) => b.count - a.count),
    suspiciousIps: ipsRes.data || [],
    incidents,
  };
}

export async function registerMonitoredDevice({ deviceName, hostIdentifier, osInfo }) {
  const client = assertSupabase();
  const { data, error } = await client.rpc('register_monitored_device', {
    p_device_name: deviceName.trim(),
    p_host_identifier: hostIdentifier.trim(),
    p_os_info: osInfo?.trim() || null,
    p_is_simulated: false,
  });

  if (error) {
    throw new Error(error.message || 'Failed to register monitored device');
  }
  const row = Array.isArray(data) ? data[0] : data;
  if (!row?.device_id || !row?.collector_token) {
    throw new Error('Unexpected response registering device');
  }
  return row;
}

export async function rotateDeviceCollectorToken(deviceId) {
  const client = assertSupabase();
  const { data, error } = await client.rpc('rotate_device_token', {
    p_device_id: deviceId,
  });

  if (error || !data) {
    throw new Error(error?.message || 'Failed to rotate device token');
  }
  return String(data);
}

export async function setDevicePaused(deviceId, shouldPause) {
  const client = assertSupabase();
  const { error } = await client
    .from('monitored_devices')
    .update({ status: shouldPause ? 'paused' : 'offline' })
    .eq('id', deviceId);

  if (error) {
    throw new Error(error.message || 'Failed to update device state');
  }
}
