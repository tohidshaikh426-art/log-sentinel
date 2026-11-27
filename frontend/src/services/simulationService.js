import { isSupabaseConfigured, supabase } from './supabaseClient';

export const DEMO_SCENARIOS = [
  {
    id: 'normal',
    title: '1. Normal Activity',
    description: 'Valid publickey logins and 1 recovered password typo.',
    expected: 'Expected: 0 high/critical incidents.',
  },
  {
    id: 'brute_force',
    title: '2. Brute Force',
    description: '7 rapid failed password attempts from 203.0.113.55.',
    expected: 'Expected: RULE_001 High alert.',
  },
  {
    id: 'password_spraying',
    title: '3. Password Spraying',
    description: '192.0.2.88 targets 5 distinct usernames in 40s.',
    expected: 'Expected: RULE_002 multi-account alert.',
  },
  {
    id: 'suspicious_success',
    title: '4. Suspicious Success',
    description: '4 failed attempts followed by a valid login for backup_admin.',
    expected: 'Expected: RULE_003 elevated alert.',
  },
  {
    id: 'repeat_offender',
    title: '5. Repeat Offender',
    description: 'Previously flagged IP 198.51.100.200 resumes failures after cooldown.',
    expected: 'Expected: RULE_005 +20 risk score bonus.',
  },
  {
    id: 'collector_offline',
    title: '6. Collector Offline',
    description: 'Sets demo collector heartbeat to 3 minutes ago (>90s threshold).',
    expected: 'Expected: Demo device flips to Offline.',
  },
];

export async function triggerCloudSimulation({ scenario, paceMs = 0 }) {
  if (!supabase || !isSupabaseConfigured) {
    throw new Error('Supabase is not configured. Use Local Offline Preview mode instead.');
  }

  const { data: sessionData, error: sessionErr } = await supabase.auth.getSession();
  const accessToken = sessionData?.session?.access_token;
  if (sessionErr || !accessToken) {
    throw new Error('Administrator session expired. Please sign in again.');
  }

  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL?.trim();
  const anonKey = (
    import.meta.env.VITE_SUPABASE_ANON_KEY ||
    import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY ||
    ''
  ).trim();

  const res = await fetch(`${supabaseUrl}/functions/v1/run-simulation`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
      apikey: anonKey,
    },
    body: JSON.stringify({ scenario, pace_ms: paceMs }),
  });

  const payload = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(payload?.error || `Simulation failed (HTTP ${res.status})`);
  }
  return payload;
}

export async function resetCloudDemoData() {
  if (!supabase || !isSupabaseConfigured) {
    throw new Error('Supabase is not configured.');
  }
  const { data, error } = await supabase.rpc('reset_demo_data');
  if (error) {
    throw new Error(error.message || 'Failed to reset simulated demo data');
  }
  return data;
}

/**
 * In-memory offline presentation fallback if cloud services are temporarily unreachable.
 * Never persists to database and always marks items with is_simulated = true.
 */
export function buildOfflinePreviewScenario(scenario) {
  const now = Date.now();
  const demoDeviceId = 'offline-demo-sim-01';
  const makeTs = (offsetMs) => new Date(now + offsetMs).toISOString();

  if (scenario === 'collector_offline') {
    return {
      device: {
        id: demoDeviceId,
        device_name: 'Offline Preview Host (Simulated)',
        host_identifier: 'demo-offline-preview',
        status: 'offline',
        last_heartbeat: makeTs(-180_000),
        last_event_at: makeTs(-180_000),
        events_received_count: 0,
        is_simulated: true,
      },
      events: [],
      incidents: [],
    };
  }

  const events = [];
  const incidents = [];
  const pushEv = (offsetMs, username, ip, eventType, result) => {
    events.push({
      id: `local-sim-${scenario}-${events.length + 1}-${now}`,
      device_id: demoDeviceId,
      event_timestamp: makeTs(offsetMs),
      username,
      source_ip: ip,
      event_type: eventType,
      auth_result: result,
      is_simulated: true,
    });
  };

  if (scenario === 'normal') {
    pushEv(-30_000, 'deploy', '198.51.100.14', 'ssh_accepted_login', 'success');
    pushEv(-20_000, 'ops', '198.51.100.15', 'ssh_failed_password', 'failure');
    pushEv(-10_000, 'ops', '198.51.100.15', 'ssh_accepted_login', 'success');
  } else if (scenario === 'brute_force') {
    for (let i = 0; i < 6; i++) {
      pushEv(-(30_000 - i * 4_000), 'admin', '203.0.113.55', 'ssh_failed_password', 'failure');
    }
    incidents.push({
      id: `local-inc-bf-${now}`,
      rule_id: 'RULE_001',
      incident_title: 'Possible brute-force attempts from 203.0.113.55',
      source_ip: '203.0.113.55',
      severity: 'high',
      risk_score: 56,
      status: 'open',
      event_count: 6,
      is_simulated: true,
    });
  } else if (scenario === 'password_spraying') {
    for (const [i, u] of ['alice', 'bob', 'charlie', 'oracle', 'postgres'].entries()) {
      pushEv(-(30_000 - i * 5_000), u, '192.0.2.88', 'ssh_invalid_user', 'failure');
    }
    incidents.push({
      id: `local-inc-spray-${now}`,
      rule_id: 'RULE_002',
      incident_title: 'Potential password spraying from 192.0.2.88',
      source_ip: '192.0.2.88',
      severity: 'high',
      risk_score: 70,
      status: 'open',
      event_count: 5,
      is_simulated: true,
    });
  } else if (scenario === 'suspicious_success') {
    for (let i = 0; i < 4; i++) {
      pushEv(-(30_000 - i * 5_000), 'backup_admin', '203.0.113.99', 'ssh_failed_password', 'failure');
    }
    pushEv(-4_000, 'backup_admin', '203.0.113.99', 'ssh_accepted_login', 'success');
    incidents.push({
      id: `local-inc-saf-${now}`,
      rule_id: 'RULE_003',
      incident_title: "Suspicious login after failures for 'backup_admin' from 203.0.113.99",
      source_ip: '203.0.113.99',
      severity: 'high',
      risk_score: 74,
      status: 'open',
      event_count: 5,
      is_simulated: true,
    });
  } else if (scenario === 'repeat_offender') {
    for (let i = 0; i < 4; i++) {
      pushEv(-(20_000 - i * 4_000), 'root', '198.51.100.200', 'ssh_failed_password', 'failure');
    }
    incidents.push({
      id: `local-inc-rep-${now}`,
      rule_id: 'RULE_005',
      incident_title: 'Repeat offender activity from 198.51.100.200',
      source_ip: '198.51.100.200',
      severity: 'high',
      risk_score: 64,
      status: 'open',
      event_count: 4,
      is_simulated: true,
    });
  }

  return {
    device: {
      id: demoDeviceId,
      device_name: 'Offline Preview Host (Simulated)',
      host_identifier: 'demo-offline-preview',
      status: 'online',
      last_heartbeat: makeTs(0),
      last_event_at: makeTs(-4_000),
      events_received_count: events.length,
      is_simulated: true,
    },
    events: [...events].reverse(),
    incidents,
  };
}
