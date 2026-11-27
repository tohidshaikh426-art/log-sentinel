import { supabase } from './supabaseClient';

export const HEARTBEAT_STALE_MS = 90_000;

export const EMPTY_MONITORING_SUMMARY = {
  totalDevices: 0,
  onlineCount: 0,
  offlineCount: 0,
  pausedCount: 0,
  lastEventAt: null,
  lastHeartbeatAt: null,
  monitoringState: 'idle', // 'active' | 'offline' | 'paused' | 'idle'
  collectorLabel: 'No Collector',
};

export function computeEffectiveStatus(device, nowMs = Date.now()) {
  if (!device) return 'offline';
  if (device.status === 'paused') return 'paused';
  if (!device.last_heartbeat) return 'offline';
  const hbMs = Date.parse(device.last_heartbeat);
  if (!Number.isFinite(hbMs)) return 'offline';
  return nowMs - hbMs > HEARTBEAT_STALE_MS ? 'offline' : 'online';
}

export function summarizeDevices(devices, nowMs = Date.now()) {
  if (!devices || devices.length === 0) {
    return { ...EMPTY_MONITORING_SUMMARY };
  }

  let onlineCount = 0;
  let offlineCount = 0;
  let pausedCount = 0;
  let lastEventAt = null;
  let lastHeartbeatAt = null;

  for (const dev of devices) {
    const eff = computeEffectiveStatus(dev, nowMs);
    if (eff === 'online') onlineCount += 1;
    else if (eff === 'paused') pausedCount += 1;
    else offlineCount += 1;

    if (dev.last_event_at && (!lastEventAt || dev.last_event_at > lastEventAt)) {
      lastEventAt = dev.last_event_at;
    }
    if (dev.last_heartbeat && (!lastHeartbeatAt || dev.last_heartbeat > lastHeartbeatAt)) {
      lastHeartbeatAt = dev.last_heartbeat;
    }
  }

  let monitoringState = 'offline';
  let collectorLabel = `Offline (${offlineCount})`;
  if (onlineCount > 0) {
    monitoringState = 'active';
    collectorLabel = `${onlineCount} Online`;
  } else if (pausedCount === devices.length) {
    monitoringState = 'paused';
    collectorLabel = 'Paused';
  }

  return {
    totalDevices: devices.length,
    onlineCount,
    offlineCount,
    pausedCount,
    lastEventAt,
    lastHeartbeatAt,
    monitoringState,
    collectorLabel,
  };
}

/**
 * Fetch real monitored device health from Supabase's `monitored_devices_status` view.
 * Never reports monitoring as active unless at least one collector has a fresh heartbeat.
 */
export async function fetchMonitoringDevices() {
  if (!supabase) return [];

  const { data, error } = await supabase
    .from('monitored_devices_status')
    .select(
      'id, device_name, host_identifier, os_info, collector_version, status, effective_status, last_heartbeat, last_event_at, events_received_count, is_simulated',
    )
    .order('created_at', { ascending: false });

  if (error) {
    throw new Error(error.message || 'Unable to load collector status');
  }
  return data || [];
}

export async function fetchMonitoringSummary() {
  const devices = await fetchMonitoringDevices();
  return summarizeDevices(devices);
}
