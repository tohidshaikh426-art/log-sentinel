import { supabase } from './supabaseClient';

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

/**
 * Fetch real monitored device health from Supabase's `monitored_devices_status` view.
 * Never reports monitoring as active unless at least one collector has a fresh heartbeat.
 */
export async function fetchMonitoringSummary() {
  if (!supabase) {
    return { ...EMPTY_MONITORING_SUMMARY };
  }

  const { data, error } = await supabase
    .from('monitored_devices_status')
    .select('id, effective_status, last_heartbeat, last_event_at, is_simulated');

  if (error) {
    throw new Error(error.message || 'Unable to load collector status');
  }

  const devices = data || [];
  if (devices.length === 0) {
    return { ...EMPTY_MONITORING_SUMMARY };
  }

  let onlineCount = 0;
  let offlineCount = 0;
  let pausedCount = 0;
  let lastEventAt = null;
  let lastHeartbeatAt = null;

  for (const dev of devices) {
    if (dev.effective_status === 'online') onlineCount += 1;
    else if (dev.effective_status === 'paused') pausedCount += 1;
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
