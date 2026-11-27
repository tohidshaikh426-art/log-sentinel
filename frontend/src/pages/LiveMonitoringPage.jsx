import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  EmptyState,
  ErrorBanner,
  LoadingState,
  SeverityBadge,
  StatusBadge,
} from '../components/UiPrimitives';
import { useRealtimeFeed } from '../hooks/useRealtime';
import { fetchEventsPage } from '../services/dashboardService';
import {
  computeEffectiveStatus,
  fetchMonitoringDevices,
} from '../services/monitoringStatusService';
import { fetchIncidentsPage } from '../services/operationsService';
import {
  formatIpAddress,
  formatRelativeTime,
  formatTimestamp,
  sanitizeDisplayText,
} from '../utils/formatters';

const MAX_STREAM_EVENTS = 50;
const MAX_STREAM_INCIDENTS = 15;

export default function LiveMonitoringPage() {
  const [dataMode, setDataMode] = useState('all');
  const [streamPaused, setStreamPaused] = useState(false);
  const [devices, setDevices] = useState([]);
  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [nowMs, setNowMs] = useState(() => Date.now());

  const loadInitial = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [devs, evRes, incRes] = await Promise.all([
        fetchMonitoringDevices(),
        fetchEventsPage({ page: 1, pageSize: MAX_STREAM_EVENTS, dataMode }),
        fetchIncidentsPage({ page: 1, pageSize: MAX_STREAM_INCIDENTS, dataMode }),
      ]);
      setDevices(devs);
      setEvents(evRes.rows);
      setIncidents(incRes.rows);
    } catch (err) {
      setError(err.message || 'Unable to load live monitoring feed.');
    } finally {
      setLoading(false);
    }
  }, [dataMode]);

  useEffect(() => {
    loadInitial();
  }, [loadInitial]);

  // Periodically recompute 90s stale-heartbeat status in memory without DB polling
  useEffect(() => {
    const timer = setInterval(() => setNowMs(Date.now()), 15000);
    return () => clearInterval(timer);
  }, []);

  const matchesDataMode = useCallback(
    (row) => {
      if (dataMode === 'live') return !row.is_simulated;
      if (dataMode === 'simulated') return Boolean(row.is_simulated);
      return true;
    },
    [dataMode],
  );

  const { connectionState, lastMessageAt } = useRealtimeFeed({
    enabled: true,
    channelName: 'live-monitoring-page',
    onEventInsert: (newEv) => {
      if (streamPaused || !matchesDataMode(newEv)) return;
      setEvents((prev) => {
        if (prev.some((e) => e.id === newEv.id)) return prev;
        return [newEv, ...prev].slice(0, MAX_STREAM_EVENTS);
      });
    },
    onIncidentChange: (payload) => {
      if (streamPaused) return;
      if (payload.eventType === 'DELETE' && payload.old?.id) {
        setIncidents((prev) => prev.filter((inc) => inc.id !== payload.old.id));
        return;
      }
      const row = payload.new;
      if (!row || !matchesDataMode(row)) return;
      setIncidents((prev) => {
        const exists = prev.some((inc) => inc.id === row.id);
        if (exists) {
          return prev.map((inc) => (inc.id === row.id ? { ...inc, ...row } : inc));
        }
        return [row, ...prev].slice(0, MAX_STREAM_INCIDENTS);
      });
    },
    onDeviceChange: (payload) => {
      if (payload.eventType === 'DELETE' && payload.old?.id) {
        setDevices((prev) => prev.filter((d) => d.id !== payload.old.id));
        return;
      }
      const row = payload.new;
      if (!row) return;
      setDevices((prev) => {
        const exists = prev.some((d) => d.id === row.id);
        if (exists) {
          return prev.map((d) => (d.id === row.id ? { ...d, ...row } : d));
        }
        return [row, ...prev];
      });
    },
    onReconnectSync: loadInitial,
  });

  const deviceNameById = new Map(devices.map((d) => [d.id, d.device_name]));

  const rtBadgeStatus =
    connectionState === 'connected'
      ? 'online'
      : connectionState === 'reconnecting' || connectionState === 'connecting'
        ? 'investigating'
        : 'offline';

  return (
    <div>
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Live Monitoring</h1>
          <p className="soc-page-subtitle">
            Real-time Supabase WebSocket stream for collector health, authentication events, and rule alerts.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
          <StatusBadge
            status={rtBadgeStatus}
            label={`Realtime: ${connectionState.toUpperCase()}`}
            showDot
          />
          <div className="segmented-control" role="group" aria-label="Live stream scope">
            {[
              { id: 'all', label: 'All' },
              { id: 'live', label: 'Live Only' },
              { id: 'simulated', label: 'Simulated' },
            ].map((opt) => (
              <button
                key={opt.id}
                type="button"
                className={`segmented-btn ${dataMode === opt.id ? 'active' : ''}`}
                onClick={() => setDataMode(opt.id)}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => setStreamPaused((p) => !p)}
          >
            {streamPaused ? 'Resume Stream' : 'Pause Stream'}
          </button>
          <button type="button" className="btn btn-secondary btn-sm" onClick={loadInitial}>
            Sync Now
          </button>
        </div>
      </header>

      <ErrorBanner message={error} onRetry={loadInitial} />

      <section style={{ marginBottom: '1.15rem' }} aria-label="Collector health">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <h2 className="chart-card-title">Monitored Collectors &amp; Heartbeat Health</h2>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Offline threshold: 90s without heartbeat · Last push:{' '}
            {lastMessageAt ? formatRelativeTime(lastMessageAt) : 'Waiting'}
          </span>
        </div>

        {loading && devices.length === 0 ? (
          <LoadingState message="Checking collector health..." />
        ) : devices.length === 0 ? (
          <EmptyState
            title="No monitored collectors registered"
            description="Register a Linux machine in Settings to receive live heartbeats and events."
            action={
              <Link to="/settings" className="btn btn-primary btn-sm">
                Register Collector →
              </Link>
            }
          />
        ) : (
          <div className="kpi-grid" style={{ marginBottom: 0 }}>
            {devices.map((dev) => {
              const effStatus = computeEffectiveStatus(dev, nowMs);
              return (
                <div key={dev.id} className="kpi-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
                    <strong style={{ fontSize: '0.92rem' }}>
                      {sanitizeDisplayText(dev.device_name)}
                    </strong>
                    <StatusBadge status={effStatus} showDot />
                  </div>
                  <div className="mono" style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                    {sanitizeDisplayText(dev.host_identifier)}
                    {dev.collector_version ? ` · v${dev.collector_version}` : ''}
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                    Heartbeat: {formatRelativeTime(dev.last_heartbeat)}
                    <br />
                    Last event: {formatRelativeTime(dev.last_event_at)}
                    <br />
                    Events received: <strong>{dev.events_received_count ?? 0}</strong>
                  </div>
                  {dev.is_simulated ? (
                    <span className="soc-badge badge-amber" style={{ alignSelf: 'flex-start', marginTop: '0.2rem' }}>
                      SIMULATED DEVICE
                    </span>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </section>

      <section className="split-grid" aria-label="Live event and alert streams">
        <div className="table-card">
          <div
            style={{
              padding: '0.85rem 1rem',
              borderBottom: '1px solid var(--border-subtle)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <h2 className="chart-card-title">Live Event Feed (Latest {MAX_STREAM_EVENTS})</h2>
            <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              {streamPaused ? 'Paused' : 'Streaming'}
            </span>
          </div>

          {events.length === 0 ? (
            <div style={{ padding: '1rem' }}>
              <EmptyState
                title="Waiting for live authentication events"
                description="Events emitted by the Python collector or simulations will appear here immediately without refreshing."
              />
            </div>
          ) : (
            <div className="table-scroll" style={{ maxHeight: 440, overflowY: 'auto' }}>
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Source IP</th>
                    <th>User</th>
                    <th>Type</th>
                    <th>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev) => (
                    <tr key={ev.id}>
                      <td style={{ whiteSpace: 'nowrap', fontSize: '0.78rem' }}>
                        {formatTimestamp(ev.event_timestamp)}
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          {sanitizeDisplayText(
                            ev.monitored_devices?.device_name || deviceNameById.get(ev.device_id),
                            'Host',
                          )}
                          {ev.is_simulated ? ' · SIM' : ''}
                        </div>
                      </td>
                      <td className="mono">{formatIpAddress(ev.source_ip)}</td>
                      <td className="mono">{sanitizeDisplayText(ev.username)}</td>
                      <td className="mono" style={{ fontSize: '0.78rem' }}>
                        {sanitizeDisplayText(ev.event_type)}
                      </td>
                      <td>
                        <StatusBadge status={ev.auth_result} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="table-card">
          <div
            style={{
              padding: '0.85rem 1rem',
              borderBottom: '1px solid var(--border-subtle)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <h2 className="chart-card-title">Live Security Alerts</h2>
            <Link to="/incidents" style={{ fontSize: '0.8rem', color: '#60a5fa' }}>
              Investigate →
            </Link>
          </div>

          {incidents.length === 0 ? (
            <div style={{ padding: '1rem' }}>
              <EmptyState
                title="No live alerts yet"
                description="Triggered rule incidents stream here automatically as attacks are detected."
              />
            </div>
          ) : (
            <div className="table-scroll" style={{ maxHeight: 440, overflowY: 'auto' }}>
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Alert</th>
                    <th>Source IP</th>
                    <th>Severity</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((inc) => (
                    <tr key={inc.id}>
                      <td>
                        <div style={{ fontWeight: 600 }}>
                          {sanitizeDisplayText(inc.incident_title)}
                        </div>
                        <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                          <span className="mono">{inc.rule_id}</span> · Score {inc.risk_score}/100
                          {' · '}
                          {inc.event_count} events
                          {inc.is_simulated ? ' · SIMULATED' : ''}
                        </div>
                      </td>
                      <td className="mono">{formatIpAddress(inc.source_ip)}</td>
                      <td>
                        <SeverityBadge severity={inc.severity} />
                      </td>
                      <td>
                        <StatusBadge status={inc.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
