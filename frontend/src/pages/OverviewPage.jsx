import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { OverviewCharts } from '../components/OverviewCharts';
import {
  EmptyState,
  ErrorBanner,
  LoadingState,
  SeverityBadge,
  StatusBadge,
} from '../components/UiPrimitives';
import { useRealtimeFeed } from '../hooks/useRealtime';
import { fetchOverviewMetrics } from '../services/dashboardService';
import {
  formatIpAddress,
  formatRelativeTime,
  formatTimestamp,
  sanitizeDisplayText,
  scoreToSeverity,
} from '../utils/formatters';

export default function OverviewPage() {
  const [dataMode, setDataMode] = useState('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [overview, setOverview] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const result = await fetchOverviewMetrics({ dataMode });
      setOverview(result);
    } catch (err) {
      setError(err.message || 'Unable to load dashboard overview.');
    } finally {
      setLoading(false);
    }
  }, [dataMode]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const matchesMode = useCallback(
    (row) => {
      if (dataMode === 'live') return !row.is_simulated;
      if (dataMode === 'simulated') return Boolean(row.is_simulated);
      return true;
    },
    [dataMode],
  );

  useRealtimeFeed({
    enabled: true,
    channelName: 'overview-live',
    onEventInsert: (newEv) => {
      if (!matchesMode(newEv)) return;
      setOverview((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          kpis: {
            ...prev.kpis,
            totalEvents: prev.kpis.totalEvents + 1,
            successfulLogins:
              prev.kpis.successfulLogins + (newEv.auth_result === 'success' ? 1 : 0),
            failedLogins:
              prev.kpis.failedLogins + (newEv.auth_result === 'failure' ? 1 : 0),
            lastEventAt: newEv.event_timestamp || prev.kpis.lastEventAt,
          },
          timelineEvents: [
            ...prev.timelineEvents,
            { event_timestamp: newEv.event_timestamp, auth_result: newEv.auth_result },
          ].slice(-500),
        };
      });
    },
    onIncidentChange: (payload) => {
      if (payload.eventType === 'DELETE') {
        loadData();
        return;
      }
      const row = payload.new;
      if (!row || !matchesMode(row)) return;
      loadData();
    },
    onDeviceChange: () => {
      loadData();
    },
    onReconnectSync: loadData,
  });

  return (
    <div>
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Security Overview</h1>
          <p className="soc-page-subtitle">
            Real database telemetry across authentication events, rule detections, and monitored hosts.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
          <div className="segmented-control" role="group" aria-label="Dataset scope filter">
            {[
              { id: 'all', label: 'All Data' },
              { id: 'live', label: 'Live Only' },
              { id: 'simulated', label: 'Simulated Only' },
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
          <button type="button" className="btn btn-secondary btn-sm" onClick={loadData}>
            Refresh
          </button>
        </div>
      </header>

      <ErrorBanner message={error} onRetry={loadData} />

      {loading && !overview ? (
        <LoadingState message="Loading security overview..." />
      ) : overview ? (
        <>
          <section className="kpi-grid" aria-label="Key security metrics">
            <div className="kpi-card">
              <span className="kpi-label">Total Events</span>
              <span className="kpi-value accent-blue">{overview.kpis.totalEvents}</span>
              <span className="kpi-meta">
                Last event: {formatRelativeTime(overview.kpis.lastEventAt)}
              </span>
            </div>

            <div className="kpi-card">
              <span className="kpi-label">Successful Logins</span>
              <span className="kpi-value accent-green">{overview.kpis.successfulLogins}</span>
              <span className="kpi-meta">Authorized authentications</span>
            </div>

            <div className="kpi-card">
              <span className="kpi-label">Failed Logins</span>
              <span className="kpi-value accent-amber">{overview.kpis.failedLogins}</span>
              <span className="kpi-meta">Rejected or invalid attempts</span>
            </div>

            <div className="kpi-card">
              <span className="kpi-label">Total Incidents</span>
              <span className="kpi-value">{overview.kpis.totalIncidents}</span>
              <span className="kpi-meta">Deduplicated rule detections</span>
            </div>

            <div className="kpi-card">
              <span className="kpi-label">Critical / High Alerts</span>
              <span className="kpi-value accent-red">
                {overview.kpis.criticalIncidents + overview.kpis.highIncidents}
              </span>
              <span className="kpi-meta">
                {overview.kpis.criticalIncidents} critical · {overview.kpis.highIncidents} high
              </span>
            </div>

            <div className="kpi-card">
              <span className="kpi-label">Monitored Devices</span>
              <span className="kpi-value">
                {overview.kpis.onlineDevices} / {overview.kpis.monitoredDevices}
              </span>
              <span className="kpi-meta">Online within 90s heartbeat</span>
            </div>
          </section>

          <OverviewCharts
            timelineEvents={overview.timelineEvents}
            kpis={overview.kpis}
            severityCounts={overview.severityCounts}
            topSuspiciousIps={overview.topSuspiciousIps}
          />

          <section className="split-grid" aria-label="Recent incidents and suspicious IPs">
            <div className="table-card">
              <div
                style={{
                  padding: '0.9rem 1rem',
                  borderBottom: '1px solid var(--border-subtle)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <h2 className="chart-card-title">Recent Incidents</h2>
                <Link to="/incidents" style={{ fontSize: '0.8rem', color: '#60a5fa' }}>
                  View all →
                </Link>
              </div>
              {overview.recentIncidents.length === 0 ? (
                <div style={{ padding: '1rem' }}>
                  <EmptyState
                    title="No security incidents yet"
                    description="Rule detections will appear here when suspicious patterns occur."
                  />
                </div>
              ) : (
                <div className="table-scroll">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Incident</th>
                        <th>Source IP</th>
                        <th>Severity</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {overview.recentIncidents.map((inc) => (
                        <tr key={inc.id}>
                          <td>
                            <div style={{ fontWeight: 600 }}>
                              {sanitizeDisplayText(inc.incident_title)}
                            </div>
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                              <span className="mono">{inc.rule_id}</span> ·{' '}
                              {formatTimestamp(inc.last_observed)}
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

            <div className="table-card">
              <div
                style={{
                  padding: '0.9rem 1rem',
                  borderBottom: '1px solid var(--border-subtle)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <h2 className="chart-card-title">Top Suspicious IPs</h2>
                <Link to="/ip-analysis" style={{ fontSize: '0.8rem', color: '#60a5fa' }}>
                  Full IP analysis →
                </Link>
              </div>
              {overview.topSuspiciousIps.length === 0 ? (
                <div style={{ padding: '1rem' }}>
                  <EmptyState
                    title="No IP activity recorded"
                    description="Source IP statistics appear once authentication events are ingested."
                  />
                </div>
              ) : (
                <div className="table-scroll">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Source IP</th>
                        <th>Failures</th>
                        <th>Incidents</th>
                        <th>Max Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {overview.topSuspiciousIps.map((row) => (
                        <tr key={String(row.source_ip)}>
                          <td className="mono">
                            <Link
                              to={`/events?ip=${encodeURIComponent(formatIpAddress(row.source_ip))}`}
                              style={{ color: '#93c5fd' }}
                            >
                              {formatIpAddress(row.source_ip)}
                            </Link>
                          </td>
                          <td>{row.failed_attempts}</td>
                          <td>{row.incident_count}</td>
                          <td>
                            <SeverityBadge severity={scoreToSeverity(row.max_risk_score)} />{' '}
                            <span className="mono" style={{ fontSize: '0.78rem' }}>
                              {row.max_risk_score}/100
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}
