import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  EmptyState,
  ErrorBanner,
  LoadingState,
  SeverityBadge,
} from '../components/UiPrimitives';
import { fetchIpSummary } from '../services/dashboardService';
import {
  formatIpAddress,
  formatTimestamp,
  scoreToSeverity,
} from '../utils/formatters';

export default function IpAnalysisPage() {
  const [includeSimulated, setIncludeSimulated] = useState(true);
  const [ipFilter, setIpFilter] = useState('');
  const [sortBy, setSortBy] = useState('risk');
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadIps = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await fetchIpSummary({ includeSimulated, limit: 150 });
      setRows(data);
    } catch (err) {
      setError(err.message || 'Unable to load IP threat summary.');
    } finally {
      setLoading(false);
    }
  }, [includeSimulated]);

  useEffect(() => {
    loadIps();
  }, [loadIps]);

  const visibleRows = useMemo(() => {
    const q = ipFilter.trim().toLowerCase();
    const filtered = q
      ? rows.filter((r) => formatIpAddress(r.source_ip).toLowerCase().includes(q))
      : [...rows];

    filtered.sort((a, b) => {
      if (sortBy === 'failures') return (b.failed_attempts || 0) - (a.failed_attempts || 0);
      if (sortBy === 'total') return (b.total_events || 0) - (a.total_events || 0);
      if (sortBy === 'recent') {
        return Date.parse(b.last_observed || 0) - Date.parse(a.last_observed || 0);
      }
      const riskDiff = (b.max_risk_score || 0) - (a.max_risk_score || 0);
      return riskDiff !== 0
        ? riskDiff
        : (b.failed_attempts || 0) - (a.failed_attempts || 0);
    });
    return filtered;
  }, [rows, ipFilter, sortBy]);

  return (
    <div>
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">IP Threat Analysis</h1>
          <p className="soc-page-subtitle">
            Server-side aggregated authentication counts and risk scores per source IP (no external paid IP APIs).
          </p>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={loadIps}>
          Refresh
        </button>
      </header>

      <div className="filter-bar">
        <input
          type="search"
          className="filter-input"
          aria-label="Filter by IP address"
          placeholder="Filter by IP address (e.g. 203.0.113)..."
          value={ipFilter}
          onChange={(e) => setIpFilter(e.target.value)}
        />

        <select
          className="filter-select"
          aria-label="Sort IP summary"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
        >
          <option value="risk">Sort by Max Risk Score</option>
          <option value="failures">Sort by Failed Attempts</option>
          <option value="total">Sort by Total Events</option>
          <option value="recent">Sort by Most Recent</option>
        </select>

        <div className="segmented-control" role="group" aria-label="Include simulated events">
          <button
            type="button"
            className={`segmented-btn ${includeSimulated ? 'active' : ''}`}
            onClick={() => setIncludeSimulated(true)}
          >
            All Data
          </button>
          <button
            type="button"
            className={`segmented-btn ${!includeSimulated ? 'active' : ''}`}
            onClick={() => setIncludeSimulated(false)}
          >
            Live Only
          </button>
        </div>
      </div>

      <ErrorBanner message={error} onRetry={loadIps} />

      {loading ? (
        <LoadingState message="Aggregating IP statistics..." />
      ) : visibleRows.length === 0 ? (
        <EmptyState
          title="No source IPs to display"
          description="Source IP statistics are calculated automatically as authentication events arrive."
        />
      ) : (
        <div className="table-card">
          <div className="table-scroll">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Total Events</th>
                  <th>Failed</th>
                  <th>Success</th>
                  <th>Incidents</th>
                  <th>Risk Score</th>
                  <th>First Observed</th>
                  <th>Last Observed</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {visibleRows.map((row) => {
                  const ip = formatIpAddress(row.source_ip);
                  const score = row.max_risk_score || 0;
                  const sev = scoreToSeverity(score);
                  const barColor =
                    sev === 'critical'
                      ? '#ef4444'
                      : sev === 'high'
                        ? '#f97316'
                        : sev === 'medium'
                          ? '#f59e0b'
                          : '#22c55e';
                  return (
                    <tr key={ip}>
                      <td className="mono" style={{ fontWeight: 600 }}>
                        {ip}
                      </td>
                      <td>{row.total_events}</td>
                      <td style={{ color: row.failed_attempts > 0 ? '#f87171' : 'inherit' }}>
                        {row.failed_attempts}
                      </td>
                      <td style={{ color: row.successful_logins > 0 ? '#4ade80' : 'inherit' }}>
                        {row.successful_logins}
                      </td>
                      <td>{row.incident_count}</td>
                      <td>
                        <div className="risk-meter">
                          <div className="risk-track" aria-hidden="true">
                            <div
                              className="risk-fill"
                              style={{ width: `${Math.min(100, score)}%`, backgroundColor: barColor }}
                            />
                          </div>
                          <span className="mono" style={{ fontSize: '0.78rem' }}>
                            {score}
                          </span>
                          <SeverityBadge severity={sev} />
                        </div>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(row.first_observed)}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(row.last_observed)}</td>
                      <td>
                        <Link
                          to={`/events?ip=${encodeURIComponent(ip)}`}
                          className="btn btn-secondary btn-sm"
                        >
                          View Events
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
