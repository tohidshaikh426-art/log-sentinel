import { useCallback, useEffect, useState } from 'react';
import {
  EmptyState,
  ErrorBanner,
  LoadingState,
  SeverityBadge,
  StatusBadge,
} from '../components/UiPrimitives';
import { useRealtimeFeed } from '../hooks/useRealtime';
import { useToast } from '../hooks/useToast';
import {
  fetchIncidentLinkedEvents,
  fetchIncidentsPage,
  updateIncidentTriage,
} from '../services/operationsService';
import {
  formatIpAddress,
  formatTimestamp,
  sanitizeDisplayText,
} from '../utils/formatters';

const PAGE_SIZE = 20;

export default function IncidentsPage() {
  const { showToast } = useToast();

  const [searchInput, setSearchInput] = useState('');
  const [appliedSearch, setAppliedSearch] = useState('');
  const [severity, setSeverity] = useState('all');
  const [status, setStatus] = useState('all');
  const [dataMode, setDataMode] = useState('all');
  const [page, setPage] = useState(1);

  const [incidents, setIncidents] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [activeIncident, setActiveIncident] = useState(null);
  const [linkedEvents, setLinkedEvents] = useState([]);
  const [loadingLinked, setLoadingLinked] = useState(false);
  const [triageStatus, setTriageStatus] = useState('open');
  const [triageNotes, setTriageNotes] = useState('');
  const [savingTriage, setSavingTriage] = useState(false);

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetchIncidentsPage({
        page,
        pageSize: PAGE_SIZE,
        search: appliedSearch,
        severity,
        status,
        dataMode,
      });
      setIncidents(res.rows);
      setTotalCount(res.totalCount);
    } catch (err) {
      setError(err.message || 'Unable to load security incidents.');
    } finally {
      setLoading(false);
    }
  }, [page, appliedSearch, severity, status, dataMode]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  useRealtimeFeed({
    enabled: true,
    channelName: 'incidents-page-live',
    onIncidentChange: (payload) => {
      if (payload.eventType === 'DELETE' && payload.old?.id) {
        setIncidents((prev) => prev.filter((r) => r.id !== payload.old.id));
        if (activeIncident?.id === payload.old.id) setActiveIncident(null);
        return;
      }
      const row = payload.new;
      if (!row) return;
      if (dataMode === 'live' && row.is_simulated) return;
      if (dataMode === 'simulated' && !row.is_simulated) return;
      if (severity !== 'all' && row.severity !== severity) return;
      if (status !== 'all' && row.status !== status) return;

      if (activeIncident?.id === row.id) {
        setActiveIncident((prev) => (prev ? { ...prev, ...row } : prev));
      }

      setIncidents((prev) => {
        const exists = prev.some((r) => r.id === row.id);
        if (exists) {
          return prev.map((r) => (r.id === row.id ? { ...r, ...row } : r));
        }
        if (page === 1 && !appliedSearch) {
          setTotalCount((c) => c + 1);
          return [row, ...prev].slice(0, PAGE_SIZE);
        }
        return prev;
      });
    },
    onReconnectSync: loadIncidents,
  });

  useEffect(() => {
    if (!activeIncident) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape' && !savingTriage) setActiveIncident(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [activeIncident, savingTriage]);

  async function openInvestigation(inc) {
    setActiveIncident(inc);
    setTriageStatus(inc.status || 'open');
    setTriageNotes(inc.investigation_notes || '');
    setLinkedEvents([]);
    setLoadingLinked(true);
    try {
      const rows = await fetchIncidentLinkedEvents(inc.id);
      setLinkedEvents(rows);
    } catch {
      setLinkedEvents([]);
    } finally {
      setLoadingLinked(false);
    }
  }

  async function handleSaveTriage(e) {
    e.preventDefault();
    if (!activeIncident) return;
    setSavingTriage(true);
    try {
      const updated = await updateIncidentTriage(activeIncident.id, {
        status: triageStatus,
        investigationNotes: triageNotes,
      });
      setActiveIncident(updated);
      setIncidents((prev) => prev.map((row) => (row.id === updated.id ? updated : row)));
      showToast(`Incident marked as ${updated.status}.`, 'success');
    } catch (err) {
      showToast(err.message || 'Failed to update incident.', 'error');
    } finally {
      setSavingTriage(false);
    }
  }

  function handleSearchSubmit(e) {
    e.preventDefault();
    setPage(1);
    setAppliedSearch(searchInput.trim());
  }

  function handleResetFilters() {
    setSearchInput('');
    setAppliedSearch('');
    setSeverity('all');
    setStatus('all');
    setDataMode('all');
    setPage(1);
  }

  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
  const breakdown = activeIncident?.evidence?.score_breakdown || null;
  const sampleUsers = Array.isArray(activeIncident?.evidence?.sample_usernames)
    ? activeIncident.evidence.sample_usernames
    : [];

  return (
    <div>
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Security Incidents</h1>
          <p className="soc-page-subtitle">
            Investigate rule-based threat detections, inspect risk score breakdowns, and track triage status.
          </p>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={loadIncidents}>
          Refresh
        </button>
      </header>

      <form className="filter-bar" onSubmit={handleSearchSubmit}>
        <input
          type="search"
          className="filter-input"
          aria-label="Search incidents by title, rule ID, username, or exact IP"
          placeholder="Search title, RULE_001, username, or exact IP..."
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
        />

        <select
          className="filter-select"
          aria-label="Filter by severity"
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <select
          className="filter-select"
          aria-label="Filter by incident status"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
        >
          <option value="all">All Statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
        </select>

        <select
          className="filter-select"
          aria-label="Filter by data mode"
          value={dataMode}
          onChange={(e) => {
            setDataMode(e.target.value);
            setPage(1);
          }}
        >
          <option value="all">All Data</option>
          <option value="live">Live Only</option>
          <option value="simulated">Simulated Only</option>
        </select>

        <button type="submit" className="btn btn-primary btn-sm">
          Search
        </button>
        <button type="button" className="btn btn-secondary btn-sm" onClick={handleResetFilters}>
          Reset
        </button>
      </form>

      <ErrorBanner message={error} onRetry={loadIncidents} />

      {loading ? (
        <LoadingState message="Loading security incidents..." />
      ) : incidents.length === 0 ? (
        <EmptyState
          title="No security incidents found"
          description="No incidents matched your filters. Rule alerts appear automatically when suspicious authentication patterns are detected."
        />
      ) : (
        <div className="table-card">
          <div className="table-scroll">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Incident</th>
                  <th>Source IP</th>
                  <th>User</th>
                  <th>Severity</th>
                  <th>Risk Score</th>
                  <th>Events</th>
                  <th>Status</th>
                  <th>Last Observed</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => (
                  <tr key={inc.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>
                        {sanitizeDisplayText(inc.incident_title)}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        <span className="mono">{inc.rule_id}</span> ·{' '}
                        {sanitizeDisplayText(inc.monitored_devices?.device_name, 'Device')}
                        {inc.is_simulated ? ' · SIMULATED' : ''}
                      </div>
                    </td>
                    <td className="mono">{formatIpAddress(inc.source_ip)}</td>
                    <td className="mono">{sanitizeDisplayText(inc.username)}</td>
                    <td>
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="mono" style={{ fontWeight: 600 }}>
                      {inc.risk_score}/100
                    </td>
                    <td>{inc.event_count}</td>
                    <td>
                      <StatusBadge status={inc.status} />
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(inc.last_observed)}</td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() => openInvestigation(inc)}
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination-bar">
            <span>
              Page <strong>{page}</strong> of <strong>{totalPages}</strong> ({totalCount} total
              incidents)
            </span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}

      {activeIncident ? (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="incident-detail-title"
          onClick={() => {
            if (!savingTriage) setActiveIncident(null);
          }}
        >
          <div
            className="modal-panel"
            style={{ maxWidth: 740, maxHeight: '90vh', overflowY: 'auto' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.75rem', alignItems: 'flex-start' }}>
              <div>
                <div style={{ display: 'flex', gap: '0.45rem', alignItems: 'center', marginBottom: '0.35rem' }}>
                  <span className="mono soc-badge badge-blue">{activeIncident.rule_id}</span>
                  <SeverityBadge severity={activeIncident.severity} />
                  <StatusBadge status={activeIncident.status} />
                  {activeIncident.is_simulated ? (
                    <span className="soc-badge badge-amber">SIMULATED</span>
                  ) : null}
                </div>
                <h2 id="incident-detail-title" style={{ fontSize: '1.1rem' }}>
                  {sanitizeDisplayText(activeIncident.incident_title)}
                </h2>
              </div>
              <span className="mono" style={{ fontSize: '1.15rem', fontWeight: 700 }}>
                {activeIncident.risk_score}/100
              </span>
            </div>

            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', margin: '0.65rem 0' }}>
              {sanitizeDisplayText(activeIncident.description)}
            </p>

            <div className="evidence-grid">
              <div className="evidence-chip">
                <div className="evidence-chip-label">Source IP</div>
                <div className="evidence-chip-value mono">
                  {formatIpAddress(activeIncident.source_ip)}
                </div>
              </div>
              <div className="evidence-chip">
                <div className="evidence-chip-label">Observed Events</div>
                <div className="evidence-chip-value">{activeIncident.event_count}</div>
              </div>
              <div className="evidence-chip">
                <div className="evidence-chip-label">First Observed</div>
                <div className="evidence-chip-value" style={{ fontSize: '0.82rem' }}>
                  {formatTimestamp(activeIncident.first_observed)}
                </div>
              </div>
              <div className="evidence-chip">
                <div className="evidence-chip-label">Last Observed</div>
                <div className="evidence-chip-value" style={{ fontSize: '0.82rem' }}>
                  {formatTimestamp(activeIncident.last_observed)}
                </div>
              </div>
            </div>

            {breakdown ? (
              <div style={{ marginTop: '0.85rem' }}>
                <strong style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                  Explainable Risk Score Breakdown
                </strong>
                <div className="evidence-grid">
                  <div className="evidence-chip">
                    <div className="evidence-chip-label">Failure Points</div>
                    <div className="evidence-chip-value">+{breakdown.failure_points ?? 0}</div>
                  </div>
                  <div className="evidence-chip">
                    <div className="evidence-chip-label">Target Spread</div>
                    <div className="evidence-chip-value">+{breakdown.target_spread_points ?? 0}</div>
                  </div>
                  <div className="evidence-chip">
                    <div className="evidence-chip-label">Success After Fail</div>
                    <div className="evidence-chip-value">
                      +{breakdown.success_after_failure_bonus ?? 0}
                    </div>
                  </div>
                  <div className="evidence-chip">
                    <div className="evidence-chip-label">Velocity / Repeat</div>
                    <div className="evidence-chip-value">
                      +{(breakdown.velocity_bonus ?? 0) + (breakdown.repeat_offender_bonus ?? 0)}
                    </div>
                  </div>
                </div>
                {sampleUsers.length > 0 ? (
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Targeted usernames:{' '}
                    <span className="mono">{sampleUsers.map((u) => sanitizeDisplayText(u)).join(', ')}</span>
                  </p>
                ) : null}
              </div>
            ) : null}

            <div style={{ marginTop: '0.95rem' }}>
              <strong style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                Supporting Authentication Events ({linkedEvents.length})
              </strong>
              {loadingLinked ? (
                <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
                  Loading linked events...
                </p>
              ) : linkedEvents.length === 0 ? (
                <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
                  No linked raw events recorded for this incident.
                </p>
              ) : (
                <div className="table-scroll" style={{ maxHeight: 180, overflowY: 'auto', marginTop: '0.4rem', border: '1px solid var(--border-subtle)', borderRadius: 6 }}>
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>User</th>
                        <th>Type</th>
                        <th>Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {linkedEvents.map((ev) => (
                        <tr key={ev.id}>
                          <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(ev.event_timestamp)}</td>
                          <td className="mono">{sanitizeDisplayText(ev.username)}</td>
                          <td className="mono">{sanitizeDisplayText(ev.event_type)}</td>
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

            <form onSubmit={handleSaveTriage} style={{ marginTop: '1rem', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.9rem' }}>
              <div className="form-group">
                <label className="form-label" htmlFor="triage-status">
                  Incident Status
                </label>
                <select
                  id="triage-status"
                  className="form-input"
                  value={triageStatus}
                  onChange={(e) => setTriageStatus(e.target.value)}
                  disabled={savingTriage}
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating (Reviewed)</option>
                  <option value="resolved">Resolved</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="triage-notes">
                  Investigation Notes
                </label>
                <textarea
                  id="triage-notes"
                  className="form-input"
                  rows={3}
                  maxLength={2000}
                  placeholder="Record triage findings, verified owner activity, or remediation notes..."
                  value={triageNotes}
                  onChange={(e) => setTriageNotes(e.target.value)}
                  disabled={savingTriage}
                />
              </div>

              <div className="modal-actions">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setActiveIncident(null)}
                  disabled={savingTriage}
                >
                  Close
                </button>
                <button type="submit" className="btn btn-primary" disabled={savingTriage}>
                  {savingTriage ? 'Saving...' : 'Save Triage'}
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : null}
    </div>
  );
}
