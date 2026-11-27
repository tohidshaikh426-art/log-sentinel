import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  EmptyState,
  ErrorBanner,
  LoadingState,
  StatusBadge,
} from '../components/UiPrimitives';
import { fetchDevicesList, fetchEventsPage } from '../services/dashboardService';
import {
  formatIpAddress,
  formatTimestamp,
  sanitizeDisplayText,
} from '../utils/formatters';

const PAGE_SIZE = 25;

export default function EventsPage() {
  const [searchParams] = useSearchParams();
  const initialIp = searchParams.get('ip') || '';

  const [searchInput, setSearchInput] = useState(initialIp);
  const [appliedSearch, setAppliedSearch] = useState(initialIp);
  const [authResult, setAuthResult] = useState('all');
  const [deviceId, setDeviceId] = useState('all');
  const [dataMode, setDataMode] = useState('all');
  const [page, setPage] = useState(1);

  const [devices, setDevices] = useState([]);
  const [events, setEvents] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedEvent, setSelectedEvent] = useState(null);

  useEffect(() => {
    fetchDevicesList()
      .then(setDevices)
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedEvent) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape') setSelectedEvent(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selectedEvent]);

  const loadEvents = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetchEventsPage({
        page,
        pageSize: PAGE_SIZE,
        search: appliedSearch,
        authResult,
        deviceId,
        dataMode,
      });
      setEvents(res.rows);
      setTotalCount(res.totalCount);
    } catch (err) {
      setError(err.message || 'Unable to load authentication events.');
    } finally {
      setLoading(false);
    }
  }, [page, appliedSearch, authResult, deviceId, dataMode]);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  function handleSearchSubmit(e) {
    e.preventDefault();
    setPage(1);
    setAppliedSearch(searchInput.trim());
  }

  function handleClearFilters() {
    setSearchInput('');
    setAppliedSearch('');
    setAuthResult('all');
    setDeviceId('all');
    setDataMode('all');
    setPage(1);
  }

  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  return (
    <div>
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Authentication Events</h1>
          <p className="soc-page-subtitle">
            Bounded, paginated authentication telemetry from monitored devices and log uploads.
          </p>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={loadEvents}>
          Refresh
        </button>
      </header>

      <form className="filter-bar" onSubmit={handleSearchSubmit}>
        <input
          type="search"
          className="filter-input"
          aria-label="Search events by username, exact IP, event type, or raw text"
          placeholder="Search username, exact IP, or event type..."
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
        />

        <select
          className="filter-select"
          aria-label="Filter by authentication result"
          value={authResult}
          onChange={(e) => {
            setAuthResult(e.target.value);
            setPage(1);
          }}
        >
          <option value="all">All Results</option>
          <option value="success">Success</option>
          <option value="failure">Failure</option>
          <option value="unknown">Unknown</option>
        </select>

        <select
          className="filter-select"
          aria-label="Filter by monitored device"
          value={deviceId}
          onChange={(e) => {
            setDeviceId(e.target.value);
            setPage(1);
          }}
        >
          <option value="all">All Devices</option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>
              {d.device_name}
            </option>
          ))}
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
        <button type="button" className="btn btn-secondary btn-sm" onClick={handleClearFilters}>
          Reset
        </button>
      </form>

      <ErrorBanner message={error} onRetry={loadEvents} />

      {loading ? (
        <LoadingState message="Querying authentication events..." />
      ) : events.length === 0 ? (
        <EmptyState
          title="No matching authentication events"
          description="Try clearing filters, running the Python collector, or simulating activity in Demo Mode."
        />
      ) : (
        <div className="table-card">
          <div className="table-scroll">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Event Time</th>
                  <th>Device</th>
                  <th>Source IP</th>
                  <th>Username</th>
                  <th>Event Type</th>
                  <th>Method</th>
                  <th>Result</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.id}>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(ev.event_timestamp)}</td>
                    <td>
                      <div>{sanitizeDisplayText(ev.monitored_devices?.device_name, 'Unknown')}</div>
                      {ev.is_simulated ? (
                        <span className="soc-badge badge-amber" style={{ marginTop: 2 }}>
                          SIMULATED
                        </span>
                      ) : null}
                    </td>
                    <td className="mono">{formatIpAddress(ev.source_ip)}</td>
                    <td className="mono">{sanitizeDisplayText(ev.username)}</td>
                    <td className="mono">{sanitizeDisplayText(ev.event_type)}</td>
                    <td>{sanitizeDisplayText(ev.auth_method)}</td>
                    <td>
                      <StatusBadge status={ev.auth_result} />
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() => setSelectedEvent(ev)}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination-bar">
            <span>
              Showing page <strong>{page}</strong> of <strong>{totalPages}</strong> ({totalCount}{' '}
              total events)
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

      {selectedEvent ? (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="event-inspect-title"
          onClick={() => setSelectedEvent(null)}
        >
          <div className="modal-panel" style={{ maxWidth: 620 }} onClick={(e) => e.stopPropagation()}>
            <h2 id="event-inspect-title" style={{ fontSize: '1.05rem', marginBottom: '0.75rem' }}>
              Event Inspection
            </h2>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.84rem' }}>
              <div>
                <strong>Timestamp:</strong> {formatTimestamp(selectedEvent.event_timestamp)}
              </div>
              <div>
                <strong>Result:</strong> <StatusBadge status={selectedEvent.auth_result} />
              </div>
              <div>
                <strong>Source IP:</strong>{' '}
                <span className="mono">{formatIpAddress(selectedEvent.source_ip)}</span>
              </div>
              <div>
                <strong>Username:</strong>{' '}
                <span className="mono">{sanitizeDisplayText(selectedEvent.username)}</span>
              </div>
              <div>
                <strong>Event Type:</strong>{' '}
                <span className="mono">{sanitizeDisplayText(selectedEvent.event_type)}</span>
              </div>
              <div>
                <strong>Service / Method:</strong>{' '}
                {sanitizeDisplayText(selectedEvent.service)} /{' '}
                {sanitizeDisplayText(selectedEvent.auth_method)}
              </div>
            </div>
            <div style={{ marginTop: '0.9rem' }}>
              <strong style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                Sanitized Raw Log (Plain Text)
              </strong>
              <pre className="raw-log-box">{sanitizeDisplayText(selectedEvent.raw_event)}</pre>
            </div>
            <div className="modal-actions">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setSelectedEvent(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
