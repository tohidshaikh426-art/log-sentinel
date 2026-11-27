import { useCallback, useEffect, useState } from 'react';
import {
  EmptyState,
  ErrorBanner,
  LoadingState,
  SeverityBadge,
} from '../components/UiPrimitives';
import { useToast } from '../hooks/useToast';
import { fetchReportDataset } from '../services/operationsService';
import { formatIpAddress, formatTimestamp } from '../utils/formatters';
import { buildSecurityReportCsv, triggerCsvDownload } from '../utils/reportExport';

export default function ReportsPage() {
  const { showToast } = useToast();

  const [dataMode, setDataMode] = useState('all');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadReport = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await fetchReportDataset({ dataMode, dateFrom, dateTo });
      setReport(data);
    } catch (err) {
      setError(err.message || 'Unable to generate security report.');
    } finally {
      setLoading(false);
    }
  }, [dataMode, dateFrom, dateTo]);

  useEffect(() => {
    loadReport();
  }, [loadReport]);

  function handleDownloadCsv() {
    if (!report) return;
    const csv = buildSecurityReportCsv(report);
    const stamp = new Date().toISOString().slice(0, 10);
    triggerCsvDownload(csv, `log-sentinel-report-${dataMode}-${stamp}.csv`);
    showToast('CSV security report downloaded.', 'success');
  }

  function handlePrintPdf() {
    window.print();
  }

  return (
    <div>
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Security Reports</h1>
          <p className="soc-page-subtitle">
            Export CSV audit summaries or print clean PDF reports directly from verified database records.
          </p>
        </div>

        <div className="no-print" style={{ display: 'flex', gap: '0.55rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={handleDownloadCsv}
            disabled={!report || loading}
          >
            Download CSV Report
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={handlePrintPdf}
            disabled={!report || loading}
          >
            Print / Save PDF
          </button>
        </div>
      </header>

      <div className="filter-bar no-print">
        <select
          className="filter-select"
          aria-label="Report dataset scope"
          value={dataMode}
          onChange={(e) => setDataMode(e.target.value)}
        >
          <option value="all">All Data (Live + Simulated)</option>
          <option value="live">Live Monitoring Only</option>
          <option value="simulated">Simulated Demo Only</option>
        </select>

        <label style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
          From:{' '}
          <input
            type="date"
            className="filter-select"
            value={dateFrom}
            onChange={(e) => setDateFrom(e.target.value)}
          />
        </label>

        <label style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
          To:{' '}
          <input
            type="date"
            className="filter-select"
            value={dateTo}
            onChange={(e) => setDateTo(e.target.value)}
          />
        </label>

        <button type="button" className="btn btn-secondary btn-sm" onClick={loadReport}>
          Refresh Summary
        </button>
      </div>

      <ErrorBanner message={error} onRetry={loadReport} />

      {loading && !report ? (
        <LoadingState message="Compiling security report..." />
      ) : report ? (
        <>
          <div className="soc-card" style={{ marginBottom: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.75rem' }}>
              <strong>Executive Summary</strong>
              <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                Generated: {formatTimestamp(report.generatedAt)} · Scope: {report.dataMode}
              </span>
            </div>

            <div className="kpi-grid" style={{ marginBottom: 0 }}>
              <div className="kpi-card">
                <span className="kpi-label">Total Events</span>
                <span className="kpi-value accent-blue">{report.totals.totalEvents}</span>
              </div>
              <div className="kpi-card">
                <span className="kpi-label">Successful Logins</span>
                <span className="kpi-value accent-green">{report.totals.successfulLogins}</span>
              </div>
              <div className="kpi-card">
                <span className="kpi-label">Failed Logins</span>
                <span className="kpi-value accent-amber">{report.totals.failedLogins}</span>
              </div>
              <div className="kpi-card">
                <span className="kpi-label">Detected Incidents</span>
                <span className="kpi-value accent-red">{report.totals.detectedIncidents}</span>
              </div>
            </div>
          </div>

          <div className="split-grid" style={{ marginBottom: '1rem' }}>
            <div className="table-card">
              <div style={{ padding: '0.85rem 1rem', borderBottom: '1px solid var(--border-subtle)' }}>
                <h2 className="chart-card-title">Severity Summary</h2>
              </div>
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Incident Count</th>
                  </tr>
                </thead>
                <tbody>
                  {['critical', 'high', 'medium', 'low'].map((sev) => (
                    <tr key={sev}>
                      <td>
                        <SeverityBadge severity={sev} />
                      </td>
                      <td className="mono">{report.severitySummary[sev]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="table-card">
              <div style={{ padding: '0.85rem 1rem', borderBottom: '1px solid var(--border-subtle)' }}>
                <h2 className="chart-card-title">Detection Rule Summary</h2>
              </div>
              {report.ruleSummary.length === 0 ? (
                <div style={{ padding: '1rem' }}>
                  <EmptyState
                    title="No rule triggers"
                    description="Triggered detection rules will summarize here."
                  />
                </div>
              ) : (
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Rule ID</th>
                      <th>Incidents</th>
                      <th>Max Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.ruleSummary.map((r) => (
                      <tr key={r.rule_id}>
                        <td className="mono">{r.rule_id}</td>
                        <td>{r.count}</td>
                        <td className="mono">{r.max_score}/100</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <div className="table-card">
            <div style={{ padding: '0.85rem 1rem', borderBottom: '1px solid var(--border-subtle)' }}>
              <h2 className="chart-card-title">Suspicious IP Summary (Top 50)</h2>
            </div>
            {report.suspiciousIps.length === 0 ? (
              <div style={{ padding: '1rem' }}>
                <EmptyState
                  title="No IP records in selected scope"
                  description="Source IP statistics appear once events are available."
                />
              </div>
            ) : (
              <div className="table-scroll">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Source IP</th>
                      <th>Total Events</th>
                      <th>Failed</th>
                      <th>Success</th>
                      <th>Incidents</th>
                      <th>Max Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.suspiciousIps.map((ip) => (
                      <tr key={String(ip.source_ip)}>
                        <td className="mono">{formatIpAddress(ip.source_ip)}</td>
                        <td>{ip.total_events}</td>
                        <td>{ip.failed_attempts}</td>
                        <td>{ip.successful_logins}</td>
                        <td>{ip.incident_count}</td>
                        <td className="mono">{ip.max_risk_score}/100</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      ) : null}
    </div>
  );
}
