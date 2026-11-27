import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  EmptyState,
  ErrorBanner,
  LoadingState,
  SeverityBadge,
} from '../components/UiPrimitives';
import { useToast } from '../hooks/useToast';
import {
  analyzeUploadedLogFile,
  fetchUploadHistory,
} from '../services/operationsService';
import { formatTimestamp, sanitizeDisplayText } from '../utils/formatters';

const ALLOWED_EXTENSIONS = ['.log', '.txt', '.csv'];
const MAX_FILE_BYTES = 1_800_000;

export default function LogAnalyzerPage() {
  const { showToast } = useToast();

  const [fileFormat, setFileFormat] = useState('auth_log');
  const [selectedFileName, setSelectedFileName] = useState('');
  const [fileContent, setFileContent] = useState('');
  const [dragActive, setDragActive] = useState(false);

  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  const [history, setHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(true);

  const loadHistory = useCallback(async () => {
    setLoadingHistory(true);
    try {
      const rows = await fetchUploadHistory(15);
      setHistory(rows);
    } catch {
      // Non-fatal; upload form remains usable
    } finally {
      setLoadingHistory(false);
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  function handleFileSelection(file) {
    setError('');
    setResult(null);
    if (!file) return;

    const lower = file.name.toLowerCase();
    const hasValidExt = ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext));
    if (!hasValidExt) {
      setError('Unsupported file extension. Please upload a .log, .txt, or .csv file.');
      return;
    }
    if (file.size === 0) {
      setError('The selected file is empty.');
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setError('File size exceeds the 1.8 MB upload limit.');
      return;
    }

    if (lower.endsWith('.csv')) {
      setFileFormat('csv');
    }

    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === 'string' ? reader.result : '';
      if (text.includes('\u0000')) {
        setError('Rejected unsafe binary file content.');
        return;
      }
      setSelectedFileName(file.name);
      setFileContent(text);
    };
    reader.onerror = () => {
      setError('Unable to read the selected file.');
    };
    reader.readAsText(file);
  }

  async function handleAnalyze(e) {
    e.preventDefault();
    if (!selectedFileName || !fileContent) {
      setError('Choose a supported log or CSV file first.');
      return;
    }

    setAnalyzing(true);
    setError('');
    try {
      const summary = await analyzeUploadedLogFile({
        filename: selectedFileName,
        fileFormat,
        content: fileContent,
      });
      setResult(summary);
      showToast(
        `Analyzed ${summary.parsed_count} events (${summary.incidents_created} incident(s)).`,
        'success',
      );
      loadHistory();
    } catch (err) {
      setError(err.message || 'Log analysis failed.');
      showToast(err.message || 'Log analysis failed.', 'error');
    } finally {
      setAnalyzing(false);
    }
  }

  return (
    <div>
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Historical Log Analyzer</h1>
          <p className="soc-page-subtitle">
            Upload Ubuntu auth.log, systemd journal, or documented CSV logs to scan with the same v1.0 detection rules.
          </p>
        </div>
      </header>

      <ErrorBanner message={error} />

      <form className="soc-card" onSubmit={handleAnalyze} style={{ marginBottom: '1.15rem' }}>
        <div className="form-grid-2" style={{ marginBottom: '0.85rem' }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label" htmlFor="upload-format">
              Log Format
            </label>
            <select
              id="upload-format"
              className="form-input"
              value={fileFormat}
              onChange={(e) => setFileFormat(e.target.value)}
              disabled={analyzing}
            >
              <option value="auth_log">Ubuntu / Debian auth.log</option>
              <option value="journal">Systemd Journal (short-iso)</option>
              <option value="csv">Documented CSV</option>
            </select>
          </div>

          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label" htmlFor="upload-file-input">
              Select Log File (.log, .txt, .csv — max 1.8 MB)
            </label>
            <input
              id="upload-file-input"
              type="file"
              accept=".log,.txt,.csv"
              className="form-input"
              onChange={(e) => handleFileSelection(e.target.files?.[0] || null)}
              disabled={analyzing}
            />
          </div>
        </div>

        <div
          className={`upload-dropzone ${dragActive ? 'active' : ''}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragActive(true);
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragActive(false);
            handleFileSelection(e.dataTransfer.files?.[0] || null);
          }}
        >
          {selectedFileName ? (
            <div>
              <strong>Selected:</strong> <span className="mono">{selectedFileName}</span> (
              {fileContent.split(/\r?\n/).length} lines ready)
            </div>
          ) : (
            <div>
              Drag and drop a supported <span className="mono">.log</span>,{' '}
              <span className="mono">.txt</span>, or <span className="mono">.csv</span> file here, or
              choose one above.
            </div>
          )}
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
            CSV required headers: <span className="mono">event_timestamp, event_type, auth_result</span>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.65rem', marginTop: '0.9rem' }}>
          <button type="submit" className="btn btn-primary" disabled={!fileContent || analyzing}>
            {analyzing ? 'Scanning & Persisting Results...' : 'Analyze Log File'}
          </button>
        </div>
      </form>

      {result ? (
        <section className="soc-card" aria-label="Latest analysis summary" style={{ marginBottom: '1.15rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
            <h2 style={{ fontSize: '1.02rem' }}>
              Analysis Result: <span className="mono">{sanitizeDisplayText(result.filename)}</span>
            </h2>
            <Link to="/incidents" className="btn btn-secondary btn-sm">
              Open Incidents →
            </Link>
          </div>

          <div className="evidence-grid">
            <div className="evidence-chip">
              <div className="evidence-chip-label">Total Lines</div>
              <div className="evidence-chip-value">{result.total_lines}</div>
            </div>
            <div className="evidence-chip">
              <div className="evidence-chip-label">Parsed Auth Events</div>
              <div className="evidence-chip-value" style={{ color: '#4ade80' }}>
                {result.parsed_count}
              </div>
            </div>
            <div className="evidence-chip">
              <div className="evidence-chip-label">Newly Stored / Duplicates</div>
              <div className="evidence-chip-value">
                {result.accepted_count} / {result.duplicate_count}
              </div>
            </div>
            <div className="evidence-chip">
              <div className="evidence-chip-label">Ignored / Malformed</div>
              <div className="evidence-chip-value">
                {result.ignored_count} / {result.malformed_count}
              </div>
            </div>
            <div className="evidence-chip">
              <div className="evidence-chip-label">Incidents Detected</div>
              <div className="evidence-chip-value" style={{ color: '#fb923c' }}>
                {result.incidents_created}
              </div>
            </div>
          </div>

          {Array.isArray(result.incidents) && result.incidents.length > 0 ? (
            <div style={{ marginTop: '0.75rem' }}>
              <strong style={{ fontSize: '0.84rem' }}>Detected Suspicious Patterns</strong>
              <div className="table-scroll" style={{ marginTop: '0.4rem' }}>
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th>Title</th>
                      <th>Source IP</th>
                      <th>Severity</th>
                      <th>Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.incidents.map((inc) => (
                      <tr key={inc.dedup_key}>
                        <td className="mono">{inc.rule_id}</td>
                        <td>{sanitizeDisplayText(inc.incident_title)}</td>
                        <td className="mono">{inc.source_ip || '—'}</td>
                        <td>
                          <SeverityBadge severity={inc.severity} />
                        </td>
                        <td className="mono">{inc.risk_score}/100</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}

          {Array.isArray(result.malformed_samples) && result.malformed_samples.length > 0 ? (
            <div style={{ marginTop: '0.85rem' }}>
              <strong style={{ fontSize: '0.84rem', color: '#fbbf24' }}>
                Malformed / Unrecognized Line Samples
              </strong>
              <ul style={{ marginTop: '0.35rem', paddingLeft: '1.25rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                {result.malformed_samples.map((m, i) => (
                  <li key={`${m.line_number}-${i}`}>
                    Line {m.line_number}: {sanitizeDisplayText(m.reason)} (
                    <span className="mono">{sanitizeDisplayText(m.raw_snippet)}</span>)
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </section>
      ) : null}

      <section className="table-card" aria-label="Past log uploads">
        <div style={{ padding: '0.9rem 1rem', borderBottom: '1px solid var(--border-subtle)' }}>
          <h2 className="chart-card-title">Recent Upload Analyses</h2>
        </div>
        {loadingHistory ? (
          <div style={{ padding: '1rem' }}>
            <LoadingState message="Loading upload history..." />
          </div>
        ) : history.length === 0 ? (
          <div style={{ padding: '1rem' }}>
            <EmptyState
              title="No uploaded files yet"
              description="Uploaded log analysis summaries are saved here for auditability."
            />
          </div>
        ) : (
          <div className="table-scroll">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Analyzed At</th>
                  <th>Filename</th>
                  <th>Format</th>
                  <th>Lines</th>
                  <th>Parsed</th>
                  <th>Malformed</th>
                  <th>Incidents</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item) => (
                  <tr key={item.id}>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(item.created_at)}</td>
                    <td className="mono">{sanitizeDisplayText(item.filename)}</td>
                    <td className="mono">{item.file_format}</td>
                    <td>{item.total_lines}</td>
                    <td>{item.parsed_count}</td>
                    <td>{item.malformed_count}</td>
                    <td>{item.incidents_created}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
