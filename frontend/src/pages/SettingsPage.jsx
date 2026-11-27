import { useCallback, useEffect, useState } from 'react';
import {
  ConfirmModal,
  EmptyState,
  ErrorBanner,
  LoadingState,
  StatusBadge,
} from '../components/UiPrimitives';
import { useToast } from '../hooks/useToast';
import { fetchDevicesList } from '../services/dashboardService';
import {
  registerMonitoredDevice,
  rotateDeviceCollectorToken,
  setDevicePaused,
} from '../services/operationsService';
import { formatTimestamp, sanitizeDisplayText } from '../utils/formatters';

const RULES_REFERENCE = [
  {
    id: 'RULE_001',
    name: 'Repeated Failed Authentication (Possible Brute Force)',
    threshold: '>= 5 failures / IP',
    window: '120s (2 min)',
  },
  {
    id: 'RULE_002',
    name: 'Multiple Target Accounts (Potential Password Spraying)',
    threshold: '>= 4 distinct usernames / IP',
    window: '300s (5 min)',
  },
  {
    id: 'RULE_003',
    name: 'Suspicious Success After Failures',
    threshold: 'Success after >= 3 failures (same IP + user)',
    window: '600s (10 min)',
  },
  {
    id: 'RULE_004',
    name: 'High-Volume Authentication Failures',
    threshold: '>= 20 total failures / device',
    window: '300s (5 min)',
  },
  {
    id: 'RULE_005',
    name: 'Repeat Offender Activity',
    threshold: '>= 3 new failures (300s cooldown, 24h lookback)',
    window: '300s (5 min)',
  },
];

export default function SettingsPage() {
  const { showToast } = useToast();

  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [deviceName, setDeviceName] = useState('');
  const [hostIdentifier, setHostIdentifier] = useState('');
  const [osInfo, setOsInfo] = useState('Ubuntu 24.04 LTS');
  const [registering, setRegistering] = useState(false);

  const [issuedCredential, setIssuedCredential] = useState(null);
  const [rotateTarget, setRotateTarget] = useState(null);
  const [rotating, setRotating] = useState(false);

  const loadDevices = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const list = await fetchDevicesList();
      setDevices(list);
    } catch (err) {
      setError(err.message || 'Unable to load monitored devices.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDevices();
  }, [loadDevices]);

  async function handleRegister(e) {
    e.preventDefault();
    if (!deviceName.trim() || !hostIdentifier.trim()) {
      showToast('Device name and host identifier are required.', 'error');
      return;
    }

    setRegistering(true);
    try {
      const creds = await registerMonitoredDevice({ deviceName, hostIdentifier, osInfo });
      setIssuedCredential({
        deviceName: deviceName.trim(),
        deviceId: creds.device_id,
        collectorToken: creds.collector_token,
      });
      setDeviceName('');
      setHostIdentifier('');
      showToast('Monitored device registered. Copy the one-time token now.', 'success');
      loadDevices();
    } catch (err) {
      showToast(err.message || 'Failed to register device.', 'error');
    } finally {
      setRegistering(false);
    }
  }

  async function handleTogglePause(dev) {
    const shouldPause = dev.effective_status !== 'paused';
    try {
      await setDevicePaused(dev.id, shouldPause);
      showToast(
        shouldPause ? `Paused ${dev.device_name}.` : `Resumed ${dev.device_name}.`,
        'info',
      );
      loadDevices();
    } catch (err) {
      showToast(err.message || 'Failed to update device status.', 'error');
    }
  }

  async function handleConfirmRotate() {
    if (!rotateTarget) return;
    setRotating(true);
    try {
      const newToken = await rotateDeviceCollectorToken(rotateTarget.id);
      setIssuedCredential({
        deviceName: rotateTarget.device_name,
        deviceId: rotateTarget.id,
        collectorToken: newToken,
      });
      setRotateTarget(null);
      showToast('Collector token rotated. Update collector/.env on the host.', 'warning');
    } catch (err) {
      showToast(err.message || 'Failed to rotate collector token.', 'error');
    } finally {
      setRotating(false);
    }
  }

  const supabaseBaseUrl = import.meta.env.VITE_SUPABASE_URL?.trim() || 'https://your-project.supabase.co';

  return (
    <div>
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Settings &amp; Device Provisioning</h1>
          <p className="soc-page-subtitle">
            Register monitored Linux hosts, manage per-device collector tokens, and inspect v1.0 rule thresholds.
          </p>
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={loadDevices}>
          Refresh Devices
        </button>
      </header>

      <ErrorBanner message={error} onRetry={loadDevices} />

      {issuedCredential ? (
        <section
          className="soc-card"
          style={{
            marginBottom: '1.15rem',
            borderColor: 'rgba(34, 197, 94, 0.45)',
            background: 'rgba(34, 197, 94, 0.06)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
            <strong style={{ color: '#4ade80' }}>
              One-Time Collector Configuration ({sanitizeDisplayText(issuedCredential.deviceName)})
            </strong>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setIssuedCredential(null)}
            >
              Dismiss
            </button>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
            Copy this token now—only its SHA-256 hash is saved in the database, so it cannot be shown again.
          </p>
          <pre className="raw-log-box">
{`LOG_SENTINEL_INGEST_URL=${supabaseBaseUrl}/functions/v1/ingest-events
LOG_SENTINEL_HEARTBEAT_URL=${supabaseBaseUrl}/functions/v1/collector-heartbeat
LOG_SENTINEL_DEVICE_ID=${issuedCredential.deviceId}
LOG_SENTINEL_DEVICE_NAME=${issuedCredential.deviceName}
LOG_SENTINEL_COLLECTOR_TOKEN=${issuedCredential.collectorToken}`}
          </pre>
        </section>
      ) : null}

      <section className="soc-card" style={{ marginBottom: '1.15rem' }}>
        <h2 className="chart-card-title" style={{ marginBottom: '0.75rem' }}>
          Register Monitored Linux Host
        </h2>
        <form onSubmit={handleRegister}>
          <div className="form-grid-2">
            <div className="form-group">
              <label className="form-label" htmlFor="dev-name">
                Display Name
              </label>
              <input
                id="dev-name"
                type="text"
                className="form-input"
                placeholder="e.g. Ubuntu Lab Server"
                value={deviceName}
                onChange={(e) => setDeviceName(e.target.value)}
                disabled={registering}
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="dev-host-id">
                Unique Host Identifier
              </label>
              <input
                id="dev-host-id"
                type="text"
                className="form-input"
                placeholder="e.g. ubuntu-lab-01"
                value={hostIdentifier}
                onChange={(e) => setHostIdentifier(e.target.value)}
                disabled={registering}
                required
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="dev-os">
              Operating System Info
            </label>
            <input
              id="dev-os"
              type="text"
              className="form-input"
              value={osInfo}
              onChange={(e) => setOsInfo(e.target.value)}
              disabled={registering}
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={registering}>
            {registering ? 'Registering...' : 'Register Device & Generate Token'}
          </button>
        </form>
      </section>

      <section className="table-card" style={{ marginBottom: '1.15rem' }}>
        <div style={{ padding: '0.85rem 1rem', borderBottom: '1px solid var(--border-subtle)' }}>
          <h2 className="chart-card-title">Monitored Devices</h2>
        </div>
        {loading ? (
          <div style={{ padding: '1rem' }}>
            <LoadingState message="Loading registered devices..." />
          </div>
        ) : devices.length === 0 ? (
          <div style={{ padding: '1rem' }}>
            <EmptyState
              title="No monitored devices registered"
              description="Register a Linux host above to issue a per-device collector token."
            />
          </div>
        ) : (
          <div className="table-scroll">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Host ID</th>
                  <th>Status</th>
                  <th>Version</th>
                  <th>Events</th>
                  <th>Last Heartbeat</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((dev) => (
                  <tr key={dev.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{sanitizeDisplayText(dev.device_name)}</div>
                      {dev.is_simulated ? (
                        <span className="soc-badge badge-amber">SIMULATED</span>
                      ) : null}
                    </td>
                    <td className="mono">{sanitizeDisplayText(dev.host_identifier)}</td>
                    <td>
                      <StatusBadge status={dev.effective_status} showDot />
                    </td>
                    <td className="mono">{sanitizeDisplayText(dev.collector_version)}</td>
                    <td>{dev.events_received_count}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(dev.last_heartbeat)}</td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleTogglePause(dev)}
                        >
                          {dev.effective_status === 'paused' ? 'Resume' : 'Pause'}
                        </button>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => setRotateTarget(dev)}
                        >
                          Rotate Token
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="table-card">
        <div style={{ padding: '0.85rem 1rem', borderBottom: '1px solid var(--border-subtle)' }}>
          <h2 className="chart-card-title">Version 1.0 Detection Rules Reference</h2>
        </div>
        <div className="table-scroll">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Name</th>
                <th>Default Threshold</th>
                <th>Window</th>
              </tr>
            </thead>
            <tbody>
              {RULES_REFERENCE.map((rule) => (
                <tr key={rule.id}>
                  <td className="mono">{rule.id}</td>
                  <td>{rule.name}</td>
                  <td>{rule.threshold}</td>
                  <td>{rule.window}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <ConfirmModal
        open={Boolean(rotateTarget)}
        title="Rotate Collector Token?"
        message={`Rotating the token for "${rotateTarget?.device_name || ''}" immediately invalidates its previous collector secret until updated in collector/.env.`}
        confirmLabel="Rotate Token"
        confirmVariant="danger"
        busy={rotating}
        onConfirm={handleConfirmRotate}
        onCancel={() => setRotateTarget(null)}
      />
    </div>
  );
}
