import { useCallback, useEffect, useMemo, useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { StatusBadge } from '../components/UiPrimitives';
import { useAuth } from '../hooks/useAuth';
import { useRealtimeFeed } from '../hooks/useRealtime';
import { useToast } from '../hooks/useToast';
import {
  fetchMonitoringDevices,
  summarizeDevices,
} from '../services/monitoringStatusService';

export const NAV_ITEMS = [
  { to: '/', label: 'Overview', icon: '◈', section: 'Monitoring' },
  { to: '/live', label: 'Live Monitoring', icon: '◉', section: 'Monitoring' },
  { to: '/events', label: 'Events', icon: '≡', section: 'Monitoring' },
  { to: '/incidents', label: 'Incidents', icon: '▲', section: 'Investigation' },
  { to: '/ip-analysis', label: 'IP Analysis', icon: '◎', section: 'Investigation' },
  { to: '/analyzer', label: 'Log Analyzer', icon: '⇪', section: 'Investigation' },
  { to: '/reports', label: 'Reports', icon: '▤', section: 'Operations' },
  { to: '/settings', label: 'Settings', icon: '⚙', section: 'Operations' },
];

export default function SocLayout() {
  const { user, profile, signOut } = useAuth();
  const { showToast } = useToast();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [clockText, setClockText] = useState(() => new Date().toLocaleString());
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [devices, setDevices] = useState([]);

  const loadDevices = useCallback(async () => {
    try {
      const list = await fetchMonitoringDevices();
      setDevices(list);
    } catch {
      setDevices([]);
    }
  }, []);

  useEffect(() => {
    loadDevices();
    // Re-evaluate 90s heartbeat staleness locally every 15s (zero DB polling)
    const staleTimer = setInterval(() => setNowMs(Date.now()), 15000);
    const clockTimer = setInterval(() => {
      setClockText(new Date().toLocaleString());
    }, 1000);

    return () => {
      clearInterval(staleTimer);
      clearInterval(clockTimer);
    };
  }, [loadDevices]);

  const { connectionState } = useRealtimeFeed({
    enabled: Boolean(user),
    channelName: 'soc-topbar-devices',
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
    onReconnectSync: loadDevices,
  });

  const statusSummary = useMemo(() => summarizeDevices(devices, nowMs), [devices, nowMs]);
  const hasSimulatedDevice = useMemo(() => devices.some((d) => d.is_simulated), [devices]);

  useEffect(() => {
    if (!drawerOpen) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape') setDrawerOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [drawerOpen]);

  async function handleSignOut() {
    try {
      await signOut();
      showToast('Signed out cleanly.', 'info');
    } catch (err) {
      showToast(err.message || 'Unable to sign out.', 'error');
    }
  }

  const sections = ['Monitoring', 'Investigation', 'Operations'];
  const displayName = profile?.full_name || user?.email || 'Administrator';

  return (
    <div className="soc-app">
      <div
        className={`sidebar-backdrop ${drawerOpen ? 'open' : ''}`}
        onClick={() => setDrawerOpen(false)}
        aria-hidden="true"
      />

      <aside className={`soc-sidebar ${drawerOpen ? 'open' : ''}`} aria-label="Main navigation">
        <div className="soc-brand">
          <div className="soc-brand-mark" aria-hidden="true">LS</div>
          <div className="soc-brand-text">
            <span className="soc-brand-title">Log Sentinel</span>
            <span className="soc-brand-sub">Defensive SOC v1.0</span>
          </div>
        </div>

        <nav className="soc-nav">
          {sections.map((section) => (
            <div key={section}>
              <div className="soc-nav-section">{section}</div>
              {NAV_ITEMS.filter((item) => item.section === section).map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  onClick={() => setDrawerOpen(false)}
                  className={({ isActive }) =>
                    `soc-nav-link ${isActive ? 'active' : ''}`
                  }
                >
                  <span className="soc-nav-icon" aria-hidden="true">
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="soc-sidebar-footer">
          <div>Realtime: {connectionState}</div>
          <div>Heartbeat threshold: 90s</div>
        </div>
      </aside>

      <div className="soc-content-wrap">
        <header className="soc-topbar">
          <div className="soc-topbar-left">
            <button
              type="button"
              className="soc-menu-btn"
              onClick={() => setDrawerOpen((v) => !v)}
              aria-label="Toggle navigation menu"
              aria-expanded={drawerOpen}
            >
              ☰
            </button>
            <span className="soc-topbar-title">Security Operations Dashboard</span>
          </div>

          <div className="soc-topbar-right">
            {hasSimulatedDevice ? (
              <span className="soc-badge badge-amber">SIMULATED DATA ACTIVE</span>
            ) : null}
            <StatusBadge
              status={statusSummary.monitoringState}
              label={`Monitoring: ${statusSummary.monitoringState.toUpperCase()}`}
              showDot
            />
            <StatusBadge
              status={
                statusSummary.onlineCount > 0
                  ? 'online'
                  : statusSummary.totalDevices === 0
                    ? 'idle'
                    : 'offline'
              }
              label={`Collector: ${statusSummary.collectorLabel}`}
              showDot
            />
            <span className="soc-clock" aria-label="Current local date and time">
              {clockText}
            </span>
            <div className="soc-user-chip">
              <span title={user?.email || ''}>{displayName}</span>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleSignOut}
              >
                Logout
              </button>
            </div>
          </div>
        </header>

        <main className="soc-main">
          <Outlet context={{ statusSummary, refreshStatus: loadDevices, connectionState }} />
        </main>
      </div>
    </div>
  );
}
