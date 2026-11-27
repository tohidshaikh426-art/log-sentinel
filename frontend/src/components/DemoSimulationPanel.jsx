import { useState } from 'react';
import { ConfirmModal } from './UiPrimitives';
import { useToast } from '../hooks/useToast';
import {
  buildOfflinePreviewScenario,
  DEMO_SCENARIOS,
  resetCloudDemoData,
  triggerCloudSimulation,
} from '../services/simulationService';

export default function DemoSimulationPanel({ onCloudComplete, onOfflinePreview, onOfflineReset }) {
  const { showToast } = useToast();
  const [paceMs, setPaceMs] = useState(350);
  const [offlineFallback, setOfflineFallback] = useState(false);
  const [busyScenario, setBusyScenario] = useState('');
  const [confirmResetOpen, setConfirmResetOpen] = useState(false);
  const [resetting, setResetting] = useState(false);

  async function handleRunScenario(scenarioId) {
    setBusyScenario(scenarioId);
    try {
      if (offlineFallback) {
        const localData = buildOfflinePreviewScenario(scenarioId);
        onOfflinePreview?.(localData, scenarioId);
        showToast(`Local offline simulation "${scenarioId}" rendered (not saved to DB).`, 'warning');
        return;
      }

      const res = await triggerCloudSimulation({ scenario: scenarioId, paceMs });
      showToast(
        res.message ||
          `Simulated ${res.events_generated} event(s) and ${res.incidents_generated} incident(s).`,
        'info',
      );
      onCloudComplete?.();
    } catch (err) {
      showToast(err.message || 'Simulation failed. Try Offline Preview if cloud is unreachable.', 'error');
    } finally {
      setBusyScenario('');
    }
  }

  async function handleConfirmReset() {
    setResetting(true);
    try {
      if (offlineFallback) {
        onOfflineReset?.();
        setConfirmResetOpen(false);
        showToast('Cleared local offline preview records.', 'info');
        return;
      }

      const summary = await resetCloudDemoData();
      setConfirmResetOpen(false);
      showToast(
        `Demo reset complete (${summary?.events_deleted ?? 0} events, ${summary?.incidents_deleted ?? 0} incidents removed; live logs untouched).`,
        'success',
      );
      onCloudComplete?.();
    } catch (err) {
      showToast(err.message || 'Unable to reset demo data.', 'error');
    } finally {
      setResetting(false);
    }
  }

  return (
    <section
      className="soc-card"
      aria-label="Demo and simulation mode"
      style={{
        marginBottom: '1.15rem',
        borderColor: 'rgba(245, 158, 11, 0.45)',
        background: 'rgba(245, 158, 11, 0.05)',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: '0.8rem',
          flexWrap: 'wrap',
          marginBottom: '0.85rem',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span className="soc-badge badge-amber">SIMULATION MODE</span>
            <h2 className="chart-card-title">Controlled Threat Demonstration Scenarios</h2>
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Generates synthetic authentication events tagged <span className="mono">is_simulated=true</span>.
            Simulated records never represent real host compromises and can be reset safely without affecting live logs.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
          <select
            className="filter-select"
            aria-label="Simulation event rate"
            value={paceMs}
            onChange={(e) => setPaceMs(Number(e.target.value))}
            disabled={Boolean(busyScenario) || offlineFallback}
          >
            <option value={0}>Rate: Instant Burst (0ms)</option>
            <option value={350}>Rate: Realistic Stream (350ms)</option>
            <option value={700}>Rate: Slow Walkthrough (700ms)</option>
          </select>

          <label style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            <input
              type="checkbox"
              checked={offlineFallback}
              onChange={(e) => setOfflineFallback(e.target.checked)}
            />
            Offline Local Preview
          </label>

          <button
            type="button"
            className="btn btn-danger btn-sm"
            onClick={() => setConfirmResetOpen(true)}
            disabled={Boolean(busyScenario)}
          >
            Reset Demo Data
          </button>
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(215px, 1fr))',
          gap: '0.65rem',
        }}
      >
        {DEMO_SCENARIOS.map((sc) => {
          const isBusy = busyScenario === sc.id;
          return (
            <div
              key={sc.id}
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                padding: '0.75rem',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                gap: '0.55rem',
              }}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>{sc.title}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                  {sc.description}
                </div>
                <div style={{ fontSize: '0.74rem', color: '#fbbf24', marginTop: '0.25rem' }}>
                  {sc.expected}
                </div>
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={Boolean(busyScenario)}
                onClick={() => handleRunScenario(sc.id)}
              >
                {isBusy ? 'Running...' : 'Run Scenario'}
              </button>
            </div>
          );
        })}
      </div>

      <ConfirmModal
        open={confirmResetOpen}
        title="Reset Simulated Demo Data?"
        message="This permanently removes only records flagged as simulated (is_simulated = true). Real Linux monitoring logs and devices will not be deleted."
        confirmLabel="Reset Demo Data"
        confirmVariant="danger"
        busy={resetting}
        onConfirm={handleConfirmReset}
        onCancel={() => setConfirmResetOpen(false)}
      />
    </section>
  );
}
