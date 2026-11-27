import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import DemoSimulationPanel from './components/DemoSimulationPanel';
import { ToastProvider } from './hooks/useToast';
import { buildOfflinePreviewScenario, DEMO_SCENARIOS } from './services/simulationService';

const mockTriggerCloudSimulation = vi.fn();
const mockResetCloudDemoData = vi.fn();

vi.mock('./services/simulationService', async () => {
  const actual = await vi.importActual('./services/simulationService');
  return {
    ...actual,
    triggerCloudSimulation: (...args) => mockTriggerCloudSimulation(...args),
    resetCloudDemoData: (...args) => mockResetCloudDemoData(...args),
  };
});

describe('Phase 11 Demo / Simulation Mode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders all 6 synthetic scenarios with unmistakable SIMULATION MODE notice', () => {
    render(
      <ToastProvider>
        <MemoryRouter>
          <DemoSimulationPanel />
        </MemoryRouter>
      </ToastProvider>,
    );

    expect(screen.getByText('SIMULATION MODE')).toBeInTheDocument();
    for (const sc of DEMO_SCENARIOS) {
      expect(screen.getByText(sc.title)).toBeInTheDocument();
    }
    expect(screen.getAllByRole('button', { name: 'Run Scenario' })).toHaveLength(6);
  });

  it('triggers cloud simulation with selected pace and requires confirmation before resetting demo data', async () => {
    mockTriggerCloudSimulation.mockResolvedValue({
      events_generated: 7,
      incidents_generated: 1,
    });
    mockResetCloudDemoData.mockResolvedValue({
      events_deleted: 7,
      incidents_deleted: 1,
      devices_deleted: 1,
    });
    const onCloudComplete = vi.fn();

    render(
      <ToastProvider>
        <MemoryRouter>
          <DemoSimulationPanel onCloudComplete={onCloudComplete} />
        </MemoryRouter>
      </ToastProvider>,
    );

    fireEvent.change(screen.getByLabelText('Simulation event rate'), {
      target: { value: '700' },
    });

    const runButtons = screen.getAllByRole('button', { name: 'Run Scenario' });
    fireEvent.click(runButtons[1]); // 2. Brute Force

    await waitFor(() => {
      expect(mockTriggerCloudSimulation).toHaveBeenCalledWith({
        scenario: 'brute_force',
        paceMs: 700,
      });
      expect(onCloudComplete).toHaveBeenCalled();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Reset Demo Data' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(mockResetCloudDemoData).not.toHaveBeenCalled();

    const modalButtons = screen.getAllByRole('button', { name: 'Reset Demo Data' });
    fireEvent.click(modalButtons[modalButtons.length - 1]);

    await waitFor(() => {
      expect(mockResetCloudDemoData).toHaveBeenCalledTimes(1);
    });
  });

  it('supports offline local preview fallback without cloud calls', () => {
    const onOfflinePreview = vi.fn();
    render(
      <ToastProvider>
        <MemoryRouter>
          <DemoSimulationPanel onOfflinePreview={onOfflinePreview} />
        </MemoryRouter>
      </ToastProvider>,
    );

    fireEvent.click(screen.getByLabelText('Offline Local Preview'));
    fireEvent.click(screen.getAllByRole('button', { name: 'Run Scenario' })[2]); // Password Spraying

    expect(mockTriggerCloudSimulation).not.toHaveBeenCalled();
    expect(onOfflinePreview).toHaveBeenCalledTimes(1);
    const preview = buildOfflinePreviewScenario('password_spraying');
    expect(preview.incidents[0].rule_id).toBe('RULE_002');
    expect(preview.incidents[0].is_simulated).toBe(true);
  });
});
