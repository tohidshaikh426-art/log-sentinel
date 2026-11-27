import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AppRoutes } from './App';
import { ConfirmModal } from './components/UiPrimitives';
import { ToastProvider } from './hooks/useToast';
import { NAV_ITEMS } from './layouts/SocLayout';

const mockUseAuth = vi.fn();
const mockFetchMonitoringSummary = vi.fn();

vi.mock('./hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
  AuthProvider: ({ children }) => children,
}));

vi.mock('./services/monitoringStatusService', async () => {
  const actual = await vi.importActual('./services/monitoringStatusService');
  return {
    ...actual,
    fetchMonitoringSummary: () => mockFetchMonitoringSummary(),
  };
});

function renderAt(path) {
  return render(
    <ToastProvider>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </ToastProvider>,
  );
}

describe('Phase 7 Auth, Protected Routes, and SOC Layout', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchMonitoringSummary.mockResolvedValue({
      totalDevices: 0,
      onlineCount: 0,
      offlineCount: 0,
      pausedCount: 0,
      lastEventAt: null,
      lastHeartbeatAt: null,
      monitoringState: 'idle',
      collectorLabel: 'No Collector',
    });
  });

  it('redirects unauthenticated users to login and validates login inputs', async () => {
    mockUseAuth.mockReturnValue({
      user: null,
      profile: null,
      loading: false,
      isConfigured: true,
      signIn: vi.fn(),
      signOut: vi.fn(),
    });

    renderAt('/');
    expect(screen.getByRole('heading', { name: 'Log Sentinel' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign In' })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Administrator Email'), {
      target: { value: 'invalid-email' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }));
    expect(screen.getByRole('alert')).toHaveTextContent('valid administrator email');
  });

  it('renders SOC layout with all 8 nav links and honest collector status when authenticated', async () => {
    mockUseAuth.mockReturnValue({
      user: { id: 'u1', email: 'admin@logsentinel.local' },
      profile: { id: 'u1', full_name: 'SOC Admin', email: 'admin@logsentinel.local' },
      loading: false,
      isConfigured: true,
      signIn: vi.fn(),
      signOut: vi.fn(),
    });

    renderAt('/');

    await waitFor(() => {
      expect(screen.getByText('Monitoring: IDLE')).toBeInTheDocument();
      expect(screen.getByText('Collector: No Collector')).toBeInTheDocument();
    });

    for (const item of NAV_ITEMS) {
      expect(screen.getByRole('link', { name: new RegExp(item.label) })).toBeInTheDocument();
    }

    fireEvent.click(screen.getByRole('link', { name: /Incidents/ }));
    expect(screen.getByRole('heading', { name: 'Security Incidents' })).toBeInTheDocument();
  });

  it('supports Escape key dismissal on ConfirmModal', () => {
    const onCancel = vi.fn();
    render(
      <ConfirmModal
        open
        title="Reset Demo Data"
        message="This removes simulated records only."
        onConfirm={vi.fn()}
        onCancel={onCancel}
      />,
    );
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});
