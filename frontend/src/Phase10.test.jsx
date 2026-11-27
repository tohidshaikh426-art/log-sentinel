import { act, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useRealtimeFeed } from './hooks/useRealtime';
import LiveMonitoringPage from './pages/LiveMonitoringPage';
import {
  computeEffectiveStatus,
  HEARTBEAT_STALE_MS,
  summarizeDevices,
} from './services/monitoringStatusService';

const {
  mockChannelFactory,
  mockRemoveChannel,
  mockFetchMonitoringDevices,
  mockFetchEventsPage,
  mockFetchIncidentsPage,
} = vi.hoisted(() => ({
  mockChannelFactory: vi.fn(),
  mockRemoveChannel: vi.fn(),
  mockFetchMonitoringDevices: vi.fn(),
  mockFetchEventsPage: vi.fn(),
  mockFetchIncidentsPage: vi.fn(),
}));

vi.mock('./services/supabaseClient', () => ({
  isSupabaseConfigured: true,
  supabase: {
    channel: (...args) => mockChannelFactory(...args),
    removeChannel: (...args) => mockRemoveChannel(...args),
  },
}));

vi.mock('./services/monitoringStatusService', async () => {
  const actual = await vi.importActual('./services/monitoringStatusService');
  return {
    ...actual,
    fetchMonitoringDevices: (...args) => mockFetchMonitoringDevices(...args),
  };
});

vi.mock('./services/dashboardService', () => ({
  fetchEventsPage: (...args) => mockFetchEventsPage(...args),
}));

vi.mock('./services/operationsService', () => ({
  fetchIncidentsPage: (...args) => mockFetchIncidentsPage(...args),
}));

function setupFakeChannel() {
  const handlers = [];
  let statusCb = null;
  const channelObj = {
    on: vi.fn((_type, filter, cb) => {
      handlers.push({ filter, cb });
      return channelObj;
    }),
    subscribe: vi.fn((cb) => {
      statusCb = cb;
      return channelObj;
    }),
  };
  mockChannelFactory.mockReturnValue(channelObj);
  return {
    channelObj,
    emitStatus: (status) => act(() => statusCb?.(status)),
    emitTable: (table, payload) => {
      act(() => {
        for (const h of handlers) {
          if (h.filter.table === table) h.cb(payload);
        }
      });
    },
  };
}

describe('Phase 10 Supabase Realtime & Stale Heartbeat Detection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('computes offline status accurately when heartbeat exceeds 90s threshold', () => {
    const now = Date.parse('2026-11-27T15:00:00Z');
    const freshDev = {
      id: 'd1',
      status: 'online',
      last_heartbeat: new Date(now - 30_000).toISOString(),
    };
    const staleDev = {
      id: 'd2',
      status: 'online',
      last_heartbeat: new Date(now - HEARTBEAT_STALE_MS - 5000).toISOString(),
    };

    expect(computeEffectiveStatus(freshDev, now)).toBe('online');
    expect(computeEffectiveStatus(staleDev, now)).toBe('offline');

    const summary = summarizeDevices([staleDev], now);
    expect(summary.onlineCount).toBe(0);
    expect(summary.offlineCount).toBe(1);
    expect(summary.monitoringState).toBe('offline');
  });

  it('useRealtimeFeed avoids duplicate channels on re-render, handles reconnect sync, and cleans up on unmount', () => {
    const fake = setupFakeChannel();
    const onEventInsert = vi.fn();
    const onReconnectSync = vi.fn();

    const { result, rerender, unmount } = renderHook(
      ({ cb }) =>
        useRealtimeFeed({
          enabled: true,
          channelName: 'test-chan',
          onEventInsert: cb,
          onReconnectSync,
        }),
      { initialProps: { cb: onEventInsert } },
    );

    expect(mockChannelFactory).toHaveBeenCalledTimes(1);
    fake.emitStatus('SUBSCRIBED');
    expect(result.current.connectionState).toBe('connected');

    // Re-rendering with a new callback identity must NOT re-subscribe or leak listeners
    const onEventInsert2 = vi.fn();
    rerender({ cb: onEventInsert2 });
    expect(mockChannelFactory).toHaveBeenCalledTimes(1);

    fake.emitTable('authentication_events', {
      new: { id: 'e1', event_type: 'ssh_failed_password' },
    });
    expect(onEventInsert2).toHaveBeenCalledWith({ id: 'e1', event_type: 'ssh_failed_password' });

    // Reconnect after channel error triggers resync callback
    fake.emitStatus('CHANNEL_ERROR');
    expect(result.current.connectionState).toBe('reconnecting');
    fake.emitStatus('SUBSCRIBED');
    expect(onReconnectSync).toHaveBeenCalledTimes(1);

    unmount();
    expect(mockRemoveChannel).toHaveBeenCalledWith(fake.channelObj);
  });

  it('LiveMonitoringPage updates feed live without refresh, deduplicates events, and supports pausing stream', async () => {
    const fake = setupFakeChannel();
    mockFetchMonitoringDevices.mockResolvedValue([
      {
        id: 'dev-1',
        device_name: 'Ubuntu Prod Server',
        host_identifier: 'ubuntu-prod-01',
        status: 'online',
        effective_status: 'online',
        last_heartbeat: new Date().toISOString(),
        last_event_at: new Date().toISOString(),
        events_received_count: 1,
        is_simulated: false,
      },
    ]);
    mockFetchEventsPage.mockResolvedValue({ rows: [], totalCount: 0, page: 1, pageSize: 50 });
    mockFetchIncidentsPage.mockResolvedValue({ rows: [], totalCount: 0, page: 1, pageSize: 15 });

    render(
      <MemoryRouter>
        <LiveMonitoringPage />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText('Ubuntu Prod Server')).toBeInTheDocument();
    });
    fake.emitStatus('SUBSCRIBED');
    expect(screen.getByText('Realtime: CONNECTED')).toBeInTheDocument();

    // Push live event via Realtime
    const ev = {
      id: 'evt-live-1',
      device_id: 'dev-1',
      event_timestamp: '2026-11-27T15:10:00Z',
      source_ip: '203.0.113.55/32',
      username: 'root',
      event_type: 'ssh_failed_password',
      auth_result: 'failure',
      is_simulated: false,
    };
    fake.emitTable('authentication_events', { new: ev });
    // Duplicate push of same ID must be ignored
    fake.emitTable('authentication_events', { new: ev });

    await waitFor(() => {
      expect(screen.getAllByText('203.0.113.55')).toHaveLength(1);
    });

    // Pause stream stops incoming updates from appending
    fireEvent.click(screen.getByRole('button', { name: 'Pause Stream' }));
    fake.emitTable('authentication_events', {
      new: { ...ev, id: 'evt-live-2', source_ip: '198.51.100.99/32' },
    });
    expect(screen.queryByText('198.51.100.99')).not.toBeInTheDocument();
  });
});
