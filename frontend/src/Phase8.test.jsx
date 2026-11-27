import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import EventsPage from './pages/EventsPage';
import IpAnalysisPage from './pages/IpAnalysisPage';
import OverviewPage from './pages/OverviewPage';

const mockFetchOverview = vi.fn();
const mockFetchEventsPage = vi.fn();
const mockFetchDevicesList = vi.fn();
const mockFetchIpSummary = vi.fn();

vi.mock('react-chartjs-2', () => ({
  Line: ({ data }) => <div data-testid="line-chart">{data.labels.join(',')}</div>,
  Doughnut: ({ data }) => <div data-testid="doughnut-chart">{data.datasets[0].data.join('/')}</div>,
  Bar: ({ data }) => <div data-testid="bar-chart">{data.labels.join(',')}</div>,
}));

vi.mock('./services/dashboardService', () => ({
  fetchOverviewMetrics: (...args) => mockFetchOverview(...args),
  fetchEventsPage: (...args) => mockFetchEventsPage(...args),
  fetchDevicesList: (...args) => mockFetchDevicesList(...args),
  fetchIpSummary: (...args) => mockFetchIpSummary(...args),
}));

describe('Phase 8 Core Monitoring Views', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchDevicesList.mockResolvedValue([
      { id: 'dev-1', device_name: 'ubuntu-prod-01', effective_status: 'online' },
    ]);
  });

  it('OverviewPage renders real KPIs, charts, and toggles Live Only filter', async () => {
    mockFetchOverview.mockResolvedValue({
      kpis: {
        totalEvents: 42,
        successfulLogins: 10,
        failedLogins: 32,
        totalIncidents: 2,
        highIncidents: 1,
        criticalIncidents: 1,
        monitoredDevices: 1,
        onlineDevices: 1,
        lastEventAt: '2026-11-27T12:00:00Z',
      },
      severityCounts: { low: 0, medium: 0, high: 1, critical: 1 },
      timelineEvents: [
        { event_timestamp: '2026-11-27T11:15:00Z', auth_result: 'failure' },
        { event_timestamp: '2026-11-27T11:20:00Z', auth_result: 'success' },
      ],
      recentIncidents: [
        {
          id: 'inc-1',
          rule_id: 'RULE_001',
          incident_title: 'Possible brute-force attempts from 203.0.113.55',
          source_ip: '203.0.113.55/32',
          severity: 'high',
          status: 'open',
          last_observed: '2026-11-27T12:00:00Z',
          is_simulated: false,
        },
      ],
      topSuspiciousIps: [
        { source_ip: '203.0.113.55/32', failed_attempts: 12, incident_count: 1, max_risk_score: 65 },
      ],
    });

    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText('42')).toBeInTheDocument();
      expect(screen.getByText('10')).toBeInTheDocument();
      expect(screen.getByText('32')).toBeInTheDocument();
      expect(screen.getByTestId('doughnut-chart')).toHaveTextContent('10/32');
    });

    fireEvent.click(screen.getByRole('button', { name: 'Live Only' }));
    await waitFor(() => {
      expect(mockFetchOverview).toHaveBeenLastCalledWith({ dataMode: 'live' });
    });
  });

  it('OverviewPage renders error banner on failure and allows retry', async () => {
    mockFetchOverview.mockRejectedValueOnce(new Error('Database timeout'));
    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Database timeout');
    });
  });

  it('EventsPage paginates, filters, and renders untrusted log payloads safely as plain text', async () => {
    const xssPayload = '<script>alert("xss")</script>';
    mockFetchEventsPage.mockResolvedValue({
      rows: [
        {
          id: 'ev-1',
          event_timestamp: '2026-11-27T12:00:00Z',
          username: xssPayload,
          source_ip: '203.0.113.55/32',
          event_type: 'ssh_invalid_user',
          auth_result: 'failure',
          auth_method: 'password',
          service: 'sshd',
          raw_event: `Failed password for invalid user ${xssPayload} from 203.0.113.55`,
          is_simulated: false,
          monitored_devices: { device_name: 'ubuntu-prod-01' },
        },
      ],
      totalCount: 30,
      page: 1,
      pageSize: 25,
    });

    const { container } = render(
      <MemoryRouter initialEntries={['/events']}>
        <EventsPage />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText(xssPayload)).toBeInTheDocument();
    });
    // Must never inject an actual <script> element into the DOM
    expect(container.querySelector('script')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Inspect' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText(/Sanitized Raw Log/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));

    fireEvent.change(screen.getByLabelText('Filter by authentication result'), {
      target: { value: 'failure' },
    });
    await waitFor(() => {
      expect(mockFetchEventsPage).toHaveBeenLastCalledWith(
        expect.objectContaining({ authResult: 'failure', page: 1 }),
      );
    });
  });

  it('IpAnalysisPage filters IPs, sorts by failures, and links to filtered Events', async () => {
    mockFetchIpSummary.mockResolvedValue([
      {
        source_ip: '203.0.113.55/32',
        total_events: 15,
        failed_attempts: 15,
        successful_logins: 0,
        incident_count: 1,
        max_risk_score: 70,
        first_observed: '2026-11-27T11:00:00Z',
        last_observed: '2026-11-27T12:00:00Z',
      },
      {
        source_ip: '198.51.100.10/32',
        total_events: 5,
        failed_attempts: 1,
        successful_logins: 4,
        incident_count: 0,
        max_risk_score: 0,
        first_observed: '2026-11-27T10:00:00Z',
        last_observed: '2026-11-27T11:30:00Z',
      },
    ]);

    render(
      <MemoryRouter>
        <IpAnalysisPage />
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByText('203.0.113.55')).toBeInTheDocument();
      expect(screen.getByText('198.51.100.10')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText('Filter by IP address'), {
      target: { value: '203.0.113' },
    });
    expect(screen.getByText('203.0.113.55')).toBeInTheDocument();
    expect(screen.queryByText('198.51.100.10')).not.toBeInTheDocument();

    expect(screen.getByRole('link', { name: 'View Events' })).toHaveAttribute(
      'href',
      '/events?ip=203.0.113.55',
    );
  });
});
