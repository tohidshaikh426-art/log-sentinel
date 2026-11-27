import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from './hooks/useToast';
import IncidentsPage from './pages/IncidentsPage';
import LogAnalyzerPage from './pages/LogAnalyzerPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';
import { buildSecurityReportCsv, escapeCsvCell } from './utils/reportExport';

const mockFetchIncidentsPage = vi.fn();
const mockFetchIncidentLinkedEvents = vi.fn();
const mockUpdateIncidentTriage = vi.fn();
const mockAnalyzeUploadedLogFile = vi.fn();
const mockFetchUploadHistory = vi.fn();
const mockFetchReportDataset = vi.fn();
const mockFetchDevicesList = vi.fn();
const mockRegisterMonitoredDevice = vi.fn();
const mockRotateDeviceCollectorToken = vi.fn();
const mockSetDevicePaused = vi.fn();

vi.mock('./services/operationsService', () => ({
  fetchIncidentsPage: (...args) => mockFetchIncidentsPage(...args),
  fetchIncidentLinkedEvents: (...args) => mockFetchIncidentLinkedEvents(...args),
  updateIncidentTriage: (...args) => mockUpdateIncidentTriage(...args),
  analyzeUploadedLogFile: (...args) => mockAnalyzeUploadedLogFile(...args),
  fetchUploadHistory: (...args) => mockFetchUploadHistory(...args),
  fetchReportDataset: (...args) => mockFetchReportDataset(...args),
  registerMonitoredDevice: (...args) => mockRegisterMonitoredDevice(...args),
  rotateDeviceCollectorToken: (...args) => mockRotateDeviceCollectorToken(...args),
  setDevicePaused: (...args) => mockSetDevicePaused(...args),
}));

vi.mock('./services/dashboardService', () => ({
  fetchDevicesList: (...args) => mockFetchDevicesList(...args),
}));

function withProviders(ui) {
  return render(
    <ToastProvider>
      <MemoryRouter>{ui}</MemoryRouter>
    </ToastProvider>,
  );
}

describe('Phase 9 Incidents, Log Analyzer, Reports & Settings', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('IncidentsPage displays evidence breakdown, loads linked events, and saves triage updates', async () => {
    const sampleInc = {
      id: 'inc-1',
      device_id: 'dev-1',
      rule_id: 'RULE_001',
      incident_title: 'Possible brute-force attempts from 203.0.113.55',
      description: 'Observed 6 failed attempts in 120s.',
      source_ip: '203.0.113.55/32',
      username: 'admin',
      severity: 'high',
      risk_score: 58,
      status: 'open',
      first_observed: '2026-11-27T11:55:00Z',
      last_observed: '2026-11-27T11:56:00Z',
      event_count: 6,
      evidence: {
        sample_usernames: ['admin'],
        score_breakdown: {
          failure_points: 40,
          target_spread_points: 6,
          success_after_failure_bonus: 0,
          velocity_bonus: 10,
          repeat_offender_bonus: 0,
        },
      },
      investigation_notes: '',
      is_simulated: false,
      monitored_devices: { device_name: 'ubuntu-prod-01' },
    };

    mockFetchIncidentsPage.mockResolvedValue({
      rows: [sampleInc],
      totalCount: 1,
      page: 1,
      pageSize: 20,
    });
    mockFetchIncidentLinkedEvents.mockResolvedValue([
      {
        id: 'ev-1',
        event_timestamp: '2026-11-27T11:56:00Z',
        username: 'admin',
        event_type: 'ssh_failed_password',
        auth_result: 'failure',
      },
    ]);
    mockUpdateIncidentTriage.mockResolvedValue({
      ...sampleInc,
      status: 'resolved',
      investigation_notes: 'Verified test.',
    });

    withProviders(<IncidentsPage />);

    await waitFor(() => {
      expect(screen.getByText(/Possible brute-force attempts/)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Investigate' }));
    await waitFor(() => {
      expect(screen.getByText('Explainable Risk Score Breakdown')).toBeInTheDocument();
      expect(screen.getByText('+40')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText('Incident Status'), { target: { value: 'resolved' } });
    fireEvent.change(screen.getByLabelText('Investigation Notes'), {
      target: { value: 'Verified test.' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save Triage' }));

    await waitFor(() => {
      expect(mockUpdateIncidentTriage).toHaveBeenCalledWith('inc-1', {
        status: 'resolved',
        investigationNotes: 'Verified test.',
      });
    });
  });

  it('LogAnalyzerPage validates extension and renders analysis summary on upload', async () => {
    mockFetchUploadHistory.mockResolvedValue([]);
    mockAnalyzeUploadedLogFile.mockResolvedValue({
      upload_id: 'u-1',
      filename: 'sample_auth.log',
      file_format: 'auth_log',
      total_lines: 6,
      parsed_count: 5,
      accepted_count: 5,
      duplicate_count: 0,
      ignored_count: 0,
      malformed_count: 1,
      malformed_samples: [{ line_number: 6, reason: 'Bad header', raw_snippet: 'broken' }],
      incidents_created: 1,
      incidents: [
        {
          dedup_key: 'live:dev:RULE_001:203.0.113.55',
          rule_id: 'RULE_001',
          incident_title: 'Possible brute-force attempts',
          source_ip: '203.0.113.55',
          severity: 'high',
          risk_score: 51,
        },
      ],
    });

    withProviders(<LogAnalyzerPage />);

    const badFile = new File(['binary'], 'malware.exe', { type: 'application/octet-stream' });
    fireEvent.change(screen.getByLabelText(/Select Log File/), { target: { files: [badFile] } });
    expect(screen.getByRole('alert')).toHaveTextContent('Unsupported file extension');

    const goodFile = new File(['Nov 26 21:41:01 host sshd[1]: Failed password'], 'sample_auth.log', {
      type: 'text/plain',
    });
    fireEvent.change(screen.getByLabelText(/Select Log File/), { target: { files: [goodFile] } });

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Analyze Log File' })).toBeEnabled();
    });
    fireEvent.click(screen.getByRole('button', { name: 'Analyze Log File' }));

    await waitFor(() => {
      expect(screen.getByText('Detected Suspicious Patterns')).toBeInTheDocument();
      expect(screen.getByText('RULE_001')).toBeInTheDocument();
      expect(screen.getByText(/Malformed \/ Unrecognized Line Samples/)).toBeInTheDocument();
    });
  });

  it('ReportsPage builds formula-safe CSV and renders summary tables', async () => {
    expect(escapeCsvCell('=CMD()')).toBe('"\'=CMD()"');

    const dataset = {
      generatedAt: '2026-11-27T15:00:00Z',
      dataMode: 'all',
      dateFrom: '',
      dateTo: '',
      totals: {
        totalEvents: 100,
        successfulLogins: 75,
        failedLogins: 25,
        detectedIncidents: 2,
      },
      severitySummary: { low: 0, medium: 1, high: 1, critical: 0 },
      ruleSummary: [{ rule_id: 'RULE_001', count: 2, max_score: 60 }],
      suspiciousIps: [
        {
          source_ip: '203.0.113.55/32',
          total_events: 20,
          failed_attempts: 20,
          successful_logins: 0,
          incident_count: 2,
          max_risk_score: 60,
          last_observed: '2026-11-27T14:55:00Z',
        },
      ],
      incidents: [],
    };
    const csv = buildSecurityReportCsv(dataset);
    expect(csv).toContain('"Total Authentication Events","100"');
    expect(csv).toContain('"RULE_001","2","60"');

    mockFetchReportDataset.mockResolvedValue(dataset);
    withProviders(<ReportsPage />);

    await waitFor(() => {
      expect(screen.getByText('100')).toBeInTheDocument();
      expect(screen.getByText('RULE_001')).toBeInTheDocument();
      expect(screen.getByText('203.0.113.55')).toBeInTheDocument();
    });
  });

  it('SettingsPage registers a device and prompts confirmation before rotating tokens', async () => {
    mockFetchDevicesList.mockResolvedValue([
      {
        id: 'dev-1',
        device_name: 'Ubuntu Lab Server',
        host_identifier: 'ubuntu-lab-01',
        effective_status: 'offline',
        collector_version: '1.0.0',
        events_received_count: 15,
        last_heartbeat: null,
        is_simulated: false,
      },
    ]);
    mockRegisterMonitoredDevice.mockResolvedValue({
      device_id: 'dev-new-123',
      collector_token: 'one-time-token-abcdef',
    });

    withProviders(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByText('ubuntu-lab-01')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New VM' } });
    fireEvent.change(screen.getByLabelText('Unique Host Identifier'), {
      target: { value: 'new-vm-01' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Register Device & Generate Token' }));

    await waitFor(() => {
      expect(screen.getByText(/One-Time Collector Configuration/)).toBeInTheDocument();
      expect(screen.getByText(/one-time-token-abcdef/)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Rotate Token' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  });
});
