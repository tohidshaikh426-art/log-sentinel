import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import { formatIpAddress } from '../utils/formatters';
import { EmptyState } from './UiPrimitives';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
);

const BASE_GRID_COLOR = 'rgba(148, 163, 184, 0.12)';
const BASE_TICK_COLOR = '#94a3b8';

const COMMON_OPTIONS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      labels: {
        color: '#cbd5e1',
        boxWidth: 12,
        font: { size: 11 },
      },
    },
  },
};

function buildTimelineBuckets(events) {
  const buckets = new Map();
  for (const ev of events) {
    const dt = new Date(ev.event_timestamp);
    if (Number.isNaN(dt.getTime())) continue;
    const key = `${String(dt.getHours()).padStart(2, '0')}:00`;
    const curr = buckets.get(key) || { label: key, success: 0, failure: 0 };
    if (ev.auth_result === 'success') curr.success += 1;
    else if (ev.auth_result === 'failure') curr.failure += 1;
    buckets.set(key, curr);
  }
  return Array.from(buckets.values());
}

export function OverviewCharts({ timelineEvents, kpis, severityCounts, topSuspiciousIps }) {
  const timelineBuckets = buildTimelineBuckets(timelineEvents);
  const totalAuthSplit = (kpis.successfulLogins || 0) + (kpis.failedLogins || 0);
  const totalSeverity =
    (severityCounts.low || 0) +
    (severityCounts.medium || 0) +
    (severityCounts.high || 0) +
    (severityCounts.critical || 0);

  return (
    <section className="charts-grid" aria-label="Security analytics charts">
      <div className="chart-card">
        <div className="chart-card-header">
          <h2 className="chart-card-title">Authentication Activity (Last 24h)</h2>
        </div>
        <div className="chart-canvas-wrap">
          {timelineBuckets.length === 0 ? (
            <EmptyState
              title="No recent activity"
              description="Authentication events from the last 24 hours will plot here."
            />
          ) : (
            <Line
              data={{
                labels: timelineBuckets.map((b) => b.label),
                datasets: [
                  {
                    label: 'Successful Logins',
                    data: timelineBuckets.map((b) => b.success),
                    borderColor: '#22c55e',
                    backgroundColor: 'rgba(34, 197, 94, 0.14)',
                    fill: true,
                    tension: 0.25,
                  },
                  {
                    label: 'Failed Logins',
                    data: timelineBuckets.map((b) => b.failure),
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.14)',
                    fill: true,
                    tension: 0.25,
                  },
                ],
              }}
              options={{
                ...COMMON_OPTIONS,
                scales: {
                  x: { grid: { color: BASE_GRID_COLOR }, ticks: { color: BASE_TICK_COLOR } },
                  y: {
                    beginAtZero: true,
                    grid: { color: BASE_GRID_COLOR },
                    ticks: { color: BASE_TICK_COLOR, precision: 0 },
                  },
                },
              }}
            />
          )}
        </div>
      </div>

      <div className="chart-card">
        <div className="chart-card-header">
          <h2 className="chart-card-title">Successful vs. Failed Logins</h2>
        </div>
        <div className="chart-canvas-wrap">
          {totalAuthSplit === 0 ? (
            <EmptyState
              title="No login results yet"
              description="Success and failure ratios appear once events are stored."
            />
          ) : (
            <Doughnut
              data={{
                labels: ['Successful Logins', 'Failed Logins'],
                datasets: [
                  {
                    data: [kpis.successfulLogins, kpis.failedLogins],
                    backgroundColor: ['#22c55e', '#ef4444'],
                    borderColor: '#111827',
                    borderWidth: 2,
                  },
                ],
              }}
              options={{
                ...COMMON_OPTIONS,
                cutout: '62%',
              }}
            />
          )}
        </div>
      </div>

      <div className="chart-card">
        <div className="chart-card-header">
          <h2 className="chart-card-title">Incidents by Severity</h2>
        </div>
        <div className="chart-canvas-wrap">
          {totalSeverity === 0 ? (
            <EmptyState
              title="No incidents detected"
              description="Detected security incidents grouped by severity will appear here."
            />
          ) : (
            <Bar
              data={{
                labels: ['Low', 'Medium', 'High', 'Critical'],
                datasets: [
                  {
                    label: 'Incidents',
                    data: [
                      severityCounts.low,
                      severityCounts.medium,
                      severityCounts.high,
                      severityCounts.critical,
                    ],
                    backgroundColor: ['#22c55e', '#f59e0b', '#f97316', '#ef4444'],
                    borderRadius: 4,
                  },
                ],
              }}
              options={{
                ...COMMON_OPTIONS,
                plugins: { legend: { display: false } },
                scales: {
                  x: { grid: { display: false }, ticks: { color: BASE_TICK_COLOR } },
                  y: {
                    beginAtZero: true,
                    grid: { color: BASE_GRID_COLOR },
                    ticks: { color: BASE_TICK_COLOR, precision: 0 },
                  },
                },
              }}
            />
          )}
        </div>
      </div>

      <div className="chart-card">
        <div className="chart-card-header">
          <h2 className="chart-card-title">Top Suspicious IP Risk Scores</h2>
        </div>
        <div className="chart-canvas-wrap">
          {topSuspiciousIps.length === 0 ? (
            <EmptyState
              title="No source IPs recorded"
              description="Source IP failure and risk telemetry will appear here."
            />
          ) : (
            <Bar
              data={{
                labels: topSuspiciousIps.map((row) => formatIpAddress(row.source_ip)),
                datasets: [
                  {
                    label: 'Max Risk Score',
                    data: topSuspiciousIps.map((row) => row.max_risk_score || 0),
                    backgroundColor: topSuspiciousIps.map((row) => {
                      const s = row.max_risk_score || 0;
                      if (s >= 75) return '#ef4444';
                      if (s >= 50) return '#f97316';
                      if (s >= 25) return '#f59e0b';
                      return '#3b82f6';
                    }),
                    borderRadius: 4,
                  },
                ],
              }}
              options={{
                ...COMMON_OPTIONS,
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: {
                  x: {
                    min: 0,
                    max: 100,
                    grid: { color: BASE_GRID_COLOR },
                    ticks: { color: BASE_TICK_COLOR },
                  },
                  y: { grid: { display: false }, ticks: { color: BASE_TICK_COLOR } },
                },
              }}
            />
          )}
        </div>
      </div>
    </section>
  );
}
