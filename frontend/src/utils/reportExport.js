import { formatIpAddress, sanitizeDisplayText } from './formatters';

/**
 * Neutralize spreadsheet formula injection (=, +, -, @) and RFC 4180 quote cells.
 */
export function escapeCsvCell(value) {
  if (value === null || value === undefined) return '""';
  let text = String(value).replace(/[\r\n]+/g, ' ');
  if (/^[=+\-@\t]/.test(text)) {
    text = `'${text}`;
  }
  return `"${text.replace(/"/g, '""')}"`;
}

function rowToCsv(cells) {
  return cells.map(escapeCsvCell).join(',');
}

export function buildSecurityReportCsv(report) {
  const lines = [];

  lines.push(rowToCsv(['Log Sentinel Security Summary Report']));
  lines.push(rowToCsv(['Analysis Date (UTC)', report.generatedAt]));
  lines.push(rowToCsv(['Dataset Scope', report.dataMode]));
  lines.push(
    rowToCsv([
      'Date Filter',
      report.dateFrom || report.dateTo
        ? `${report.dateFrom || 'Start'} to ${report.dateTo || 'Now'}`
        : 'All Available Dates',
    ]),
  );
  lines.push('');

  lines.push(rowToCsv(['Metric', 'Value']));
  lines.push(rowToCsv(['Total Authentication Events', report.totals.totalEvents]));
  lines.push(rowToCsv(['Successful Logins', report.totals.successfulLogins]));
  lines.push(rowToCsv(['Failed Logins', report.totals.failedLogins]));
  lines.push(rowToCsv(['Detected Incidents', report.totals.detectedIncidents]));
  lines.push(rowToCsv(['Low Severity Incidents', report.severitySummary.low]));
  lines.push(rowToCsv(['Medium Severity Incidents', report.severitySummary.medium]));
  lines.push(rowToCsv(['High Severity Incidents', report.severitySummary.high]));
  lines.push(rowToCsv(['Critical Severity Incidents', report.severitySummary.critical]));
  lines.push('');

  lines.push(rowToCsv(['Detection Rule Summary']));
  lines.push(rowToCsv(['Rule ID', 'Incident Count', 'Max Risk Score']));
  for (const r of report.ruleSummary) {
    lines.push(rowToCsv([r.rule_id, r.count, r.max_score]));
  }
  lines.push('');

  lines.push(rowToCsv(['Top Suspicious IP Summary']));
  lines.push(
    rowToCsv([
      'Source IP',
      'Total Events',
      'Failed Attempts',
      'Successful Logins',
      'Incidents',
      'Max Risk Score',
      'Last Observed',
    ]),
  );
  for (const ip of report.suspiciousIps) {
    lines.push(
      rowToCsv([
        formatIpAddress(ip.source_ip),
        ip.total_events,
        ip.failed_attempts,
        ip.successful_logins,
        ip.incident_count,
        ip.max_risk_score,
        ip.last_observed || '',
      ]),
    );
  }
  lines.push('');

  lines.push(rowToCsv(['Detected Incidents (Up to 200 Most Recent)']));
  lines.push(
    rowToCsv([
      'Rule ID',
      'Title',
      'Source IP',
      'Username',
      'Severity',
      'Risk Score',
      'Status',
      'Event Count',
      'First Observed',
      'Last Observed',
      'Simulated',
    ]),
  );
  for (const inc of report.incidents) {
    lines.push(
      rowToCsv([
        inc.rule_id,
        sanitizeDisplayText(inc.incident_title, ''),
        formatIpAddress(inc.source_ip),
        sanitizeDisplayText(inc.username, ''),
        inc.severity,
        inc.risk_score,
        inc.status,
        inc.event_count,
        inc.first_observed,
        inc.last_observed,
        inc.is_simulated ? 'Yes' : 'No',
      ]),
    );
  }

  return lines.join('\r\n');
}

export function triggerCsvDownload(csvText, filename) {
  const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
