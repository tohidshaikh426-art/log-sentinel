/**
 * Strip ASCII control characters so untrusted log text renders cleanly as plain text.
 * React escapes HTML automatically when rendered inside JSX text nodes.
 */
export function sanitizeDisplayText(value, fallback = '—') {
  if (value === null || value === undefined || value === '') return fallback;
  return String(value).replace(/[\x00-\x1f\x7f]/g, ' ').trim() || fallback;
}

export function formatTimestamp(isoString) {
  if (!isoString) return 'Never';
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return 'Invalid date';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatRelativeTime(isoString) {
  if (!isoString) return 'Never';
  const ms = Date.parse(isoString);
  if (!Number.isFinite(ms)) return '—';
  const diffSec = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const mins = Math.floor(diffSec / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

export function scoreToSeverity(score) {
  const n = Number(score) || 0;
  if (n >= 75) return 'critical';
  if (n >= 50) return 'high';
  if (n >= 25) return 'medium';
  return 'low';
}

export function formatIpAddress(ip) {
  if (!ip) return '—';
  // PostgreSQL INET sometimes includes '/32' or '/128' depending on serialization
  return String(ip).split('/')[0];
}
