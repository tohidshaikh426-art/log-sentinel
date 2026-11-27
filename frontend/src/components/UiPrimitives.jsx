import { useEffect } from 'react';

export function LoadingState({ message = 'Loading security data...' }) {
  return (
    <div className="state-box" role="status" aria-busy="true">
      <div className="state-box-title">{message}</div>
      <p>Fetching records from Supabase.</p>
    </div>
  );
}

export function EmptyState({ title, description, action = null }) {
  return (
    <div className="state-box">
      <div className="state-box-title">{title}</div>
      <p>{description}</p>
      {action ? <div style={{ marginTop: '0.9rem' }}>{action}</div> : null}
    </div>
  );
}

export function ErrorBanner({ message, onRetry = null }) {
  if (!message) return null;
  return (
    <div className="error-banner" role="alert">
      <span>{message}</span>
      {onRetry ? (
        <button type="button" className="btn btn-secondary btn-sm" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}

const SEVERITY_CLASS = {
  low: 'badge-green',
  medium: 'badge-amber',
  high: 'badge-orange',
  critical: 'badge-red',
};

export function SeverityBadge({ severity }) {
  const key = (severity || 'low').toLowerCase();
  const cls = SEVERITY_CLASS[key] || 'badge-neutral';
  return <span className={`soc-badge ${cls}`}>{key.toUpperCase()}</span>;
}

const STATUS_CLASS = {
  online: 'badge-green',
  active: 'badge-green',
  success: 'badge-green',
  resolved: 'badge-green',
  investigating: 'badge-amber',
  paused: 'badge-amber',
  open: 'badge-orange',
  offline: 'badge-red',
  failure: 'badge-red',
  idle: 'badge-neutral',
  unknown: 'badge-neutral',
};

export function StatusBadge({ status, label = null, showDot = false }) {
  const key = (status || 'unknown').toLowerCase();
  const cls = STATUS_CLASS[key] || 'badge-neutral';
  return (
    <span className={`soc-badge ${cls}`}>
      {showDot ? <span className="soc-dot" aria-hidden="true" /> : null}
      {label || key}
    </span>
  );
}

export function ConfirmModal({
  open,
  title,
  message,
  confirmLabel = 'Confirm',
  confirmVariant = 'danger',
  busy = false,
  onConfirm,
  onCancel,
}) {
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape' && !busy) {
        onCancel();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, busy, onCancel]);

  if (!open) return null;

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-modal-title"
      onClick={() => {
        if (!busy) onCancel();
      }}
    >
      <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
        <h3 id="confirm-modal-title" style={{ marginBottom: '0.5rem' }}>
          {title}
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>{message}</p>
        <div className="modal-actions">
          <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            type="button"
            className={`btn ${confirmVariant === 'danger' ? 'btn-danger' : 'btn-primary'}`}
            onClick={onConfirm}
            disabled={busy}
          >
            {busy ? 'Processing...' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
