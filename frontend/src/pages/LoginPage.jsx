import { useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { ErrorBanner } from '../components/UiPrimitives';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../hooks/useToast';

export default function LoginPage() {
  const { user, loading, isConfigured, signIn } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState('');

  if (!loading && user) {
    const dest = location.state?.from?.pathname || '/';
    return <Navigate to={dest} replace />;
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setFormError('');

    const cleanEmail = email.trim();
    if (!cleanEmail || !cleanEmail.includes('@')) {
      setFormError('Enter a valid administrator email address.');
      return;
    }
    if (!password) {
      setFormError('Password is required.');
      return;
    }

    setSubmitting(true);
    try {
      await signIn(cleanEmail, password);
      showToast('Signed in to Log Sentinel SOC.', 'success');
      const dest = location.state?.from?.pathname || '/';
      navigate(dest, { replace: true });
    } catch (err) {
      setFormError(err.message || 'Unable to sign in. Check your credentials.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-shell">
      <section className="login-card" aria-labelledby="login-heading">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.7rem', marginBottom: '1.15rem' }}>
          <div className="soc-brand-mark" aria-hidden="true">LS</div>
          <div>
            <h1 id="login-heading" style={{ fontSize: '1.25rem', lineHeight: 1.2 }}>
              Log Sentinel
            </h1>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Administrator Security Console
            </p>
          </div>
        </div>

        {!isConfigured ? (
          <div className="error-banner" role="alert">
            <span>
              Supabase environment variables are missing. Create{' '}
              <code className="mono">frontend/.env.local</code> with{' '}
              <code className="mono">VITE_SUPABASE_URL</code> and{' '}
              <code className="mono">VITE_SUPABASE_ANON_KEY</code> (or{' '}
              <code className="mono">VITE_SUPABASE_PUBLISHABLE_KEY</code>), then restart Vite.
            </span>
          </div>
        ) : null}

        <ErrorBanner message={formError} />

        <form onSubmit={handleSubmit} noValidate>
          <div className="form-group">
            <label className="form-label" htmlFor="login-email">
              Administrator Email
            </label>
            <input
              id="login-email"
              type="email"
              className="form-input"
              autoComplete="email"
              placeholder="admin@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={!isConfigured || submitting}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="login-password">
              Password
            </label>
            <div className="password-row">
              <input
                id="login-password"
                type={showPassword ? 'text' : 'password'}
                className="form-input"
                autoComplete="current-password"
                placeholder="Enter password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={!isConfigured || submitting}
                style={{ paddingRight: '3.6rem' }}
                required
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword((v) => !v)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%', marginTop: '0.4rem' }}
            disabled={!isConfigured || submitting}
          >
            {submitting ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>

        <p style={{ marginTop: '1.1rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          Protected by Supabase Authentication and PostgreSQL Row Level Security.
        </p>
      </section>
    </div>
  );
}
