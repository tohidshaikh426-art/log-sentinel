import { Navigate, useLocation } from 'react-router-dom';
import { LoadingState } from './UiPrimitives';
import { useAuth } from '../hooks/useAuth';

export default function ProtectedRoute({ children }) {
  const { user, loading, isConfigured } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="login-shell">
        <div style={{ width: '100%', maxWidth: 420 }}>
          <LoadingState message="Verifying administrator session..." />
        </div>
      </div>
    );
  }

  if (!isConfigured || !user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}
