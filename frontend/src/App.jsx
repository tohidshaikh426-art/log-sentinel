import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import ProtectedRoute from './components/ProtectedRoute';
import { AuthProvider } from './hooks/useAuth';
import { ToastProvider } from './hooks/useToast';
import SocLayout from './layouts/SocLayout';
import LoginPage from './pages/LoginPage';
import PhaseStubPage from './pages/PhaseStubPage';

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <SocLayout />
          </ProtectedRoute>
        }
      >
        <Route
          index
          element={
            <PhaseStubPage
              title="Security Overview"
              subtitle="KPI metrics, authentication trends, and recent threat activity."
              phaseNote="Phase 8"
            />
          }
        />
        <Route
          path="live"
          element={
            <PhaseStubPage
              title="Live Monitoring"
              subtitle="Collector health, real-time event stream, and simulation controls."
              phaseNote="Phases 10–11"
            />
          }
        />
        <Route
          path="events"
          element={
            <PhaseStubPage
              title="Authentication Events"
              subtitle="Searchable, paginated authentication telemetry."
              phaseNote="Phase 8"
            />
          }
        />
        <Route
          path="incidents"
          element={
            <PhaseStubPage
              title="Security Incidents"
              subtitle="Rule-based detections, risk scores, evidence, and triage workflow."
              phaseNote="Phase 9"
            />
          }
        />
        <Route
          path="ip-analysis"
          element={
            <PhaseStubPage
              title="IP Analysis"
              subtitle="Per-source IP authentication counts, failures, and risk summaries."
              phaseNote="Phase 8"
            />
          }
        />
        <Route
          path="analyzer"
          element={
            <PhaseStubPage
              title="Historical Log Analyzer"
              subtitle="Upload Ubuntu auth.log, journal, or CSV files for threat scanning."
              phaseNote="Phase 9"
            />
          }
        />
        <Route
          path="reports"
          element={
            <PhaseStubPage
              title="Reports"
              subtitle="Downloadable CSV and printable PDF security summaries."
              phaseNote="Phase 9"
            />
          }
        />
        <Route
          path="settings"
          element={
            <PhaseStubPage
              title="Settings"
              subtitle="Monitored device tokens, collector instructions, and rule thresholds."
              phaseNote="Phase 9"
            />
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </AuthProvider>
    </ToastProvider>
  );
}
