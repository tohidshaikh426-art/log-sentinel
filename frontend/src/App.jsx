import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import ProtectedRoute from './components/ProtectedRoute';
import { AuthProvider } from './hooks/useAuth';
import { ToastProvider } from './hooks/useToast';
import SocLayout from './layouts/SocLayout';
import EventsPage from './pages/EventsPage';
import IpAnalysisPage from './pages/IpAnalysisPage';
import LoginPage from './pages/LoginPage';
import OverviewPage from './pages/OverviewPage';
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
        <Route index element={<OverviewPage />} />
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
        <Route path="events" element={<EventsPage />} />
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
        <Route path="ip-analysis" element={<IpAnalysisPage />} />
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
