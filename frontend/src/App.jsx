import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import ProtectedRoute from './components/ProtectedRoute';
import { AuthProvider } from './hooks/useAuth';
import { ToastProvider } from './hooks/useToast';
import SocLayout from './layouts/SocLayout';
import EventsPage from './pages/EventsPage';
import IncidentsPage from './pages/IncidentsPage';
import IpAnalysisPage from './pages/IpAnalysisPage';
import LiveMonitoringPage from './pages/LiveMonitoringPage';
import LogAnalyzerPage from './pages/LogAnalyzerPage';
import LoginPage from './pages/LoginPage';
import OverviewPage from './pages/OverviewPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';

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
        <Route path="live" element={<LiveMonitoringPage />} />
        <Route path="events" element={<EventsPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="ip-analysis" element={<IpAnalysisPage />} />
        <Route path="analyzer" element={<LogAnalyzerPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="settings" element={<SettingsPage />} />
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
