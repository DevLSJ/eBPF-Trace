import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { AuthProvider } from './hooks/auth-context';
import { CasesProvider } from './hooks/cases-context';
import { StreamProvider } from './hooks/stream-context';
import { ToastProvider } from './hooks/toast-context';
import { DashboardPage } from './features/dashboard/DashboardPage';
import { ScansPage } from './features/scans/ScansPage';
import { EvaluationPage } from './features/evaluation/EvaluationPage';
import { InstallsPage } from './features/installs/InstallsPage';
import { EventsPage } from './features/events/EventsPage';
import { TopologyPage } from './features/topology/TopologyPage';
import { PoliciesPage } from './features/policies/PoliciesPage';
import { AuditPage } from './features/audit/AuditPage';
import { SettingsPage } from './features/settings/SettingsPage';
import { ReportPage } from './features/report/ReportPage';

// 로그인(W16): AuthProvider 가 active 세션일 때만 아래(실시간 연결 · 건 목록 · 화면)를 그린다
export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <StreamProvider>
          <CasesProvider>
            <Routes>
              <Route element={<AppShell />}>
                <Route index element={<DashboardPage />} />
                <Route path="installs" element={<InstallsPage />} />
                <Route path="scans" element={<ScansPage />} />
                <Route path="evaluation" element={<EvaluationPage />} />
                <Route path="events" element={<EventsPage />} />
                <Route path="topology" element={<TopologyPage />} />
                <Route path="policies" element={<PoliciesPage />} />
                <Route path="audit" element={<AuditPage />} />
                <Route path="settings" element={<SettingsPage />} />
                <Route path="report" element={<ReportPage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Routes>
          </CasesProvider>
        </StreamProvider>
      </AuthProvider>
    </ToastProvider>
  );
}
