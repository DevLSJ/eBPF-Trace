import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { Page } from './components/Page';
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
import { DemoPage } from './features/demo/DemoPage';

// 로그인(W16): AuthProvider 가 active 세션일 때만 아래(실시간 연결 · 건 목록 · 화면)를 그린다
// 화면마다 공통 틀 <Page>(R1 11/04 — 스크롤 없는 페이지, 스크롤은 화면 안 채움 칸 [data-fill] 에서만)
export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <StreamProvider>
          <CasesProvider>
            <Routes>
              <Route element={<AppShell />}>
                <Route index element={<Page><DashboardPage /></Page>} />
                <Route path="installs" element={<Page><InstallsPage /></Page>} />
                <Route path="scans" element={<Page><ScansPage /></Page>} />
                <Route path="evaluation" element={<Page><EvaluationPage /></Page>} />
                <Route path="events" element={<Page><EventsPage /></Page>} />
                <Route path="topology" element={<Page><TopologyPage /></Page>} />
                <Route path="policies" element={<Page><PoliciesPage /></Page>} />
                <Route path="audit" element={<Page><AuditPage /></Page>} />
                <Route path="settings" element={<Page><SettingsPage /></Page>} />
                <Route path="report" element={<Page><ReportPage /></Page>} />
                <Route path="demo" element={<Page><DemoPage /></Page>} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Routes>
          </CasesProvider>
        </StreamProvider>
      </AuthProvider>
    </ToastProvider>
  );
}
