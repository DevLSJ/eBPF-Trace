import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { StreamProvider } from './hooks/stream-context';
import { DashboardPage } from './features/dashboard/DashboardPage';
import { EventsPage } from './features/events/EventsPage';
import { TopologyPage } from './features/topology/TopologyPage';
import { PoliciesPage } from './features/policies/PoliciesPage';
import { AuditPage } from './features/audit/AuditPage';

export default function App() {
  return (
    <StreamProvider>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="events" element={<EventsPage />} />
          <Route path="topology" element={<TopologyPage />} />
          <Route path="policies" element={<PoliciesPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </StreamProvider>
  );
}
