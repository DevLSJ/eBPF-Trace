import { Sidebar } from '@/components/sidebar';
import { Topbar } from '@/components/topbar';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid h-screen grid-cols-[232px_1fr] overflow-hidden">
      <Sidebar />
      <main className="flex min-w-0 flex-col overflow-hidden">
        <Topbar crumb="DevLSJ / Supply Chain Watch" />
        <div className="flex-1 overflow-auto p-6">{children}</div>
      </main>
    </div>
  );
}
