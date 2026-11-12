import { OverviewFeed } from '@/components/feed';

export default function OverviewPage() {
  return (
    <section className="flex h-full flex-col gap-3">
      <div>
        <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-3">Overview</div>
        <h1 className="text-[20px] font-semibold tracking-tight">실시간 위협 모니터링</h1>
      </div>
      <div className="min-h-0 flex-1">
        <OverviewFeed />
      </div>
    </section>
  );
}
