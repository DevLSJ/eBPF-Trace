export default function Page() {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-3">Overview</div>
        <h1 className="text-[20px] font-semibold tracking-tight">실시간 위협 모니터링</h1>
      </div>
      <div className="rounded-xl border border-line bg-surface p-6 text-[13px] text-fg-2 shadow-card">
        Phase 2(수집기)·3(정적)·5(대시보드)에서 구현됩니다. 셸·WebSocket 연결은 동작합니다.
      </div>
    </section>
  );
}
