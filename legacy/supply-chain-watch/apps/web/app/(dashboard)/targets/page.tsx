export default function Page() {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-3">Repository Inspection</div>
        <h1 className="text-[20px] font-semibold tracking-tight">검사 레포지토리</h1>
      </div>
      <div className="rounded-xl border border-line bg-surface p-6 text-[13px] text-fg-2 shadow-card">
        레포 등록·테이블·다중 검사 시작은 Phase 2·5에서 구현됩니다.
      </div>
    </section>
  );
}
