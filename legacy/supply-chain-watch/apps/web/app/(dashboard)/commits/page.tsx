export default function Page() {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-3">Commit Analysis</div>
        <h1 className="text-[20px] font-semibold tracking-tight">커밋 상세 분석</h1>
      </div>
      <div className="rounded-xl border border-line bg-surface p-6 text-[13px] text-fg-2 shadow-card">
        피드·레포 테이블에서 커밋을 선택하면 상세로 이동합니다. Phase 5에서 구현됩니다.
      </div>
    </section>
  );
}
