export default async function CommitDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <section className="flex flex-col gap-3">
      <div>
        <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-3">
          Commit Analysis
        </div>
        <h1 className="text-[20px] font-semibold tracking-tight">커밋 상세 분석 · #{id}</h1>
      </div>
      <div className="rounded-xl border border-line bg-surface p-6 text-[13px] text-fg-2 shadow-card">
        파일 브라우저·코드 패널·분석 드로어는 Phase 5에서 구현됩니다.
      </div>
    </section>
  );
}
