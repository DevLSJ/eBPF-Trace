export default function Page() {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-3">Settings</div>
        <h1 className="text-[20px] font-semibold tracking-tight">설정 · 백오피스</h1>
      </div>
      <div className="rounded-xl border border-line bg-surface p-6 text-[13px] text-fg-2 shadow-card">
        API 연결·알림·프롬프트·룰·CI 게이트 탭은 Phase 6에서 구현됩니다.
      </div>
    </section>
  );
}
