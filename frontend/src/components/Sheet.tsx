import { X } from 'lucide-react';
import { useEffect, type ReactNode } from 'react';

// 오른쪽 상세 시트 — 목록 위치는 그대로, 열린 항목은 URL(?id=)에 남긴다. Esc 로 닫는다.
export function Sheet({
  kind,
  title,
  actions,
  onClose,
  children,
  className = 'w-[420px]',
}: {
  kind: string;
  title: ReactNode;
  actions?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  className?: string;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT')) return;
      onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <aside
      data-sheet={kind}
      aria-label={typeof title === 'string' ? title : '상세'}
      className={`flex min-h-0 shrink-0 flex-col rounded-lg border border-slate-200 bg-white ${className}`}
    >
      <header className="flex h-11 shrink-0 items-center gap-2 border-b border-slate-100 px-4">
        <h2 className="min-w-0 flex-1 truncate text-sm font-semibold text-slate-800">{title}</h2>
        {actions}
        <button type="button" onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700" aria-label="닫기">
          <X className="size-4" />
        </button>
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
    </aside>
  );
}

// 시트 안 소제목 + 내용
export function Section({ title, children, testId }: { title: ReactNode; children: ReactNode; testId?: string }) {
  return (
    <section className="border-t border-slate-100 px-4 py-3 first:border-t-0" data-testid={testId}>
      <h3 className="mb-2 text-xs font-semibold text-slate-700">{title}</h3>
      {children}
    </section>
  );
}
