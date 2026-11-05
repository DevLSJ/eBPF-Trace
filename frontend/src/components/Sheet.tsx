import { ChevronLeft, ChevronRight, X } from 'lucide-react';
import { useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { dialogOpen, typingTarget } from '../lib/shell';
import { SheetHostContext } from './header-slot';
import type { SheetNav } from './sheet-nav';

export type { SheetNav } from './sheet-nav';

// 상세 패널 [11/05 결정 — 목업 sheet-1105 와 같은 모습]: 표 옆 칸이 아니라 본문 위에 겹쳐 오른쪽에서 미끄러져 나온다.
//   - 뒤는 살짝 어둡게(누르면 닫힘) · Esc · ✕ 닫기 · 닫힐 때도 미끄러져 나감
//   - size: 'wide' = 본문 70% · 최대 1080px(공급망 검사 · 설치 검사), 'normal' = 720px(이벤트 · 감사 로그 · 토폴로지). 768 미만은 전체 화면
//   - nav: 보이는 목록(현재 쪽) 안의 앞뒤 — 머리 「n / m ‹ ›」 · ↑↓, 닫지 않고 넘긴다
//   - 열린 항목은 URL(?id=)에 남는다(화면 쪽). 같은 kind 가 방금 닫히고 다시 열리면(key 로 다시 그리기 · 이전/다음) 애니메이션을 되풀이하지 않는다
const lastGone: { kind: string; at: number } = { kind: '', at: 0 };
// 나가는 애니메이션 길이 = --t-base(11/04f 원칙: 모션 토큰)
const baseMs = () => parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--t-base')) || 200;
// 패널 밖에 열린 대화상자 · 메뉴(도우미 · 알림 · 계정 메뉴) — 그쪽이 Esc 를 먼저 받는다
const otherOverlay = () =>
  [...document.querySelectorAll('[role="dialog"], [role="menu"]')].some((el) => !el.closest('.sg-sheet-layer') && el.getClientRects().length > 0);
const reduced = () => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

export function Sheet({
  kind,
  title,
  actions,
  onClose,
  children,
  size = 'normal',
  nav,
}: {
  kind: string;
  title: ReactNode;
  actions?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  size?: 'wide' | 'normal';
  nav?: SheetNav;
}) {
  const host = useContext(SheetHostContext);
  const [still] = useState(() => lastGone.kind === kind && Date.now() - lastGone.at < 120);
  const [closing, setClosing] = useState(false);
  const closingRef = useRef(false);
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);
  useEffect(
    () => () => {
      lastGone.kind = kind;
      lastGone.at = Date.now();
    },
    [kind],
  );
  const close = useCallback(() => {
    if (closingRef.current) return;
    if (reduced()) return onCloseRef.current();
    closingRef.current = true;
    setClosing(true);
    setTimeout(() => {
      lastGone.kind = ''; // 닫고 나서 다시 여는 것은 새로 미끄러져 들어온다
      onCloseRef.current();
    }, baseMs());
  }, []);
  const navRef = useRef(nav);
  useEffect(() => {
    navRef.current = nav;
  }, [nav]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey || typingTarget(e) || dialogOpen() || otherOverlay()) return;
      const n = navRef.current;
      const act = e.key === 'Escape' ? close : e.key === 'ArrowUp' ? n?.prev : e.key === 'ArrowDown' ? n?.next : null;
      if (!act) return;
      e.preventDefault();
      act();
    };
    // 캡처 단계: 도우미 등이 먼저 닫혀 「열린 게 없다」로 보이기 전에 판단한다
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [close]);

  const label = typeof title === 'string' ? title : '상세';
  const layer = (
    <div
      className={`sg-sheet-layer${still ? ' still' : ''}${closing ? ' closing' : ''}`}
      data-layer={kind}
      onClick={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <aside data-sheet={kind} data-size={size} role="dialog" aria-label={label} className="sg-card sg-sheet flex min-h-0 flex-col overflow-hidden">
        <header className="sg-sheet-head flex shrink-0 items-center gap-3 border-b border-border">
          <h2 className="min-w-0 flex-1 truncate text-base font-semibold text-text">{title}</h2>
          {actions}
          {nav && nav.total > 1 && (
            <div className="sg-sheet-nav flex items-center gap-0.5 border-r border-border pr-2" data-part="sheet-nav">
              <span className="num mr-1.5 text-[13px] text-text-3" data-part="sheet-pos">
                {nav.pos + 1} / {nav.total}
              </span>
              <button type="button" data-action="sheet-prev" disabled={!nav.prev} onClick={() => nav.prev?.()} aria-label="이전 항목(↑)" title="이전 항목(↑)" className="rounded p-1 text-text-3 hover:bg-surface-2 hover:text-text disabled:opacity-30">
                <ChevronLeft className="size-4" />
              </button>
              <button type="button" data-action="sheet-next" disabled={!nav.next} onClick={() => nav.next?.()} aria-label="다음 항목(↓)" title="다음 항목(↓)" className="rounded p-1 text-text-3 hover:bg-surface-2 hover:text-text disabled:opacity-30">
                <ChevronRight className="size-4" />
              </button>
            </div>
          )}
          <button type="button" data-action="sheet-close" onClick={close} className="rounded p-1 text-text-3 hover:bg-surface-2 hover:text-text" aria-label="닫기" title="닫기(Esc)">
            <X className="size-4" />
          </button>
        </header>
        <div className="sg-sheet-body min-h-0 flex-1 overflow-y-auto">{children}</div>
      </aside>
    </div>
  );
  return host ? createPortal(layer, host) : layer;
}

// 패널 안 주제 블록: 소제목 15px 굵게 + 구분선(첫 블록 제외)
export function Section({ title, children, testId }: { title: ReactNode; children: ReactNode; testId?: string }) {
  return (
    <section className="sg-sheet-section" data-testid={testId}>
      <h3 className="sg-sheet-h3">{title}</h3>
      {children}
    </section>
  );
}
