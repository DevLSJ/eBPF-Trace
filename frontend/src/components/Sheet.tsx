import { ChevronLeft, ChevronRight, X } from 'lucide-react';
import { useCallback, useContext, useEffect, useId, useRef, useState, type KeyboardEvent as RKeyboardEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { dialogOpen, typingTarget } from '../lib/shell';
import { SheetHostContext } from './header-slot';
import type { SheetNav } from './sheet-nav';
import './table-kit.css';

export type { SheetNav } from './sheet-nav';

// 상세 패널 [11/05 결정 — 목업 sheet-1105 와 같은 모습]: 표 옆 칸이 아니라 본문 위에 겹쳐 오른쪽에서 미끄러져 나온다.
//   - 뒤는 살짝 어둡게(누르면 닫힘) · Esc · ✕ 닫기 · 닫힐 때도 미끄러져 나감
//   - size: 'wide' = 본문 70% · 최대 1080px(공급망 검사 · 설치 검사), 'normal' = 720px(이벤트 · 감사 로그 · 토폴로지). 768 미만은 전체 화면
//   - nav: 보이는 목록(현재 쪽) 안의 앞뒤 — 머리 「n / m ‹ ›」 · ↑↓, 닫지 않고 넘긴다
//   - 열린 항목은 URL(?id=)에 남는다(화면 쪽). 같은 kind 가 방금 닫히고 다시 열리면(key 로 다시 그리기 · 이전/다음) 애니메이션을 되풀이하지 않는다
// 11/09(선택 props — 안 주면 머리 52 · 탭 줄 없음 그대로):
//   - subtitle 제목 아래 한 줄(12.5 보조색) · badges 제목 옆 배지 칸
//   - tabs · tab · onTab 머리 아래 탭 줄(role=tablist, ←→ Home End 로 옮기며 고름). 주소 쿼리는 쓰는 쪽(useListQuery: 첫 탭은 쿼리 없음 · 나머지 ?tab=)
//   - 모든 시트: aria-modal · 열면 초점을 시트 안으로(고른 탭, 없으면 시트) · Tab 은 시트 안에서만 · 닫으면 연 자리로 초점
//     (시트 밖 입력칸에서 쓰는 중이면 초점을 빼앗지 않는다)
const lastGone: { kind: string; at: number } = { kind: '', at: 0 };
// 나가는 애니메이션 길이 = --t-base(11/04f 원칙: 모션 토큰)
const baseMs = () => parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--t-base')) || 200;
// 패널 밖에 열린 대화상자 · 메뉴(도우미 · 알림 · 계정 메뉴) — 그쪽이 Esc 를 먼저 받는다
// 11/09: 펼친 선택 상자 · 칸 고르기([data-overlay])도 — 그것부터 닫는다
const otherOverlay = () =>
  [...document.querySelectorAll('[role="dialog"], [role="menu"], [data-overlay]')].some((el) => !el.closest('.sg-sheet-layer') && el.getClientRects().length > 0);
const reduced = () => typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]';
const focusables = (root: HTMLElement) =>
  [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((x) => x.tabIndex >= 0 && x.getClientRects().length > 0 && !x.closest('dialog'));
export interface SheetTab {
  key: string;
  label: ReactNode;
  count?: number;
}

export function Sheet({
  kind,
  title,
  actions,
  onClose,
  children,
  size = 'normal',
  nav,
  subtitle,
  badges,
  tabs,
  tab,
  onTab,
}: {
  kind: string;
  title: ReactNode;
  actions?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  size?: 'wide' | 'normal';
  nav?: SheetNav;
  subtitle?: ReactNode;
  badges?: ReactNode;
  tabs?: SheetTab[];
  tab?: string | null;
  onTab?: (key: string) => void;
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

  // 초점: 열면 시트 안으로, 닫히면(사라지면) 연 자리로
  const asideRef = useRef<HTMLElement>(null);
  useEffect(() => {
    const aside = asideRef.current;
    if (!aside) return;
    const prev = document.activeElement as HTMLElement | null;
    const opener = prev && prev !== document.body && !aside.contains(prev) ? prev : null;
    const busy = !!prev && !aside.contains(prev) && /^(input|textarea|select)$/i.test(prev.tagName);
    if (!busy) (aside.querySelector<HTMLElement>('[role="tab"][aria-selected="true"]') ?? aside).focus({ preventScroll: true });
    return () => {
      const now = document.activeElement;
      if (opener?.isConnected && (!now || now === document.body || !now.isConnected || aside.contains(now))) opener.focus({ preventScroll: true });
    };
  }, []);
  const trap = (e: RKeyboardEvent<HTMLElement>) => {
    if (e.key !== 'Tab' || e.defaultPrevented || (e.target as Element).closest('dialog')) return;
    const aside = asideRef.current!;
    const els = focusables(aside);
    if (!els.length) {
      e.preventDefault();
      return;
    }
    const first = els[0];
    const last = els[els.length - 1];
    const at = document.activeElement;
    if (e.shiftKey && (at === first || at === aside || !aside.contains(at))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (at === last || !aside.contains(at))) {
      e.preventDefault();
      first.focus();
    }
  };
  const uid = useId();
  const tabId = (k: string) => `${uid}-tab-${k}`;
  const curTab = tabs?.find((t) => t.key === tab)?.key ?? tabs?.[0]?.key;
  const onTabKey = (e: RKeyboardEvent<HTMLElement>) => {
    if (!tabs?.length) return;
    const i = tabs.findIndex((t) => t.key === curTab);
    const to = e.key === 'ArrowRight' ? (i + 1) % tabs.length : e.key === 'ArrowLeft' ? (i - 1 + tabs.length) % tabs.length : e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    onTab?.(tabs[to].key);
    asideRef.current?.querySelector<HTMLElement>(`#${CSS.escape(tabId(tabs[to].key))}`)?.focus();
  };
  const rich = subtitle != null || badges != null;

  const label = typeof title === 'string' ? title : '상세';
  const layer = (
    <div
      className={`sg-sheet-layer${still ? ' still' : ''}${closing ? ' closing' : ''}`}
      data-layer={kind}
      onClick={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <aside
        ref={asideRef}
        data-sheet={kind}
        data-size={size}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        tabIndex={-1}
        onKeyDown={trap}
        className="sg-card sg-sheet flex min-h-0 flex-col overflow-hidden"
      >
        <header className={`sg-sheet-head flex shrink-0 items-center gap-3${tabs?.length ? '' : ' border-b border-border'}`} data-rich={rich ? '' : undefined}>
          {rich ? (
            <div className="min-w-0 flex-1">
              <div className="flex min-w-0 items-center gap-2">
                <h2 className="min-w-0 truncate text-base font-semibold text-text">{title}</h2>
                {badges != null && (
                  <span className="flex shrink-0 items-center gap-1.5" data-part="sheet-badges">
                    {badges}
                  </span>
                )}
              </div>
              {subtitle != null && (
                <p className="tk-sheet-sub truncate" data-part="sheet-subtitle">
                  {subtitle}
                </p>
              )}
            </div>
          ) : (
            <h2 className="min-w-0 flex-1 truncate text-base font-semibold text-text">{title}</h2>
          )}
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
        {!!tabs?.length && (
          <div role="tablist" aria-label={`${label} 탭`} className="tk-sheet-tabs" data-part="sheet-tabs" onKeyDown={onTabKey}>
            {tabs.map((t) => {
              const on = t.key === curTab;
              return (
                <button
                  key={t.key}
                  id={tabId(t.key)}
                  type="button"
                  role="tab"
                  data-tab={t.key}
                  aria-selected={on}
                  aria-controls={`${uid}-panel`}
                  tabIndex={on ? 0 : -1}
                  className="tk-sheet-tab"
                  onClick={() => !on && onTab?.(t.key)}
                >
                  {t.label}
                  {t.count != null && (
                    <span className="tk-tab-count num" data-part="tab-count">
                      {t.count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}
        <div
          className="sg-sheet-body min-h-0 flex-1 overflow-y-auto"
          {...(tabs?.length && curTab ? { role: 'tabpanel', id: `${uid}-panel`, 'aria-labelledby': tabId(curTab) } : {})}
        >
          {children}
        </div>
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
