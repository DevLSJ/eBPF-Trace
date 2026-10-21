import { ShieldCheck, X } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useCases } from '../hooks/cases-context';
import { useStream } from '../hooks/stream-context';
import { useToast } from '../hooks/toast-context';
import { loadSetup, pendingGuides, pickCase, recentCases, saveSetup, SOURCE_LABEL } from '../lib/guide';
import { caseLabel } from '../lib/types';
import { ChatPanel } from './ChatPanel';
import { GuidePanel } from './GuidePanel';

// 오른쪽 아래 「도우미」 버튼 하나 → 패널(10/20 확정, 목업 shared/guide.js).
// 탭: 「대응 가이드」 + 「AI 도우미」(10/20 W13 — /api/info chat 이 true 일 때만. 아니면 가이드 하나).
// AI 도우미 본문은 패널이 닫혀도 남아 있어 화면을 옮기는 동안에도 답을 계속 받는다.
// - 새 건이 열리면 대시보드에서만 자동으로 연다. 다른 화면은 배지 + 왼쪽 아래 토스트 「가이드 열기」
//   (떠 있는 패널이 상세 시트의 판정 칸 · 정책 편집기 「저장 후 적용」을 가린다 — 목업 실측)
// - 화면을 옮기거나 가이드 안의 링크를 누르면 닫힌다(배지는 남음). Esc 로 닫히고 포커스는 연 곳으로
type TabId = 'guide' | 'chat';
const GUIDE_TAB = { id: 'guide', label: '대응 가이드' } as const;
const CHAT_TAB = { id: 'chat', label: 'AI 도우미' } as const;

export function Assistant() {
  const { cases, error } = useCases();
  const { subscribe, info } = useStream();
  const chatOn = info?.chat === true;
  const TABS = chatOn ? [GUIDE_TAB, CHAT_TAB] : [GUIDE_TAB];
  const toast = useToast();
  const { pathname, search } = useLocation();
  const [open, setOpen] = useState(false);
  const [tabSel, setTab] = useState<TabId>('guide');
  const tab: TabId = tabSel === 'chat' && !chatOn ? 'guide' : tabSel;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [, setRev] = useState(0);
  const bump = useCallback(() => setRev((n) => n + 1), []);
  const fabRef = useRef<HTMLButtonElement>(null);
  const tabRefs = useRef(new Map<TabId, HTMLButtonElement>());
  const opener = useRef<Element | null>(null);
  const known = useRef<Set<string> | null>(null);
  const pathRef = useRef(pathname);
  const focusTab = useRef(false);

  // 화면(경로 · 쿼리)이 바뀌면 닫는다 — 포커스는 건드리지 않는다
  const loc = pathname + search;
  const [prevLoc, setPrevLoc] = useState(loc);
  if (loc !== prevLoc) {
    setPrevLoc(loc);
    setOpen(false);
  }

  useEffect(() => {
    pathRef.current = pathname;
    // 구축 순서 ② 정책 확인: 정책 화면을 한 번 열면 완료
    if (pathname === '/policies' && !loadSetup().visitedPolicies) saveSetup({ ...loadSetup(), visitedPolicies: true });
  }, [pathname]);

  const openRef = useRef(open);
  useEffect(() => {
    openRef.current = open;
  }, [open]);

  const show = useCallback((id: TabId = 'guide') => {
    if (!openRef.current) opener.current = document.activeElement;
    openRef.current = true;
    setOpen(true);
    setTab(id);
    focusTab.current = true;
  }, []);

  const close = useCallback((silent?: boolean) => {
    openRef.current = false;
    setOpen(false);
    const back = opener.current && opener.current.isConnected && opener.current !== document.body ? opener.current : fabRef.current;
    opener.current = null;
    if (!silent && back instanceof HTMLElement) back.focus();
  }, []);

  useEffect(() => {
    if (open && focusTab.current) {
      focusTab.current = false;
      // AI 도우미 탭은 입력 칸에 포커스(ChatPanel 이 한다)
      if (tab !== 'chat') tabRefs.current.get(tab)?.focus();
    }
  }, [open, tab]);

  // Esc: 패널만 닫는다(밑의 상세 시트까지 닫히지 않게 캡처 단계에서 멈춘다)
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.preventDefault();
      e.stopPropagation();
      close();
    };
    document.addEventListener('keydown', onKey, true);
    return () => document.removeEventListener('keydown', onKey, true);
  }, [open, close]);

  // 처음 받은 건(시드)은 「새 건」이 아니다
  useEffect(() => {
    if (!cases) return;
    if (!known.current) known.current = new Set();
    for (const c of cases) known.current.add(c.id);
  }, [cases]);

  // 새 건(WS {type:"case"} 의 처음 보는 id)이 열리면 그 건을 고르고, 대시보드면 연다 · 아니면 토스트
  useEffect(
    () =>
      subscribe((m) => {
        if (m.type !== 'case' || !known.current || known.current.has(m.data.id)) return;
        const c = m.data;
        known.current.add(c.id);
        if (c.state !== 'open') return;
        setSelectedId(c.id);
        if (pathRef.current === '/') show('guide');
        else
          toast(`대응 가이드 준비됨 — ${SOURCE_LABEL[c.source]} ${caseLabel(c)}`, {
            tone: 'warn',
            key: `guide:${c.id}`,
            action: { label: '가이드 열기', run: () => (setSelectedId(c.id), show('guide')) },
          });
      }),
    [subscribe, show, toast],
  );

  const list = cases ?? [];
  const pend = pendingGuides(list);

  return (
    <>
      <button
        ref={fabRef}
        type="button"
        data-part="assistant-fab"
        data-ready={String(cases !== null || error != null)}
        aria-label={pend ? `도우미 열기 — 미완료 가이드 ${pend}건` : '도우미 열기'}
        aria-expanded={open}
        aria-haspopup="dialog"
        onClick={() => (open ? close() : show(tab))}
        className="fixed right-6 bottom-6 z-[60] grid size-[52px] place-items-center rounded-full bg-indigo-600 text-white shadow-[0_6px_18px_rgba(79,70,229,.35)] hover:bg-indigo-700 focus-visible:outline-3 focus-visible:outline-offset-2 focus-visible:outline-indigo-200"
      >
        <ShieldCheck className="size-6" aria-hidden />
        <span
          data-part="assistant-badge"
          hidden={!pend}
          className={`num absolute -top-1 -right-1 min-w-5 rounded-full border-2 border-white bg-red-600 px-1 text-center text-[11px] leading-4 font-semibold text-white ${pend ? '' : 'hidden'}`}
        >
          {pend}
        </span>
      </button>
      <section
        data-part="assistant"
        role="dialog"
        aria-label="SupplyGuard 도우미"
        hidden={!open}
        className={`fixed right-6 bottom-[88px] z-[60] h-[min(600px,calc(100vh-112px))] w-[400px] flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-[0_12px_36px_rgba(15,23,42,.2)] ${open ? 'flex' : 'hidden'}`}
      >
        <header className="flex shrink-0 items-center gap-2 border-b border-slate-100 px-3 py-2.5">
          <ShieldCheck className="size-4 text-indigo-600" aria-hidden />
          <b className="text-sm text-slate-900">도우미</b>
          <button type="button" className="ml-auto rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700" aria-label="닫기" onClick={() => close()}>
            <X className="size-4" />
          </button>
        </header>
        <div role="tablist" aria-label="도우미" className="grid shrink-0 border-b border-slate-200" style={{ gridTemplateColumns: `repeat(${TABS.length}, 1fr)` }}>
          {TABS.map((t) => (
            <button
              key={t.id}
              ref={(el) => {
                if (el) tabRefs.current.set(t.id, el);
                else tabRefs.current.delete(t.id);
              }}
              type="button"
              role="tab"
              id={`assist-tab-${t.id}`}
              data-tab={t.id}
              aria-selected={tab === t.id}
              aria-controls={`assist-${t.id}`}
              onClick={() => setTab(t.id)}
              className={`border-b-2 py-2 text-[13px] font-medium ${tab === t.id ? 'border-indigo-600 text-indigo-700' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div
          role="tabpanel"
          id="assist-guide"
          aria-labelledby="assist-tab-guide"
          data-part="guide"
          // 목업은 data-case — React 는 대시보드 판정 대기 행의 data-case 와 겹쳐 이름을 바꿨다(10/20)
          data-guide-case={pickCase(recentCases(list), selectedId)?.id ?? ''}
          hidden={tab !== 'guide'}
          className="min-h-0 flex-1 overflow-y-auto p-3"
          // 가이드 안의 화면 이동 링크를 누르면 닫는다(열린 채 두면 오른쪽 시트의 판정 버튼 · 「적용」을 가린다)
          onClick={(e) => {
            if ((e.target as HTMLElement).closest('a[href^="/"]')) close(true);
          }}
        >
          {open && tab === 'guide' && <GuidePanel cases={list} selectedId={selectedId} onSelect={setSelectedId} onChange={bump} />}
        </div>
        {chatOn && (
          <div
            role="tabpanel"
            id="assist-chat"
            aria-labelledby="assist-tab-chat"
            hidden={tab !== 'chat'}
            className={`min-h-0 flex-1 flex-col ${tab === 'chat' ? 'flex' : 'hidden'}`}
            // 관련 화면 링크: 지금 화면과 같은 주소여도 닫는다(다른 주소면 화면 이동으로 닫힌다)
            onClick={(e) => {
              if ((e.target as HTMLElement).closest('a[href^="/"]')) close(true);
            }}
          >
            <ChatPanel active={open && tab === 'chat'} />
          </div>
        )}
      </section>
    </>
  );
}
