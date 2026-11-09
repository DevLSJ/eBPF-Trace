import { useCallback, useEffect, useState } from 'react';
import { dialogOpen, loadJSON, saveJSON, typingTarget } from '../../lib/shell';

// E. 사이드바 접기(10/20 확정) — 목업 shared/shell-plus.js collapser.
// 넓은 화면: 누르면 접기/펼치기, 이 브라우저(localStorage)에 기억.
// 폭 단계(11/10 셸 배치 — 참고 사이트 원리): 1280 이상 = 글자 있는 사이드바 · 768~1279 = 아이콘만(자동) · 768 미만 = 서랍.
// 1279px 이하(옛 1100): 기본 접힘(아이콘만). 펼친 상태는 그 화면 동안만(저장하지 않고, 화면을 옮기거나 폭이 바뀌면 다시 접힘) — 본문 위에 겹쳐 뜬다. `[` 단축키
// 768px 미만(10/30 계약 §7): 사이드바는 서랍 — 제목 줄의 메뉴 버튼으로 열고(배경 dim), Esc · 이동 · 배경 누름으로 닫힌다
export const SIDEBAR_KEY = 'supplyguard.sidebar';
const NARROW = '(max-width: 1279px)';
const MOBILE = '(max-width: 767px)';

const matches = (q: string) => typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia(q).matches;
const narrowNow = () => matches(NARROW);

export function useSidebar(pathname: string) {
  const [narrow, setNarrow] = useState(narrowNow);
  const [mobile, setMobile] = useState(() => matches(MOBILE));
  const [pref, setPref] = useState<string>(() => loadJSON(SIDEBAR_KEY, 'expanded'));
  const [narrowOpen, setNarrowOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [prevPath, setPrevPath] = useState(pathname);
  if (pathname !== prevPath) {
    setPrevPath(pathname);
    setNarrowOpen(false);
    setMobileOpen(false);
  }

  useEffect(() => {
    const m = window.matchMedia(NARROW);
    const mm = window.matchMedia(MOBILE);
    const on = () => {
      setNarrow(m.matches);
      setMobile(mm.matches);
      setNarrowOpen(false);
      setMobileOpen(false);
    };
    m.addEventListener('change', on);
    mm.addEventListener('change', on);
    return () => {
      m.removeEventListener('change', on);
      mm.removeEventListener('change', on);
    };
  }, []);

  // 서랍은 늘 펼친 모양
  const collapsed = mobile ? false : narrow ? !narrowOpen : pref === 'collapsed';

  const toggle = useCallback(() => {
    if (mobile) {
      setMobileOpen((o) => !o);
      return;
    }
    if (narrow) {
      setNarrowOpen((o) => !o);
      return;
    }
    const next = pref === 'collapsed' ? 'expanded' : 'collapsed';
    saveJSON(SIDEBAR_KEY, next);
    setPref(next);
  }, [mobile, narrow, pref]);
  const openMobile = useCallback(() => setMobileOpen(true), []);
  const closeMobile = useCallback(() => setMobileOpen(false), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '[' || e.metaKey || e.ctrlKey || e.altKey || typingTarget(e) || dialogOpen()) return;
      e.preventDefault();
      toggle();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [toggle]);

  return { collapsed, narrow, mobile, mobileOpen, toggle, openMobile, closeMobile };
}
