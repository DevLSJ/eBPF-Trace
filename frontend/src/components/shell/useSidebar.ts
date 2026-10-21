import { useCallback, useEffect, useState } from 'react';
import { dialogOpen, loadJSON, saveJSON, typingTarget } from '../../lib/shell';

// E. 사이드바 접기(10/20 확정) — 목업 shared/shell-plus.js collapser.
// 넓은 화면: 누르면 접기/펼치기, 이 브라우저(localStorage)에 기억.
// 1100px 이하: 기본 접힘. 펼친 상태는 그 화면 동안만(저장하지 않고, 화면을 옮기거나 폭이 바뀌면 다시 접힘). `[` 단축키
export const SIDEBAR_KEY = 'supplyguard.sidebar';
const NARROW = '(max-width: 1100px)';

const narrowNow = () => typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia(NARROW).matches;

export function useSidebar(pathname: string) {
  const [narrow, setNarrow] = useState(narrowNow);
  const [pref, setPref] = useState<string>(() => loadJSON(SIDEBAR_KEY, 'expanded'));
  const [narrowOpen, setNarrowOpen] = useState(false);
  const [prevPath, setPrevPath] = useState(pathname);
  if (pathname !== prevPath) {
    setPrevPath(pathname);
    setNarrowOpen(false);
  }

  useEffect(() => {
    const m = window.matchMedia(NARROW);
    const on = () => {
      setNarrow(m.matches);
      setNarrowOpen(false);
    };
    m.addEventListener('change', on);
    return () => m.removeEventListener('change', on);
  }, []);

  const collapsed = narrow ? !narrowOpen : pref === 'collapsed';

  const toggle = useCallback(() => {
    if (narrow) {
      setNarrowOpen((o) => !o);
      return;
    }
    const next = pref === 'collapsed' ? 'expanded' : 'collapsed';
    saveJSON(SIDEBAR_KEY, next);
    setPref(next);
  }, [narrow, pref]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '[' || e.metaKey || e.ctrlKey || e.altKey || typingTarget(e) || dialogOpen()) return;
      e.preventDefault();
      toggle();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [toggle]);

  return { collapsed, narrow, toggle };
}
