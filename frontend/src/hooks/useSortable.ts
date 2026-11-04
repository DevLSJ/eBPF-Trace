import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { josa, LAYOUT_EVENT, mergeLayout, readLayout, writeLayout, type LayoutScope } from '../lib/layout';
import { reducedMotion } from '../lib/motion';

// 길게 눌러 순서 바꾸기(11/04d 목업 shared/sortable.js 확정 동작, R1 11/04). 의존성 없음 — Pointer Events + FLIP.
//   적용: 사이드바(묶음 안에서만, 대시보드 고정) · 평가 지표 6칸 · (R2) 대시보드 KPI. 화면마다 순서를 따로 기억(lib/layout.ts)
//   조작: 주 버튼(마우스 왼쪽 · 터치 · 펜)을 0.4초 누르면 「집힘」(떠오름 · grabbing · 놓일 자리 점선) → 끌면 같은 묶음 안에서 자리가 바뀌고 → 놓으면 저장.
//     0.4초 전에 떼면 클릭 그대로 · 0.4초 안에 8px 넘게 움직이면 취소(텍스트 선택 · 스크롤 그대로) · 집은 뒤 떼면 클릭 · 링크 이동 없음 · Esc 는 원래 자리(서랍 · 메뉴의 Esc 보다 먼저)
//   키보드: 항목 포커스 + Alt+↑/↓(그리드는 Alt+←/→ 도) 한 칸, 포커스 유지. aria-live(polite) 알림 · 항목마다 aria-describedby 로 사용법 한 줄
//   터치: 집힌 뒤 touchmove 를 막아 화면이 스크롤되지 않고, 길게 누르기 메뉴 · 링크 끌기를 막는다(touch-action 은 그대로)
//   prefers-reduced-motion 이면 다른 항목이 미끄러지는 애니메이션(FLIP) · 제자리로 돌아가는 움직임이 없다
// 쓰는 쪽: 컨테이너에 ref · className={sort.containerClass}, 항목(컨테이너의 직계 자식)은 sort.order 순서로 그리고 {...sort.itemProps(id)} · sort.pickedClass(id)
export const HOLD_MS = 400;
export const SLOP = 8;

// ── 알림(스크린 리더) — 화면에 하나 ──
function ensureA11y() {
  if (document.getElementById('sg-sort-live')) return;
  const live = document.createElement('div');
  live.id = 'sg-sort-live';
  live.className = 'sg-sr-only';
  live.setAttribute('role', 'status');
  live.setAttribute('aria-live', 'polite');
  const help = document.createElement('div');
  help.id = 'sg-sort-help';
  help.className = 'sg-sr-only';
  help.textContent = '길게 눌러 끌거나 Alt+화살표로 순서를 바꿉니다';
  document.body.append(live, help);
}
let liveTimer = 0;
function announce(text: string) {
  ensureA11y();
  const el = document.getElementById('sg-sort-live')!;
  el.textContent = '';
  window.clearTimeout(liveTimer);
  liveTimer = window.setTimeout(() => (el.textContent = text), 30); // 같은 문장도 다시 읽히게 비웠다가 채운다
}

// ── 진행 중인 끌기(한 번에 하나) · 클릭 삼키기 — 창 전체 리스너는 한 번만 ──
let active: { picked: () => boolean; escape: () => void } | null = null;
let swallowUntil = 0;
let installed = false;
function installGlobal() {
  if (installed) return;
  installed = true;
  window.addEventListener(
    'click',
    (e) => {
      if (performance.now() < swallowUntil) {
        swallowUntil = 0;
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    },
    true,
  );
  window.addEventListener('pointerdown', () => (swallowUntil = 0), true); // 새로 누르면 새 클릭 — 삼키지 않는다
  window.addEventListener(
    'keydown',
    (e) => {
      if (active && e.key === 'Escape') {
        e.preventDefault();
        e.stopImmediatePropagation();
        active.escape();
      }
    },
    true,
  );
  document.addEventListener('touchmove', (e) => active?.picked() && e.cancelable && e.preventDefault(), { passive: false });
  window.addEventListener('contextmenu', (e) => active && e.preventDefault(), true);
}
const clearSelection = () => {
  try {
    getSelection()?.removeAllRanges();
  } catch {
    /* 없음 */
  }
};
const same = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

interface Drag {
  id: string;
  pid: number;
  x0: number;
  y0: number;
  x: number;
  y: number;
  timer: number;
  picked: boolean;
  cancelled: boolean;
  bx: number;
  by: number;
  from: string[];
}

export function useSortable<E extends HTMLElement = HTMLElement>({
  scope,
  ids,
  layout = 'list',
  labelOf,
  focusable = true,
  onEnd,
}: {
  scope: LayoutScope;
  // 기본 순서(지금 그릴 수 있는 항목 전부)
  ids: string[];
  layout?: 'list' | 'grid';
  labelOf: (id: string) => string;
  // 항목이 이미 포커스를 받는 요소(링크 · 버튼)인가 — 아니면 tabIndex 0 을 준다(평가 지표 칸)
  focusable?: boolean;
  // 끌기 · 누르기가 끝났을 때(미뤄 둔 다시 그리기 — R2 대시보드)
  onEnd?: () => void;
}) {
  const ref = useRef<E>(null);
  const [saved, setSaved] = useState(() => readLayout(scope));
  const [live, setLive] = useState<string[] | null>(null);
  const [picked, setPicked] = useState<string | null>(null);
  const order = live ?? mergeLayout(saved, ids);
  const grid = layout === 'grid';

  const st = useRef<Drag | null>(null);
  const flipFrom = useRef<Map<string, DOMRect> | null>(null);
  const refocus = useRef<string | null>(null);
  const marker = useRef<HTMLDivElement | null>(null);
  // 최신 값 — 창 리스너(한 번 붙임)가 읽는다
  const cur = useRef({ order, labelOf, onEnd, grid });
  useLayoutEffect(() => {
    cur.current = { order, labelOf, onEnd, grid };
  });

  // 설정 「화면 배치 기본 순서로」 → 저장값을 다시 읽는다(열린 사이드바는 바로 기본 순서)
  useEffect(() => {
    ensureA11y();
    installGlobal();
    const on = () => setSaved(readLayout(scope));
    document.addEventListener(LAYOUT_EVENT, on);
    return () => document.removeEventListener(LAYOUT_EVENT, on);
  }, [scope]);

  const items = useCallback(
    () => (ref.current ? [...ref.current.children].filter((e): e is HTMLElement => e instanceof HTMLElement && e.dataset.sortScope === scope) : []),
    [scope],
  );
  const itemOf = useCallback((id: string) => items().find((e) => e.dataset.sortId === id) ?? null, [items]);
  // 다른 항목이 옮긴 자리로 미끄러지게(FLIP) — 바꾸기 직전 자리를 적어 둔다
  const snapshot = useCallback(() => {
    if (reducedMotion()) return;
    flipFrom.current = new Map(items().map((e) => [e.dataset.sortId!, e.getBoundingClientRect()]));
  }, [items]);

  // 그린 뒤: FLIP · 집은 항목이 포인터를 따라감 · 자리 표시 · 키보드로 옮긴 항목에 포커스
  useLayoutEffect(() => {
    const from = flipFrom.current;
    flipFrom.current = null;
    const d = st.current;
    if (from) {
      const others = items().filter((e) => !(d?.picked && e.dataset.sortId === d.id));
      for (const e of others) {
        e.style.transition = 'none';
        e.style.transform = '';
      }
      const moved: HTMLElement[] = [];
      for (const e of others) {
        const a = from.get(e.dataset.sortId!);
        if (!a) continue;
        const b = e.getBoundingClientRect();
        const dx = a.left - b.left;
        const dy = a.top - b.top;
        if (Math.abs(dx) > 0.5 || Math.abs(dy) > 0.5) {
          e.style.transform = `translate(${dx}px, ${dy}px)`;
          moved.push(e);
        } else e.style.transition = '';
      }
      if (moved.length) {
        void ref.current?.offsetWidth;
        for (const e of moved) {
          e.style.transition = 'transform var(--t-base) var(--ease)';
          e.style.transform = '';
        }
        window.setTimeout(() => moved.forEach((e) => !e.style.transform && (e.style.transition = '')), 260);
      }
    }
    if (d?.picked && !d.cancelled) {
      follow();
      placeMarker();
    }
    if (refocus.current) {
      itemOf(refocus.current)?.focus({ preventScroll: true });
      refocus.current = null;
    }
  });

  function follow() {
    const d = st.current;
    const el = d && itemOf(d.id);
    if (!d || !el) return;
    el.style.transform = `translate(${d.x - d.x0 - (el.offsetLeft - d.bx)}px, ${d.y - d.y0 - (el.offsetTop - d.by)}px) scale(1.03)`;
  }
  function placeMarker() {
    const d = st.current;
    const el = d && itemOf(d.id);
    const m = marker.current;
    if (!el || !m) return;
    Object.assign(m.style, { left: `${el.offsetLeft}px`, top: `${el.offsetTop}px`, width: `${el.offsetWidth}px`, height: `${el.offsetHeight}px` });
  }
  // 항목의 레이아웃 자리(변환 무시) — 컨테이너는 position: relative(.sg-sortable)라 offsetParent 다
  function layoutRect(el: HTMLElement) {
    const c = ref.current!.getBoundingClientRect();
    const left = c.left + ref.current!.clientLeft - ref.current!.scrollLeft + el.offsetLeft;
    const top = c.top + ref.current!.clientTop - ref.current!.scrollTop + el.offsetTop;
    return { left, top, right: left + el.offsetWidth, bottom: top + el.offsetHeight, width: el.offsetWidth, height: el.offsetHeight };
  }
  // 포인터 자리 → 몇 번째(끄는 항목을 뺀 목록 기준). 목록은 세로 가운데, 그리드는 읽는 순서(줄 위 → 같은 줄 왼쪽 절반)
  function targetIndex(d: Drag) {
    const others = items().filter((e) => e.dataset.sortId !== d.id);
    for (let i = 0; i < others.length; i++) {
      const r = layoutRect(others[i]);
      if (cur.current.grid ? d.y < r.top || (d.y <= r.bottom && d.x < r.left + r.width / 2) : d.y < r.top + r.height / 2) return [i, others] as const;
    }
    return [others.length, others] as const;
  }
  function settle(el: HTMLElement | null) {
    if (!el) return;
    if (reducedMotion()) {
      el.style.transform = '';
      el.style.transition = '';
      return;
    }
    el.style.transition = 'transform var(--t-base) var(--ease)';
    el.style.transform = '';
    window.setTimeout(() => !el.style.transform && (el.style.transition = ''), 260);
  }
  function dropMarker() {
    marker.current?.remove();
    marker.current = null;
  }

  function pick() {
    const d = st.current;
    const el = d && itemOf(d.id);
    if (!d || !el) return end();
    d.picked = true;
    d.from = cur.current.order.slice();
    d.bx = el.offsetLeft;
    d.by = el.offsetTop;
    const m = document.createElement('div');
    m.className = 'sg-sort-marker';
    m.setAttribute('aria-hidden', 'true');
    ref.current?.append(m);
    marker.current = m;
    placeMarker();
    document.documentElement.classList.add('sg-sorting');
    clearSelection();
    follow();
    setLive(d.from.slice());
    setPicked(d.id);
  }
  function drop() {
    const d = st.current!;
    const label = cur.current.labelOf(d.id);
    const now = cur.current.order.slice();
    settle(itemOf(d.id));
    dropMarker();
    if (same(now, d.from)) announce(`${label}${josa(label, ['을', '를'])} 제자리에 놓음`);
    else {
      writeLayout(scope, now);
      announce(`${label}${josa(label, ['을', '를'])} ${now.indexOf(d.id) + 1}번째로 옮김`);
    }
    setSaved(now);
    setLive(null);
    setPicked(null);
  }
  function escape() {
    const d = st.current;
    if (!d || d.cancelled) return;
    if (!d.picked) return end();
    snapshot();
    settle(itemOf(d.id));
    dropMarker();
    announce('순서 바꾸기를 취소함');
    d.cancelled = true; // 놓을 때 클릭을 삼킨다
    document.documentElement.classList.remove('sg-sorting');
    setLive(null);
    setPicked(null);
  }
  function end() {
    const d = st.current;
    if (!d) return;
    window.clearTimeout(d.timer);
    window.removeEventListener('pointermove', onMove, true);
    window.removeEventListener('pointerup', onUp, true);
    window.removeEventListener('pointercancel', onCancel, true);
    document.documentElement.classList.remove('sg-sorting');
    st.current = null;
    active = null;
    cur.current.onEnd?.();
  }
  function onMove(e: PointerEvent) {
    const d = st.current;
    if (!d || e.pointerId !== d.pid) return;
    d.x = e.clientX;
    d.y = e.clientY;
    if (d.cancelled) return;
    if (!d.picked) {
      if (Math.hypot(d.x - d.x0, d.y - d.y0) > SLOP) end();
      return;
    }
    e.preventDefault();
    clearSelection();
    follow();
    const [idx, others] = targetIndex(d);
    const o = cur.current.order;
    if (idx === o.indexOf(d.id)) return;
    const next = others.map((x) => x.dataset.sortId!);
    next.splice(idx, 0, d.id);
    if (same(next, o)) return;
    snapshot();
    cur.current = { ...cur.current, order: next };
    setLive(next);
  }
  function onUp(e: PointerEvent) {
    const d = st.current;
    if (!d || e.pointerId !== d.pid) return;
    if (d.picked && !d.cancelled) drop();
    if (d.picked || d.cancelled) swallowUntil = performance.now() + 400; // 집은 뒤 떼면 클릭 · 링크 이동 없음
    end();
  }
  function onCancel(e: PointerEvent) {
    const d = st.current;
    if (!d || e.pointerId !== d.pid) return;
    if (d.picked && !d.cancelled) escape();
    end();
  }

  // 컨테이너 리스너(네이티브 — 창 리스너와 같은 단계에서 다룬다)
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const onDown = (e: PointerEvent) => {
      if (st.current || active || !e.isPrimary) return;
      if (e.pointerType === 'mouse' && (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey)) return;
      const el = (e.target as Element).closest?.<HTMLElement>('[data-sort-id]');
      if (!el || el.parentElement !== c || el.dataset.sortScope !== scope) return;
      const inner = (e.target as Element).closest('button, input, select, textarea, [contenteditable]');
      if (inner && inner !== el && el.contains(inner)) return; // 칸 안의 버튼 · 입력은 그대로
      st.current = {
        id: el.dataset.sortId!,
        pid: e.pointerId,
        x0: e.clientX,
        y0: e.clientY,
        x: e.clientX,
        y: e.clientY,
        timer: window.setTimeout(pick, HOLD_MS),
        picked: false,
        cancelled: false,
        bx: 0,
        by: 0,
        from: [],
      };
      active = { picked: () => !!(st.current?.picked && !st.current.cancelled), escape };
      window.addEventListener('pointermove', onMove, true);
      window.addEventListener('pointerup', onUp, true);
      window.addEventListener('pointercancel', onCancel, true);
    };
    // 링크 · 이미지의 기본 끌기(HTML5 drag)는 쓰지 않는다
    const onDrag = (e: DragEvent) => {
      const el = (e.target as Element).closest?.('[data-sort-id]');
      if (el && el.parentElement === c) e.preventDefault();
    };
    // 키보드: Alt+↑/↓(그리드는 ←/→ 도) 한 칸
    const onKey = (e: KeyboardEvent) => {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      const el = e.target as HTMLElement;
      if (!el.dataset?.sortId || el.parentElement !== c || el.dataset.sortScope !== scope) return;
      const g = cur.current.grid;
      const prev = e.key === 'ArrowUp' || (g && e.key === 'ArrowLeft');
      const next = e.key === 'ArrowDown' || (g && e.key === 'ArrowRight');
      if (!prev && !next) return;
      e.preventDefault();
      e.stopPropagation();
      if (st.current) return;
      const id = el.dataset.sortId;
      const o = cur.current.order.slice();
      const i = o.indexOf(id);
      const j = i + (prev ? -1 : 1);
      const label = cur.current.labelOf(id);
      if (j < 0 || j >= o.length) return announce(`${label}${josa(label, ['은', '는'])} 이미 ${prev ? '맨 앞' : '맨 끝'}입니다`);
      o.splice(i, 1);
      o.splice(j, 0, id);
      snapshot();
      writeLayout(scope, o);
      refocus.current = id;
      cur.current = { ...cur.current, order: o };
      setSaved(o);
      announce(`${label}${josa(label, ['을', '를'])} ${j + 1}번째로 옮김`);
    };
    c.addEventListener('pointerdown', onDown);
    c.addEventListener('dragstart', onDrag);
    c.addEventListener('keydown', onKey);
    return () => {
      c.removeEventListener('pointerdown', onDown);
      c.removeEventListener('dragstart', onDrag);
      c.removeEventListener('keydown', onKey);
    };
    // 함수들은 ref(cur · st)로 최신 값을 읽는다 — 한 번만 붙인다
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope]);

  return {
    ref,
    order,
    picked,
    containerClass: 'sg-sortable',
    itemProps: (id: string) => ({ 'data-sort-id': id, 'data-sort-scope': scope, 'aria-describedby': 'sg-sort-help', ...(focusable ? {} : { tabIndex: 0 }) }),
    pickedClass: (id: string) => (picked === id ? 'sg-sort-picked' : ''),
  };
}
