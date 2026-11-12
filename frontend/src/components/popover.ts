import { useEffect, useRef, type CSSProperties, type RefObject } from 'react';

// 펼침 상자 공통(11/09 — 칸 고르기 · 필터 Select): 트리거 바로 아래(자리가 모자라면 위) · 트리거 폭 이상 · 화면 안.
// 잘리지 않게 body 에 붙이고, 모달(<dialog>) 안이면 그 dialog 에 붙인다(top layer 밖은 눌리지 않는다).
// 바깥 누르기 · Esc · 창 크기 · 스크롤을 여기서 듣는다. 붙는 상자에는 data-overlay 를 달아 시트 · 셸의 Esc 가 먼저 가져가지 않게 한다.
export interface Pop {
  style: CSSProperties;
  host: HTMLElement;
}

export function placePop(anchor: HTMLElement, { align = 'start', maxH = 288, gap = 4 }: { align?: 'start' | 'end'; maxH?: number; gap?: number } = {}): Pop {
  const r = anchor.getBoundingClientRect();
  const below = innerHeight - r.bottom - gap - 8;
  const above = r.top - gap - 8;
  const up = below < Math.min(maxH, 200) && above > below;
  const style: CSSProperties = { position: 'fixed', minWidth: Math.round(r.width), maxHeight: Math.max(120, Math.min(maxH, up ? above : below)) };
  if (align === 'end') style.right = Math.max(8, Math.round(innerWidth - r.right));
  else style.left = Math.max(8, Math.round(r.left));
  if (up) style.bottom = Math.round(innerHeight - r.top + gap);
  else style.top = Math.round(r.bottom + gap);
  return { style, host: (anchor.closest('dialog') as HTMLElement | null) ?? document.body };
}

// 열려 있는 동안: 바깥(트리거 · 상자 밖) 누르면 onClose(false), Esc 면 onClose(true) — true 는 「트리거로 초점」
// 창 크기 · 스크롤이 바뀌면 onMove 로 자리를 다시 잡는다
export function usePopEvents(open: boolean, refs: RefObject<HTMLElement | null>[], onClose: (focusBack: boolean) => void, onMove: () => void) {
  const fns = useRef({ refs, onClose, onMove });
  useEffect(() => {
    fns.current = { refs, onClose, onMove };
  });
  useEffect(() => {
    if (!open) return;
    const inside = (t: EventTarget | null) => fns.current.refs.some((r) => !!r.current && t instanceof Node && r.current.contains(t));
    const down = (e: PointerEvent) => {
      if (!inside(e.target)) fns.current.onClose(false);
    };
    const key = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.preventDefault(); // 모달 안이면 창 닫기(cancel)도 막는다
      e.stopPropagation();
      fns.current.onClose(true);
    };
    const move = (e: Event) => {
      // 상자 안 목록 스크롤은 자리와 상관없다
      if (e.type === 'scroll' && inside(e.target)) return;
      fns.current.onMove();
    };
    document.addEventListener('pointerdown', down, true);
    document.addEventListener('keydown', key, true);
    window.addEventListener('resize', move);
    window.addEventListener('scroll', move, true);
    return () => {
      document.removeEventListener('pointerdown', down, true);
      document.removeEventListener('keydown', key, true);
      window.removeEventListener('resize', move);
      window.removeEventListener('scroll', move, true);
    };
  }, [open]);
}

// 화면 읽기 프로그램 알림(칸 옮김 등) — 화면에 하나
export function announce(text: string) {
  let el = document.getElementById('sg-tk-live');
  if (!el) {
    el = document.createElement('div');
    el.id = 'sg-tk-live';
    el.className = 'sg-sr-only';
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
    document.body.append(el);
  }
  const live = el;
  live.textContent = '';
  window.setTimeout(() => (live.textContent = text), 30);
}
