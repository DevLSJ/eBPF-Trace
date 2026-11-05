import { useEffect, type RefObject } from 'react';

// 페이지 대신 본문(main)만 스크롤되는 셸에서, 마우스 휠에 부드러운 관성을 준다.
// - 안쪽 스크롤 영역(표·드로어·대화상자)이 아직 더 스크롤될 수 있으면 그쪽을 우선한다.
// - 확대(ctrl+휠)·가로 휠·모달이 열린 동안은 브라우저 기본 동작에 맡긴다.
// - 움직임 줄이기(prefers-reduced-motion) 설정이면 아무것도 하지 않는다.
export function useSmoothScroll(ref: RefObject<HTMLElement | null>) {
  useEffect(() => {
    const el = ref.current;
    if (!el || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    let target: number | null = null, raf = 0;
    const step = () => {
      if (target === null) { raf = 0; return; }
      const diff = target - el.scrollTop;
      if (Math.abs(diff) < .5) { el.scrollTop = target; target = null; raf = 0; return; }
      el.scrollTop += diff * .22;
      raf = requestAnimationFrame(step);
    };
    const onScroll = () => { if (!raf) target = null; };
    const onWheel = (e: WheelEvent) => {
      if (e.ctrlKey || e.metaKey || Math.abs(e.deltaX) > Math.abs(e.deltaY)) return;
      if (document.querySelector('dialog[open], .notify-drawer')) return;
      for (let node = e.target as HTMLElement | null; node && node !== el; node = node.parentElement) {
        const style = getComputedStyle(node);
        if (/(auto|scroll)/.test(style.overflowY) && node.scrollHeight > node.clientHeight + 1) {
          const up = e.deltaY < 0;
          if ((up && node.scrollTop > 0) || (!up && node.scrollTop + node.clientHeight < node.scrollHeight - 1)) return;
        }
      }
      const max = el.scrollHeight - el.clientHeight;
      if (max <= 0) return;
      e.preventDefault();
      const delta = e.deltaMode === 1 ? e.deltaY * 40 : e.deltaMode === 2 ? e.deltaY * el.clientHeight : e.deltaY;
      if (target === null) target = el.scrollTop;
      target = Math.max(0, Math.min(max, target + delta));
      if (!raf) raf = requestAnimationFrame(step);
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    el.addEventListener('scroll', onScroll, { passive: true });
    return () => { el.removeEventListener('wheel', onWheel); el.removeEventListener('scroll', onScroll); cancelAnimationFrame(raf); };
  }, [ref]);
}
