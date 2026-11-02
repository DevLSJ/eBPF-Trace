import { useEffect, useRef, useState } from 'react';

// 숫자 변화 카운트업(10/30 계약 §7 모션, 600ms ease-out). prefers-reduced-motion: reduce 면 바로 바꾼다.
// 지금 보이는 값(shownRef)에서 새 값으로 간다 — StrictMode 의 효과 이중 실행에도 처음부터 다시 센다
const reduced = () => typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

export function useCountUp(value: number, ms = 600): number {
  const [shown, setShown] = useState(() => (reduced() ? value : 0));
  const shownRef = useRef(shown);
  useEffect(() => {
    const from = shownRef.current;
    if (from === value) return;
    const start = performance.now();
    const set = (n: number) => {
      shownRef.current = n;
      setShown(n);
    };
    let raf = requestAnimationFrame(function tick(t) {
      if (reduced()) {
        set(value);
        return;
      }
      const p = Math.min(1, (t - start) / ms);
      // 끝 3% 는 바로 목표값으로(같은 화면의 숫자들이 같은 프레임에 끝나도록)
      const e = p >= 0.97 ? 1 : 1 - (1 - p) ** 3;
      set(Math.round(from + (value - from) * e));
      if (p < 1) raf = requestAnimationFrame(tick);
    });
    return () => cancelAnimationFrame(raf);
  }, [value, ms]);
  return shown;
}
