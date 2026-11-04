import { useEffect, useRef, useState } from 'react';
import { countUpMs, reducedMotion } from '../lib/motion';

// 숫자 변화 카운트업(11/04e KPI 카드 · 11/04f 애니메이션 원칙, R1 11/04): 처음 그리기는 바로 값, 값이 바뀔 때만 ease-out 으로 센다.
// 길이는 모션 토큰(--t-slow × 2 = 640ms)에서 읽는다. prefers-reduced-motion: reduce 면 바로 바꾼다.
// 지금 보이는 값(shownRef)에서 새 값으로 간다 — StrictMode 의 효과 이중 실행에도 처음부터 다시 센다
export function useCountUp(value: number, ms?: number): number {
  const [shown, setShown] = useState(value);
  const shownRef = useRef(shown);
  useEffect(() => {
    const from = shownRef.current;
    if (from === value) return;
    const dur = ms ?? countUpMs();
    const start = performance.now();
    const set = (n: number) => {
      shownRef.current = n;
      setShown(n);
    };
    if (reducedMotion() || !Number.isFinite(from) || Math.abs(value - from) > 1e6) {
      set(value);
      return;
    }
    let raf = requestAnimationFrame(function tick(t) {
      const p = Math.min(1, (t - start) / dur);
      // 끝 3% 는 바로 목표값으로(같은 화면의 숫자들이 같은 프레임에 끝나도록)
      const e = p >= 0.97 ? 1 : 1 - (1 - p) ** 3;
      set(Math.round(from + (value - from) * e));
      if (p < 1) raf = requestAnimationFrame(tick);
    });
    return () => cancelAnimationFrame(raf);
  }, [value, ms]);
  return shown;
}
