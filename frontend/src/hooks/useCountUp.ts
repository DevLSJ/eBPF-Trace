import { useEffect, useRef, useState } from 'react';

// 숫자가 바뀔 때 이전 값에서 새 값으로 짧게 세어 올라간다. 움직임 줄이기 설정이면 즉시 바꾼다.
export function useCountUp(value: number, duration = 600) {
  const [shown, setShown] = useState(value);
  const previous = useRef(value);
  useEffect(() => {
    const from = previous.current, to = value;
    previous.current = value;
    if (from === to) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || !Number.isFinite(from) || !Number.isFinite(to)) { setShown(to); return; }
    let raf = 0; const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration), eased = 1 - Math.pow(1 - t, 3);
      setShown(Math.round(from + (to - from) * eased));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value, duration]);
  return shown;
}
