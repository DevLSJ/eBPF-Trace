import { useCallback, useEffect, useRef } from "react";
import { useStream } from "../../hooks/stream-context";
import { useFilters } from "../../hooks/useFilters";
import { useInterval, useLoad } from "../../hooks/useLoad";
import { api } from "../../lib/api";
import type { SummaryRange } from "../../lib/types";

// 대시보드 종합(GET /api/summary) 기간 · 불러오기(R2 11/04 — Overview.tsx 에서 뺌: 화면 부품 파일은 부품만 내보낸다)
export const RANGES: [SummaryRange, string][] = [
  ["1h", "1시간"],
  ["24h", "24시간"],
  ["7d", "7일"],
];
export const RANGE_KO = Object.fromEntries(RANGES) as Record<string, string>;

// 기간 · 종합 불러오기 — 30초마다, 새 위반(WS)이 들어오면 잠깐 모았다가 다시 계산
export function useSummary() {
  const { subscribe } = useStream();
  // 기간은 화면 상태로만(10/21, 주소에 남기지 않음)
  const [filters, setFilters] = useFilters("/");
  const range = (
    RANGES.some(([r]) => r === filters.range) ? filters.range : "24h"
  ) as SummaryRange;
  const load = useCallback(() => api.summary(range), [range]);
  const sum = useLoad(load);
  const { reload } = sum;
  useInterval(reload, 30_000);
  const timer = useRef<number | undefined>(undefined);
  useEffect(
    () =>
      subscribe((m) => {
        if (m.type !== "verdict" || !m.data.matched) return;
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(reload, 800);
      }),
    [subscribe, reload],
  );
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return {
    range,
    setRange: (r: SummaryRange) => setFilters({ range: r }),
    sum,
  };
}
