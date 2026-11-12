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

// 기간 · 종합 불러오기 — 30초마다, 새 위반(WS)이 들어오면 잠깐 모았다가 다시 계산.
// 11/09 G31: 받은 시각(최종 갱신)을 같이 둔다 · G32: 탭이 가려져 있으면 갱신을 건너뛰고(건너뛴 것만 기억), 다시 보이면 바로 한 번
const hidden = () => document.visibilityState === "hidden";
export function useSummary() {
  const { subscribe } = useStream();
  // 기간은 화면 상태로만(10/21, 주소에 남기지 않음)
  const [filters, setFilters] = useFilters("/");
  const range = (
    RANGES.some(([r]) => r === filters.range) ? filters.range : "24h"
  ) as SummaryRange;
  const load = useCallback(
    () => api.summary(range).then((s) => ({ s, at: Date.now() })),
    [range],
  );
  const sum = useLoad(load);
  const { reload } = sum;
  // 가려진 동안 건너뛴 갱신이 있으면 true — 다시 보일 때 한 번 부르고 지운다
  const missed = useRef(false);
  const refresh = useCallback(() => {
    if (hidden()) missed.current = true;
    else reload();
  }, [reload]);
  useInterval(refresh, 30_000);
  useEffect(() => {
    const onVisible = () => {
      if (hidden() || !missed.current) return;
      missed.current = false;
      reload();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [reload]);
  const timer = useRef<number | undefined>(undefined);
  useEffect(
    () =>
      subscribe((m) => {
        if (m.type !== "verdict" || !m.data.matched) return;
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(refresh, 800);
      }),
    [subscribe, refresh],
  );
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return {
    range,
    setRange: (r: SummaryRange) => setFilters({ range: r }),
    data: sum.data?.s ?? null,
    error: sum.error,
    loading: sum.loading,
    // 마지막으로 받은 시각(ms) — 아직 없으면 null
    updatedAt: sum.data?.at ?? null,
    // 새로고침 단추: 가려져 있어도 누르면 바로
    reload,
  };
}
