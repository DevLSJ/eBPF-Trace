import { FileText } from "lucide-react";
import { Link } from "react-router-dom";
import { Empty, LoadError, Panel } from "../../components/Panel";
import { ChartRow, KpiRow, RangeChips, TopPanel } from "./Overview";
import { useSummary } from "./summary";
import { SignalPills } from "./SignalPills";
import { LevelBadge } from "../../components/VerdictBadge";
import { useCases } from "../../hooks/cases-context";
import { useStream } from "../../hooks/stream-context";
import { fmtNum } from "../../lib/format";
import { TimeText } from "../../components/list/cells";
import { scanHref, SOURCE_LABEL } from "../../lib/guide";
import { installDest, topologyDest } from "../../lib/nav";
import { caseLabel, type Case } from "../../lib/types";
import "./dashboard.css";
import { IntegrateBanner } from "../integration/IntegrateBanner";

// 대시보드 — 「지금 처리할 일이 있나?」(판정 대기) + 「지금까지 무엇을 수집 · 탐지했나?」(eBPF 수집 종합, 10/16)
// 11/04e 재배치(R2 11/04, 목업 mock/README.md 11/04e A): 머리 한 줄(상태 신호등 · 「eBPF 감시 중」 · 기간) → KPI 6칸(종합 카드 밖 독립 줄, 길게 눌러 옮기기)
//   → 차트 줄 3칸(수집량 추이 1.8 : 위반 추이 1 : 설치 검사 결과 1.2) → 아래 3칸(판정 대기 · 많이 걸린 정책 · 위반 많은 컨테이너 — 남은 높이 채움, 몸통만 스크롤).
//   768 이상은 화면 안에 다 들어간다(스크롤 0). 시연 카드는 대시보드에서 뺐다(R3 시연 페이지, 사용자 결정 R2 11/04)
export function DashboardPage() {
  const { stats } = useStream();
  const { range, setRange, sum } = useSummary();
  const s = sum.data ?? null;
  return (
    <div data-part="dashboard" data-section="overview" className="sg-dash">
      <IntegrateBanner />
      <div data-part="dash-top" className="sg-dash-top">
        <SignalPills />
        <span
          data-part="dash-live"
          className="sg-dash-live flex items-center gap-1.5 text-xs text-text-3"
        >
          <span className="size-2 sg-blink rounded-full bg-ok" aria-hidden />
          eBPF 감시 중 · 초당{" "}
          <span className="num">
            {fmtNum(Math.round((stats?.eventsPerSec ?? 0) * 10) / 10)}
          </span>{" "}
          evt
        </span>
        <RangeChips range={range} onPick={setRange} />
      </div>
      <KpiRow s={s} range={range} error={sum.error} />
      <ChartRow s={s} />
      <div data-part="bottom" className="sg-dash-bottom">
        <Pending />
        <TopPanel kind="rules" s={s} />
        <TopPanel kind="containers" s={s} />
      </div>
    </div>
  );
}

// 판정 대기 — 설치 · 런타임 · 공급망 검사 건(열린 것), 최근 순. 판정했지만 적용 전인 제안은 바닥줄 한 줄
function Pending() {
  const { cases, error } = useCases();
  const pending = (cases ?? [])
    .filter((c) => c.state === "open")
    .sort((a, b) => b.openedAt.localeCompare(a.openedAt));
  const awaitingApply = (cases ?? []).filter(
    (c) => c.state === "decided",
  ).length;
  return (
    <div data-card="pending" className="flex min-w-0">
      <Panel
        testId="pending"
        className="w-full"
        title={
          <span className="flex items-baseline gap-1.5">
            판정 대기
            <b
              className={`num text-base ${pending.length ? "text-warn-text" : "text-text-3"}`}
              data-testid="pending-count"
            >
              {cases ? pending.length : "—"}
            </b>
          </span>
        }
        sub="격리 · 경고된 설치 · 격리된 런타임"
        more={{ to: "/installs", label: "설치 검사" }}
        foot={
          awaitingApply > 0 && (
            <div className="sg-pend-foot">
              <Link
                to="/policies"
                className="text-accent hover:underline"
                data-testid="awaiting-apply"
              >
                적용 대기 제안 {awaitingApply}건 → 정책
              </Link>
            </div>
          )
        }
      >
        <div data-fill="" className="sg-dash-fill">
          {error && !cases ? (
            <LoadError error={error} what="건(판정 대기)" />
          ) : !cases ? (
            <Empty>불러오는 중…</Empty>
          ) : pending.length === 0 ? (
            <div
              className="flex h-full min-h-24 flex-col items-center justify-center gap-1.5 p-4 text-center text-text-3"
              data-testid="nothing-to-do"
            >
              {/* 빈 상태 아이콘 없음(11/05) · 「[무엇]이 없습니다.」 + 다음 일(11/09 SPEC §7) */}
              <b className="text-sm text-text-2">처리할 판정 대기 건이 없습니다.</b>
              <span className="text-xs">
                새 격리 · 경고가 생기면 여기에 판정 대기로 올라옵니다.
              </span>
            </div>
          ) : (
            <ul data-testid="pending-list">
              {pending.map((c) => (
                <PendingRow key={c.id} c={c} />
              ))}
            </ul>
          )}
        </div>
      </Panel>
    </div>
  );
}

const CHIP: Record<Case["source"], string> = {
  install: "bg-accent-soft text-accent-text",
  scan: "bg-warn-soft text-warn-text",
  runtime: "bg-info-soft text-info-text",
};
function PendingRow({ c }: { c: Case }) {
  const sh = scanHref(c);
  const to =
    c.source === "install" && c.installId
      ? installDest(c.installId, "pending")
      : sh
        ? { to: sh }
        : topologyDest(c.container);
  const bar =
    c.level === "killed" || c.level === "held" ? "bar-danger" : "bar-warn";
  return (
    <li className="sg-pend-row">
      {/* 한 행 두 단: 위 = 출처 · 대상 · 탐지 결과, 아래 = 걸린 규칙 · 위반 수 · 시각(1/3 폭 칸에서도 읽히게) */}
      <Link
        {...to}
        className={`sg-pend-link ${bar}`}
        data-case={c.id}
        data-source={c.source}
        aria-label={`${caseLabel(c)} 판정하기`}
      >
        <span
          className={`sg-pend-src rounded px-1.5 py-0.5 text-center text-xs font-medium whitespace-nowrap ${CHIP[c.source] ?? ""}`}
        >
          {SOURCE_LABEL[c.source] ?? c.source}
        </span>
        <span className="sg-pend-what">
          <span
            className="block truncate font-mono font-medium text-text"
            title={caseLabel(c)}
          >
            {caseLabel(c)}
          </span>
          <span className="block truncate text-xs text-text-3">
            {c.ruleIds.join(" · ")}
          </span>
        </span>
        <span className="sg-pend-badge">
          <LevelBadge level={c.level} />
        </span>
        <span className="sg-pend-meta" data-part="pend-meta">
          위반 {fmtNum(c.violations)} · <TimeText value={c.openedAt} kind="status" />
        </span>
        <span className="sg-pend-chev" aria-hidden>
          ›
        </span>
      </Link>
      {/* 건 보고서 1장(10/30 계약 §5) — 행 메뉴 「보고서」 */}
      <Link
        to={`/report?case=${encodeURIComponent(c.id)}`}
        data-action="report"
        title="건 보고서 1장"
        aria-label={`${caseLabel(c)} 보고서`}
        className="mr-1.5 inline-flex shrink-0 items-center rounded-md p-1.5 text-text-3 hover:bg-surface-2 hover:text-text"
      >
        <FileText className="size-3.5" aria-hidden />
      </Link>
    </li>
  );
}
