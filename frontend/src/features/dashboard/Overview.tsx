import { Link } from "react-router-dom";
import {
  Donut,
  LineChart,
  StackBars,
  type Point,
} from "../../components/charts";
import { KpiCard } from "../../components/KpiCard";
import { Empty, LoadError, Panel } from "../../components/Panel";
import { useSortable } from "../../hooks/useSortable";
import { fmtNum } from "../../lib/format";
import {
  kpiDelta,
  type DeltaTone,
  type KpiDelta,
  type Stripe,
} from "../../lib/kpi";
import { dest, type Dest } from "../../lib/nav";
import type { Summary, SummaryRange, SummaryTop } from "../../lib/types";
import { RANGE_KO, RANGES } from "./summary";

// eBPF 수집 종합(10/16 · 11/04e 재배치, R2 11/04) — 저장된 기록(GET /api/summary) 기반이라 재시작해도 그대로.
//   KPI 6칸(길게 눌러 옮기기 dashboardKpi) · 차트 줄(수집량 추이 선 · 위반 추이 막대 · 설치 검사 결과 도넛) · 많이 걸린 정책 · 위반 많은 컨테이너.
//   KPI 증감 줄 = summary.previous(바로 앞 같은 길이 기간) — 위반 · 격리 증가만 빨강, 그 외 중립. previous 가 없으면(null · 옛 백엔드) 「이전 기간 정보 없음」
export function RangeChips({
  range,
  onPick,
}: {
  range: SummaryRange;
  onPick: (r: SummaryRange) => void;
}) {
  return (
    <div className="sg-range-chips flex gap-1.5" role="group" aria-label="기간">
      {RANGES.map(([r, ko]) => (
        <button
          key={r}
          type="button"
          data-range={r}
          aria-pressed={range === r}
          onClick={() => onPick(r)}
          className={`rounded-full border px-2.5 py-0.5 text-xs ${range === r ? "border-accent bg-accent text-text-inverse" : "border-border text-text-2 hover:bg-surface-2"}`}
        >
          {ko}
        </button>
      ))}
    </div>
  );
}

// ── KPI 6칸 ──
interface KpiDef {
  k: string;
  label: string;
  icon: string;
  stripe: Stripe;
  value: number | null;
  text?: string;
  unit?: string;
  tone?: "danger";
  delta: KpiDelta;
  sub: string;
  // 보조 줄 툴팁(정확한 값) — 없으면 sub 그대로
  subTitle?: string;
  to: Dest;
  // 카드 툴팁 — 무엇을 세는지 한 줄(11/09 G33)
  hint: string;
}
const KPI_IDS = [
  "collected",
  "violations",
  "isolated",
  "installs",
  "decided",
  "isolation",
];

const ISO_HINT = "탐지부터 격리까지 걸린 시간의 중앙값";
// 보조 줄 숫자(11/09 G34 · G36): 100만 이상은 만 단위(「235만」) — 한 칸에 숫자 3~4개가 들어가는 줄이라 값(1천만)보다 일찍 줄인다. 정확한 값은 툴팁
const subNum = (n: number) =>
  Math.abs(n) >= 1_000_000 ? `${fmtNum(Math.round(n / 10_000))}만` : fmtNum(n);

function kpiDefs(s: Summary, range: string): KpiDef[] {
  const P = s.previous ?? null;
  const note = `지난 ${RANGE_KO[range] ?? range} 대비`;
  // 위반 · 격리 증가 = danger, 수집 감소 · 격리 지연 증가 = warn, 나머지 중립(사용자 결정 R2 · 9dafb90 11/04)
  const D = (
    cur: number | null | undefined,
    prev: number | null | undefined,
    o: { up?: DeltaTone; down?: DeltaTone; unit?: string } = {},
  ) => kpiDelta(cur, P ? prev : null, { note, ...o });
  const k = s.collected.byKind;
  const iso = s.isolation;
  const decided = s.decisions.malicious + s.decisions.falsePositive;
  // 10/30: byKind.dns 는 선택(옛 백엔드 없음) — 있을 때만 「조회 N」
  const kinds = (f: (n: number) => string) =>
    `실행 ${f(k.exec)} · 파일 ${f(k.open)} · 통신 ${f(k.connect)}${k.dns !== undefined ? ` · 조회 ${f(k.dns)}` : ""}`;
  const vio = (f: (n: number) => string) =>
    `격리 ${f(s.violations.killed + s.violations.held)} · 경고 ${f(s.violations.alert)}`;
  const ins = (f: (n: number) => string) =>
    `통과 ${f(s.installs.passed)} · 격리 ${f(s.installs.isolated)} · 거부 ${f(s.installs.refused)}`;
  const dec = (f: (n: number) => string) =>
    `악성 ${f(s.decisions.malicious)} · 오탐 ${f(s.decisions.falsePositive)} · 대기 ${f(s.decisions.pending)}`;
  return [
    {
      k: "collected",
      label: "수집한 이벤트",
      icon: "≣",
      stripe: "info",
      value: s.collected.total,
      delta: D(s.collected.total, P?.collected, { down: "warn" }), // 수집 감소 = 감시 끊김 의심(11/04 사용자 — 목업과 같게)
      sub: kinds(subNum),
      subTitle: kinds(fmtNum),
      to: dest("/events", { normal: "1" }),
      hint: "이 기간에 커널에서 수집한 실행 · 파일 · 통신 · 조회 이벤트 수(같은 1분 안 같은 동작 반복은 1건)",
    },
    {
      k: "violations",
      label: "위반",
      icon: "⚠",
      stripe: "danger",
      tone: "danger",
      value: s.violations.total,
      delta: D(s.violations.total, P?.violations, { up: "danger" }),
      sub: vio(subNum),
      subTitle: vio(fmtNum),
      to: { to: "/audit" },
      hint: "이 기간에 정책에 걸린 이벤트 수(격리 · 경고)",
    },
    {
      k: "isolated",
      label: "격리한 컨테이너",
      icon: "⛔",
      stripe: "danger",
      tone: "danger",
      value: s.isolatedContainers,
      delta: D(s.isolatedContainers, P?.isolatedContainers, { up: "danger" }),
      sub: "설치 검사 포함",
      to: dest("/audit", { action: "kill" }),
      hint: "이 기간에 격리한 컨테이너 수(설치 검사 컨테이너 포함)",
    },
    {
      k: "installs",
      label: "설치 검사",
      icon: "▣",
      stripe: "accent",
      value: s.installs.total,
      delta: D(s.installs.total, P?.installs),
      sub: ins(subNum),
      subTitle: ins(fmtNum),
      to: dest("/installs", { status: "all" }),
      hint: "이 기간에 시작한 설치 검사 수",
    },
    {
      k: "decided",
      label: "판정 완료",
      icon: "✓",
      stripe: "ok",
      value: decided,
      delta: D(decided, P?.decided),
      sub: dec(subNum),
      subTitle: dec(fmtNum),
      to: { to: "/audit?view=changes" },
      hint: "이 기간에 악성 · 오탐 판정을 마친 건 수",
    },
    // 격리 지연(10/30 계약 §3): killedAt − detectedAt 의 중앙값. 기록이 없으면(count 0 · 옛 백엔드) 「—」
    iso?.count
      ? {
          k: "isolation",
          label: "격리 지연 중앙값",
          icon: "◷",
          stripe: "warn",
          value: iso.medianMs ?? 0,
          unit: "ms",
          delta: P
            ? D(iso.medianMs, P.isolationMedianMs, { unit: " ms", up: "warn" })
            : kpiDelta(null, null),
          sub: `p95 ${fmtNum(iso.p95Ms ?? 0)} ms · 최대 ${fmtNum(iso.maxMs ?? 0)} ms · 격리 ${fmtNum(iso.count)}건`,
          to: dest("/audit", { action: "kill" }),
          hint: ISO_HINT,
        }
      : {
          k: "isolation",
          label: "격리 지연 중앙값",
          icon: "◷",
          stripe: "warn",
          value: null,
          text: "",
          delta: P
            ? { dir: "none", note: "비교할 격리 없음" }
            : kpiDelta(null, null),
          sub: "이 기간에 격리 없음",
          to: dest("/audit", { action: "kill" }),
          hint: ISO_HINT,
        },
  ];
}

export function KpiRow({
  s,
  range,
  error,
}: {
  s: Summary | null;
  range: string;
  error: unknown;
}) {
  const defs = s ? kpiDefs(s, range) : [];
  const by = new Map(defs.map((x) => [x.k, x]));
  const { ref, order, containerClass, itemProps, pickedClass } =
    useSortable<HTMLDivElement>({
      scope: "dashboardKpi",
      ids: KPI_IDS,
      layout: "grid",
      labelOf: (id) => by.get(id)?.label ?? id,
    });
  return (
    <div
      ref={ref}
      data-part="kpis"
      className={`sg-dash-kpis ${containerClass}`}
    >
      {!s ? (
        <div className="col-span-full">
          {error ? (
            <LoadError error={error} what="종합" compact />
          ) : (
            <p className="py-6 text-sm text-text-3">불러오는 중…</p>
          )}
        </div>
      ) : (
        order.map((id) => {
          const x = by.get(id)!;
          return (
            <KpiCard
              key={id}
              k={x.k}
              label={x.label}
              icon={x.icon}
              stripe={x.stripe}
              value={x.value}
              text={x.text}
              unit={x.unit}
              tone={x.tone}
              delta={x.delta}
              sub={x.sub}
              subTitle={x.subTitle ?? x.sub}
              to={x.to}
              hint={x.hint}
              className={pickedClass(id)}
              attrs={itemProps(id)}
            />
          );
        })
      )}
    </div>
  );
}

// ── 차트 줄 3칸(1.8 : 1 : 1.2) ──
const RES: [
  key: "passed" | "isolated" | "warned" | "refused" | "failed",
  label: string,
  cls: string,
][] = [
  ["passed", "통과", "dn-passed"],
  ["isolated", "격리", "dn-isolated"],
  ["warned", "경고", "dn-warned"],
  ["refused", "설치 전 거부", "dn-refused"],
  ["failed", "실패 · 미확인", "dn-failed"],
];
export function ChartRow({ s }: { s: Summary | null }) {
  // 색은 토큰(라이트: 실행 #8b5cf6 · 파일 #38bdf8 · 통신 #14b8a6 · 조회 #fb923c) — 다크에서 밝은 값으로 바뀐다. dns 는 옛 백엔드면 없다
  const hasDns = s?.collected.byKind.dns !== undefined;
  const data: Point[] = (s?.series ?? []).map((p) => ({
    ...p,
    dns: p.dns ?? 0,
  }));
  const lineKeys: [string, string, string][] = [
    ["exec", "실행", "--k-exec"],
    ["open", "파일", "--k-open"],
    ["connect", "통신", "--k-connect"],
    ...(hasDns
      ? ([["dns", "조회", "--k-dns"]] as [string, string, string][])
      : []),
  ];
  const none = <Empty>{null}</Empty>;
  return (
    <div data-part="charts" className="sg-dash-charts">
      <Card id="collected" title="수집량 추이" sub="종류별 커널 이벤트">
        {s ? (
          <LineChart
            name="collected"
            label="수집량 추이"
            keys={lineKeys}
            data={data}
            step={s.bucketSec}
          />
        ) : (
          none
        )}
      </Card>
      <Card id="violations" title="위반 추이" sub="격리 · 경고">
        {s ? (
          <StackBars
            name="violations"
            label="위반 추이"
            keys={[
              ["killed", "격리", "k-killed"],
              ["alert", "경고", "k-alert"],
            ]}
            data={data}
            step={s.bucketSec}
          />
        ) : (
          none
        )}
      </Card>
      <Card id="results" title="설치 검사 결과" sub="분포 · 판정 · 차단 목록">
        {s ? <Results s={s} /> : none}
      </Card>
    </div>
  );
}

function Card({
  id,
  title,
  sub,
  children,
}: {
  id: string;
  title: string;
  sub: string;
  children: React.ReactNode;
}) {
  return (
    <div data-card={id} className="flex min-w-0">
      <Panel title={title} sub={sub} className="w-full">
        <div className="sg-dash-chart-body">{children}</div>
      </Panel>
    </div>
  );
}

function Results({ s }: { s: Summary }) {
  const I = s.installs;
  const D = s.decisions;
  const B = s.blocklist;
  return (
    <div className="sg-res" data-results="">
      <Donut
        name="results"
        label="설치 검사 결과"
        centerLabel="설치 검사"
        items={RES.map(([k, ko, cls]) => [k, ko, cls, I[k] ?? 0])}
      />
      <div className="sg-res-side">
        <ul className="sg-res-legend">
          {RES.map(([k, ko, cls]) => (
            <li key={k} data-res={k}>
              <i className={`sw ${cls}`} aria-hidden />
              <span>{ko}</span>
              <b>{fmtNum(I[k] ?? 0)}</b>
            </li>
          ))}
        </ul>
        {/* 판정 · 차단 목록은 한 줄씩(카드 높이를 차트와 맞춘다) — 차단 목록 종류별 수는 툴팁 */}
        <span className="sg-res-line" data-part="res-decisions">
          <span className="text-text-3">판정</span> 악성{" "}
          <b className={D.malicious ? "tone-danger" : ""}>{D.malicious}</b> ·
          오탐 <b>{D.falsePositive}</b> · 대기 <b>{D.pending}</b>
        </span>
        <Link
          to="/policies"
          className="sg-res-line"
          data-part="res-blocklist"
          title={`패키지 ${B.packages} · 이미지 ${B.images} · 도메인 ${B.hosts}`}
        >
          <span className="text-text-3">차단 목록</span>{" "}
          <b data-blocklist-total="">
            {fmtNum(B.packages + B.images + B.hosts)}
          </b>
          개 ›
        </Link>
      </div>
    </div>
  );
}

// ── 아래 줄: 많이 걸린 정책 · 위반 많은 컨테이너(상위 5) ──
export function TopPanel({
  kind,
  s,
}: {
  kind: "rules" | "containers";
  s: Summary | null;
}) {
  const rules = kind === "rules";
  const rows = s ? (rules ? s.topRules : s.topContainers) : null;
  return (
    <div
      data-card={rules ? "top-rules" : "top-containers"}
      className="flex min-w-0"
    >
      <Panel
        title={rules ? "많이 걸린 정책" : "위반이 많은 컨테이너 · 패키지"}
        sub="위반 수 상위 5"
        more={
          rules
            ? { to: "/policies", label: "정책" }
            : { to: "/audit", label: "감사 로그" }
        }
        className="w-full"
      >
        <div data-fill="" className="sg-dash-fill">
          {!rows ? (
            <p className="sg-top-empty">{"\u00a0"}</p>
          ) : (
            <TopList
              testId={kind}
              rows={rows}
              keyOf={(r) => (rules ? r.ruleId : r.container) ?? ""}
              href={(k) =>
                rules
                  ? { to: `/policies?id=${encodeURIComponent(k)}` }
                  : dest("/audit", { container: k })
              }
            />
          )}
        </div>
      </Panel>
    </div>
  );
}

function TopList({
  testId,
  rows,
  keyOf,
  href,
}: {
  testId: string;
  rows: SummaryTop[];
  keyOf: (r: SummaryTop) => string;
  href: (k: string) => Dest;
}) {
  const top = rows.slice(0, 5);
  if (!top.length) return <p className="sg-top-empty">이 기간에 위반 없음</p>;
  return (
    <ol className="sg-top-list" data-top={testId}>
      {top.map((r) => (
        <li key={keyOf(r)} data-row={keyOf(r)} data-count={r.count}>
          <Link {...href(keyOf(r))} title={keyOf(r)}>
            {keyOf(r)}
          </Link>
          <span className="sg-top-bar">
            <i
              className={`lv-${r.level}`}
              style={{
                width: `${Math.max(4, (r.count / top[0].count) * 100)}%`,
              }}
            />
          </span>
          <b>{fmtNum(r.count)}</b>
        </li>
      ))}
    </ol>
  );
}
