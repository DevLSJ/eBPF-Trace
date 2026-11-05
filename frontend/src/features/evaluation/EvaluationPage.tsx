import { ChartColumn, Download } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { StatusBadge } from '../../components/Badges';
import { KpiCard } from '../../components/KpiCard';
import { useSortable } from '../../hooks/useSortable';
import type { Stripe } from '../../lib/kpi';
import { useAutoRetry } from '../../components/list/hooks';
import { EmptyState, ListError, Skeleton } from '../../components/list/ListStates';
import { PageActions } from '../../components/PageActions';
import { useLoad } from '../../hooks/useLoad';
import { api } from '../../lib/api';
import { fmtNum } from '../../lib/format';
import { INSTALL_STATUS_LABEL, type EvalModel, type EvalRuntime, type EvalScenario, type EvalStat, type EvalStatic, type Evaluation, type EvalVerdict, type InstallStatus } from '../../lib/types';
import { ChartNote, HBars, RangeChart, type BarRow } from './charts';
import { niceTicks, RATE_TICKS, type ColorKey, type TipLine } from './scale';

// 평가(11/04 U1 — 목업 mock/shared/eval.js 확정본 · 11/04b · 11/04c) — 「이 탐지는 얼마나 맞고, 어디까지 믿을 수 있나?」
// 데이터: GET /api/evaluation → {static, runtime, model, modelAll}(bench/reports 실측 파일 그대로, 없는 쪽 null · 결과 없음 404). 읽기 전용, 조회자도 본다.
// 순서: 머리(결론 한 줄 · 출처 태그) → 지표 6칸 → 두 열(정적: 판정 분포 · 규칙 적중 상위 10 · 혼동 행렬 / 런타임: 시나리오 탐지율 · 지연 범위 + 단계 막대 · 정상 설치 위반)
//       → 모델 비교(전체 폭) → 결과의 한계(전체 폭)

const pct = (x: number | null | undefined) => (x == null || !Number.isFinite(x) ? '—' : `${(x * 100).toFixed(1)}%`);
const pct0 = (x: number) => `${Math.round(x * 100)}%`;
const dec = (x: number | null | undefined) => (x == null || !Number.isFinite(x) ? '—' : x.toFixed(2));
const ms = (x: number | null | undefined) => (x == null ? '—' : `${fmtNum(x)} ms`);
const sum = (o: Record<string, number | undefined> | undefined) => Object.values(o ?? {}).reduce<number>((a, b) => a + (Number(b) || 0), 0);
// 지표 보조 줄 — 조각 안에서는 줄을 바꾸지 않는다
const hint = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).map((t) => (t as string).replace(/ /g, ' ')).join(' · ');
const ymdhm = (iso: string) => {
  const d = new Date(iso);
  const p = (x: number) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
};
// 막대 글자 — 10ms 이상은 정수, 그 아래는 소수 한 자리
const msv = (x: number) => (x >= 10 ? Math.round(x) : Math.round(x * 10) / 10);

// 판정 순서 · 색 고정(악성 → 주의 → 취약 → 정상 → 오류)
const VERDICTS: [EvalVerdict, string, ColorKey][] = [
  ['malicious', '악성', 'mal'],
  ['suspicious', '주의', 'sus'],
  ['vulnerable', '취약', 'vul'],
  ['clean', '정상', 'clean'],
  ['error', '오류', 'muted'],
];
const STAGES: ['match' | 'evidence' | 'killApi', string, ColorKey][] = [
  ['match', '판정', 'muted'],
  ['evidence', '증거 수집', 'evidence'],
  ['killApi', 'kill 호출', 'kill'],
];
const SOURCE = { static: '정적', runtime: '런타임', model: '모델', modelAll: '모델(전체)' } as const;

// ── 계산 ──
function attacks(rt: EvalRuntime | null) {
  const list = (rt?.scenarios ?? []).filter((x) => x.kind === 'attack');
  return { list, runs: list.reduce((n, x) => n + x.runs, 0), detected: list.reduce((n, x) => n + x.detected, 0) };
}
// 지표 칸 [11/04b]: 격리된 공격 전체(killLatencyMs — 백엔드 수신 → 격리). 키가 없는 옛 파일이면 격리까지 잰 공격 시나리오 중 가장 큰 값
function latencyHead(rt: EvalRuntime | null) {
  const k = rt?.killLatencyMs;
  if (k && k.p50 != null) return { p50: k.p50, p95: k.p95, hint: hint(`격리된 공격 ${fmtNum(k.n ?? 0)}회 기준`, '백엔드 수신→격리') };
  const l = attacks(rt).list.map((x) => x.latencyMs).filter((x): x is EvalStat => !!x && x.p50 != null);
  return l.length ? { p50: Math.max(...l.map((x) => x.p50)), p95: Math.max(...l.map((x) => x.p95)), hint: '공격 시나리오 중 가장 느린 값' } : null;
}
function conclusion(d: Evaluation) {
  const out: string[] = [];
  const c = d.static?.confusion;
  if (c) out.push(`정적 검사: 실제 악성 ${fmtNum(c.tp + c.fn)}개 중 ${fmtNum(c.tp)}개 탐지 · 정상 ${fmtNum(c.fp + c.tn)}개 중 ${fmtNum(c.fp)}개 오탐`);
  if (d.runtime) {
    const a = attacks(d.runtime);
    const b = d.runtime.benign;
    out.push(`런타임: 공격 ${fmtNum(a.runs)}회 중 ${fmtNum(a.detected)}회 탐지 · 정상 설치 ${fmtNum(b?.installs ?? 0)}건 중 ${fmtNum(b?.violations ?? 0)}건 위반`);
  }
  return out.join(' — ');
}
// 규칙 후보(id 가 rule 로 시작)가 시험 F1 에서 선택 모델보다 앞서는가 [11/04c]
function ruleWins(md: EvalModel) {
  const cs = md.candidates ?? [];
  const pref = cs.find((x) => x.id === md.preferredId);
  return !!pref && cs.some((x) => /^rule/.test(x.id) && x.id !== pref.id && x.test.f1 > pref.test.f1);
}
// 정상 설치 결과 중 통과(벤치 'pass' · 설치 검사 'passed')가 아닌 것
const PASS = new Set(['pass', 'passed']);

// ── 공통 부품 ──
function Card({ part, title, actions, children }: { part: string; title: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section data-part={part} className="sg-card min-w-0">
      <header className="flex min-h-11 flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-border px-4 py-2">
        <h2 className="text-[14.5px] font-semibold text-text">{title}</h2>
        {actions}
      </header>
      <div className="grid min-w-0 gap-2 px-4 pt-3 pb-3.5">{children}</div>
    </section>
  );
}
const None = ({ what }: { what: string }) => (
  <p data-part="none" className="py-3 text-xs text-text-3">
    {what} 결과 없음
  </p>
);
function Tag({ id, k, v, title }: { id: string; k: string; v: string; title?: string }) {
  return (
    <span data-tag={id} title={title} className="inline-flex h-6 max-w-full items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2 text-xs whitespace-nowrap text-text">
      <span className="text-text-3">{k}</span>
      <span className="truncate">{v}</span>
    </span>
  );
}
// 지표 칸 — 11/04e KPI 카드 모양(띠 · 아이콘 칩 · 28/700, R1 11/04). 글자 값(퍼센트 · 「—」)이라 카운트업은 없다
interface KpiDef {
  k: string;
  label: string;
  value: string;
  unit?: string;
  sub: string;
  icon: string;
  stripe: Stripe;
}
const KPI_IDS = ['static-detection', 'static-fpr', 'runtime-detection', 'runtime-fpr', 'latency', 'model-f1'];

// ── 머리 ──
function Head({ d }: { d: Evaluation }) {
  const st = d.static;
  const rt = d.runtime;
  const tags: ReactNode[] = [];
  for (const ds of st?.datasets ?? [])
    tags.push(
      <Tag
        key={ds.id}
        id={`dataset-${ds.id}`}
        k={ds.kind === 'malicious' ? '악성 세트' : '정상 세트'}
        v={ds.label}
        title={[ds.source && `${ds.source}${ds.sourceCommit ? ` @ ${ds.sourceCommit}` : ''}`, ds.files != null && `파일 ${fmtNum(ds.files)}개`, ds.listSha256 && `목록 sha256 ${ds.listSha256.slice(0, 12)}`].filter(Boolean).join(' · ')}
      />,
    );
  if (rt?.host) tags.push(<Tag key="host" id="host" k="런타임" v={`${rt.host.name} · 커널 ${rt.host.kernel} · ${rt.host.discovery}`} title={rt.host.igVersion ? `Inspektor Gadget ${rt.host.igVersion}` : undefined} />);
  const gen = [st && ['정적', st.generatedAt], rt && ['런타임', rt.generatedAt], d.model?.generatedAt && ['모델', d.model.generatedAt], d.modelAll?.generatedAt && ['모델(전체)', d.modelAll.generatedAt]].filter(Boolean) as [string, string][];
  if (gen.length) tags.push(<Tag key="generated" id="generated" k="생성" v={ymdhm(gen.map((g) => g[1]).sort().pop()!)} title={gen.map(([k, v]) => `${k} ${v}`).join(' · ')} />);
  const commits = [...new Set([st?.scanner?.backendCommit, rt?.host?.backendCommit].filter((x): x is string => !!x))];
  if (commits.length)
    tags.push(
      <Tag
        key="commit"
        id="commit"
        k="백엔드"
        v={commits.map((c) => c.slice(0, 7)).join(' · ')}
        title={[commits.join(' · '), st?.scanner && `GuardDog ${st.scanner.guarddog} · OSV-Scanner ${st.scanner.osv}`].filter(Boolean).join(' — ')}
      />,
    );
  return (
    <section data-part="eval-head" className="sg-card grid gap-2.5 px-4 py-3.5 md:px-5 md:py-4">
      <p data-part="conclusion" className="min-w-0 text-sm font-medium text-text md:text-[15px]">
        {conclusion(d) || '결과 요약 없음'}
      </p>
      <div data-part="tags" className="flex flex-wrap gap-1.5">
        {tags}
      </div>
    </section>
  );
}

function Kpis({ d }: { d: Evaluation }) {
  const st = d.static;
  const rt = d.runtime;
  const md = d.model;
  const mt = st?.metrics ?? {};
  const c = st?.confusion;
  const a = attacks(rt);
  const b = rt?.benign;
  const lat = latencyHead(rt);
  const pref = md?.candidates?.find((x) => x.id === md.preferredId);
  const by = b?.byEcosystem ? Object.entries(b.byEcosystem).map(([k, v]) => `${k} ${fmtNum(v)}`).join(', ') : '';
  const defs: KpiDef[] = [
    { k: 'static-detection', icon: '⌕', stripe: 'accent', label: '정적 악성 탐지율', value: st ? pct(mt.detectionRate) : '—', sub: c ? hint(`악성 ${fmtNum(c.tp)} / ${fmtNum(c.tp + c.fn)}`, `주의 포함 ${pct(mt.detectionRateWithSuspicious)}`) : '정적 결과 없음' },
    {
      k: 'static-fpr',
      icon: '✓',
      stripe: 'info',
      label: '정상 오탐률',
      value: st ? pct(mt.falsePositiveRate) : '—',
      sub: c ? hint(`인기 패키지 ${fmtNum(c.fp)} / ${fmtNum(c.fp + c.tn)}`, mt.falsePositiveRateWithSuspicious != null && `주의 포함 ${pct(mt.falsePositiveRateWithSuspicious)}`) : '정적 결과 없음',
    },
    { k: 'runtime-detection', icon: '▣', stripe: 'accent', label: '런타임 공격 탐지율', value: a.runs ? pct(a.detected / a.runs) : '—', sub: a.runs ? hint(`공격 ${fmtNum(a.detected)} / ${fmtNum(a.runs)}회`, `${a.list.length}종`) : '런타임 결과 없음' },
    { k: 'runtime-fpr', icon: '✓', stripe: 'info', label: '정상 설치 오탐률', value: b ? pct(b.falsePositiveRate) : '—', sub: b ? hint(`위반 ${fmtNum(b.violations)} / ${fmtNum(b.installs)}건`, by) : '런타임 결과 없음' },
    { k: 'latency', icon: '◷', stripe: 'warn', label: '탐지 → 격리 p50 / p95', value: lat ? fmtNum(lat.p50) : '—', unit: lat ? ` / ${fmtNum(lat.p95)} ms` : undefined, sub: lat ? lat.hint : '격리한 시나리오 없음' },
    { k: 'model-f1', icon: '◔', stripe: 'ok', label: '모델 시험 F1', value: pref ? dec(pref.test.f1) : '—', sub: pref ? `${pref.label}${md?.deploymentApproved ? '' : ' · 운영 미적용'}` : '모델 결과 없음' },
  ];
  return <KpiGrid defs={defs} />;
}

// 지표 6칸 — 길게 눌러(또는 Alt+←/→) 순서 바꾸기(11/04d, R1 11/04 — localStorage supplyguard.layout.evaluationKpi). 칸(div)은 tabindex 0
function KpiGrid({ defs }: { defs: KpiDef[] }) {
  const by = new Map(defs.map((x) => [x.k, x]));
  const { ref, order, containerClass, itemProps, pickedClass } = useSortable<HTMLDivElement>({ scope: 'evaluationKpi', ids: KPI_IDS, layout: 'grid', focusable: false, labelOf: (id) => by.get(id)?.label ?? id });
  return (
    <div ref={ref} data-part="kpis" className={`grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6 ${containerClass}`}>
      {order.map((id) => {
        const x = by.get(id)!;
        // 지표 칸 — 11/04e KPI 카드 모양(띠 · 아이콘 칩 · 28/700). 글자 값(퍼센트 · 「—」)이라 카운트업은 없다
        return <KpiCard key={id} k={x.k} label={x.label} icon={x.icon} stripe={x.stripe} text={x.value} unit={x.unit} sub={x.sub} wrapSub className={`eval-kpi ${pickedClass(id)}`} attrs={itemProps(id)} />;
      })}
    </div>
  );
}

// ── 정적 열 ──
function DistCard({ st }: { st: EvalStatic | null }) {
  if (!st) return <Card part="dist" title="세트별 판정 분포"><None what="정적" /></Card>;
  const label = (id: string) => st.datasets?.find((x) => x.id === id)?.label ?? id;
  const rows: BarRow[] = (st.sets ?? []).map((set) => {
    const n = sum(set.verdicts) || 1;
    const skip = sum(set.skipped);
    return {
      id: set.id,
      label: label(set.id),
      value: `n=${fmtNum(set.scanned)}`,
      bars: [VERDICTS.map(([k, , color]) => ({ key: k, v: (set.verdicts[k] ?? 0) / n, color }))],
      tip: [
        [null, `${label(set.id)} · 검사 ${fmtNum(set.scanned)} / ${fmtNum(set.total)}`],
        ...VERDICTS.map(([k, ko, color]): TipLine => [color, `${ko} ${fmtNum(set.verdicts[k] ?? 0)} (${pct((set.verdicts[k] ?? 0) / n)})`]),
        ...(skip ? [[null, `건너뜀 ${fmtNum(skip)} — ${Object.entries(set.skipped ?? {}).map(([k, v]) => `${k} ${v}`).join(' · ')}`] as TipLine] : []),
      ],
    };
  });
  return (
    <Card part="dist" title="세트별 판정 분포">
      <HBars name="verdict-dist" label="세트별 판정 분포 쌓은 막대" rows={rows} ticks={RATE_TICKS} tickFmt={pct0} legend={VERDICTS.map(([, ko, c]) => [ko, c])} labelW={130} />
      {st.durationsSec && <ChartNote>{`검사 1건 p50 ${fmtNum(st.durationsSec.p50)}초 · p95 ${fmtNum(st.durationsSec.p95)}초`}</ChartNote>}
    </Card>
  );
}
function RulesCard({ st }: { st: EvalStatic | null }) {
  const title = 'GuardDog 규칙 적중 상위 10';
  if (!st) return <Card part="rules" title={title}><None what="정적" /></Card>;
  // 합 → 악성 적중 → 이름 순서로 상위 10
  const top = [...(st.rules ?? [])]
    .sort((a, b) => b.maliciousHits + b.benignHits - (a.maliciousHits + a.benignHits) || b.maliciousHits - a.maliciousHits || a.rule.localeCompare(b.rule))
    .slice(0, 10);
  const rows: BarRow[] = top.map((r) => ({
    id: r.rule,
    label: r.rule,
    mono: true,
    value: `${fmtNum(r.maliciousHits)} · ${fmtNum(r.benignHits)}`,
    bars: [[{ key: 'malicious', v: r.maliciousHits, color: 'mal' }], [{ key: 'benign', v: r.benignHits, color: 'muted' }]],
    tip: [[null, r.rule], ['mal', `악성 세트 ${fmtNum(r.maliciousHits)}개`], ['muted', `정상 세트 ${fmtNum(r.benignHits)}개`], ...(r.installTime ? [[null, '설치 시점 규칙'] as TipLine] : [])],
  }));
  return (
    <Card part="rules" title={title}>
      {top.length ? (
        <HBars
          name="rule-hits"
          label="GuardDog 규칙별 악성 · 정상 세트 적중 수"
          rows={rows}
          ticks={niceTicks(Math.max(1, ...top.map((r) => Math.max(r.maliciousHits, r.benignHits))))}
          tickFmt={(t) => fmtNum(t)}
          legend={[['악성 세트 적중', 'mal'], ['정상 세트 적중', 'muted']]}
          labelW={170}
        />
      ) : (
        <p className="py-3 text-xs text-text-3">적중한 규칙 없음</p>
      )}
    </Card>
  );
}
function ConfusionCard({ st }: { st: EvalStatic | null }) {
  const title = '혼동 행렬 · 정적 검사';
  if (!st?.confusion) return <Card part="confusion" title={title}><None what="정적" /></Card>;
  const c = st.confusion;
  const mt = st.metrics ?? {};
  const cell = (k: string, n: number, what: string) => (
    <td data-cell={k} className="px-3 py-2">
      <b className="num mr-1.5 text-lg font-semibold text-text">{fmtNum(n)}</b>
      <span className="text-xs text-text-3">{what}</span>
    </td>
  );
  const eco = Object.entries(st.metricsByEcosystem ?? {});
  return (
    <Card part="confusion" title={title}>
      <div className="overflow-x-auto">
        <table className="text-sm" style={{ minWidth: 0 }}>
          <thead>
            <tr className="border-b border-border text-left">
              <th className="px-3 py-1.5" />
              <th className="px-3 py-1.5">판정 악성</th>
              <th className="px-3 py-1.5">악성 아님</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-b border-border">
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-3">실제 악성</th>
              {cell('tp', c.tp, '잡음')}
              {cell('fn', c.fn, '놓침')}
            </tr>
            <tr>
              <th className="px-3 py-2 text-left text-xs font-semibold text-text-3">실제 정상</th>
              {cell('fp', c.fp, '오탐')}
              {cell('tn', c.tn, '통과')}
            </tr>
          </tbody>
        </table>
      </div>
      <ChartNote>{`양성 = 판정 「악성」 · 정밀도 ${pct(mt.precision)} · 재현율 ${pct(mt.recall)} · F1 ${dec(mt.f1)}`}</ChartNote>
      {eco.length > 0 && (
        <ChartNote part="by-ecosystem">
          {`생태계별 — ${eco.map(([k, v]) => `${k} 탐지 ${pct(v.metrics.detectionRate)} · 오탐 ${pct(v.metrics.falsePositiveRate)}`).join(' / ')}`}
        </ChartNote>
      )}
    </Card>
  );
}

// ── 런타임 열 ──
function ScenarioCard({ rt }: { rt: EvalRuntime | null }) {
  const title = '시나리오별 탐지율';
  if (!rt) return <Card part="scenarios" title={title}><None what="런타임" /></Card>;
  const rows: BarRow[] = (rt.scenarios ?? []).map((x) => {
    const color: ColorKey = x.kind === 'attack' ? 'attack' : 'muted';
    return {
      id: x.id,
      label: x.label,
      value: `${fmtNum(x.detected)}/${fmtNum(x.runs)}`,
      bars: [[{ key: x.kind, v: x.runs ? x.detected / x.runs : 0, color }]],
      tip: [
        [null, x.label],
        [color, `${x.kind === 'attack' ? '공격' : '대조(정상)'} · 탐지 ${fmtNum(x.detected)} / ${fmtNum(x.runs)}회`],
        [null, `격리 ${fmtNum(x.killed)}회${x.rule ? ` · 규칙 ${x.rule}` : ''}${x.dryRun ? ' · dryRun' : ''}`],
      ],
    };
  });
  return (
    <Card part="scenarios" title={title}>
      <HBars name="scenario-rate" label="시나리오별 탐지율 막대" rows={rows} ticks={RATE_TICKS} tickFmt={pct0} legend={[['공격', 'attack'], ['대조(정상 — 0% 가 정답)', 'muted']]} labelW={150} />
    </Card>
  );
}
function LatencyCard({ rt }: { rt: EvalRuntime | null }) {
  const title = '탐지 → 격리 지연 (ms)';
  if (!rt) return <Card part="latency" title={title}><None what="런타임" /></Card>;
  const sc = rt.scenarios ?? [];
  const list = sc.filter((x): x is EvalScenario & { latencyMs: EvalStat } => !!x.latencyMs && x.latencyMs.p50 != null);
  const skipped = sc.filter((x) => x.kind === 'attack' && !(x.latencyMs && x.latencyMs.p50 != null));
  return (
    <Card part="latency" title={title}>
      {list.length ? (
        <RangeChart
          name="latency"
          label="시나리오별 탐지에서 격리까지 지연 범위"
          rows={list.map((x) => ({
            id: x.id,
            label: x.label,
            lat: x.latencyMs,
            tip: [[null, x.label], ['attack', `p50 ${ms(x.latencyMs.p50)}`], [null, `p95 ${ms(x.latencyMs.p95)}`], [null, `max ${ms(x.latencyMs.max ?? x.latencyMs.p95)}`], [null, `격리 ${fmtNum(x.killed)}회 기준`]],
          }))}
        />
      ) : (
        <p className="py-3 text-xs text-text-3">격리까지 잰 시나리오가 없습니다</p>
      )}
      {skipped.length > 0 && <ChartNote part="latency-skipped">{`격리하지 않아 빠짐: ${skipped.map((x) => `${x.label}${x.dryRun ? ' (dryRun)' : ''}`).join(' · ')}`}</ChartNote>}
      <Stages rt={rt} />
    </Card>
  );
}
// [11/04b] 단계별 막대 — p50 가로 누적(판정 → 증거 수집 → kill 호출, 합계). 첫 행은 격리된 공격 전체(killStagesMs), 그 아래 격리한 시나리오별. 툴팁에 p95.
// killStagesMs 가 없는 옛 파일이면 숨긴다. 「판정」 조각은 최소 폭 없음(11/04 사용자 결정)
function Stages({ rt }: { rt: EvalRuntime }) {
  const all = rt.killStagesMs;
  if (!all) return null;
  type St = Partial<Record<'match' | 'evidence' | 'killApi', EvalStat | null | undefined>>;
  const row = (id: string, label: string, st: St, n: number | undefined, strong?: boolean) => {
    const p = (k: keyof St) => st[k]?.p50 ?? 0;
    const total = STAGES.reduce((a, [k]) => a + p(k), 0);
    return {
      total,
      r: {
        id,
        label,
        strong,
        value: `합계 ${fmtNum(msv(total))} ms`,
        bars: [STAGES.map(([k, , color]) => ({ key: k, v: p(k), color }))],
        tip: [
          [null, label] as TipLine,
          ...STAGES.map(([k, ko, color]): TipLine => [color, st[k] ? `${ko} p50 ${fmtNum(msv(st[k]!.p50))} ms · p95 ${fmtNum(msv(st[k]!.p95))} ms` : `${ko} —`]),
          ...(n ? [[null, `격리 ${fmtNum(n)}회 기준`] as TipLine] : []),
        ],
      } satisfies BarRow,
    };
  };
  const lead = (st: St) => STAGES.map(([k]) => st[k]).find((x) => x?.n)?.n;
  const rows = [
    row('all', '격리된 공격 전체', all, lead(all) ?? rt.killLatencyMs?.n, true),
    ...(rt.scenarios ?? [])
      .filter((x) => x.evidenceMs?.p50 != null || x.killApiMs?.p50 != null)
      .map((x) => {
        const st: St = { match: x.matchLatencyMs, evidence: x.evidenceMs, killApi: x.killApiMs };
        return row(x.id, x.label, st, lead(st) ?? x.killed);
      }),
  ];
  return (
    <>
      <p data-part="stages-title" className="mt-1.5 border-t border-border pt-2.5 text-xs font-semibold text-text-2">
        단계별 시간 (p50)
      </p>
      <HBars
        name="kill-stages"
        label="탐지에서 격리까지 단계별 시간 누적 막대"
        rows={rows.map((x) => x.r)}
        ticks={niceTicks(Math.max(1, ...rows.map((x) => x.total)))}
        tickFmt={(t) => fmtNum(t)}
        legend={STAGES.map(([, ko, c]) => [ko, c])}
        labelW={150}
        valueW={88}
        minSeg={0}
      />
      <ChartNote part="stages-caption">증거를 먼저 모으고(≤0.7초) 격리합니다</ChartNote>
    </>
  );
}
function BenignCard({ rt }: { rt: EvalRuntime | null }) {
  if (!rt?.benign) return <Card part="benign" title="정상 설치 위반"><None what="런타임" /></Card>;
  const b = rt.benign;
  const rows = (b.items ?? []).filter((x) => !PASS.has(x.result) || !!x.rule);
  return (
    <Card part="benign" title={`정상 설치 위반 ${fmtNum(rows.length)}건`} actions={<span className="text-xs text-text-3">정상 설치 {fmtNum(b.installs)}건 중</span>}>
      {rows.length ? (
        <div className="overflow-x-auto">
          <table className="sg-table" data-table="benign-violations">
            <thead>
              <tr>
                {['생태계', '패키지', '결과', '규칙', '걸린 시간'].map((t) => (
                  <th key={t} className={t === '걸린 시간' ? 'num-col' : undefined}>
                    {t}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((x) => (
                <tr key={`${x.ecosystem}:${x.name}`} data-pkg={`${x.ecosystem}:${x.name}`}>
                  <td>{x.ecosystem}</td>
                  <td className="font-mono text-xs">{x.name}</td>
                  <td>
                    {x.result in INSTALL_STATUS_LABEL ? <StatusBadge status={x.result as InstallStatus} /> : <span className="rounded bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800">{x.result === 'violation' ? '위반' : x.result}</span>}
                  </td>
                  <td className="font-mono text-xs">{x.rule || '—'}</td>
                  <td className="num num-col">{x.seconds != null ? `${fmtNum(x.seconds)}초` : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="py-3 text-xs text-text-3">{`위반 없음 — 정상 설치 ${fmtNum(b.installs)}건 모두 통과`}</p>
      )}
    </Card>
  );
}

// ── 모델 비교(전체 폭) — modelAll 이 있으면 「PyPI / 전체」 탭 ──
function ModelCard({ model, modelAll }: { model: EvalModel | null; modelAll?: EvalModel | null }) {
  const [scope, setScope] = useState<'pypi' | 'all'>('pypi');
  const md = scope === 'all' && modelAll ? modelAll : model ?? modelAll ?? null;
  const tabs = model && modelAll && (
    <div data-part="model-scope" role="group" aria-label="모델 범위" className="flex rounded-md border border-border p-0.5 text-xs">
      {(
        [
          ['pypi', 'PyPI'],
          ['all', '전체'],
        ] as const
      ).map(([k, t]) => (
        <button
          key={k}
          type="button"
          aria-pressed={scope === k}
          onClick={() => setScope(k)}
          className={`rounded px-2.5 py-0.5 ${scope === k ? 'bg-accent-soft font-medium text-accent-text' : 'text-text-2 hover:bg-surface-2'}`}
        >
          {t}
        </button>
      ))}
    </div>
  );
  const actions = (
    <div className="flex items-center gap-2">
      {tabs}
      {md && !md.deploymentApproved && (
        <span data-part="not-deployed" title="선택 모델은 비교용이고 판정은 지금도 규칙으로 합니다" className="rounded bg-surface-2 px-2 py-0.5 text-xs font-medium text-text-2 ring-1 ring-border ring-inset">
          운영 미적용
        </span>
      )}
    </div>
  );
  if (!md) return <Card part="model" title="모델 비교"><None what="모델" /></Card>;
  const p = md.protocol ?? {};
  const label = (id: string) => md.candidates?.find((x) => x.id === id)?.label ?? id;
  const test = p.partitions?.test;
  return (
    <Card part="model" title="모델 비교" actions={actions}>
      <div className="overflow-x-auto">
        <table className="w-full text-sm" data-table="models">
          <thead>
            <tr className="border-b border-border">
              {['후보', '보정 F1', '시험 F1', '정밀도', '재현율', '오탐률'].map((t, i) => (
                <th key={t} className={`px-3 py-1.5 ${i ? 'text-right' : 'text-left'}`}>
                  {t}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {(md.candidates ?? []).map((x) => {
              const pick = x.id === md.preferredId;
              return (
                <tr key={x.id} data-model={x.id} aria-current={pick ? 'true' : undefined} className={`border-b border-border last:border-0 ${pick ? 'bg-accent-soft hover:!bg-accent-soft' : ''}`}>
                  <td className={`px-3 py-1.5 ${pick ? 'font-semibold shadow-[inset_3px_0_0_var(--accent)]' : ''}`} title={x.threshold != null ? `임계값 ${x.threshold}` : undefined}>
                    {x.label}
                    {pick && (
                      <span data-part="pick-badge" title="보정 구간에서 고른 모델 — 시험 구간은 선택에 쓰지 않았습니다" className="ml-2 rounded bg-indigo-100 px-1.5 py-0.5 text-xs font-medium text-indigo-800">
                        보정 기준 선택
                      </span>
                    )}
                  </td>
                  {[x.calibration.f1, x.test.f1].map((v, i) => (
                    <td key={`f${i}`} className="num px-3 py-1.5 text-right">
                      {dec(v)}
                    </td>
                  ))}
                  {[x.test.precision, x.test.recall, x.test.fpr].map((v, i) => (
                    <td key={`r${i}`} className="num px-3 py-1.5 text-right">
                      {pct(v)}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {ruleWins(md) && (
        <p data-part="rule-wins" className="text-xs font-medium text-text-2">
          시험에서는 규칙 판정이 우세 — 운영은 규칙
        </p>
      )}
      <p data-part="protocol" className="text-xs text-text-3" title={[(md.features ?? []).join(', '), md.topFeatures?.length && `상위 특징: ${md.topFeatures.map((f) => `${f.feature} ${f.weight}`).join(', ')}`].filter(Boolean).join('\n')}>
        {[`seed ${p.seed ?? '—'}`, p.split, p.selection && `선택 기준: ${p.selection}`, `특징 ${fmtNum((md.features ?? []).length)}개`, test && `시험 악성 ${fmtNum(test.malicious)} · 정상 ${fmtNum(test.benign)}`].filter(Boolean).join(' · ')}
      </p>
      {md.byEcosystem && <ByEcosystem md={md} />}
      {md.npmReference?.recall && (
        <p data-part="npm-ref" className="text-xs text-text-3">
          {`npm 참고(${md.npmReference.note ?? '재현율'}): ${Object.entries(md.npmReference.recall).map(([id, v]) => `${label(id)} ${pct(v)}`).join(' · ')}`}
        </p>
      )}
    </Card>
  );
}

// 전체 범위(model-all.json)의 생태계별 시험 지표 — 후보마다 F1 · 오탐률
function ByEcosystem({ md }: { md: EvalModel }) {
  const eco = Object.entries(md.byEcosystem ?? {});
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm" data-table="models-by-ecosystem">
        <thead>
          <tr className="border-b border-border">
            <th className="px-3 py-1.5 text-left">생태계별 시험</th>
            {eco.map(([k, v]) => (
              <th key={k} colSpan={2} className="px-3 py-1.5 text-right" title={v.test ? `시험 악성 ${v.test.malicious} · 정상 ${v.test.benign}` : undefined}>
                {k} F1 · 오탐률
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {(md.candidates ?? []).map((x) => (
            <tr key={x.id} data-model={x.id} className="border-b border-border last:border-0">
              <td className="px-3 py-1.5">{x.label}</td>
              {eco.map(([k, v]) => {
                const t = v.candidates?.[x.id]?.test;
                return [
                  <td key={`${k}-f1`} className="num px-3 py-1.5 text-right">
                    {dec(t?.f1)}
                  </td>,
                  <td key={`${k}-fpr`} className="num px-3 py-1.5 text-right">
                    {pct(t?.fpr)}
                  </td>,
                ];
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Limits({ d }: { d: Evaluation }) {
  const items: (readonly [keyof typeof SOURCE, string])[] = (['static', 'runtime', 'model'] as const).flatMap((k) => (d[k]?.limits ?? []).map((t) => [k, t] as const));
  // 전체 범위 모델(model-all.json)의 한계 중 PyPI 모델과 다른 것만
  const seen = new Set(d.model?.limits ?? []);
  for (const t of d.modelAll?.limits ?? []) if (!seen.has(t)) items.push(['modelAll', t] as const);
  return (
    <section data-part="limits" className="sg-card grid gap-2 border-l-4 border-l-warn px-4 py-3.5 md:px-5">
      <h2 className="text-[14.5px] font-semibold text-text">결과의 한계</h2>
      {items.length ? (
        <ul className="grid gap-1.5">
          {items.map(([k, t], i) => (
            <li key={i} data-src={k} className="flex items-baseline gap-2 text-[13px] text-text-2">
              <span className="inline-flex h-5 shrink-0 items-center rounded-md border border-border bg-surface-2 px-1.5 text-xs text-text-2">{SOURCE[k]}</span>
              <span className="min-w-0">{t}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-text-3">적힌 한계 없음</p>
      )}
    </section>
  );
}

function download(d: Evaluation) {
  const at = (d.static?.generatedAt ?? d.runtime?.generatedAt ?? new Date().toISOString()).slice(0, 10);
  const url = URL.createObjectURL(new Blob([`${JSON.stringify(d, null, 2)}\n`], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `supplyguard-evaluation-${at}.json`;
  a.hidden = true;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function EvaluationPage() {
  const r = useLoad(api.evaluation);
  const failing = !!r.error && r.data === undefined;
  useAutoRetry(failing, r.error, r.reload);
  const d = r.data;
  const empty = d === null || (d !== undefined && !d.static && !d.runtime && !d.model && !d.modelAll);
  const state = failing ? 'error' : d === undefined ? 'loading' : empty ? 'empty' : 'ready';
  return (
    // R4 11/04(목업 11/04e .eval-body): 768 이상은 머리 · 지표 6칸이 제자리, 아래 몸통(두 열 · 모델 비교 · 한계)만 채움 칸으로 스크롤.
    // 768 미만은 예전처럼 화면 전체가 한 칸으로 스크롤(몸통은 그대로 펼침)
    <div className="flex h-full min-h-0 flex-col gap-4 max-md:block max-md:overflow-y-auto" data-part="evaluation" data-state={state}>
      {state === 'ready' && d && (
        <PageActions>
          <button
            type="button"
            data-action="download-json"
            title="이 화면의 결과(static · runtime · model)를 JSON 한 파일로"
            onClick={() => download(d)}
            className="sg-btn sg-btn-sm sg-btn-secondary flex shrink-0 items-center gap-1.5 whitespace-nowrap"
          >
            <Download className="size-3.5" aria-hidden /> 결과 JSON
          </button>
        </PageActions>
      )}
      {state === 'error' ? (
        <div className="sg-card">
          <ListError error={r.error} what="평가 결과" onRetry={r.reload} retrying={r.loading} />
        </div>
      ) : state === 'loading' ? (
        <div className="sg-card">
          <Skeleton rows={8} />
        </div>
      ) : state === 'empty' || !d ? (
        <div className="sg-card">
          <EmptyState icon={ChartColumn} title="평가 결과 없음" hint="아직 평가를 돌린 결과가 없습니다 — 정적 · 런타임 · 모델 평가 결과가 서버에 올라오면 여기에 보입니다." />
        </div>
      ) : (
        <>
          <div className="mx-auto grid w-full max-w-[var(--content-max)] shrink-0 gap-4 max-md:mb-4">
            <Head d={d} />
            <Kpis d={d} />
          </div>
          <div data-fill="" data-part="eval-body" className="min-h-0 flex-1 overflow-y-auto max-md:overflow-visible">
          <div className="mx-auto grid max-w-[var(--content-max)] content-start gap-4">
          {/* 두 열 = 정적(왼쪽) · 런타임(오른쪽) — 열마다 위로 붙는다(Pinterest 식). 768 미만은 정적 → 런타임 한 열 */}
          <div data-part="eval-grid" className="grid items-start gap-4 md:grid-cols-2">
            <div data-col="static" className="flex min-w-0 flex-col gap-4">
              <DistCard st={d.static} />
              <RulesCard st={d.static} />
              <ConfusionCard st={d.static} />
            </div>
            <div data-col="runtime" className="flex min-w-0 flex-col gap-4">
              <ScenarioCard rt={d.runtime} />
              <LatencyCard rt={d.runtime} />
              <BenignCard rt={d.runtime} />
            </div>
          </div>
          <ModelCard model={d.model} modelAll={d.modelAll} />
          <Limits d={d} />
          </div>
          </div>
        </>
      )}
    </div>
  );
}
