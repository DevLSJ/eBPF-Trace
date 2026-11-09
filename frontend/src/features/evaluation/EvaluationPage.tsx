import { Download } from 'lucide-react';
import { Fragment, useEffect, useId, useState, type ReactNode, type TransitionEvent } from 'react';
import { StatusBadge } from '../../components/Badges';
import { KpiCard } from '../../components/KpiCard';
import { useSortable } from '../../hooks/useSortable';
import type { Stripe } from '../../lib/kpi';
import { useAutoRetry } from '../../components/list/hooks';
import { EmptyState, ListError, Skeleton } from '../../components/list/ListStates';
import { PageActions } from '../../components/PageActions';
import { screenCopy } from '../../lib/screenCopy';
import { useLoad } from '../../hooks/useLoad';
import { api } from '../../lib/api';
import { fmtNum } from '../../lib/format';
import { reducedMotion } from '../../lib/motion';
import { INSTALL_STATUS_LABEL, type EvalCandidate, type EvalModel, type EvalRuntime, type EvalScenario, type EvalStat, type EvalStatic, type Evaluation, type EvalVerdict, type InstallStatus } from '../../lib/types';
import { ChartNote, HBars, RangeChart, type BarRow } from './charts';
import { niceTicks, RATE_TICKS, type ColorKey, type TipLine } from './scale';
import { Term, type TermKey } from './terms';

// 평가(11/04 U1 — 목업 mock/shared/eval.js 확정본 · 11/04b · 11/04c) — 「이 탐지는 얼마나 맞고, 어디까지 믿을 수 있나?」
// 11/09 사용자 결정 「쉬운 이름 + 용어 툴팁 + 자세한 표 접기」: 쉬운 이름(원래 용어는 점선 밑줄 단추 → 툴팁) · 세부 표는 기본 접힘(「자세히」).
// 11/09 저녁 사용자 결정(A안 — 참고 그림의 가독성 원리): 「위 큰 숫자 3칸 + 접고 펼치는 목록 한 장(8줄)」.
//   요점 3줄 · 지표 6칸 · 두 열 카드 바둑판을 없애고, 그 정보는 위 3칸과 줄 요약(값 · 근거 · 비율 막대 · 상태 칩)으로 옮겼다.
//   줄 머리 ▶ 를 눌러야 세부(예전 카드 내용 그대로 — 차트 · 표 · 「자세히」)가 보인다. 여러 줄 동시에 열림 · 머리 「모두 펼치기 · 모두 접기」 하나 ·
//   기본 모두 접힘(기억하지 않음). 줄마다 설명 문장 대신 칸 머리 (?) 툴팁.
// 데이터: GET /api/evaluation → {static, runtime, model, modelAll}(bench/reports 실측 파일 그대로, 없는 쪽 null · 결과 없음 404). 읽기 전용, 조회자도 본다.
// 쉬운 이름 대응(화면 전체 같은 말): 재현율 → 탐지율 · 오탐률 → 오판율 · 정밀도 → 적중률 · F1 → 종합 점수 · p50 → 중간값 · p95 → 95% 이내 ·
//   혼동 행렬 → 판정 4칸 표 · 보정/시험 → 선택용/시험 · dryRun → 시험 운영 · kill 호출 → 격리 명령 · 대조(정상) → 대조군

const pct = (x: number | null | undefined) => (x == null || !Number.isFinite(x) ? '' : `${(x * 100).toFixed(1)}%`);
const pct0 = (x: number) => `${Math.round(x * 100)}%`;
const dec = (x: number | null | undefined) => (x == null || !Number.isFinite(x) ? '' : x.toFixed(2));
const ms = (x: number | null | undefined) => (x == null ? '' : `${fmtNum(x)} ms`);
const sum = (o: Record<string, number | undefined> | undefined) => Object.values(o ?? {}).reduce<number>((a, b) => a + (Number(b) || 0), 0);
// 보조 줄 — 조각 안에서는 줄을 바꾸지 않는다
const hint = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).map((t) => (t as string).replace(/ /g, ' ')).join(' · ');
const ymdhm = (iso: string) => {
  const d = new Date(iso);
  const p = (x: number) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
};
// 막대 글자 — 10ms 이상은 정수, 그 아래는 소수 한 자리
const msv = (x: number) => (x >= 10 ? Math.round(x) : Math.round(x * 10) / 10);

// 판정 순서 · 색 고정(악성 → 주의 → 취약 → 정상 → 오류). 범례의 판정 이름은 용어 단추(정상 · 오류는 설명 없음)
const VERDICTS: [EvalVerdict, string, ColorKey, TermKey | null][] = [
  ['malicious', '악성', 'mal', 'malicious'],
  ['suspicious', '주의', 'sus', 'suspicious'],
  ['vulnerable', '취약', 'vul', 'vulnerable'],
  ['clean', '정상', 'clean', null],
  ['error', '오류', 'muted', null],
];
const STAGES: ['match' | 'evidence' | 'killApi', string, ColorKey][] = [
  ['match', '규칙 판정', 'muted'],
  ['evidence', '증거 수집', 'evidence'],
  ['killApi', '격리 명령', 'kill'],
];
const SOURCE = { static: '정적', runtime: '런타임', model: '모델', modelAll: '모델(전체)' } as const;
// 모델 후보 id → 용어(규칙 후보는 설명 없음)
const MODEL_TERM: Partial<Record<string, TermKey>> = { hgb: 'hgb', logreg: 'logreg' };
const ModelName = ({ x }: { x: EvalCandidate }) => {
  const k = MODEL_TERM[x.id];
  return k ? <Term k={k}>{x.label}</Term> : <>{x.label}</>;
};

// ── 계산 ──
function attacks(rt: EvalRuntime | null) {
  const list = (rt?.scenarios ?? []).filter((x) => x.kind === 'attack');
  return { list, runs: list.reduce((n, x) => n + x.runs, 0), detected: list.reduce((n, x) => n + x.detected, 0), killed: list.reduce((n, x) => n + x.killed, 0) };
}
// 격리 시간 [11/04b]: 격리된 공격 전체(killLatencyMs — 백엔드 수신 → 격리). 키가 없는 옛 파일이면 격리까지 잰 공격 시나리오 중 가장 큰 값(basis 로 알린다)
function latencyHead(rt: EvalRuntime | null) {
  const k = rt?.killLatencyMs;
  if (k && k.p50 != null) return { p50: k.p50, p95: k.p95, n: k.n, basis: null };
  const l = attacks(rt).list.map((x) => x.latencyMs).filter((x): x is EvalStat => !!x && x.p50 != null);
  return l.length ? { p50: Math.max(...l.map((x) => x.p50)), p95: Math.max(...l.map((x) => x.p95)), n: undefined, basis: '가장 느린 시나리오 기준' } : null;
}
// 규칙 후보(id 가 rule 로 시작)가 시험 F1 에서 선택 모델보다 앞서는가 [11/04c]
function ruleWins(md: EvalModel) {
  const cs = md.candidates ?? [];
  const pref = cs.find((x) => x.id === md.preferredId);
  return !!pref && cs.some((x) => /^rule/.test(x.id) && x.id !== pref.id && x.test.f1 > pref.test.f1);
}
// 규칙 후보 중 시험 종합 점수가 가장 높은 것 · 선택 모델
function modelPicks(md: EvalModel) {
  const cs = md.candidates ?? [];
  return { rule: cs.filter((x) => /^rule/.test(x.id)).sort((a, b) => b.test.f1 - a.test.f1)[0], pref: cs.find((x) => x.id === md.preferredId) };
}
// 규칙 적중 상위 10 — 합 → 악성 적중 → 이름 순서
function topRules(st: EvalStatic) {
  return [...(st.rules ?? [])]
    .sort((a, b) => b.maliciousHits + b.benignHits - (a.maliciousHits + a.benignHits) || b.maliciousHits - a.maliciousHits || a.rule.localeCompare(b.rule))
    .slice(0, 10);
}
// 결과의 한계 — 세 파일 limits + 전체 범위 모델(model-all.json)만의 한계
function limitItems(d: Evaluation) {
  const items: (readonly [keyof typeof SOURCE, string])[] = (['static', 'runtime', 'model'] as const).flatMap((k) => (d[k]?.limits ?? []).map((t) => [k, t] as const));
  const seen = new Set(d.model?.limits ?? []);
  for (const t of d.modelAll?.limits ?? []) if (!seen.has(t)) items.push(['modelAll', t] as const);
  return items;
}
// 정상 설치 결과 중 통과(벤치 'pass' · 설치 검사 'passed')가 아닌 것
const PASS = new Set(['pass', 'passed']);

// ── 공통 부품 ──
// 「자세히」 ↔ 「접기」 — 접힌 칸(aria-controls)은 hidden. data-action 이 있어 조회자 읽기 전용 검사에서 쓰기 단추로 치지 않는다
function FoldButton({ open, onToggle, controls, name }: { open: boolean; onToggle: () => void; controls: string; name: string }) {
  return (
    <button
      type="button"
      data-action="toggle-detail"
      aria-expanded={open}
      aria-controls={controls}
      aria-label={`${name} ${open ? '접기' : '자세히'}`}
      onClick={onToggle}
      className="sg-btn sg-btn-sm sg-btn-secondary shrink-0 whitespace-nowrap"
    >
      {open ? '접기' : '자세히'}
    </button>
  );
}
// 줄 안쪽(예전 카드 본문) — 제목 줄은 목록 줄 이름이 대신한다. actions 는 위 오른쪽, detail 이 있으면 본문 아래 「자세히」 + 접힌 칸
function Body({ part, actions, detail, detailName, children }: { part: string; actions?: ReactNode; detail?: ReactNode; detailName?: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <div data-part={part} className="grid min-w-0 gap-2">
      {actions && <div className="flex flex-wrap items-center justify-end gap-2">{actions}</div>}
      {children}
      {detail && (
        <>
          <div>
            <FoldButton open={open} onToggle={() => setOpen((v) => !v)} controls={id} name={detailName ?? part} />
          </div>
          <div id={id} hidden={!open} data-part="detail" className="grid min-w-0 gap-2 border-t border-border pt-3">
            {detail}
          </div>
        </>
      )}
    </div>
  );
}
const None = ({ what }: { what: string }) => (
  <p data-part="none" className="py-2 text-xs text-text-3">
    {what} 결과 없음
  </p>
);
const Cap = ({ children, part }: { children: ReactNode; part?: string }) => (
  <p data-part={part} className="text-xs font-semibold text-text-2">
    {children}
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
// 숫자 먼저 작은 칸(판정 정확도 · 모델 요약)
function Stat({ k, value, label }: { k: string; value: string; label: ReactNode }) {
  return (
    <div data-stat={k} className="grid min-w-0 content-start gap-0.5 rounded-lg bg-surface-2 px-3 py-2">
      <b className="num text-lg leading-tight font-bold text-text">{value}</b>
      <span className="text-xs text-text-2">{label}</span>
    </div>
  );
}

// ── 위 큰 숫자 3칸(11/04e KPI 카드 모양 — 띠 · 아이콘 칩 · 28/700). 글자 값(퍼센트)이라 카운트업은 없다 ──
interface KpiDef {
  k: string;
  label: string;
  value: string;
  sub: ReactNode;
  icon: string;
  stripe: Stripe;
}
const TOP_IDS = ['static-detection', 'static-fpr', 'runtime-detection'];

function Top({ d }: { d: Evaluation }) {
  const st = d.static;
  const mt = st?.metrics ?? {};
  const c = st?.confusion;
  const a = attacks(d.runtime);
  // 보조 줄 = 근거 숫자 · 원래 용어(점선 밑줄 → 툴팁)
  const defs: KpiDef[] = [
    {
      k: 'static-detection',
      icon: '⌕',
      stripe: 'accent',
      label: '정적 악성 탐지율',
      value: st ? pct(mt.detectionRate) : '',
      sub: c ? (
        <>
          {hint(`악성 ${fmtNum(c.tp + c.fn)}개 중 ${fmtNum(c.tp)}개`)} · <Term k="recall" />
        </>
      ) : (
        '정적 결과 없음'
      ),
    },
    {
      k: 'static-fpr',
      icon: '✓',
      stripe: 'info',
      label: '정상 패키지 오판율',
      value: st ? pct(mt.falsePositiveRate) : '',
      sub: c ? (
        <>
          {hint(`정상 ${fmtNum(c.fp + c.tn)}개 중 ${fmtNum(c.fp)}개`)} · <Term k="fpr" />
        </>
      ) : (
        '정적 결과 없음'
      ),
    },
    {
      k: 'runtime-detection',
      icon: '▣',
      stripe: 'accent',
      label: '런타임 공격 탐지율',
      value: a.runs ? pct(a.detected / a.runs) : '',
      sub: a.runs ? hint(`공격 ${fmtNum(a.runs)}회 중 ${fmtNum(a.detected)}회`, `격리 ${fmtNum(a.killed)}회`) : '런타임 결과 없음',
    },
  ];
  return <TopGrid defs={defs} />;
}

// 길게 눌러(또는 Alt+←/→) 순서 바꾸기(11/04d, R1 11/04 — localStorage supplyguard.layout.evaluationKpi, 예전 6칸 순서 중 3칸만 이어 씀).
// 칸 안 용어 단추는 끌기를 시작하지 않는다(useSortable 이 칸 안 button 의 누르기는 그대로 둔다). 768 미만은 2열(셋째 칸은 두 칸 폭)
function TopGrid({ defs }: { defs: KpiDef[] }) {
  const by = new Map(defs.map((x) => [x.k, x]));
  const { ref, order, containerClass, itemProps, pickedClass } = useSortable<HTMLDivElement>({ scope: 'evaluationKpi', ids: TOP_IDS, layout: 'grid', focusable: false, labelOf: (id) => by.get(id)?.label ?? id });
  return (
    <div ref={ref} data-part="eval-top" className={`eval-top grid grid-cols-2 gap-3 md:grid-cols-3 ${containerClass}`}>
      {order.map((id) => {
        const x = by.get(id)!;
        return <KpiCard key={id} k={x.k} label={x.label} icon={x.icon} stripe={x.stripe} text={x.value} sub={x.sub} wrapSub className={`eval-kpi ${pickedClass(id)}`} attrs={itemProps(id)} />;
      })}
    </div>
  );
}

// ── 목록 8줄 ──
type ItemId = 'dist' | 'rules' | 'confusion' | 'scenarios' | 'latency' | 'benign' | 'model' | 'limits';
const ITEMS: { id: ItemId; group?: '정적' | '런타임'; name: string }[] = [
  { id: 'dist', group: '정적', name: '데이터별 판정' },
  { id: 'rules', group: '정적', name: '규칙 적중' },
  { id: 'confusion', group: '정적', name: '판정 4칸' },
  { id: 'scenarios', group: '런타임', name: '공격 시나리오' },
  { id: 'latency', group: '런타임', name: '격리까지 걸린 시간' },
  { id: 'benign', group: '런타임', name: '정상 설치 위반' },
  { id: 'model', name: '규칙 · 모델 비교' },
  { id: 'limits', name: '결과의 한계' },
];
// 상태 칩(글자 + 톤, 빨강 없음): 통과 · 주의는 기준이 있는 줄만(공격 시나리오 · 정상 설치), 규칙 우세는 모델 비교, 그 밖은 참고
type ChipKey = 'pass' | 'warn' | 'rule' | 'ref' | 'none';
const CHIP: Record<ChipKey, [string, string]> = {
  pass: ['통과', 'sg-pill-ok'],
  warn: ['주의', 'sg-pill-warn'],
  rule: ['규칙 우세', 'sg-pill-accent'],
  ref: ['참고', 'sg-pill-neutral'],
  none: ['결과 없음', 'sg-pill-neutral'],
};
interface Summary {
  value?: ReactNode; // 핵심 값(숫자 굵게)
  sub?: string; // 근거
  meter?: { v: number; tone: 'accent' | 'warn' }; // 비율이면 얇은 막대(0~1)
  chip: ChipKey;
}
const NONE: Summary = { chip: 'none' };

// 줄 요약 — 모두 응답 값에서 계산, 없는 쪽은 「결과 없음」(값 · 근거 빈 칸)
function summaries(d: Evaluation): Record<ItemId, Summary> {
  const st = d.static;
  const rt = d.runtime;
  const md = d.model ?? d.modelAll ?? null;
  const out = {} as Record<ItemId, Summary>;

  // ① 데이터별 판정: 검사한 수 / 세트 전체(비율 막대) · 세트 수 · 지표 계산에서 뺀 오류 · 건너뜀
  if (st) {
    const sets = st.sets ?? [];
    const scanned = sets.reduce((n, s) => n + (s.scanned ?? 0), 0);
    const total = sets.reduce((n, s) => n + (s.total ?? 0), 0);
    const errors = sets.reduce((n, s) => n + (s.verdicts.error ?? 0), 0);
    const skipped = sets.reduce((n, s) => n + sum(s.skipped), 0);
    out.dist = {
      value: sets.length ? (
        <>
          <b>{fmtNum(scanned)}</b>
          {` / ${fmtNum(total)}개 검사`}
        </>
      ) : undefined,
      sub: hint(`세트 ${fmtNum(sets.length)}개`, errors > 0 && `오류 ${fmtNum(errors)}건`, skipped > 0 && `건너뜀 ${fmtNum(skipped)}건`),
      meter: total ? { v: scanned / total, tone: 'accent' } : undefined,
      chip: 'ref',
    };
    // ② 규칙 적중: 1위 규칙 · 악성/정상 적중 수 · 적중한 규칙 수
    const top = topRules(st);
    const first = top[0];
    const hit = (st.rules ?? []).filter((r) => r.maliciousHits + r.benignHits > 0).length;
    out.rules = {
      value: first ? (
        <>
          {'1위 '}
          <code className="eval-code">{first.rule}</code>
        </>
      ) : undefined,
      sub: first ? hint(`악성 ${fmtNum(first.maliciousHits)}개`, `정상 ${fmtNum(first.benignHits)}개에서 걸림`, `적중 규칙 ${fmtNum(hit)}개`) : '적중한 규칙 없음',
      chip: 'ref',
    };
  } else {
    out.dist = NONE;
    out.rules = NONE;
  }
  // ③ 판정 4칸: 종합 점수(막대) · 적중률 · 탐지율
  if (st?.confusion) {
    const mt = st.metrics ?? {};
    out.confusion = {
      value:
        mt.f1 != null ? (
          <>
            <b>{dec(mt.f1)}</b>
            {' 종합 점수'}
          </>
        ) : undefined,
      sub: hint(mt.precision != null && `적중률 ${pct(mt.precision)}`, mt.recall != null && `탐지율 ${pct(mt.recall)}`),
      meter: mt.f1 != null ? { v: mt.f1, tone: 'accent' } : undefined,
      chip: 'ref',
    };
  } else out.confusion = NONE;

  if (rt) {
    // ④ 공격 시나리오: 탐지 / 공격 회수(막대) · 공격 종류 · 대조군 탐지(0회가 정답). 통과 = 공격 모두 탐지 + 대조군 탐지 0회
    const a = attacks(rt);
    const ctl = (rt.scenarios ?? []).filter((x) => x.kind === 'control');
    const cRuns = ctl.reduce((n, x) => n + x.runs, 0);
    const cDet = ctl.reduce((n, x) => n + x.detected, 0);
    out.scenarios = {
      value: a.runs ? (
        <>
          <b>{fmtNum(a.detected)}</b>
          {` / ${fmtNum(a.runs)}회 탐지`}
        </>
      ) : undefined,
      sub: a.runs ? hint(`공격 ${fmtNum(a.list.length)}종`, ctl.length > 0 && `대조군 ${fmtNum(cRuns)}회 중 탐지 ${fmtNum(cDet)}회`) : '공격 시나리오 없음',
      meter: a.runs ? { v: a.detected / a.runs, tone: 'accent' } : undefined,
      chip: !a.runs ? 'ref' : a.detected === a.runs && cDet === 0 ? 'pass' : 'warn',
    };
    // ⑤ 격리까지 걸린 시간: 중간값 · 95% 이내 · 격리 회수(옛 파일은 가장 느린 시나리오 기준)
    const lat = latencyHead(rt);
    out.latency = {
      value: lat ? (
        <>
          <b>{`${fmtNum(lat.p50)} ms`}</b>
          {' 중간값'}
        </>
      ) : undefined,
      sub: lat ? hint(`95% 이내 ${fmtNum(lat.p95)} ms`, lat.n != null && `격리 ${fmtNum(lat.n)}회 기준`, lat.basis) : '격리한 시나리오 없음',
      chip: 'ref',
    };
  } else {
    out.scenarios = NONE;
    out.latency = NONE;
  }
  // ⑥ 정상 설치 위반: 위반 / 정상 설치(막대) · 오판율 · 생태계별 설치 수. 통과 = 위반 0건
  const b = rt?.benign;
  out.benign = b
    ? {
        value: (
          <>
            <b>{fmtNum(b.violations)}</b>
            {` / ${fmtNum(b.installs)}건 위반`}
          </>
        ),
        sub: hint(`오판율 ${pct(b.falsePositiveRate)}`, ...Object.entries(b.byEcosystem ?? {}).map(([k, v]) => `${k} ${fmtNum(v)}`)),
        meter: b.installs ? { v: b.violations / b.installs, tone: 'warn' } : undefined,
        chip: b.violations === 0 ? 'pass' : 'warn',
      }
    : NONE;
  // ⑦ 규칙 · 모델 비교(PyPI 모델 — 없으면 전체 범위): 규칙 최고 · 선택 모델의 시험 종합 점수, 운영 미적용. 규칙이 앞서면 「규칙 우세」
  if (md) {
    const { rule, pref } = modelPicks(md);
    const ml = pref && pref.id !== rule?.id ? pref : undefined;
    out.model = {
      value:
        rule || ml ? (
          <>
            {rule && (
              <>
                <b>{dec(rule.test.f1)}</b>
                {' 규칙'}
              </>
            )}
            {rule && ml && ' · '}
            {ml && (
              <>
                <b>{dec(ml.test.f1)}</b>
                {' ML 모델'}
              </>
            )}
          </>
        ) : undefined,
      sub: hint('종합 점수(시험)', ml?.label, !md.deploymentApproved && '운영 미적용'),
      chip: ruleWins(md) ? 'rule' : 'ref',
    };
  } else out.model = NONE;
  // ⑧ 결과의 한계: 적힌 한계 수 · 출처별 수
  const items = limitItems(d);
  const counts = (Object.keys(SOURCE) as (keyof typeof SOURCE)[]).map((k) => [k, items.filter((x) => x[0] === k).length] as const).filter(([, n]) => n > 0);
  out.limits = {
    value: (
      <>
        <b>{fmtNum(items.length)}</b>건
      </>
    ),
    sub: items.length ? hint(...counts.map(([k, n]) => `${SOURCE[k]} ${fmtNum(n)}`)) : '적힌 한계 없음',
    chip: 'ref',
  };
  return out;
}

// 목록 줄 하나: 머리(단추 = ▶ · 이름 · 값 · 근거 · 막대 · 칩) + 안쪽(높이 0fr ↔ 1fr, --dur-base · --ease-move — 열 때 · 닫을 때 같은 값).
// 안쪽은 늘 그려 둔다(차트 폭을 미리 잼). 접히면 visibility hidden(전환이 끝난 뒤) — 포커스 · 화면 낭독기에서 빠진다.
// 열림 전환이 끝나면(settled) 안쪽 넘침을 보이게 해 차트 툴팁이 잘리지 않게 한다. 닫히면 바로 다시 자른다
function Row({ it, s, open, onToggle, children }: { it: (typeof ITEMS)[number]; s: Summary; open: boolean; onToggle: () => void; children: ReactNode }) {
  const id = useId();
  const [prevOpen, setPrevOpen] = useState(open);
  const [settled, setSettled] = useState(false);
  if (prevOpen !== open) {
    setPrevOpen(open);
    setSettled(open && reducedMotion());
  }
  // transitionend 가 오지 않는 경우(탭 숨김 등)의 안전장치
  useEffect(() => {
    if (!open || settled) return;
    const t = window.setTimeout(() => setSettled(true), 260);
    return () => window.clearTimeout(t);
  }, [open, settled]);
  const onEnd = (e: TransitionEvent) => {
    if (e.target === e.currentTarget && e.propertyName === 'grid-template-rows' && open) setSettled(true);
  };
  const [chipText, chipTone] = CHIP[s.chip];
  return (
    <li data-item={it.id} data-open={open} data-settled={open && settled ? '' : undefined} className="eval-item">
      <h2 className="m-0">
        <button
          type="button"
          id={`${id}b`}
          data-action="toggle-row"
          aria-expanded={open}
          aria-controls={`${id}p`}
          aria-labelledby={`${id}n`}
          aria-describedby={`${id}s ${id}c`}
          onClick={onToggle}
          className="eval-row"
        >
          <span data-part="caret" className="eval-caret" aria-hidden />
          <span id={`${id}n`} data-name="" className="eval-name">
            {it.group && (
              <>
                <span className="eval-group">{it.group}</span>
                <span className="eval-group"> · </span>
              </>
            )}
            <span>{it.name}</span>
          </span>
          <span id={`${id}s`} className="eval-res">
            <span className="eval-res-text">
              <span data-value="" className="eval-val">
                {s.value}
              </span>
              <span data-sub="" className="eval-sub">
                {s.sub}
              </span>
            </span>
            <span className="eval-meter-cell" aria-hidden>
              {s.meter && (
                <span data-meter="" data-v={String(s.meter.v)} className={`eval-meter tone-${s.meter.tone}`}>
                  <i style={{ width: `${Math.min(1, Math.max(0, s.meter.v)) * 100}%` }} />
                </span>
              )}
            </span>
          </span>
          <span id={`${id}c`} data-chip={s.chip} className={`eval-chip sg-pill ${chipTone}`}>
            {chipText}
          </span>
        </button>
      </h2>
      <div id={`${id}p`} role="region" aria-labelledby={`${id}n`} className="eval-panel" onTransitionEnd={onEnd}>
        <div className="eval-panel-in">
          <div className="eval-panel-body">{children}</div>
        </div>
      </div>
    </li>
  );
}

function EvalList({ d, open, onToggle, listId }: { d: Evaluation; open: ReadonlySet<ItemId>; onToggle: (id: ItemId) => void; listId: string }) {
  const s = summaries(d);
  const body: Record<ItemId, ReactNode> = {
    dist: <DistBody st={d.static} />,
    rules: <RulesBody st={d.static} />,
    confusion: <ConfusionBody st={d.static} />,
    scenarios: <ScenarioBody rt={d.runtime} />,
    latency: <LatencyBody rt={d.runtime} />,
    benign: <BenignBody rt={d.runtime} />,
    model: <ModelBody model={d.model} modelAll={d.modelAll} />,
    limits: <LimitsBody d={d} />,
  };
  return (
    <section id={listId} data-part="eval-list" aria-label="평가 항목" className="sg-card eval-list">
      <div data-part="eval-list-head" className="eval-list-head">
        <span className="eval-head-caret" aria-hidden />
        <span data-head="name">
          항목
          <Term k="colItem" q />
        </span>
        <span data-head="result">
          결과
          <Term k="colResult" q />
        </span>
        <span data-head="state" className="eval-head-state">
          상태
          <Term k="colState" q />
        </span>
      </div>
      <ul className="eval-items">
        {ITEMS.map((it) => (
          <Row key={it.id} it={it} s={s[it.id]} open={open.has(it.id)} onToggle={() => onToggle(it.id)}>
            {body[it.id]}
          </Row>
        ))}
      </ul>
    </section>
  );
}

// ── 줄 안쪽: 정적 ──
function DistBody({ st }: { st: EvalStatic | null }) {
  if (!st)
    return (
      <Body part="dist">
        <None what="정적" />
      </Body>
    );
  const label = (id: string) => st.datasets?.find((x) => x.id === id)?.label ?? id;
  const sets = st.sets ?? [];
  const rows: BarRow[] = sets.map((set) => {
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
        ...(skip ? [[null, `건너뜀 ${fmtNum(skip)}(${Object.entries(set.skipped ?? {}).map(([k, v]) => `${k} ${v}`).join(' · ')})`] as TipLine] : []),
      ],
    };
  });
  const errors = sets.reduce((n, s) => n + (s.verdicts.error ?? 0), 0);
  const skipped = sets.reduce((n, s) => n + sum(s.skipped), 0);
  // 자세히: 차트와 같은 수를 표로(키보드 · 화면 낭독기로도 읽힘)
  const detail = sets.length > 0 && (
    <>
      <div className="overflow-x-auto">
        <table className="sg-table" data-table="datasets">
          <thead>
            <tr>
              {['데이터', '검사', '악성', '주의', '취약', '정상'].map((t, i) => (
                <th key={t} className={i ? 'num-col' : undefined}>
                  {t}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sets.map((s) => (
              <tr key={s.id} data-set={s.id}>
                <td>{label(s.id)}</td>
                {[s.scanned, s.verdicts.malicious, s.verdicts.suspicious, s.verdicts.vulnerable, s.verdicts.clean].map((v, i) => (
                  <td key={i} className="num num-col">
                    {fmtNum(v ?? 0)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {(errors > 0 || skipped > 0) && <ChartNote part="dist-excluded">{hint(errors > 0 && `오류 ${fmtNum(errors)}건`, skipped > 0 && `건너뜀 ${fmtNum(skipped)}건`)}은 지표 계산에서 제외됨</ChartNote>}
    </>
  );
  return (
    <Body part="dist" detail={detail || undefined} detailName="데이터별 판정 표">
      <HBars
        name="verdict-dist"
        label="데이터별 판정 결과 쌓은 막대"
        rows={rows}
        ticks={RATE_TICKS}
        tickFmt={pct0}
        legend={VERDICTS.map(([, ko, c, t]): [ReactNode, ColorKey] => [t ? <Term k={t}>{ko}</Term> : ko, c])}
        labelW={130}
      />
      {st.durationsSec && (
        <ChartNote>
          {'검사 1건 걸린 시간('}
          <Term k="p50">중간값</Term>
          {` ${fmtNum(st.durationsSec.p50)}초 · `}
          <Term k="p95">95% 이내</Term>
          {` ${fmtNum(st.durationsSec.p95)}초)`}
        </ChartNote>
      )}
    </Body>
  );
}
// 규칙 적중 — 예전 카드 본문(1위 한 줄)은 줄 요약으로 올라가, 예전 「자세히」였던 상위 10 차트를 바로 보인다
function RulesBody({ st }: { st: EvalStatic | null }) {
  if (!st)
    return (
      <Body part="rules">
        <None what="정적" />
      </Body>
    );
  const top = topRules(st);
  const rows: BarRow[] = top.map((r) => ({
    id: r.rule,
    label: r.rule,
    mono: true,
    value: `${fmtNum(r.maliciousHits)} · ${fmtNum(r.benignHits)}`,
    bars: [[{ key: 'malicious', v: r.maliciousHits, color: 'mal' }], [{ key: 'benign', v: r.benignHits, color: 'muted' }]],
    tip: [[null, r.rule], ['mal', `악성 패키지 ${fmtNum(r.maliciousHits)}개`], ['muted', `정상 패키지 ${fmtNum(r.benignHits)}개`], ...(r.installTime ? [[null, '설치 시점 규칙'] as TipLine] : [])],
  }));
  return (
    <Body part="rules">
      <Cap>
        {'많이 걸린 '}
        <Term k="guarddog">GuardDog</Term>
        {' 규칙 상위 10'}
      </Cap>
      {top.length ? (
        <HBars
          name="rule-hits"
          label="GuardDog 규칙별 악성 · 정상 패키지에서 걸린 수"
          rows={rows}
          ticks={niceTicks(Math.max(1, ...top.map((r) => Math.max(r.maliciousHits, r.benignHits))))}
          tickFmt={(t) => fmtNum(t)}
          legend={[
            ['악성 패키지에서 걸림', 'mal'],
            ['정상 패키지에서 걸림', 'muted'],
          ]}
          labelW={170}
        />
      ) : (
        <p className="py-2 text-xs text-text-3">적중한 규칙 없음</p>
      )}
    </Body>
  );
}
function ConfusionBody({ st }: { st: EvalStatic | null }) {
  if (!st?.confusion)
    return (
      <Body part="confusion">
        <None what="정적" />
      </Body>
    );
  const c = st.confusion;
  const mt = st.metrics ?? {};
  const cell = (k: string, n: number, what: string) => (
    <td data-cell={k} className="px-3 py-2">
      <b className="num mr-1.5 text-lg font-semibold text-text">{fmtNum(n)}</b>
      <span className="text-xs text-text-3">{what}</span>
    </td>
  );
  const eco = Object.entries(st.metricsByEcosystem ?? {});
  const detail = (
    <>
      <p className="text-xs font-semibold text-text-2">
        <Term k="confusion">판정 4칸 표</Term>
        {'(실제 정답 × 판정 개수)'}
      </p>
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
              {cell('fp', c.fp, '오판')}
              {cell('tn', c.tn, '통과')}
            </tr>
          </tbody>
        </table>
      </div>
      {eco.length > 0 && <ChartNote part="by-ecosystem">{`생태계별 ${eco.map(([k, v]) => `${k} 탐지율 ${pct(v.metrics.detectionRate)} · 오판율 ${pct(v.metrics.falsePositiveRate)}`).join(' / ')}`}</ChartNote>}
    </>
  );
  return (
    <Body part="confusion" detail={detail} detailName="판정 4칸 표">
      <div data-part="confusion-stats" className="grid max-w-[560px] grid-cols-3 gap-2">
        <Stat k="precision" value={pct(mt.precision)} label={<Term k="precision">적중률</Term>} />
        <Stat k="recall" value={pct(mt.recall)} label={<Term k="recall">탐지율</Term>} />
        <Stat k="f1" value={dec(mt.f1)} label={<Term k="f1">종합 점수</Term>} />
      </div>
      {mt.detectionRateWithSuspicious != null && (
        <ChartNote part="with-suspicious">
          <Term k="suspicious">주의</Term>
          {` 판정까지 악성으로 보면 ${hint(`탐지율 ${pct(mt.detectionRateWithSuspicious)}`, mt.falsePositiveRateWithSuspicious != null && `오판율 ${pct(mt.falsePositiveRateWithSuspicious)}`)}`}
        </ChartNote>
      )}
    </Body>
  );
}

// ── 줄 안쪽: 런타임 ──
function ScenarioBody({ rt }: { rt: EvalRuntime | null }) {
  if (!rt)
    return (
      <Body part="scenarios">
        <None what="런타임" />
      </Body>
    );
  const rows: BarRow[] = (rt.scenarios ?? []).map((x) => {
    const color: ColorKey = x.kind === 'attack' ? 'attack' : 'muted';
    return {
      id: x.id,
      label: x.label,
      value: `${fmtNum(x.detected)}/${fmtNum(x.runs)}`,
      bars: [[{ key: x.kind, v: x.runs ? x.detected / x.runs : 0, color }]],
      tip: [
        [null, x.label],
        [color, `${x.kind === 'attack' ? '공격' : '대조군'} · 탐지 ${fmtNum(x.detected)} / ${fmtNum(x.runs)}회`],
        [null, `격리 ${fmtNum(x.killed)}회${x.rule ? ` · 규칙 ${x.rule}` : ''}${x.dryRun ? ' · 시험 운영' : ''}`],
      ],
    };
  });
  return (
    <Body part="scenarios">
      <HBars
        name="scenario-rate"
        label="공격 시나리오별 탐지율 막대"
        rows={rows}
        ticks={RATE_TICKS}
        tickFmt={pct0}
        legend={[
          ['공격', 'attack'],
          [
            <>
              <Term k="control">대조군</Term>
              {'(0%가 정답)'}
            </>,
            'muted',
          ],
        ]}
        labelW={150}
      />
    </Body>
  );
}
function LatencyBody({ rt }: { rt: EvalRuntime | null }) {
  if (!rt)
    return (
      <Body part="latency">
        <None what="런타임" />
      </Body>
    );
  const sc = rt.scenarios ?? [];
  const list = sc.filter((x): x is EvalScenario & { latencyMs: EvalStat } => !!x.latencyMs && x.latencyMs.p50 != null);
  const skipped = sc.filter((x) => x.kind === 'attack' && !(x.latencyMs && x.latencyMs.p50 != null));
  return (
    <Body part="latency">
      <Cap>시나리오별 범위 (ms)</Cap>
      {list.length ? (
        <RangeChart
          name="latency"
          label="시나리오별 탐지에서 격리까지 걸린 시간 범위"
          rows={list.map((x) => ({
            id: x.id,
            label: x.label,
            lat: x.latencyMs,
            tip: [[null, x.label], ['attack', `중간값 ${ms(x.latencyMs.p50)}`], [null, `95% 이내 ${ms(x.latencyMs.p95)}`], [null, `최대 ${ms(x.latencyMs.max ?? x.latencyMs.p95)}`], [null, `격리 ${fmtNum(x.killed)}회 기준`]],
          }))}
        />
      ) : (
        <p className="py-2 text-xs text-text-3">격리까지 잰 시나리오가 없습니다</p>
      )}
      {skipped.length > 0 && (
        <ChartNote part="latency-skipped">
          {'격리하지 않아 빠짐: '}
          {skipped.map((x, i) => (
            <Fragment key={x.id}>
              {i > 0 && ' · '}
              {x.label}
              {x.dryRun && (
                <>
                  {' ('}
                  <Term k="dryrun">시험 운영</Term>
                  {')'}
                </>
              )}
            </Fragment>
          ))}
        </ChartNote>
      )}
      <Stages rt={rt} />
    </Body>
  );
}
// [11/04b] 단계별 막대 — 중간값(p50) 가로 누적(규칙 판정 → 증거 수집 → 격리 명령, 합계). 첫 행은 격리된 공격 전체(killStagesMs), 그 아래 격리한 시나리오별. 툴팁에 95% 이내(p95).
// killStagesMs 가 없는 옛 파일이면 숨긴다. 「규칙 판정」 조각은 최소 폭 없음(11/04 사용자 결정)
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
          ...STAGES.map(([k, ko, color]): TipLine => [color, st[k] ? `${ko} 중간값 ${fmtNum(msv(st[k]!.p50))} ms · 95% 이내 ${fmtNum(msv(st[k]!.p95))} ms` : `${ko} 측정값 없음`]),
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
        단계별 시간 (중간값)
      </p>
      <HBars
        name="kill-stages"
        label="탐지에서 격리까지 단계별 시간 누적 막대"
        rows={rows.map((x) => x.r)}
        ticks={niceTicks(Math.max(1, ...rows.map((x) => x.total)))}
        tickFmt={(t) => fmtNum(t)}
        legend={STAGES.map(([k, ko, c]): [ReactNode, ColorKey] => [k === 'killApi' ? <Term k="killapi">{ko}</Term> : ko, c])}
        labelW={150}
        valueW={88}
        minSeg={0}
      />
      <ChartNote part="stages-caption">증거를 먼저 모으고(≤0.7초) 격리합니다</ChartNote>
    </>
  );
}
// 정상 설치 위반 — 예전 제목의 건수 · 머리 오른쪽 「정상 설치 N건 중 · 생태계별」은 줄 요약으로 올라갔다. 위반 표(있으면)는 바로 보인다
function BenignBody({ rt }: { rt: EvalRuntime | null }) {
  if (!rt?.benign)
    return (
      <Body part="benign">
        <None what="런타임" />
      </Body>
    );
  const b = rt.benign;
  const rows = (b.items ?? []).filter((x) => !PASS.has(x.result) || !!x.rule);
  return (
    <Body part="benign">
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
                  <td className="font-mono text-xs">{x.rule || ''}</td>
                  <td className="num num-col">{x.seconds != null ? `${fmtNum(x.seconds)}초` : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p data-part="benign-pass" className="py-1 text-[13px] text-text-2">{`[통과] 정상 설치 ${fmtNum(b.installs)}건 모두 위반 없음`}</p>
      )}
    </Body>
  );
}

// ── 규칙 vs ML 모델 — modelAll 이 있으면 「PyPI / 전체」 탭. 요약(규칙 최고 · 선택 모델) + 「운영은 규칙」은 보이고, 비교 표 · 실험 조건은 「자세히」 ──
function ModelBody({ model, modelAll }: { model: EvalModel | null; modelAll?: EvalModel | null }) {
  const [scope, setScope] = useState<'pypi' | 'all'>('pypi');
  const md = scope === 'all' && modelAll ? modelAll : (model ?? modelAll ?? null);
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
  if (!md)
    return (
      <Body part="model">
        <None what="모델" />
      </Body>
    );
  const actions = (
    <>
      {tabs}
      {!md.deploymentApproved && (
        <span data-part="not-deployed" title="선택 모델은 비교용이고 판정은 지금도 규칙으로 합니다" className="rounded bg-surface-2 px-2 py-0.5 text-xs font-medium text-text-2 ring-1 ring-border ring-inset">
          운영 미적용
        </span>
      )}
    </>
  );
  const p = md.protocol ?? {};
  const cs = md.candidates ?? [];
  const label = (id: string) => cs.find((x) => x.id === id)?.label ?? id;
  const test = p.partitions?.test;
  const { rule, pref } = modelPicks(md);
  const sums = [rule && (['rule', rule, '규칙'] as const), pref && pref.id !== rule?.id && (['model', pref, 'ML 모델(선택)'] as const)].filter((x) => !!x);
  const detail = (
    <>
      <div className="overflow-x-auto">
        <table className="w-full text-sm" data-table="models">
          <thead>
            <tr className="border-b border-border">
              {[
                ['candidate', '후보'],
                [
                  'f1-calibration',
                  <>
                    <Term k="f1">종합 점수</Term>(<Term k="split">선택용</Term>)
                  </>,
                ],
                ['f1-test', '종합 점수(시험)'],
                ['precision', <Term k="precision">적중률</Term>],
                ['recall', <Term k="recall">탐지율</Term>],
                ['fpr', <Term k="fpr">오판율</Term>],
              ].map(([k, t], i) => (
                <th key={k as string} className={`px-3 py-1.5 ${i ? 'text-right' : 'text-left'}`}>
                  {t}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {cs.map((x) => {
              const pick = x.id === md.preferredId;
              return (
                <tr key={x.id} data-model={x.id} aria-current={pick ? 'true' : undefined} className={`border-b border-border last:border-0 ${pick ? 'bg-accent-soft hover:!bg-accent-soft' : ''}`}>
                  <td className={`px-3 py-1.5 ${pick ? 'font-semibold shadow-[inset_3px_0_0_var(--accent)]' : ''}`} title={x.threshold != null ? `기준값 ${x.threshold}` : undefined}>
                    {x.label}
                    {pick && (
                      <span data-part="pick-badge" title="선택용 구간에서 고른 모델(시험 구간은 고를 때 쓰지 않음)" className="ml-2 rounded bg-indigo-100 px-1.5 py-0.5 text-xs font-medium text-indigo-800">
                        선택한 모델
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
      <p data-part="protocol" className="text-xs text-text-3" title={[(md.features ?? []).join(', '), md.topFeatures?.length && `상위 특징: ${md.topFeatures.map((f) => `${f.feature} ${f.weight}`).join(', ')}`].filter(Boolean).join('\n')}>
        {'실험 조건: '}
        {[p.seed != null && `seed ${p.seed}`, p.split, p.selection && `선택 기준: ${p.selection}`, `특징 ${fmtNum((md.features ?? []).length)}개`, test && `시험 악성 ${fmtNum(test.malicious)} · 정상 ${fmtNum(test.benign)}`].filter(Boolean).join(' · ')}
      </p>
      {md.byEcosystem && <ByEcosystem md={md} />}
      {md.npmReference?.recall && (
        <p data-part="npm-ref" className="text-xs text-text-3">
          {`npm 참고(${md.npmReference.note ?? '탐지율'}): ${Object.entries(md.npmReference.recall).map(([id, v]) => `${label(id)} ${pct(v)}`).join(' · ')}`}
        </p>
      )}
    </>
  );
  return (
    <Body part="model" actions={actions} detail={detail} detailName="규칙 · 모델 비교 표">
      <div data-part="model-summary" className="grid gap-2 sm:grid-cols-2">
        {sums.map(([k, x, kind]) => (
          <div key={k} data-sum={k} className="grid min-w-0 content-start gap-1 rounded-lg bg-surface-2 px-3 py-2.5">
            <p className="text-xs text-text-3">{kind}</p>
            <p className="text-[13px] font-semibold text-text">
              <ModelName x={x} />
            </p>
            <p className="flex flex-wrap items-baseline gap-x-4 gap-y-0.5">
              <span className="inline-flex items-baseline gap-1.5">
                <b className="num text-lg leading-tight font-bold text-text">{dec(x.test.f1)}</b>
                <span className="text-xs text-text-2">
                  <Term k="f1">종합 점수</Term>
                </span>
              </span>
              <span className="inline-flex items-baseline gap-1.5">
                <b className="num text-sm font-semibold text-text">{pct(x.test.fpr)}</b>
                <span className="text-xs text-text-2">
                  <Term k="fpr">오판율</Term>
                </span>
              </span>
            </p>
          </div>
        ))}
      </div>
      {ruleWins(md) && (
        <p data-part="rule-wins" className="text-xs font-medium text-text-2">
          [규칙 우세] 시험 결과에 따라 운영은 규칙 판정 사용
        </p>
      )}
    </Body>
  );
}

// 전체 범위(model-all.json)의 생태계별 시험 지표 — 후보마다 종합 점수 · 오판율
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
                {k} 종합 점수 · 오판율
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

// 측정 출처(예전 머리 「측정 출처」 접힘) — 세트 · 런타임 호스트 · 생성 시각(가장 늦은) · 백엔드 커밋 앞 7자리
function sourceTags(d: Evaluation) {
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
        title={[commits.join(' · '), st?.scanner && `GuardDog ${st.scanner.guarddog} · OSV-Scanner ${st.scanner.osv}`].filter(Boolean).join('\n')}
      />,
    );
  return tags;
}

// 결과의 한계 — 예전 본문(적힌 한계 N건 · 출처별)은 줄 요약으로 올라가, 예전 「자세히」였던 문장 목록을 바로 보인다. 아래에 측정 출처
function LimitsBody({ d }: { d: Evaluation }) {
  const items = limitItems(d);
  const tags = sourceTags(d);
  return (
    <Body part="limits">
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
      {tags.length > 0 && (
        <div data-part="sources" className="mt-1 grid gap-1.5 border-t border-border pt-2.5">
          <Cap>측정 출처</Cap>
          <div data-part="tags" className="flex flex-wrap gap-1.5">
            {tags}
          </div>
        </div>
      )}
    </Body>
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
  // 열린 줄(기본 모두 접힘 · 기억하지 않음). 「모두 펼치기」 = 하나라도 접혀 있으면 전부 열고, 전부 열려 있으면(「모두 접기」) 전부 닫는다
  const [open, setOpen] = useState<ReadonlySet<ItemId>>(() => new Set());
  const allOpen = open.size === ITEMS.length;
  const listId = useId();
  const toggle = (id: ItemId) =>
    setOpen((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  return (
    // R4 11/04(목업 11/04e .eval-body): 768 이상은 위 3칸이 제자리, 아래 목록만 채움 칸으로 스크롤.
    // 768 미만은 예전처럼 화면 전체가 한 칸으로 스크롤(목록은 그대로 펼침)
    <div className="flex h-full min-h-0 flex-col gap-4 max-md:block max-md:overflow-y-auto" data-part="evaluation" data-state={state}>
      <p data-part="screen-copy" data-screen="evaluation" className="m-0 shrink-0 truncate text-[length:var(--fs-sm)] text-text-3 max-md:mb-3">
        {screenCopy('evaluation')}
      </p>
      {state === 'ready' && d && (
        <PageActions>
          <button
            type="button"
            data-action="toggle-all"
            aria-expanded={allOpen}
            aria-controls={listId}
            onClick={() => setOpen(allOpen ? new Set() : new Set(ITEMS.map((x) => x.id)))}
            className="sg-btn sg-btn-sm sg-btn-secondary shrink-0 whitespace-nowrap"
          >
            {allOpen ? '모두 접기' : '모두 펼치기'}
          </button>
          <button
            type="button"
            data-action="download-json"
            title="이 화면의 결과(static · runtime · model)를 JSON 한 파일로"
            onClick={() => download(d)}
            className="sg-btn sg-btn-sm sg-btn-secondary flex shrink-0 items-center gap-1.5 whitespace-nowrap max-md:min-w-0 max-md:px-2"
          >
            {/* 768 미만은 아이콘만(머리 칸이 좁아 「모두 펼치기」와 함께 들어가게) — 이름은 그대로 */}
            <Download className="size-3.5" aria-hidden /> <span className="max-md:sr-only">결과 JSON</span>
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
          <EmptyState what="평가 결과" hint="정적 · 런타임 · 모델 평가를 돌려 결과가 서버에 올라오면 여기에 보입니다." />
        </div>
      ) : (
        <>
          <div className="mx-auto w-full max-w-[var(--content-max)] shrink-0 max-md:mb-4">
            <Top d={d} />
          </div>
          <div data-fill="" data-part="eval-body" className="min-h-0 flex-1 overflow-y-auto max-md:overflow-visible">
            <div className="mx-auto max-w-[var(--content-max)]">
              <EvalList d={d} open={open} onToggle={toggle} listId={listId} />
            </div>
          </div>
        </>
      )}
    </div>
  );
}
