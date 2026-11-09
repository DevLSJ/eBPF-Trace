import { Download } from 'lucide-react';
import { Fragment, useId, useState, type ReactNode } from 'react';
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
import { INSTALL_STATUS_LABEL, type EvalCandidate, type EvalModel, type EvalRuntime, type EvalScenario, type EvalStat, type EvalStatic, type Evaluation, type EvalVerdict, type InstallStatus } from '../../lib/types';
import { ChartNote, HBars, RangeChart, type BarRow } from './charts';
import { niceTicks, RATE_TICKS, type ColorKey, type TipLine } from './scale';
import { Term, type TermKey } from './terms';

// 평가(11/04 U1 — 목업 mock/shared/eval.js 확정본 · 11/04b · 11/04c) — 「이 탐지는 얼마나 맞고, 어디까지 믿을 수 있나?」
// 11/09 사용자 결정 「평가 = 요점 3줄 + 쉬운 이름 + 용어 툴팁 + 자세한 표 접기」(용어 · 글씨가 많아 읽기 어렵다):
//   요점 3줄(숫자 먼저, 응답에서 계산) · 지표 · 제목은 쉬운 이름(원래 용어는 점선 밑줄 단추 → 툴팁) · 세부 표 · 출처 · 한계 목록은 기본 접힘(「자세히」).
// 데이터: GET /api/evaluation → {static, runtime, model, modelAll}(bench/reports 실측 파일 그대로, 없는 쪽 null · 결과 없음 404). 읽기 전용, 조회자도 본다.
// 순서: 머리(요점 3줄 · 측정 출처 접힘) → 지표 6칸 → 두 열(정적: 판정 결과 · 규칙 적중 · 판정 정확도 / 런타임: 시나리오 탐지율 · 격리 시간 + 단계 막대 · 정상 설치 위반)
//       → 규칙 vs ML 모델(전체 폭) → 결과의 한계(전체 폭)
// 쉬운 이름 대응(화면 전체 같은 말): 재현율 → 탐지율 · 오탐률 → 오판율 · 정밀도 → 적중률 · F1 → 종합 점수 · p50 → 중간값 · p95 → 95% 이내 ·
//   혼동 행렬 → 판정 4칸 표 · 보정/시험 → 선택용/시험 · dryRun → 시험 운영 · kill 호출 → 격리 명령 · 대조(정상) → 대조군

const pct = (x: number | null | undefined) => (x == null || !Number.isFinite(x) ? '—' : `${(x * 100).toFixed(1)}%`);
const pct0 = (x: number) => `${Math.round(x * 100)}%`;
const dec = (x: number | null | undefined) => (x == null || !Number.isFinite(x) ? '—' : x.toFixed(2));
const ms = (x: number | null | undefined) => (x == null ? '—' : `${fmtNum(x)} ms`);
const sum = (o: Record<string, number | undefined> | undefined) => Object.values(o ?? {}).reduce<number>((a, b) => a + (Number(b) || 0), 0);
// 지표 보조 줄 — 조각 안에서는 줄을 바꾸지 않는다
const hint = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).map((t) => (t as string).replace(/ /g, '\u00a0')).join(' · ');
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
  if (k && k.p50 != null) return { p50: k.p50, p95: k.p95, basis: null };
  const l = attacks(rt).list.map((x) => x.latencyMs).filter((x): x is EvalStat => !!x && x.p50 != null);
  return l.length ? { p50: Math.max(...l.map((x) => x.p50)), p95: Math.max(...l.map((x) => x.p95)), basis: '가장 느린 시나리오 기준' } : null;
}
// 요점 3줄(11/09) — 숫자(현상) 먼저 → 쉬운 이름 → 근거. 모두 응답 값에서 계산하고, 없는 쪽은 「… 결과 없음」
interface Point {
  k: 'static-detection' | 'false-alarm' | 'runtime';
  num: string;
  label: string;
  basis: ReactNode;
}
function keyPoints(d: Evaluation): Point[] {
  const c = d.static?.confusion;
  const mt = d.static?.metrics ?? {};
  const a = attacks(d.runtime);
  const b = d.runtime?.benign;
  const lat = latencyHead(d.runtime);
  const falses = [c && `정상 패키지 ${fmtNum(c.fp + c.tn)}개 중 ${fmtNum(c.fp)}개 오판`, b && `정상 설치 ${fmtNum(b.installs)}건 중 위반 ${fmtNum(b.violations)}건`].filter(Boolean).join(' · ');
  return [
    {
      k: 'static-detection',
      num: c ? pct(mt.detectionRate) : '—',
      label: '정적 악성 탐지율',
      basis: c ? `실제 악성 패키지 ${fmtNum(c.tp + c.fn)}개 중 ${fmtNum(c.tp)}개 탐지됨` : '정적 검사 결과 없음',
    },
    {
      k: 'false-alarm',
      num: c ? pct(mt.falsePositiveRate) : b ? pct(b.falsePositiveRate) : '—',
      label: !c && b ? '정상 설치 오판율' : '정상 패키지 오판율',
      basis: falses || '오판 결과 없음',
    },
    {
      k: 'runtime',
      num: a.runs ? pct(a.detected / a.runs) : '—',
      label: '런타임 공격 탐지율',
      basis: a.runs ? (
        <>
          {a.detected === a.runs ? `공격 ${fmtNum(a.runs)}회 모두 탐지` : `공격 ${fmtNum(a.runs)}회 중 ${fmtNum(a.detected)}회 탐지`}
          {a.killed > 0 && ` · ${fmtNum(a.killed)}회 격리`}
          {lat && (
            <>
              {' · 격리까지 '}
              <Term k="p50">중간값</Term>
              {` ${fmtNum(lat.p50)} ms`}
            </>
          )}
        </>
      ) : (
        '런타임 결과 없음'
      ),
    },
  ];
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
// 카드 — detail 이 있으면 머리 오른쪽에 「자세히」, 본문 아래에 접힌 칸
function Card({
  part,
  title,
  actions,
  detail,
  detailName,
  level = 3,
  className = '',
  children,
}: {
  part: string;
  title: ReactNode;
  actions?: ReactNode;
  detail?: ReactNode;
  detailName?: string;
  level?: 2 | 3;
  className?: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const H = level === 2 ? 'h2' : 'h3';
  return (
    <section data-part={part} className={`sg-card min-w-0 ${className}`}>
      <header className="flex min-h-11 flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-border px-4 py-2">
        <H className="text-[14.5px] font-semibold text-text">{title}</H>
        {(actions || detail) && (
          <div className="flex flex-wrap items-center gap-2">
            {actions}
            {detail && <FoldButton open={open} onToggle={() => setOpen((v) => !v)} controls={id} name={detailName ?? (typeof title === 'string' ? title : part)} />}
          </div>
        )}
      </header>
      <div className="grid min-w-0 gap-2 px-4 pt-3 pb-3.5">
        {children}
        {detail && (
          <div id={id} hidden={!open} data-part="detail" className="grid min-w-0 gap-2 border-t border-border pt-3">
            {detail}
          </div>
        )}
      </div>
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
// 숫자 먼저 작은 칸(판정 정확도 · 모델 요약)
function Stat({ k, value, label }: { k: string; value: string; label: ReactNode }) {
  return (
    <div data-stat={k} className="grid min-w-0 content-start gap-0.5 rounded-lg bg-surface-2 px-3 py-2">
      <b className="num text-lg leading-tight font-bold text-text">{value}</b>
      <span className="text-xs text-text-2">{label}</span>
    </div>
  );
}
// 지표 칸 — 11/04e KPI 카드 모양(띠 · 아이콘 칩 · 28/700, R1 11/04). 글자 값(퍼센트 · 「—」)이라 카운트업은 없다
interface KpiDef {
  k: string;
  label: string;
  value: string;
  unit?: string;
  sub: ReactNode;
  icon: string;
  stripe: Stripe;
}
const KPI_IDS = ['static-detection', 'static-fpr', 'runtime-detection', 'runtime-fpr', 'latency', 'model-f1'];

// ── 머리: 요점 3줄 + 측정 출처(접힘) ──
function Head({ d }: { d: Evaluation }) {
  const [open, setOpen] = useState(false);
  const id = useId();
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
    <section data-part="eval-head" className="sg-card grid gap-2 px-4 py-3 md:px-5 md:py-3.5">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-[14.5px] font-semibold text-text">요점</h2>
        {tags.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-3" aria-hidden>
              측정 출처
            </span>
            <FoldButton open={open} onToggle={() => setOpen((v) => !v)} controls={id} name="측정 출처" />
          </div>
        )}
      </div>
      {/* 768 이상은 세 칸(숫자 · 이름 · 근거)을 줄끼리 맞춘다(subgrid), 그 아래는 숫자 · 이름 한 줄 + 근거 다음 줄 */}
      <ol data-part="key-points" className="grid gap-y-1.5 md:grid-cols-[max-content_max-content_minmax(0,1fr)] md:gap-x-4">
        {keyPoints(d).map((p) => (
          <li key={p.k} data-point={p.k} className="grid grid-cols-[minmax(64px,max-content)_minmax(0,1fr)] items-baseline gap-x-3 md:col-span-full md:grid-cols-subgrid">
            <b data-num="" className="num text-lg leading-snug font-bold text-text">
              {p.num}
            </b>
            <span data-label="" className="text-sm font-semibold text-text">
              {p.label}
            </span>
            <span data-basis="" className="col-span-2 min-w-0 text-[13px] text-text-2 md:col-span-1">
              {p.basis}
            </span>
          </li>
        ))}
      </ol>
      {tags.length > 0 && (
        <div id={id} hidden={!open} data-part="detail" className="grid gap-1.5 border-t border-border pt-2.5">
          <p className="text-xs font-semibold text-text-3">측정 출처</p>
          <div data-part="tags" className="flex flex-wrap gap-1.5">
            {tags}
          </div>
        </div>
      )}
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
  // 보조 줄 = 근거 숫자 · 원래 용어(점선 밑줄 → 툴팁)
  const defs: KpiDef[] = [
    {
      k: 'static-detection',
      icon: '⌕',
      stripe: 'accent',
      label: '정적 악성 탐지율',
      value: st ? pct(mt.detectionRate) : '—',
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
      value: st ? pct(mt.falsePositiveRate) : '—',
      sub: c ? (
        <>
          {hint(`정상 ${fmtNum(c.fp + c.tn)}개 중 ${fmtNum(c.fp)}개`)} · <Term k="fpr" />
        </>
      ) : (
        '정적 결과 없음'
      ),
    },
    { k: 'runtime-detection', icon: '▣', stripe: 'accent', label: '런타임 공격 탐지율', value: a.runs ? pct(a.detected / a.runs) : '—', sub: a.runs ? hint(`공격 ${fmtNum(a.runs)}회 중 ${fmtNum(a.detected)}회`, `${a.list.length}종`) : '런타임 결과 없음' },
    {
      k: 'runtime-fpr',
      icon: '✓',
      stripe: 'info',
      label: '정상 설치 오판율',
      value: b ? pct(b.falsePositiveRate) : '—',
      sub: b ? (
        <>
          {hint(`정상 설치 ${fmtNum(b.installs)}건 중 ${fmtNum(b.violations)}건`)} · <Term k="fpr" />
        </>
      ) : (
        '런타임 결과 없음'
      ),
    },
    {
      k: 'latency',
      icon: '◷',
      stripe: 'warn',
      label: '격리까지 걸린 시간',
      value: lat ? fmtNum(lat.p50) : '—',
      unit: lat ? ' ms' : undefined,
      sub: lat ? (
        <>
          <Term k="p50">중간값</Term> · <Term k="p95">95% 이내</Term>
          {` ${hint(`${fmtNum(lat.p95)} ms`, lat.basis)}`}
        </>
      ) : (
        '격리한 시나리오 없음'
      ),
    },
    {
      k: 'model-f1',
      icon: '◔',
      stripe: 'ok',
      label: 'ML 모델 종합 점수',
      value: pref ? dec(pref.test.f1) : '—',
      sub: pref ? (
        <>
          <ModelName x={pref} />
          {md?.deploymentApproved ? '' : ` · ${hint('운영 미적용')}`} · <Term k="f1" />
        </>
      ) : (
        '모델 결과 없음'
      ),
    },
  ];
  return <KpiGrid defs={defs} />;
}

// 지표 6칸 — 길게 눌러(또는 Alt+←/→) 순서 바꾸기(11/04d, R1 11/04 — localStorage supplyguard.layout.evaluationKpi). 칸(div)은 tabindex 0.
// 칸 안 용어 단추는 끌기를 시작하지 않는다(useSortable 이 칸 안 button 의 누르기는 그대로 둔다)
function KpiGrid({ defs }: { defs: KpiDef[] }) {
  const by = new Map(defs.map((x) => [x.k, x]));
  const { ref, order, containerClass, itemProps, pickedClass } = useSortable<HTMLDivElement>({ scope: 'evaluationKpi', ids: KPI_IDS, layout: 'grid', focusable: false, labelOf: (id) => by.get(id)?.label ?? id });
  return (
    <div ref={ref} data-part="kpis" className={`grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6 ${containerClass}`}>
      {order.map((id) => {
        const x = by.get(id)!;
        return <KpiCard key={id} k={x.k} label={x.label} icon={x.icon} stripe={x.stripe} text={x.value} unit={x.unit} sub={x.sub} wrapSub className={`eval-kpi ${pickedClass(id)}`} attrs={itemProps(id)} />;
      })}
    </div>
  );
}

// 두 열 머리 — 정적 · 런타임을 쉬운 말과 함께
function ColTitle({ k, term, easy }: { k: TermKey; term: string; easy: string }) {
  return (
    <h2 data-col-title="" className="px-1 text-[13px] font-semibold text-text-2">
      <Term k={k}>{term}</Term> · {easy}
    </h2>
  );
}

// ── 정적 열 ──
function DistCard({ st }: { st: EvalStatic | null }) {
  const title = '데이터별 판정 결과';
  if (!st) return <Card part="dist" title={title}><None what="정적" /></Card>;
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
        ...(skip ? [[null, `건너뜀 ${fmtNum(skip)} — ${Object.entries(set.skipped ?? {}).map(([k, v]) => `${k} ${v}`).join(' · ')}`] as TipLine] : []),
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
      {(errors > 0 || skipped > 0) && <ChartNote part="dist-excluded">{hint(errors > 0 && `오류 ${fmtNum(errors)}건`, skipped > 0 && `건너뜀 ${fmtNum(skipped)}건`)} — 지표 계산에서 제외됨</ChartNote>}
    </>
  );
  return (
    <Card part="dist" title={title} detail={detail || undefined} detailName="데이터별 판정 표">
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
          {'검사 1건 걸린 시간 — '}
          <Term k="p50">중간값</Term>
          {` ${fmtNum(st.durationsSec.p50)}초 · `}
          <Term k="p95">95% 이내</Term>
          {` ${fmtNum(st.durationsSec.p95)}초`}
        </ChartNote>
      )}
    </Card>
  );
}
function RulesCard({ st }: { st: EvalStatic | null }) {
  const title = (
    <>
      {'많이 걸린 '}
      <Term k="guarddog">GuardDog</Term>
      {' 규칙 상위 10'}
    </>
  );
  if (!st) return <Card part="rules" title={title} detailName="규칙 적중"><None what="정적" /></Card>;
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
    tip: [[null, r.rule], ['mal', `악성 패키지 ${fmtNum(r.maliciousHits)}개`], ['muted', `정상 패키지 ${fmtNum(r.benignHits)}개`], ...(r.installTime ? [[null, '설치 시점 규칙'] as TipLine] : [])],
  }));
  const first = top[0];
  const detail = top.length > 0 && (
    <HBars
      name="rule-hits"
      label="GuardDog 규칙별 악성 · 정상 패키지에서 걸린 수"
      rows={rows}
      ticks={niceTicks(Math.max(1, ...top.map((r) => Math.max(r.maliciousHits, r.benignHits))))}
      tickFmt={(t) => fmtNum(t)}
      legend={[['악성 패키지에서 걸림', 'mal'], ['정상 패키지에서 걸림', 'muted']]}
      labelW={170}
    />
  );
  return (
    <Card part="rules" title={title} detail={detail || undefined} detailName="규칙 적중 차트">
      {first ? (
        <p data-part="rules-top" className="text-[13px] text-text-2">
          {'1위 '}
          <code className="font-mono text-xs break-all text-text">{first.rule}</code>
          {` — 악성 ${fmtNum(first.maliciousHits)}개 · 정상 ${fmtNum(first.benignHits)}개에서 걸림`}
        </p>
      ) : (
        <p className="py-3 text-xs text-text-3">적중한 규칙 없음</p>
      )}
    </Card>
  );
}
function ConfusionCard({ st }: { st: EvalStatic | null }) {
  const title = '판정 정확도';
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
  const detail = (
    <>
      <p className="text-xs font-semibold text-text-2">
        <Term k="confusion">판정 4칸 표</Term>
        {' — 실제 정답 × 판정 개수'}
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
      {eco.length > 0 && <ChartNote part="by-ecosystem">{`생태계별 — ${eco.map(([k, v]) => `${k} 탐지율 ${pct(v.metrics.detectionRate)} · 오판율 ${pct(v.metrics.falsePositiveRate)}`).join(' / ')}`}</ChartNote>}
    </>
  );
  return (
    <Card part="confusion" title={title} detail={detail} detailName="판정 4칸 표">
      <div data-part="confusion-stats" className="grid grid-cols-3 gap-2">
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
    </Card>
  );
}

// ── 런타임 열 ──
function ScenarioCard({ rt }: { rt: EvalRuntime | null }) {
  const title = '공격 시나리오별 탐지율';
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
        [color, `${x.kind === 'attack' ? '공격' : '대조군'} · 탐지 ${fmtNum(x.detected)} / ${fmtNum(x.runs)}회`],
        [null, `격리 ${fmtNum(x.killed)}회${x.rule ? ` · 규칙 ${x.rule}` : ''}${x.dryRun ? ' · 시험 운영' : ''}`],
      ],
    };
  });
  return (
    <Card part="scenarios" title={title}>
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
              {' — 0%가 정답'}
            </>,
            'muted',
          ],
        ]}
        labelW={150}
      />
    </Card>
  );
}
function LatencyCard({ rt }: { rt: EvalRuntime | null }) {
  const title = '격리까지 걸린 시간 (ms)';
  if (!rt) return <Card part="latency" title={title}><None what="런타임" /></Card>;
  const sc = rt.scenarios ?? [];
  const list = sc.filter((x): x is EvalScenario & { latencyMs: EvalStat } => !!x.latencyMs && x.latencyMs.p50 != null);
  const skipped = sc.filter((x) => x.kind === 'attack' && !(x.latencyMs && x.latencyMs.p50 != null));
  return (
    <Card part="latency" title={title}>
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
        <p className="py-3 text-xs text-text-3">격리까지 잰 시나리오가 없습니다</p>
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
    </Card>
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
          ...STAGES.map(([k, ko, color]): TipLine => [color, st[k] ? `${ko} 중간값 ${fmtNum(msv(st[k]!.p50))} ms · 95% 이내 ${fmtNum(msv(st[k]!.p95))} ms` : `${ko} —`]),
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
function BenignCard({ rt }: { rt: EvalRuntime | null }) {
  if (!rt?.benign) return <Card part="benign" title="정상 설치 위반"><None what="런타임" /></Card>;
  const b = rt.benign;
  const rows = (b.items ?? []).filter((x) => !PASS.has(x.result) || !!x.rule);
  const by = b.byEcosystem ? Object.entries(b.byEcosystem).map(([k, v]) => `${k} ${fmtNum(v)}`) : [];
  // 위반은 세부가 아니라 바로 볼 현상 — 있으면 표를 접지 않는다
  return (
    <Card part="benign" title={`정상 설치 위반 ${fmtNum(rows.length)}건`} actions={<span className="text-xs text-text-3">{hint(`정상 설치 ${fmtNum(b.installs)}건 중`, ...by)}</span>}>
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

// ── 규칙 vs ML 모델(전체 폭) — modelAll 이 있으면 「PyPI / 전체」 탭. 요약(규칙 최고 · 선택 모델) + 「운영은 규칙」은 보이고, 비교 표 · 실험 조건은 접힘 ──
function ModelCard({ model, modelAll }: { model: EvalModel | null; modelAll?: EvalModel | null }) {
  const [scope, setScope] = useState<'pypi' | 'all'>('pypi');
  const md = scope === 'all' && modelAll ? modelAll : model ?? modelAll ?? null;
  const title = '규칙 vs ML 모델';
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
  if (!md) return <Card part="model" level={2} title={title}><None what="모델" /></Card>;
  const p = md.protocol ?? {};
  const cs = md.candidates ?? [];
  const label = (id: string) => cs.find((x) => x.id === id)?.label ?? id;
  const test = p.partitions?.test;
  const pref = cs.find((x) => x.id === md.preferredId);
  const rule = cs.filter((x) => /^rule/.test(x.id)).sort((a, b) => b.test.f1 - a.test.f1)[0];
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
                      <span data-part="pick-badge" title="선택용 구간에서 고른 모델 — 시험 구간은 고를 때 쓰지 않음" className="ml-2 rounded bg-indigo-100 px-1.5 py-0.5 text-xs font-medium text-indigo-800">
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
        {'실험 조건 — '}
        {[`seed ${p.seed ?? '—'}`, p.split, p.selection && `선택 기준: ${p.selection}`, `특징 ${fmtNum((md.features ?? []).length)}개`, test && `시험 악성 ${fmtNum(test.malicious)} · 정상 ${fmtNum(test.benign)}`].filter(Boolean).join(' · ')}
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
    <Card part="model" level={2} title={title} actions={actions} detail={detail} detailName="규칙 · 모델 비교 표">
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
          시험에서는 규칙 판정이 우세 — 운영은 규칙
        </p>
      )}
    </Card>
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

// 결과의 한계 — 출처별 개수는 보이고, 문장 목록은 「자세히」
function Limits({ d }: { d: Evaluation }) {
  const items: (readonly [keyof typeof SOURCE, string])[] = (['static', 'runtime', 'model'] as const).flatMap((k) => (d[k]?.limits ?? []).map((t) => [k, t] as const));
  // 전체 범위 모델(model-all.json)의 한계 중 PyPI 모델과 다른 것만
  const seen = new Set(d.model?.limits ?? []);
  for (const t of d.modelAll?.limits ?? []) if (!seen.has(t)) items.push(['modelAll', t] as const);
  const counts = (Object.keys(SOURCE) as (keyof typeof SOURCE)[]).map((k) => [k, items.filter((x) => x[0] === k).length] as const).filter(([, n]) => n > 0);
  const detail = items.length > 0 && (
    <ul className="grid gap-1.5">
      {items.map(([k, t], i) => (
        <li key={i} data-src={k} className="flex items-baseline gap-2 text-[13px] text-text-2">
          <span className="inline-flex h-5 shrink-0 items-center rounded-md border border-border bg-surface-2 px-1.5 text-xs text-text-2">{SOURCE[k]}</span>
          <span className="min-w-0">{t}</span>
        </li>
      ))}
    </ul>
  );
  return (
    <Card part="limits" level={2} title="결과의 한계" className="border-l-4 border-l-warn" detail={detail || undefined} detailName="결과의 한계 목록">
      {items.length ? (
        <p data-part="limits-summary" className="text-[13px] text-text-2">
          {`적힌 한계 ${fmtNum(items.length)}건 — ${counts.map(([k, n]) => `${SOURCE[k]} ${fmtNum(n)}`).join(' · ')}`}
        </p>
      ) : (
        <p className="text-xs text-text-3">적힌 한계 없음</p>
      )}
    </Card>
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
    // R4 11/04(목업 11/04e .eval-body): 768 이상은 머리(요점) · 지표 6칸이 제자리, 아래 몸통(두 열 · 모델 비교 · 한계)만 채움 칸으로 스크롤.
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
          <EmptyState what="평가 결과" hint="정적 · 런타임 · 모델 평가를 돌려 결과가 서버에 올라오면 여기에 보입니다." />
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
                  <ColTitle k="static" term="정적" easy="패키지 코드 검사" />
                  <DistCard st={d.static} />
                  <RulesCard st={d.static} />
                  <ConfusionCard st={d.static} />
                </div>
                <div data-col="runtime" className="flex min-w-0 flex-col gap-4">
                  <ColTitle k="runtime" term="런타임" easy="설치 · 실행 감시" />
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
