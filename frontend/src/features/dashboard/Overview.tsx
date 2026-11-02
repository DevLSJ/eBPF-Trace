import { useCallback, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { LoadError } from '../../components/Panel';
import { useCountUp } from '../../hooks/useCountUp';
import { useStream } from '../../hooks/stream-context';
import { useFilters } from '../../hooks/useFilters';
import { useInterval, useLoad } from '../../hooks/useLoad';
import { api } from '../../lib/api';
import { fmtNum, fmtTime } from '../../lib/format';
import { dest, type Dest } from '../../lib/nav';
import type { Level, Summary, SummaryRange, SummaryTop } from '../../lib/types';

// eBPF 수집 종합(10/16, 목업 확정) — 「지금까지 무엇을 수집 · 탐지했나?」 저장된 기록(GET /api/summary) 기반이라 재시작해도 그대로.
const RANGES: [SummaryRange, string][] = [
  ['1h', '1시간'],
  ['24h', '24시간'],
  ['7d', '7일'],
];

export function Overview() {
  const { stats, subscribe } = useStream();
  // 기간은 화면 상태로만(10/21, 주소에 남기지 않음)
  const [filters, setFilters] = useFilters('/');
  const range = (RANGES.some(([r]) => r === filters.range) ? filters.range : '24h') as SummaryRange;
  const load = useCallback(() => api.summary(range), [range]);
  const sum = useLoad(load);
  const { reload } = sum;
  useInterval(reload, 30_000);
  // 새 위반이 들어오면(WS) 잠깐 모았다가 다시 계산
  const timer = useRef<number | undefined>(undefined);
  useEffect(
    () =>
      subscribe((m) => {
        if (m.type !== 'verdict' || !m.data.matched) return;
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(reload, 800);
      }),
    [subscribe, reload],
  );
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const pick = (r: SummaryRange) => setFilters({ range: r });
  const s = sum.data;

  return (
    <section className="sg-card flex min-h-0 flex-col overflow-hidden" data-section="overview">
      <header className="flex shrink-0 flex-wrap items-center gap-3 border-b border-border px-4 py-2.5">
        <h2 className="text-sm font-semibold text-slate-800">eBPF 수집 종합</h2>
        <span className="flex items-center gap-1.5 text-xs text-slate-500">
          <span className="size-2 animate-pulse rounded-full bg-emerald-500" aria-hidden />
          감시 중 · 초당 <span className="num">{fmtNum(stats?.eventsPerSec ?? 0)}</span> evt
        </span>
        <div className="ml-auto flex gap-1.5" role="group" aria-label="기간">
          {RANGES.map(([r, ko]) => (
            <button
              key={r}
              type="button"
              data-range={r}
              aria-pressed={range === r}
              onClick={() => pick(r)}
              className={`rounded-full border px-2.5 py-0.5 text-xs ${range === r ? 'border-indigo-600 bg-indigo-600 text-white' : 'border-slate-300 text-slate-600 hover:bg-slate-50'}`}
            >
              {ko}
            </button>
          ))}
        </div>
      </header>
      {sum.error && !s ? (
        <div className="p-4">
          <LoadError error={sum.error} what="종합" />
        </div>
      ) : !s ? (
        <p className="p-4 text-sm text-slate-400">불러오는 중…</p>
      ) : (
        <div className="grid min-h-0 gap-3 overflow-y-auto px-4 py-3" data-part="overview-body">
          <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
            {/* 10/30: byKind.dns 는 선택(옛 백엔드 없음) — 있을 때만 「조회 N」 */}
            <Kpi
              k="collected"
              label="수집한 이벤트"
              value={s.collected.total}
              sub={`실행 ${fmtNum(s.collected.byKind.exec)} · 파일 ${fmtNum(s.collected.byKind.open)} · 통신 ${fmtNum(s.collected.byKind.connect)}${s.collected.byKind.dns !== undefined ? ` · 조회 ${fmtNum(s.collected.byKind.dns)}` : ''}`}
              to={dest('/events', { normal: '1' })}
            />
            <Kpi k="violations" label="위반" value={s.violations.total} sub={`격리 ${fmtNum(s.violations.killed + s.violations.held)} · 경고 ${fmtNum(s.violations.alert)}`} to={{ to: '/audit' }} danger />
            <Kpi k="isolated" label="격리한 컨테이너" value={s.isolatedContainers} sub="설치 검사 포함" to={dest('/audit', { action: 'kill' })} danger />
            <Kpi k="installs" label="설치 검사" value={s.installs.total} sub={`통과 ${s.installs.passed} · 격리 ${s.installs.isolated} · 거부 ${s.installs.refused}`} to={dest('/installs', { status: 'all' })} />
            <Kpi k="decided" label="판정 완료" value={s.decisions.malicious + s.decisions.falsePositive} sub={`악성 ${s.decisions.malicious} · 오탐 ${s.decisions.falsePositive} · 대기 ${s.decisions.pending}`} to={{ to: '/audit?view=changes' }} />
            {/* 격리 지연(10/30 계약 §3): killedAt − detectedAt 의 중앙값. 기록이 없으면(count 0 · 옛 백엔드) 「—」 */}
            <Kpi
              k="isolation"
              label="격리 지연 중앙값"
              value={s.isolation?.count ? `${fmtNum(s.isolation.medianMs ?? 0)} ms` : '—'}
              sub={s.isolation?.count ? `격리 ${fmtNum(s.isolation.count)}건 · p95 ${fmtNum(s.isolation.p95Ms ?? 0)} ms · 최대 ${fmtNum(s.isolation.maxMs ?? 0)} ms` : '격리 타임라인 기록 없음'}
              to={dest('/audit', { action: 'kill' })}
            />
          </div>
          <div className="grid gap-3 md:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
            <Card title="수집량 추이 — 종류별">
              {/* 색은 토큰(라이트: 실행 #8b5cf6 · 파일 #38bdf8 · 통신 #14b8a6 · 조회 #fb923c) — 다크에서 밝은 값으로 바뀐다 */}
              <Stacked name="collected" s={s} keys={[['exec', '실행', 'var(--k-exec)'], ['open', '파일', 'var(--k-open)'], ['connect', '통신', 'var(--k-connect)'], ...(s.collected.byKind.dns !== undefined ? ([['dns', '조회', 'var(--k-dns)']] as [Key, string, string][]) : [])]} />
            </Card>
            <Card title="위반 추이">
              <Stacked name="violations" s={s} keys={[['killed', '격리', 'var(--danger)'], ['alert', '경고', 'var(--warn)']]} />
            </Card>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <Card title="많이 걸린 정책">
              <TopList testId="rules" rows={s.topRules} keyOf={(r) => r.ruleId ?? ''} href={(k) => ({ to: `/policies?id=${encodeURIComponent(k)}` })} />
            </Card>
            <Card title="위반이 많은 컨테이너 · 패키지">
              <TopList testId="containers" rows={s.topContainers} keyOf={(r) => r.container ?? ''} href={(k) => dest('/audit', { container: k })} />
            </Card>
            <Card title="설치 검사 · 판정">
              <Results s={s} />
            </Card>
          </div>
        </div>
      )}
    </section>
  );
}

// 스탯 타일(10/30 계약 §7): 큰 숫자 24px/600 · 라벨 12px text-3 · 보조 한 줄, 누르면 들리는 카드. 숫자는 600ms 카운트업
function Kpi({ k, label, value, sub, to, danger }: { k: string; label: string; value: number | string; sub: string; to: Dest; danger?: boolean }) {
  const n = useCountUp(typeof value === 'number' ? value : 0);
  return (
    <Link {...to} className="sg-card sg-card-hover grid min-w-0 gap-0.5 rounded-[var(--r-md)] bg-surface-2 px-3 py-2 shadow-none hover:border-accent" data-kpi={k}>
      <span className="truncate text-xs text-text-3">{label}</span>
      <b className={`num truncate text-2xl font-semibold ${danger && value ? 'text-danger' : 'text-text'}`} data-value="">
        {typeof value === 'number' ? fmtNum(n) : value}
      </b>
      <span className="truncate text-[11px] text-slate-500" title={sub}>
        {sub}
      </span>
    </Link>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="grid min-w-0 content-start gap-1.5">
      <h3 className="text-xs font-semibold text-slate-600">{title}</h3>
      {children}
    </div>
  );
}

type Key = 'exec' | 'open' | 'connect' | 'dns' | 'killed' | 'alert';
// 쌓은 막대 — 칸마다 <g data-bucket>, 조각마다 rect[data-kind]. dns(10/30)는 series 에 없을 수 있다(0 으로)
function Stacked({ name, s, keys }: { name: string; s: Summary; keys: [Key, string, string][] }) {
  const pts = s.series;
  const tot = (p: Summary['series'][number]) => keys.reduce((n, [k]) => n + (p[k] ?? 0), 0);
  const max = Math.max(4, ...pts.map(tot));
  const W = 100 * pts.length;
  const H = 100;
  const label = (t: string) => (s.bucketSec >= 21600 ? `${new Date(t).getMonth() + 1}/${new Date(t).getDate()}` : fmtTime(t).slice(0, 5));
  const every = Math.ceil(pts.length / 6);
  return (
    <div data-chart={name} className="grid gap-1">
      <div className="flex gap-3 text-[11px] text-slate-500">
        {keys.map(([k, ko, c]) => (
          <span key={k} className="flex items-center gap-1" data-key={k}>
            <i className="size-2 rounded-sm" style={{ background: c }} />
            {ko}
          </span>
        ))}
        <span className="num ml-auto">최대 {fmtNum(max)}</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="h-24 w-full" role="img" aria-label={name === 'collected' ? '수집량 추이' : '위반 추이'}>
        {pts.map((p, i) => {
          let acc = 0;
          return (
            <g key={p.t} data-bucket={p.t}>
              <title>{`${label(p.t)} · ${keys.map(([k, ko]) => `${ko} ${fmtNum(p[k] ?? 0)}`).join(' · ')}`}</title>
              {keys.map(([k, , c]) => {
                const v = p[k] ?? 0;
                if (!v) return null;
                const y1 = H - ((acc + v) / max) * H;
                const y0 = H - (acc / max) * H;
                acc += v;
                return <rect key={k} data-kind={k} x={i * 100 + 15} y={y1} width={70} height={Math.max(0.5, y0 - y1)} style={{ fill: c }} />;
              })}
              {!tot(p) && <rect x={i * 100 + 15} y={H - 1} width={70} height={1} style={{ fill: 'var(--border)' }} />}
            </g>
          );
        })}
      </svg>
      <div className="flex justify-between text-[10px] text-slate-400">
        {pts
          .filter((_, i) => i % every === 0)
          .map((p) => (
            <span key={p.t} className="num">
              {label(p.t)}
            </span>
          ))}
      </div>
    </div>
  );
}

const barColor: Record<Level, string> = { normal: 'bg-slate-300', alert: 'bg-amber-500', held: 'bg-red-500', killed: 'bg-red-600' };
function TopList({ testId, rows, keyOf, href }: { testId: string; rows: SummaryTop[]; keyOf: (r: SummaryTop) => string; href: (k: string) => Dest }) {
  const top = rows.slice(0, 5);
  if (!top.length) return <p className="text-xs text-slate-400">이 기간에 위반 없음</p>;
  return (
    <ol className="grid gap-1" data-top={testId}>
      {top.map((r) => (
        <li key={keyOf(r)} data-row={keyOf(r)} data-count={r.count} className="grid grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_2.5rem] items-center gap-2 text-xs">
          <Link {...href(keyOf(r))} className="truncate font-mono text-slate-700 hover:text-indigo-600" title={keyOf(r)}>
            {keyOf(r)}
          </Link>
          <span className="h-1.5 overflow-hidden rounded bg-slate-100">
            <i className={`block h-full ${barColor[r.level]}`} style={{ width: `${Math.max(4, (r.count / top[0].count) * 100)}%` }} />
          </span>
          <b className="num text-right">{fmtNum(r.count)}</b>
        </li>
      ))}
    </ol>
  );
}

function Results({ s }: { s: Summary }) {
  const I = s.installs;
  const D = s.decisions;
  const B = s.blocklist;
  const chip = (ko: string, n: number, cls: string) => (
    <span key={ko} className={`rounded px-1.5 py-0.5 ${cls}`}>
      {ko} <b className="num">{n}</b>
    </span>
  );
  return (
    <div className="grid gap-1.5 text-xs" data-results="">
      <div className="grid gap-1">
        <span className="text-slate-500">설치 검사</span>
        <span className="flex flex-wrap gap-1">
          {chip('통과', I.passed, 'bg-emerald-50 text-emerald-700')}
          {chip('격리', I.isolated, 'bg-red-50 text-red-700')}
          {chip('경고', I.warned, 'bg-amber-50 text-amber-800')}
          {chip('설치 전 거부', I.refused, 'bg-slate-800 text-white')}
          {chip('실패 · 미확인', I.failed, 'bg-slate-100 text-slate-600')}
        </span>
      </div>
      <div className="grid gap-1">
        <span className="text-slate-500">판정</span>
        <span className="flex flex-wrap gap-1">
          {chip('악성', D.malicious, 'bg-red-50 text-red-700')}
          {chip('오탐', D.falsePositive, 'bg-blue-50 text-blue-700')}
          {chip('대기', D.pending, 'bg-amber-50 text-amber-800')}
        </span>
      </div>
      <Link to="/policies" className="text-indigo-600 hover:underline">
        차단 목록 <b className="num" data-blocklist-total="">{fmtNum(B.packages + B.images + B.hosts)}</b> (패키지 {B.packages} · 이미지 {B.images} · 도메인 {B.hosts})
      </Link>
    </div>
  );
}
