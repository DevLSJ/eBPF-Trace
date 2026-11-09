import { Check, ChevronDown, Loader2, Minus, Play, TriangleAlert, X } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { ActionButton } from '../../components/ActionButton';
import { FlowHero } from '../../components/FlowHero';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { useAuth } from '../../hooks/auth-context';
import { useCountUp } from '../../hooks/useCountUp';
import { useInterval, useLoad } from '../../hooks/useLoad';
import { useStream } from '../../hooks/stream-context';
import { useToast } from '../../hooks/toast-context';
import { api, ApiError } from '../../lib/api';
import { screenCopy } from '../../lib/screenCopy';
import { fmtNum } from '../../lib/format';
import type { Info, IntegrationContainer, IntegrationEnv, IntegrationStatus, IntegrationTest, Kind } from '../../lib/types';
import { envChecks, FLOW, type Tone } from './model';
import { ScenarioWizard } from './ScenarioWizard';
import './integration.css';

// 「연동」 페이지(11/06 사용자 결정): 내 컨테이너를 라벨 한 줄로 SupplyGuard 에 붙이는 절차.
//   위 = 흐름 그림(자동 재생) · 왼쪽 = ① 환경 점검 ② 라벨 한 줄 ③ 연결 확인 · 오른쪽 = 감시 중 컨테이너(3초마다, 들어오고 나갈 때 애니메이션)
//   문구 규칙(11/06): 요점 위주 개조식 명사형 종결

const WATCH_BY: Record<string, string> = { all: '전체 감시', name: '이름', label: '라벨' };
const ENFORCE_BY: Record<string, string> = { all: '전체', name: '이름', label: '라벨', sandbox: '설치 검사', demo: '시연' };

export function IntegrationPage() {
  const { info } = useStream();
  const { isAdmin } = useAuth();
  const load = useCallback(() => api.integration(), []);
  const { data, error, reload } = useLoad<IntegrationStatus>(load);
  const running = data?.test?.state === 'running';
  useInterval(reload, running ? 1000 : 3000);
  const desc = (
    <p data-part="screen-copy" data-screen="integration" className="m-0 shrink-0 truncate text-[length:var(--fs-sm)] text-text-3">
      {screenCopy('integration')}
    </p>
  );
  if (error && !data)
    return (
      <div data-part="integration" data-state="error" className="int-page">
        {desc}
        <LoadError error={error} what="연동 상태" />
      </div>
    );
  return (
    <div data-part="integration" data-state={data ? 'ready' : 'loading'} className="int-page">
      {desc}
      <section className="int-hero sg-card" data-part="int-hero">
        <div className="int-hero-head">
          <h2 className="int-hero-title">라벨 한 줄로 내 컨테이너 연동</h2>
          <ul className="int-key" data-part="int-key">
            <li>감시 = 라벨 supplyguard.watch=true</li>
            <li>격리 = 라벨 supplyguard.enforce=true 추가 시에만</li>
            <li>서버 재시작 · 설정 변경 없음</li>
          </ul>
        </div>
        <FlowHero nodes={FLOW} part="int-flow" />
      </section>
      <div className="int-main">
        {data ? <ScenarioWizard env={data.env} containers={data.containers} /> : <section className="int-wizard sg-card"><Skeleton rows={8} /></section>}
        <div className="int-side">
          <EnvCard data={data} info={info} isAdmin={isAdmin} onStarted={reload} />
          <WatchList data={data} />
        </div>
      </div>
    </div>
  );
}

// 환경 점검 + 수집 확인(시험 컨테이너) — 기본은 요약 한 줄, 펼치면 항목 · 조치(확인 필요가 있으면 처음부터 펼침)
function EnvCard({ data, info, isAdmin, onStarted }: { data?: IntegrationStatus; info: Info | null; isAdmin: boolean; onStarted: () => void }) {
  const warn = data ? envChecks(data.env, info).filter((c) => c.tone === 'warn').length : 0;
  const [open, setOpen] = useState<boolean | null>(null);
  const shown = open ?? warn > 0;
  return (
    <section className="int-step sg-card" data-part="step-env" data-open={String(shown)} style={{ ['--d' as string]: 0 }}>
      <header className="int-step-head">
        <b className="int-step-title">환경 점검</b>
        <span className="int-step-sub">이 서버에서 실제 수집이 되는지</span>
        <button type="button" className="int-env-toggle" data-part="env-toggle" aria-expanded={shown} onClick={() => setOpen(!shown)}>
          {shown ? '접기' : '펼치기'} <ChevronDown className={`size-3.5 int-chev ${shown ? 'up' : ''}`} aria-hidden />
        </button>
      </header>
      <div className="int-step-body">
        {data ? <EnvChecks env={data.env} info={info} open={shown} /> : <Skeleton rows={2} />}
        {data && shown && <TestStep env={data.env} test={data.test} isAdmin={isAdmin} onStarted={onStarted} />}
      </div>
    </section>
  );
}

function Skeleton({ rows }: { rows: number }) {
  return (
    <div className="int-skel" aria-hidden>
      {Array.from({ length: rows }, (_, i) => (
        <span key={i} />
      ))}
    </div>
  );
}

const TONE_ICON: Record<Tone, ReactNode> = {
  ok: <Check className="size-3.5" aria-hidden />,
  warn: <TriangleAlert className="size-3.5" aria-hidden />,
  off: <Minus className="size-3.5" aria-hidden />,
};

function EnvChecks({ env, info, open }: { env: IntegrationEnv; info: Info | null; open: boolean }) {
  const checks = envChecks(env, info);
  const warn = checks.filter((c) => c.tone === 'warn').length;
  return (
    <>
      <p className={`int-verdict ${warn ? 'warn' : 'ok'}`} data-part="env-verdict">
        {warn ? `확인 필요 ${warn}건, 아래 조치 참고` : env.source === 'gadget' ? '실제 수집 준비됨' : '모의 이벤트로 동작 중'}
      </p>
      {open && <ul className="int-checks" data-part="env-checks">
        {checks.map((c, i) => (
          <li key={c.id} data-check={c.id} data-tone={c.tone} className={`int-check tone-${c.tone}`} style={{ ['--i' as string]: i }}>
            <span className="int-check-ico">{TONE_ICON[c.tone]}</span>
            <span className="int-check-label">{c.label}</span>
            <span className="int-check-value" title={c.value}>
              {c.value}
            </span>
            {c.hint && <span className="int-check-hint">{c.hint}</span>}
          </li>
        ))}
      </ul>}
    </>
  );
}

const KINDS: { k: Kind; label: string }[] = [
  { k: 'exec', label: '실행' },
  { k: 'open', label: '파일' },
  { k: 'connect', label: '통신' },
  { k: 'dns', label: '조회' },
];

function Count({ n }: { n: number }) {
  const v = useCountUp(n);
  return <>{fmtNum(v)}</>;
}

function TestStep({ env, test, isAdmin, onStarted }: { env: IntegrationEnv; test: IntegrationTest | null; isAdmin: boolean; onStarted: () => void }) {
  const toast = useToast();
  const [starting, setStarting] = useState(false);
  const start = async () => {
    setStarting(true);
    try {
      await api.integrationTest();
      onStarted();
    } catch (e) {
      toast(`연결 테스트를 시작하지 못했습니다${e instanceof ApiError ? `(${e.message}).` : '. 잠시 뒤 다시 시도하세요.'}`, { key: 'int-test', tone: 'warn' });
    } finally {
      setStarting(false);
    }
  };
  const running = test?.state === 'running';
  const total = test ? Object.values(test.events).reduce((a, b) => a + (b ?? 0), 0) : 0;
  // 꺼진 사유(11/09 SPEC §7 — 마침표 없음): 권한 · 환경 · 진행 중
  const why = !isAdmin ? '연결 테스트를 실행할 권한이 없습니다' : !env.testable ? '이 서버에는 Docker가 없어 실행할 수 없습니다' : running || starting ? '연결 테스트가 진행 중입니다' : '';
  return (
    <div className="int-test" data-part="test-step" data-state={test?.state ?? 'idle'}>
      <div className="int-test-bar">
        <ActionButton className="sg-btn sg-btn-primary" data-part="test-start" reason={why} onClick={start}>
          {running || starting ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <Play className="size-4" aria-hidden />} 연결 테스트
        </ActionButton>
        <span className="int-test-what">
          {why && !running ? why : `시험 컨테이너(${env.probeImage}, 감시 라벨만 · 네트워크 없음) 약 3초 실행 뒤 삭제됨`}
        </span>
      </div>
      {test && (
        <div className={`int-test-result ${test.state}`} data-part="test-result" key={test.id}>
          {running && <div className="int-progress" aria-hidden><i /></div>}
          <div className="int-test-line">
            {test.state === 'passed' ? <Check className="size-4" aria-hidden /> : test.state === 'failed' ? <X className="size-4" aria-hidden /> : <Loader2 className="size-4 animate-spin" aria-hidden />}
            <b data-part="test-state">{test.state === 'passed' ? `[통과] 이벤트 ${fmtNum(total)}건 수신, 연결 확인됨` : test.state === 'failed' ? '[실패] 연결 확인 안 됨' : `[대기] ${test.container} 이벤트 수신 대기 중`}</b>
          </div>
          <div className="int-counts" data-part="test-counts">
            {KINDS.map(({ k, label }) => (
              <span key={k} className={`int-count k-${k} ${(test.events[k] ?? 0) > 0 ? 'got' : ''}`} data-kind={k}>
                <b>
                  <Count n={test.events[k] ?? 0} />
                </b>
                {label}
              </span>
            ))}
          </div>
          {test.state === 'failed' && test.error && (
            <ul className="int-points warn" data-part="test-error">
              <li>{test.error}</li>
              <li>① 환경 점검의 「확인 필요」 항목 조치 후 다시 시도</li>
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

// 감시 목록 — 새로 들어온 행은 강조하며 미끄러져 들어오고, 사라진 행은 잠깐 흐려진 뒤 빠진다
function WatchList({ data }: { data?: IntegrationStatus }) {
  const rows = useMemo(() => data?.containers ?? [], [data]);
  const [prevRows, setPrevRows] = useState<IntegrationContainer[]>([]);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const [gone, setGone] = useState<IntegrationContainer[]>([]);
  if (rows !== prevRows) {
    const before = new Set(prevRows.map((r) => r.id));
    const now = new Set(rows.map((r) => r.id));
    setFresh(new Set(rows.filter((r) => !before.has(r.id)).map((r) => r.id)));
    const left = prevRows.filter((r) => !now.has(r.id));
    if (left.length) setGone(left);
    setPrevRows(rows);
  }
  useEffect(() => {
    if (!gone.length) return;
    const t = window.setTimeout(() => setGone([]), 700);
    return () => window.clearTimeout(t);
  }, [gone]);
  const watched = rows.filter((r) => r.watched);
  const enforced = rows.filter((r) => r.enforce);
  return (
    <Panel
      className="int-watch min-h-0"
      testId="int-watch"
      title="감시 중 컨테이너"
      sub="3초마다 갱신"
      actions={
        <span className="int-sum" data-part="watch-sum">
          <b>{fmtNum(watched.length)}</b> 감시 · <b className="danger">{fmtNum(enforced.length)}</b> 격리 대상 · {fmtNum(rows.length - watched.length)} 감시 밖
        </span>
      }
    >
      <div className="int-watch-body">
        {data?.listError && <p className="int-points warn" role="alert">컨테이너 목록을 읽지 못했습니다({data.listError}).</p>}
        {!data ? (
          <Skeleton rows={6} />
        ) : rows.length + gone.length === 0 ? (
          <div data-part="watch-empty">
            <Empty>실행 중인 컨테이너가 없습니다.</Empty>
          </div>
        ) : (
          <ul className="int-rows" data-part="watch-rows">
            {rows.map((r) => (
              <li key={r.id} data-container={r.name} data-watched={String(r.watched)} data-enforce={String(r.enforce)} className={`int-row ${r.watched ? '' : 'out'} ${fresh.has(r.id) ? 'in' : ''}`}>
                <span className={`int-row-dot ${r.enforce ? 'danger' : r.watched ? 'ok' : ''}`} aria-hidden />
                <span className="int-row-name" title={r.name}>
                  {r.name}
                </span>
                <span className="int-row-image" title={r.image}>
                  {r.image}
                </span>
                <span className="int-row-tags">
                  {r.watched ? <span className="sg-pill sg-pill-ok" data-tag="watch">{WATCH_BY[r.watchBy ?? ''] ?? '감시'}</span> : <span className="sg-pill sg-pill-neutral" data-tag="watch">감시 밖</span>}
                  {r.watched &&
                    (r.enforce ? (
                      <span className="sg-pill sg-pill-danger" data-tag="enforce">
                        격리 · {ENFORCE_BY[r.enforceBy ?? ''] ?? ''}
                      </span>
                    ) : (
                      <span className="sg-pill sg-pill-warn" data-tag="enforce" title="supplyguard.enforce=true 라벨이 있어야 격리됨">
                        격리 보류
                      </span>
                    ))}
                </span>
              </li>
            ))}
            {gone.map((r) => (
              <li key={`gone-${r.id}`} className="int-row gone" aria-hidden>
                <span className="int-row-dot" />
                <span className="int-row-name">{r.name}</span>
                <span className="int-row-image">{r.image}</span>
                <span className="int-row-tags">
                  <span className="sg-pill sg-pill-neutral">종료</span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
}
