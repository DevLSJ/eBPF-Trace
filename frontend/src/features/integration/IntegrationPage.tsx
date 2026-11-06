import { Check, Copy, Loader2, Minus, Play, TriangleAlert, X } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { FlowHero } from '../../components/FlowHero';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { useAuth } from '../../hooks/auth-context';
import { useCopyCommand } from '../../hooks/useCopyCommand';
import { useCountUp } from '../../hooks/useCountUp';
import { useInterval, useLoad } from '../../hooks/useLoad';
import { useStream } from '../../hooks/stream-context';
import { useToast } from '../../hooks/toast-context';
import { api, ApiError } from '../../lib/api';
import { fmtNum } from '../../lib/format';
import type { Info, IntegrationContainer, IntegrationEnv, IntegrationStatus, IntegrationTest, Kind } from '../../lib/types';
import { envChecks, FLOW, labelSnippet, type Tone } from './model';
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
  if (error && !data) return <LoadError error={error} what="연동 상태" />;
  return (
    <div data-part="integration" data-state={data ? 'ready' : 'loading'} className="int-page">
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
      <div className="int-cols">
        <div className="int-steps">
          <StepCard n={1} title="환경 점검" sub="이 서버에서 실제 수집이 되는지" part="step-env" delay={0}>
            {data ? <EnvChecks env={data.env} info={info} /> : <Skeleton rows={6} />}
          </StepCard>
          <StepCard n={2} title="라벨 한 줄" sub="compose 또는 docker run 에 추가" part="step-label" delay={1}>
            {data ? <LabelStep env={data.env} /> : <Skeleton rows={4} />}
          </StepCard>
          <StepCard n={3} title="연결 확인" sub="시험 컨테이너로 이벤트 수신 확인" part="step-test" delay={2}>
            {data ? <TestStep env={data.env} test={data.test} isAdmin={isAdmin} onStarted={reload} /> : <Skeleton rows={3} />}
          </StepCard>
        </div>
        <WatchList data={data} />
      </div>
    </div>
  );
}

function StepCard({ n, title, sub, part, delay, children }: { n: number; title: string; sub: string; part: string; delay: number; children: ReactNode }) {
  return (
    <section className="int-step sg-card" data-part={part} style={{ ['--d' as string]: delay }}>
      <header className="int-step-head">
        <span className="int-step-n">{n}</span>
        <b className="int-step-title">{title}</b>
        <span className="int-step-sub">{sub}</span>
      </header>
      <div className="int-step-body">{children}</div>
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

function EnvChecks({ env, info }: { env: IntegrationEnv; info: Info | null }) {
  const checks = envChecks(env, info);
  const warn = checks.filter((c) => c.tone === 'warn').length;
  return (
    <>
      <p className={`int-verdict ${warn ? 'warn' : 'ok'}`} data-part="env-verdict">
        {warn ? `확인 필요 ${warn}건 — 아래 조치 참고` : env.source === 'gadget' ? '실제 수집 준비됨' : '모의 이벤트로 동작 중'}
      </p>
      <ul className="int-checks" data-part="env-checks">
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
      </ul>
    </>
  );
}

function LabelStep({ env }: { env: IntegrationEnv }) {
  const [kind, setKind] = useState<'compose' | 'run'>('compose');
  const [enforce, setEnforce] = useState(false);
  const copy = useCopyCommand();
  const text = labelSnippet(kind, env, enforce);
  return (
    <div className="int-label" data-part="label-step">
      <div className="int-label-bar">
        <div className="int-tabs" role="tablist" aria-label="형식">
          {(['compose', 'run'] as const).map((k) => (
            <button key={k} type="button" role="tab" aria-selected={kind === k} data-tab={k} className={`int-tab ${kind === k ? 'on' : ''}`} onClick={() => setKind(k)}>
              {k === 'compose' ? 'docker compose' : 'docker run'}
            </button>
          ))}
        </div>
        <label className="int-enforce">
          <input type="checkbox" data-part="label-enforce" checked={enforce} onChange={(e) => setEnforce(e.target.checked)} />
          격리까지 맡기기
        </label>
        <button type="button" className="sg-btn sg-btn-sm sg-btn-secondary" data-part="label-copy" onClick={() => copy(text)}>
          <Copy className="size-3.5" aria-hidden /> 복사
        </button>
      </div>
      <pre className="int-code" data-part="label-code" key={`${kind}-${enforce}`}>
        {text.split('\n').map((line, i) => (
          <span key={i} className={line.includes('supplyguard.') ? 'hl' : undefined}>
            {line}
            {'\n'}
          </span>
        ))}
      </pre>
      <ul className="int-points" data-part="label-points">
        <li>라벨이 붙은 컨테이너만 감시 대상에 추가됨</li>
        <li>라벨 변경은 컨테이너를 다시 만들 때 적용됨(docker compose up -d)</li>
        <li>{enforce ? '정책 위반 시 증거 수집 뒤 즉시 격리됨' : '격리 라벨이 없으면 위반은 「격리 보류」로 기록만 됨'}</li>
      </ul>
    </div>
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
      toast(e instanceof ApiError ? e.message : '연결 테스트를 시작하지 못했습니다', { key: 'int-test', tone: 'warn' });
    } finally {
      setStarting(false);
    }
  };
  const running = test?.state === 'running';
  const total = test ? Object.values(test.events).reduce((a, b) => a + (b ?? 0), 0) : 0;
  const disabled = !isAdmin || !env.testable || running || starting;
  const why = !isAdmin ? '관리자만 실행 가능' : !env.testable ? '이 서버에서는 실행 불가(Docker 없음)' : running ? '진행 중' : '';
  return (
    <div className="int-test" data-part="test-step" data-state={test?.state ?? 'idle'}>
      <div className="int-test-bar">
        <button type="button" className="sg-btn sg-btn-primary" data-part="test-start" disabled={disabled} onClick={start} title={why || undefined}>
          {running || starting ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <Play className="size-4" aria-hidden />} 연결 테스트
        </button>
        <span className="int-test-what">
          {why && !running ? why : `시험 컨테이너(${env.probeImage}, 감시 라벨만 · 네트워크 없음) 약 3초 실행 뒤 삭제됨`}
        </span>
      </div>
      {test && (
        <div className={`int-test-result ${test.state}`} data-part="test-result" key={test.id}>
          {running && <div className="int-progress" aria-hidden><i /></div>}
          <div className="int-test-line">
            {test.state === 'passed' ? <Check className="size-4" aria-hidden /> : test.state === 'failed' ? <X className="size-4" aria-hidden /> : <Loader2 className="size-4 animate-spin" aria-hidden />}
            <b data-part="test-state">{test.state === 'passed' ? `연결 확인됨 — 이벤트 ${fmtNum(total)}건 수신` : test.state === 'failed' ? '연결 확인 실패' : `수신 대기 중 — ${test.container}`}</b>
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
        {data?.listError && <p className="int-points warn">목록을 읽지 못함 — {data.listError}</p>}
        {!data ? (
          <Skeleton rows={6} />
        ) : rows.length + gone.length === 0 ? (
          <div data-part="watch-empty">
            <Empty>실행 중인 컨테이너 없음</Empty>
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
