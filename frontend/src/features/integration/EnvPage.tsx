import { Check, Loader2, Minus, Play, TriangleAlert, X } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ActionButton } from '../../components/ActionButton';
import { Panel } from '../../components/Panel';
import { useAuth } from '../../hooks/auth-context';
import { useCountUp } from '../../hooks/useCountUp';
import { useStream } from '../../hooks/stream-context';
import { useToast } from '../../hooks/toast-context';
import { api, ApiError, failText } from '../../lib/api';
import { fmtNum } from '../../lib/format';
import type { Info, IntegrationEnv, IntegrationTest, Kind } from '../../lib/types';
import { envChecks, type Tone } from './model';
import { IntFrame, Skeleton } from './parts';
import { useIntegration } from './useIntegration';
import './integration.css';

// 「연동 › 환경 점검」(11/09 밤 — 연동 페이지 오른쪽 카드를 페이지로): 수집 준비 상태(늘 펼침) + 연결 테스트(관리자만 시작)
export function IntegrationEnvPage() {
  const { info } = useStream();
  const { isAdmin } = useAuth();
  const { data, error, reload } = useIntegration();
  return (
    <IntFrame page="env" screen="integration/env" ready={!!data} error={error}>
      <div className="int-env-grid">
        <Panel className="int-env" testId="int-env" title="수집 준비 상태" sub="이 서버에서 실제 수집이 되는지">
          <div className="int-panel-body">{data ? <EnvChecks env={data.env} info={info} /> : <Skeleton rows={6} />}</div>
        </Panel>
        <Panel
          className="int-env"
          testId="int-test"
          title="연결 테스트"
          sub="시험 컨테이너로 수집 확인"
          actions={
            <Link to="/integration/watch" data-part="to-watch" className="int-link">
              감시 중 컨테이너 보기 ›
            </Link>
          }
        >
          <div className="int-panel-body">{data ? <TestStep env={data.env} test={data.test} isAdmin={isAdmin} onStarted={reload} /> : <Skeleton rows={3} />}</div>
        </Panel>
      </div>
    </IntFrame>
  );
}

const TONE_ICON: Record<Tone, ReactNode> = {
  ok: <Check className="size-3.5" aria-hidden />,
  warn: <TriangleAlert className="size-3.5" aria-hidden />,
  off: <Minus className="size-3.5" aria-hidden />,
};

// 현상을 먼저, 조치는 hint 로(확인 필요 항목 아래 한 줄)
function EnvChecks({ env, info }: { env: IntegrationEnv; info: Info | null }) {
  const checks = envChecks(env, info);
  const warn = checks.filter((c) => c.tone === 'warn').length;
  return (
    <>
      <p className={`int-verdict ${warn ? 'warn' : 'ok'}`} data-part="env-verdict">
        {warn ? `확인 필요 ${warn}건, 아래 조치 참고` : env.source === 'gadget' ? '실제 수집 준비됨' : '모의 이벤트로 동작 중'}
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
      toast(e instanceof ApiError ? failText('연결 테스트를 시작하지 못했습니다.', e) : '연결 테스트를 시작하지 못했습니다. 잠시 뒤 다시 시도하세요.', { key: 'int-test', tone: 'warn' });
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
              <li>수집 준비 상태의 「확인 필요」 항목 조치 후 다시 시도</li>
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
