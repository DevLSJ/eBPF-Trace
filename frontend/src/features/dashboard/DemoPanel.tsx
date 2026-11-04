import { Check, Play, RotateCw, TriangleAlert } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { TimelineBar } from '../../components/TimelineBar';
import { fmtSec, isolationMs } from '../../lib/timeline';
import { useCases } from '../../hooks/cases-context';
import { useStream } from '../../hooks/stream-context';
import { api, ApiError, errorText } from '../../lib/api';
import { installDest } from '../../lib/nav';
import { DEMO_SCENARIOS, type DemoRun, type DemoScenario, type InstallSession, type Timeline } from '../../lib/types';

// 시연 패널(10/30 계약 §4) — 대시보드 맨 위 카드 「시연」. 관리자이고 /api/info.demo 가 true 일 때만(DashboardPage 가 가린다).
// 시나리오 6개 → 「시연 시작」(POST /api/demo/run) → 단계 레일 6단계 · 경과 시간 · 타임라인 막대(⑤ 뒤) → 결과 한 줄 · 「다시 실행」.
// 데이터: GET /api/demo 2초 폴링(실행 중일 때만) + 기존 WS 판정 + 설치 세션(GET /api/installs/{id}). 첫 위반이 오면 설치 시트를 자동으로 연다

const DESC: Record<DemoScenario, string> = {
  all: '전부 순서대로',
  shell: '외부 스크립트 실행 + 비밀 파일 접근',
  revshell: '리버스 셸 포트 4444',
  'direct-ip': 'DNS 없이 공인 IP 접속',
  domain: '예약 도메인 example.com 접속',
  'dns-exfil': 'DNS 질의로 데이터 실어 보내기',
  benign: '정상 설치 대조군(위반 없이 통과)',
  chain: '연쇄 공격(다운로드 → 외부 연결 → 비밀 파일)',
};
const STEPS = ['컨테이너 시작', '설치 진행', '커널 이벤트 수집', '규칙 위반', '격리 · 증거', '판정 대기'];
const POLL_MS = 2000;
// 자동으로 설치 시트를 연 실행(run.id) — 화면을 오가도 한 번만
const opened = new Set<string>();

type Seen = { events: number; violation: boolean; timeline: Timeline | null };
const NONE: Seen = { events: 0, violation: false, timeline: null };

export function DemoPanel() {
  const { subscribe } = useStream();
  const { cases } = useCases();
  const navigate = useNavigate();
  const [scenario, setScenario] = useState<DemoScenario>('all');
  const [run, setRun] = useState<DemoRun | null>(null);
  const [session, setSession] = useState<InstallSession | null>(null);
  const [seen, setSeen] = useState<Seen>(NONE);
  const [error, setError] = useState<{ text: string; retry: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const runRef = useRef<DemoRun | null>(null);
  const sessionTimer = useRef<number | undefined>(undefined);

  const adopt = useCallback((r: DemoRun | null) => {
    setRun((cur) => {
      if (r && cur?.id !== r.id) {
        setSeen(NONE);
        setSession(null);
      }
      runRef.current = r;
      return r;
    });
  }, []);

  const loadSession = useCallback((id: string) => {
    api
      .install(id)
      .then((s) => {
        if (runRef.current?.installId === id) setSession(s);
      })
      .catch(() => {});
  }, []);

  // 처음: 실행 중이거나 마지막 실행을 보인다
  useEffect(() => {
    let live = true;
    api
      .demo()
      .then((d) => live && adopt(d.running ?? d.last))
      .catch((e: unknown) => live && setError({ text: `시연 상태를 읽지 못했습니다 — ${errorText(e)}`, retry: false }));
    return () => {
      live = false;
    };
  }, [adopt]);

  // 세션은 실행이 정해지면 바로, 실행 중에는 2초마다(GET /api/demo 와 함께)
  const running = run?.status === 'running';
  const installId = run?.installId;
  useEffect(() => {
    if (installId) loadSession(installId);
  }, [installId, loadSession]);
  useEffect(() => {
    if (!running) return;
    const t = window.setInterval(() => {
      api
        .demo()
        .then((d) => adopt(d.running ?? d.last))
        .catch(() => {});
      if (installId) loadSession(installId);
    }, POLL_MS);
    return () => window.clearInterval(t);
  }, [running, installId, adopt, loadSession]);
  useEffect(() => {
    if (!running) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [running]);

  // WS: 이 실행의 컨테이너 이벤트 → ③ 수집 · ④ 첫 위반 · ⑤ killedAt. 세션은 잠깐 뒤 다시 읽어 위반 · 격리 · 건을 맞춘다
  useEffect(
    () =>
      subscribe((m) => {
        const r = runRef.current;
        if (m.type !== 'verdict' || !r || m.data.event.containerName !== r.container) return;
        const v = m.data;
        setSeen((s) => ({ events: s.events + 1, violation: s.violation || v.matched, timeline: s.timeline ?? (v.timeline?.killedAt ? v.timeline : null) }));
        window.clearTimeout(sessionTimer.current);
        sessionTimer.current = window.setTimeout(() => loadSession(r.installId), 300);
      }),
    [subscribe, loadSession],
  );
  useEffect(() => () => window.clearTimeout(sessionTimer.current), []);

  // 첫 위반 → 설치 시트(주소에는 id 만)
  useEffect(() => {
    if (!run || !seen.violation || opened.has(run.id)) return;
    opened.add(run.id);
    navigate(installDest(run.installId).to, { state: installDest(run.installId).state });
  }, [run, seen.violation, navigate]);

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.demoRun(scenario);
      adopt(r);
      setNow(Date.now());
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        const cur = (e.body?.running as DemoRun | undefined) ?? null;
        if (cur) adopt(cur);
        setError({ text: `시연이 이미 실행 중입니다${cur ? ` — ${cur.scenario}` : ''}. 끝나면 다시 실행하세요`, retry: false });
      } else setError({ text: errorText(e), retry: true });
    } finally {
      setBusy(false);
    }
  };

  const violations = session?.violationCount ?? session?.violations?.reduce((n, v) => n + (v.count || 1), 0) ?? 0;
  const collected = Object.values(session?.activity?.kinds ?? {}).reduce((n, v) => n + (v ?? 0), 0);
  const timeline = seen.timeline ?? session?.isolation?.timeline ?? null;
  const caseOpen = !!session?.caseId || (cases ?? []).some((c) => c.installId === run?.installId);
  const done = [
    !!run && run.status !== 'refused',
    !!session && session.status !== 'refused',
    seen.events > 0 || collected > 0,
    seen.violation || violations > 0,
    !!timeline?.killedAt || !!session?.isolation || session?.status === 'isolated',
    caseOpen,
  ];
  const active = running ? done.findIndex((d) => !d) : -1;
  const rules = new Set((session?.violations ?? []).map((v) => v.ruleId).filter(Boolean));
  const elapsed = run ? Math.max(0, Math.round(((run.finishedAt ? Date.parse(run.finishedAt) : now) - Date.parse(run.startedAt)) / 1000)) : 0;
  const result = (() => {
    if (!run || running) return null;
    if (run.status === 'refused') return { tone: 'text-slate-700', text: '거부됨(차단 목록) — 차단 목록에 있어 설치 전 거부됨, 차단 해제 후 다시' };
    if (run.status === 'timeout') return { tone: 'text-amber-700', text: '시간 초과 — 90초 안에 끝나지 않아 컨테이너를 멈췄습니다' };
    if (run.status === 'failed') return { tone: 'text-red-700', text: `실패${run.exitCode !== null ? ` — 종료 코드 ${run.exitCode}` : ''}` };
    if (session?.status === 'isolated' || timeline?.killedAt) {
      const ms = isolationMs(timeline);
      return { tone: 'text-red-700', text: `격리됨 — 규칙 ${rules.size || violations}개${ms !== null ? ` · ${fmtSec(ms)}` : ''}` };
    }
    if (session?.status === 'warned' || violations > 0) return { tone: 'text-amber-700', text: `경고 — 규칙 ${rules.size || violations}개 · 격리 정책에는 걸리지 않음` };
    return { tone: 'text-emerald-700', text: '통과 — 위반 없음' };
  })();

  return (
    <section data-testid="demo" className="sg-card flex flex-col gap-3 border-indigo-200 p-4 text-sm" aria-label="시연">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-sm font-semibold text-slate-800">시연</h2>
        <label className="flex min-w-0 items-center gap-2 text-xs text-slate-600">
          시나리오
          <select
            data-testid="demo-scenario"
            className="h-8 min-w-0 rounded-md border border-slate-300 bg-white px-2 text-sm text-slate-800"
            value={scenario}
            disabled={running}
            onChange={(e) => setScenario(e.target.value as DemoScenario)}
          >
            {DEMO_SCENARIOS.map((k) => (
              <option key={k} value={k}>
                {k} — {DESC[k]}
              </option>
            ))}
          </select>
        </label>
        <span className="text-xs text-slate-500" data-part="demo-desc">
          {DESC[scenario]}
        </span>
        <button
          type="button"
          onClick={() => void start()}
          disabled={busy || running}
          className="sg-btn sg-btn-primary ml-auto"
        >
          {running ? (
            <>
              <RotateCw className="size-3.5 sg-spin" aria-hidden /> 실행 중…
            </>
          ) : run ? (
            <>
              <RotateCw className="size-3.5" aria-hidden /> 다시 실행
            </>
          ) : (
            <>
              <Play className="size-3.5" aria-hidden /> 시연 시작
            </>
          )}
        </button>
      </div>
      {error && (
        <div data-part="demo-error" role="alert" className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
          <TriangleAlert className="size-4 shrink-0" aria-hidden />
          <span className="min-w-0 flex-1">{error.text}</span>
          {error.retry && (
            <button type="button" onClick={() => void start()} disabled={busy} className="shrink-0 rounded-md border border-red-300 bg-white px-2 py-1 font-medium hover:bg-red-100 disabled:opacity-50">
              다시 시도
            </button>
          )}
        </div>
      )}
      {run && (
        <div className="grid gap-2" data-run={run.id} data-run-status={run.status}>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
            <span>
              {run.scenario} · <span className="font-mono">{run.container}</span>
            </span>
            {running ? (
              <span data-part="demo-elapsed" className="num text-indigo-700">
                실행 중 · {elapsed}초 경과
              </span>
            ) : (
              <span data-part="demo-elapsed" className="num">
                {elapsed}초 걸림
              </span>
            )}
            {run.simulated && <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px]">모의 재생</span>}
            <Link {...installDest(run.installId)} className="ml-auto text-indigo-600 hover:underline">
              설치 검사에서 보기 →
            </Link>
          </div>
          <ol data-testid="demo-rail" className="grid grid-cols-3 gap-1 md:grid-cols-[repeat(6,minmax(0,1fr))]">
            {STEPS.map((label, i) => {
              const state = done[i] ? 'done' : i === active ? 'active' : 'todo';
              return (
                <li key={label} data-step={i + 1} data-state={state} className="flex min-w-0 items-center gap-1.5">
                  <span
                    aria-hidden
                    className={`relative grid size-5 shrink-0 place-items-center rounded-full text-[10px] font-semibold ${
                      state === 'done' ? 'bg-emerald-600 text-white' : state === 'active' ? 'sg-pulse-ring bg-indigo-600 text-white' : 'bg-slate-200 text-slate-600'
                    }`}
                  >
                    {state === 'done' ? <Check className="size-3" /> : i + 1}
                  </span>
                  <span className={`truncate text-xs ${state === 'todo' ? 'text-slate-400' : 'text-slate-800'}`} title={label}>
                    {label}
                  </span>
                  {i < STEPS.length - 1 && <i className={`h-px min-w-2 flex-1 ${done[i] ? 'bg-emerald-400' : 'bg-slate-200'}`} aria-hidden />}
                </li>
              );
            })}
          </ol>
          {timeline && <TimelineBar timeline={timeline} compact />}
          {result && (
            <p data-part="demo-result" className={`text-sm font-medium ${result.tone}`}>
              {result.text}
            </p>
          )}
        </div>
      )}
    </section>
  );
}
