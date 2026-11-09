import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useStream } from '../../hooks/stream-context';
import { api, ApiError, failText, isUnsupported } from '../../lib/api';
import type { DemoRun, DemoScenario, Evidence, InstallSession, Verdict } from '../../lib/types';

// 시연 페이지 데이터(R3 11/04) — 옛 대시보드 DemoPanel.tsx 의 폴링 · 실행 로직을 옮겼다.
//   GET /api/demo: 실행 중 1초 · 그 밖 4초(다른 곳에서 시작한 실행도 알아채 단추를 잠근다)
//   GET /api/installs/{installId}: 실행이 정해지면 바로 · 실행 중 1초 · 그 컨테이너 WS 판정 0.3초 뒤
//   GET /api/evidence?container=: 격리로 끝난 실행만 한 번(없으면 1초 간격 2번 더 — 증거 저장이 kill 보다 조금 늦을 수 있다), 끝내 없으면 null 「정보 없음」
//   실시간 스트림: 그 컨테이너 판정(시간 순)
// 첫 위반이 와도 설치 시트로 옮기지 않는다(11/04e B — 녹화 중 페이지 고정)

const POLL_RUNNING_MS = 1000;
const POLL_IDLE_MS = 4000;
const EVIDENCE_TRIES = 3;
const EVIDENCE_GAP_MS = 1000;

// 고른 시나리오 · 마지막 실행은 화면을 옮겨도 남는다(돌아오면 그대로)
let lastScenario: DemoScenario = 'shell';

export interface DemoError {
  status: number | null;
  text: string;
}

export function useDemo(enabled: boolean) {
  const { subscribe, verdicts } = useStream();
  const [scenario, setScenarioState] = useState<DemoScenario>(lastScenario);
  const [run, setRun] = useState<DemoRun | null>(null);
  const [session, setSession] = useState<InstallSession | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null | undefined>(undefined);
  const [error, setError] = useState<DemoError | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [starting, setStarting] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const runRef = useRef<DemoRun | null>(null);
  const sessionTimer = useRef<number | undefined>(undefined);

  const setScenario = useCallback((k: DemoScenario) => {
    lastScenario = k;
    setScenarioState(k);
  }, []);

  // 새 실행이면 세션 · 증거를 비운다
  const adopt = useCallback((r: DemoRun | null) => {
    if (r && runRef.current?.id !== r.id) {
      setSession(null);
      setEvidence(undefined);
    }
    runRef.current = r;
    setRun(r);
    // 실행 중이 아니면 409 띠는 거둔다(끝나면 다시 시작할 수 있다)
    if (!r || r.status !== 'running') setError((e) => (e?.status === 409 ? null : e));
  }, []);

  const loadSession = useCallback((id: string) => {
    if (!id) return;
    api
      .install(id)
      .then((s) => {
        if (runRef.current?.installId === id) setSession(s);
      })
      .catch(() => {});
  }, []);

  const refresh = useCallback(() => {
    return api.demo().then(
      (d) => {
        setLoadError(null);
        const r = d.running ?? d.last;
        adopt(r);
        if (r?.installId) loadSession(r.installId);
      },
      (e: unknown) => setLoadError(e),
    );
  }, [adopt, loadSession]);

  const running = run?.status === 'running';
  useEffect(() => {
    if (!enabled) return;
    void refresh();
  }, [enabled, refresh]);
  useEffect(() => {
    if (!enabled) return;
    const t = window.setInterval(() => void refresh(), running ? POLL_RUNNING_MS : POLL_IDLE_MS);
    return () => window.clearInterval(t);
  }, [enabled, running, refresh]);
  useEffect(() => {
    if (!running) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [running]);

  // WS: 이 실행의 컨테이너 판정이 오면 세션을 잠깐 뒤 다시 읽는다(위반 · 격리 · 건)
  useEffect(
    () =>
      subscribe((m) => {
        const r = runRef.current;
        if (m.type !== 'verdict' || !r || m.data.event.containerName !== r.container) return;
        window.clearTimeout(sessionTimer.current);
        sessionTimer.current = window.setTimeout(() => loadSession(r.installId), 300);
      }),
    [subscribe, loadSession],
  );
  useEffect(() => () => window.clearTimeout(sessionTimer.current), []);

  // 증거: 격리로 끝난 실행만
  const isolatedDone = !!run && run.status !== 'running' && session?.status === 'isolated';
  const runId = run?.id;
  const container = run?.container;
  const containerId = session?.containerId;
  useEffect(() => {
    if (!isolatedDone || !container || evidence !== undefined) return;
    let live = true;
    let timer: number | undefined;
    const tryOnce = (left: number) => {
      api.evidence(container).then(
        (list) => {
          if (!live) return;
          const hit = (list ?? []).find((x) => !containerId || x.containerId === containerId) ?? (list ?? [])[0] ?? null;
          if (hit || left <= 1) setEvidence(hit);
          else timer = window.setTimeout(() => tryOnce(left - 1), EVIDENCE_GAP_MS);
        },
        () => live && setEvidence(null),
      );
    };
    tryOnce(EVIDENCE_TRIES);
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [isolatedDone, runId, container, containerId, evidence]);

  const start = useCallback(async () => {
    if (starting || runRef.current?.status === 'running') return;
    setStarting(true);
    setError(null);
    try {
      const r = await api.demoRun(scenario);
      adopt(r);
      setNow(Date.now());
      if (r.installId) loadSession(r.installId);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        const cur = (e.body?.running as DemoRun | undefined) ?? null;
        if (cur) adopt(cur);
        setError({ status: 409, text: '이미 실행 중입니다. 끝나면 다시 시작할 수 있습니다.' });
        void refresh();
      } else if (e instanceof ApiError && e.status === 503) setError({ status: 503, text: e.message || 'Docker 에 연결할 수 없습니다' });
      else if (isUnsupported(e)) setError({ status: 404, text: '이 백엔드에는 시연 API 가 없습니다(DEMO_ENABLED 꺼짐)' });
      else setError({ status: e instanceof ApiError ? e.status : null, text: failText('시연을 시작하지 못했습니다.', e) });
    } finally {
      setStarting(false);
    }
  }, [starting, scenario, adopt, loadSession, refresh]);

  // 그 컨테이너의 실시간 이벤트 — 시간 순
  const streamEvs = useMemo<Verdict[]>(
    () => (container ? verdicts.filter((v) => v.event.containerName === container).sort((a, b) => a.event.timestamp.localeCompare(b.event.timestamp)) : []),
    [verdicts, container],
  );

  return { scenario, setScenario, run, session, evidence, error, loadError, starting, now, start, streamEvs };
}
