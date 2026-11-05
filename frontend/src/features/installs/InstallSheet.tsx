import { FileSearch, FileText } from 'lucide-react';
import { useCallback, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { AttackChain } from '../../components/AttackChain';
import { stepsFromViolations } from '../../lib/chain';
import { DecisionBadge, StatusBadge } from '../../components/Badges';
import { DecisionBox } from '../../components/DecisionBox';
import { Empty, LoadError } from '../../components/Panel';
import { Section, Sheet, type SheetNav } from '../../components/Sheet';
import { TimelineBar } from '../../components/TimelineBar';
import { LevelBadge } from '../../components/VerdictBadge';
import { useCases } from '../../hooks/cases-context';
import { useInterval, useLoad } from '../../hooks/useLoad';
import { api } from '../../lib/api';
import { fmtDateTime, fmtNum } from '../../lib/format';
import { evidenceDest } from '../../lib/evidence';
import { duration, ECOSYSTEM, installCommand, packageName, sessionLabel, violationTotal } from '../../lib/pkg';
import type { InstallScan, InstallSession } from '../../lib/types';
import { StaticBadge } from './StaticBadge';
import { hasStaticCell, mismatchNote, skipText } from './staticScan';

const LIST_LABEL = { packages: '패키지', images: '이미지', hosts: '도메인' } as const;

export function InstallSheet({ id, onClose, onChanged, nav }: { id: string; onClose: () => void; onChanged: () => void; nav?: SheetNav }) {
  const load = useCallback(() => api.install(id), [id]);
  const detail = useLoad(load);
  const s = detail.data;
  // 11/04: 설치가 끝나도 자동 정적 검사가 실행 중이면 계속 2초마다 다시 부른다
  const running = s?.status === 'running' || s?.scan?.status === 'running';
  const reload = detail.reload;
  const tick = useCallback(() => {
    if (running) reload();
  }, [running, reload]);
  useInterval(tick, 2000);

  // 판정이 바뀌면(이 시트 · 다른 화면 · WS) 목록의 판정 열도 다시 그린다
  const { cases } = useCases();
  const decision = s?.caseId ? cases?.find((c) => c.id === s.caseId)?.decision : undefined;
  useEffect(() => {
    if (decision) onChanged();
  }, [decision, onChanged]);

  return (
    <Sheet
      kind="install"
      size="wide"
      nav={nav}
      title={s ? `${s.manager} ${sessionLabel(s)}` : '설치 세션'}
      onClose={onClose}
    >
      {detail.error && !s ? (
        <LoadError error={detail.error} what="설치 세션 상세" />
      ) : !s ? (
        <Empty>불러오는 중…</Empty>
      ) : (
        <div className="flex min-h-full flex-col">
          <div className="flex-1">
            <Section title="결과">
              <Summary s={s} />
              {/* 격리 타임라인(10/30 계약 §3) — 격리 세션의 첫 kill 판정. 옛 백엔드는 없음 */}
              {s.isolation?.timeline && (
                <div className="mt-3">
                  <TimelineBar timeline={s.isolation.timeline} />
                </div>
              )}
              <div className="mt-2 flex flex-wrap gap-2">
                {s.status === 'isolated' && (
                  <Link {...evidenceDest(s.container)} className="sg-btn sg-btn-sm sg-btn-secondary inline-flex items-center gap-1.5">
                    <FileSearch className="size-3.5" aria-hidden /> 증거 보기
                  </Link>
                )}
                {(s.status === 'isolated' || s.status === 'warned') && (
                  <Link to={`/report?install=${encodeURIComponent(s.id)}`} data-action="report" className="sg-btn sg-btn-sm sg-btn-secondary inline-flex items-center gap-1.5">
                    <FileText className="size-3.5" aria-hidden /> 보고서
                  </Link>
                )}
              </div>
            </Section>
            {s.status !== 'refused' && (
              <>
                <Section title="정적 분석 비교" testId="osv">
                  <OsvCompare s={s} />
                </Section>
                <Section title="공격 체인" testId="install-chain">
                  <AttackChain steps={stepsFromViolations(s.violations ?? [])} />
                </Section>
                <Section title="활동 요약" testId="activity">
                  <Activity s={s} />
                </Section>
              </>
            )}
          </div>
          <div className="sticky bottom-0 border-t border-slate-200 bg-white px-4 py-3" data-testid="decision-area">
            <h3 className="mb-2 flex items-center gap-2 text-xs font-semibold text-slate-700">
              판정 {decision === 'pending' && <DecisionBadge decision="pending" />}
            </h3>
            <DecisionBox caseId={s.caseId} />
          </div>
        </div>
      )}
    </Sheet>
  );
}

function Summary({ s }: { s: InstallSession }) {
  return (
    <dl className="grid grid-cols-[4.5rem_1fr] gap-x-3 gap-y-1 text-sm">
      <dt className="text-slate-500">설치 결과</dt>
      <dd>
        <StatusBadge status={s.status} />
      </dd>
      <dt className="text-slate-500">명령</dt>
      <dd className="font-mono text-xs break-all" data-testid="install-command">
        {installCommand(s)}
      </dd>
      {s.status === 'refused' && s.refusedBy && (
        <>
          <dt className="text-slate-500">거부 이유</dt>
          <dd className="text-xs" data-testid="refused-by">
            차단 목록의 {LIST_LABEL[s.refusedBy.list] ?? s.refusedBy.list} <code className="font-mono">{s.refusedBy.value}</code> — 컨테이너를 띄우기 전에 거부
          </dd>
        </>
      )}
      <dt className="text-slate-500">시작</dt>
      <dd className="num">{fmtDateTime(s.startedAt)}</dd>
      {s.status !== 'refused' && (
        <>
          <dt className="text-slate-500">걸린 시간</dt>
          <dd className="num">
            {s.status === 'running' ? '진행 중' : duration(s.startedAt, s.finishedAt ?? s.containerExitedAt)}
            {s.exitCode !== undefined && s.exitCode !== null && <span className="text-slate-500"> · 종료 코드 {s.exitCode}</span>}
          </dd>
          <dt className="text-slate-500">컨테이너</dt>
          <dd className="font-mono text-xs break-all">{s.container}</dd>
          <dt className="text-slate-500">이미지</dt>
          <dd className="font-mono text-xs">{s.image}</dd>
        </>
      )}
    </dl>
  );
}

// 정적 vs 커널 탐지 — 「SCA 가 못 잡는 행위를 커널이 잡는다」(M1)
//   11/04 종합 판정: 자동 정적 검사(scan)가 있으면 왼쪽 = 「정적 검사 · GuardDog + OSV」, 건너뜀 · 옛 세션이면 지금의 OSV 이름 조회 칸(건너뜀은 부제에 이유).
//   엇갈릴 때만 빨간 한 줄. 768 미만은 두 칸을 한 열로
function OsvCompare({ s }: { s: InstallSession }) {
  const kernel = violationTotal(s) ?? 0;
  const note = mismatchNote(s);
  return (
    <>
      <div className="grid grid-cols-2 gap-2 text-sm max-md:grid-cols-1">
        {hasStaticCell(s.scan) ? <StaticCell s={s} sc={s.scan} /> : <OsvCell s={s} why={s.scan ? skipText(s) : ''} />}
        <div className={`rounded-md border px-3 py-2 ${kernel ? 'border-red-200 bg-red-50' : 'border-slate-200'}`} data-testid="kernel-result" data-cell="kernel">
          <div className="text-xs text-slate-500">커널 탐지 · eBPF</div>
          <div>
            <b className={`num text-lg ${kernel ? 'text-red-700' : 'text-slate-900'}`}>{fmtNum(kernel)}</b>
            <span className="text-slate-600">건 위반 행위</span>
          </div>
          <div className="text-xs text-slate-400">설치 중 실제로 한 일</div>
        </div>
      </div>
      {note && (
        <p className="mt-2 text-xs font-medium text-red-600" data-part="cmp-note">
          {note}
        </p>
      )}
    </>
  );
}

// 자동 정적 검사 결과(11/04) — 배지 · 위험 점수(악성만 빨강, 실행 중 · 실패면 숨김) · 대상 라벨 + 받은 버전 · 공급망 검사 링크
function StaticCell({ s, sc }: { s: InstallSession; sc: InstallScan }) {
  const done = sc.status === 'done';
  const mal = done && sc.verdict === 'malicious';
  return (
    <div className="grid min-w-0 content-start gap-1 rounded-md border border-slate-200 px-3 py-2" data-testid="static-result" data-cell="static">
      <div className="text-xs text-slate-500" data-part="static-head">
        정적 검사 · GuardDog + OSV
      </div>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <StaticBadge s={s} />
        {done && sc.riskScore != null && (
          <span className={`num text-xs ${mal ? 'font-semibold text-red-600' : 'text-slate-500'}`} data-part="risk">
            위험 점수 {sc.riskScore.toFixed(1)} / 10
          </span>
        )}
      </div>
      <div className="text-xs break-words break-keep text-slate-400" data-part="static-target">
        <span className="font-mono">{sc.label}</span>
        {sc.version && ` · ${sc.version}`}
        {sc.reused && ' · 24시간 안 검사 결과 재사용'}
      </div>
      {sc.id && (
        <Link to={`/scans?id=${encodeURIComponent(sc.id)}`} className="justify-self-start text-xs text-indigo-700 hover:underline" data-action="scan-link">
          공급망 검사에서 보기 →
        </Link>
      )}
    </div>
  );
}

// 정적 분석(OSV, 버전 무관) — 자동 정적 검사가 없거나(옛 세션) 건너뛰었을 때. why = 건너뛴 이유(부제 끝)
function OsvCell({ s, why }: { s: InstallSession; why: string }) {
  const name = packageName(s.packages[0] ?? '');
  const eco = ECOSYSTEM[s.manager];
  const load = useCallback(() => api.osv(eco, name), [eco, name]);
  const osv = useLoad(load);
  const failed = !!osv.error || !!osv.data?.error;
  return (
    <div className="min-w-0 rounded-md border border-slate-200 px-3 py-2" data-testid="osv-result" data-cell="osv">
      <div className="text-xs text-slate-500">
        정적 분석 · OSV <span className="text-slate-400">(버전 무관)</span>
      </div>
      {failed ? (
        <div className="font-semibold text-slate-500" data-osv="failed" title={osv.data?.error ?? undefined}>
          조회 실패
        </div>
      ) : !osv.data ? (
        <div className="text-slate-400">조회 중…</div>
      ) : (
        <div data-osv={osv.data.vulns}>
          <b className="num text-lg text-slate-900">{fmtNum(osv.data.vulns)}</b>
          <span className="text-slate-600">건 알려진 취약점</span>
          {osv.data.ids.length > 0 && <div className="truncate font-mono text-xs text-slate-400">{osv.data.ids.slice(0, 3).join(', ')}</div>}
        </div>
      )}
      <div className={`font-mono text-xs text-slate-400 ${why ? 'break-words break-keep' : 'truncate'}`}>
        {eco} · {name}
        {why && <span className="font-sans"> · {why}</span>}
      </div>
    </div>
  );
}

// 활동 요약 타일 — 종류별(10/30: 「조회」 = dns 질의)
const KIND_LABEL = { exec: '실행', open: '파일', connect: '통신', dns: '조회' } as const;

function Activity({ s }: { s: InstallSession }) {
  const a = s.activity;
  if (!a) return <p className="text-xs text-slate-400">활동 요약 없음</p>;
  return (
    <div className="grid gap-3 text-sm">
      <div className="grid grid-cols-4 gap-2">
        {(['exec', 'open', 'connect', 'dns'] as const).map((k) => (
          <div key={k} className="rounded-md border border-slate-200 px-2.5 py-2" data-kind-tile={k}>
            <b className="num text-lg">{fmtNum(a.kinds[k] ?? 0)}</b>
            <div className="text-xs text-slate-500">{KIND_LABEL[k]}</div>
          </div>
        ))}
      </div>
      <div>
        <div className="mb-1 text-xs text-slate-500">접속한 곳 {a.hosts.length}</div>
        <ul className="grid gap-1">
          {a.hosts.map((h) => (
            <li key={`${h.host}:${h.port}`} className="flex items-center gap-2 text-xs">
              <span className="min-w-0 flex-1 truncate font-mono" title={`${h.ip}:${h.port}`}>
                {h.host || h.ip}:{h.port}
              </span>
              <span className="num text-slate-400">×{h.count}</span>
              <LevelBadge level={h.level} />
            </li>
          ))}
        </ul>
      </div>
      <div>
        <div className="mb-1 text-xs text-slate-500">실행한 프로그램 {a.programs.length}</div>
        <ul className="grid gap-1">
          {a.programs.map((p, i) => (
            <li key={i} className="flex items-center gap-2 text-xs">
              <span className="min-w-0 flex-1 truncate font-mono" title={p.args}>
                {p.args || p.comm}
              </span>
              <span className="num text-slate-400">×{p.count}</span>
              <LevelBadge level={p.level} />
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
