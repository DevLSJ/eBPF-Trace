import { FileSearch } from 'lucide-react';
import { useCallback, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { AttackChain } from '../../components/AttackChain';
import { stepsFromViolations } from '../../lib/chain';
import { DecisionBadge, StatusBadge } from '../../components/Badges';
import { DecisionBox } from '../../components/DecisionBox';
import { Empty, LoadError } from '../../components/Panel';
import { Section, Sheet } from '../../components/Sheet';
import { LevelBadge } from '../../components/VerdictBadge';
import { useCases } from '../../hooks/cases-context';
import { useInterval, useLoad } from '../../hooks/useLoad';
import { api } from '../../lib/api';
import { fmtDateTime, fmtNum } from '../../lib/format';
import { evidenceHref } from '../../lib/evidence';
import { duration, ECOSYSTEM, installCommand, packageName, sessionLabel, violationTotal } from '../../lib/pkg';
import type { InstallSession } from '../../lib/types';

const LIST_LABEL = { packages: '패키지', images: '이미지', hosts: '도메인' } as const;

export function InstallSheet({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const load = useCallback(() => api.install(id), [id]);
  const detail = useLoad(load);
  const s = detail.data;
  const running = s?.status === 'running';
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
      title={s ? `${s.manager} ${sessionLabel(s)}` : '설치 세션'}
      onClose={onClose}
      className="w-[440px]"
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
              {s.status === 'isolated' && (
                <Link to={evidenceHref(s.container)} className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-indigo-200 px-2.5 py-1 text-xs text-indigo-700 hover:bg-indigo-50">
                  <FileSearch className="size-3.5" aria-hidden /> 증거 보기
                </Link>
              )}
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

// 정적 분석(OSV, 버전 무관) vs 커널 탐지 — 「SCA 가 못 잡는 행위를 커널이 잡는다」(M1)
function OsvCompare({ s }: { s: InstallSession }) {
  const name = packageName(s.packages[0] ?? '');
  const eco = ECOSYSTEM[s.manager];
  const load = useCallback(() => api.osv(eco, name), [eco, name]);
  const osv = useLoad(load);
  const kernel = violationTotal(s) ?? 0;
  const failed = !!osv.error || !!osv.data?.error;

  return (
    <div className="grid grid-cols-2 gap-2 text-sm">
      <div className="rounded-md border border-slate-200 px-3 py-2" data-testid="osv-result">
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
            {osv.data.ids.length > 0 && <div className="truncate font-mono text-[11px] text-slate-400">{osv.data.ids.slice(0, 3).join(', ')}</div>}
          </div>
        )}
        <div className="truncate font-mono text-[11px] text-slate-400">
          {eco} · {name}
        </div>
      </div>
      <div className={`rounded-md border px-3 py-2 ${kernel ? 'border-red-200 bg-red-50' : 'border-slate-200'}`} data-testid="kernel-result">
        <div className="text-xs text-slate-500">커널 탐지 · eBPF</div>
        <div>
          <b className={`num text-lg ${kernel ? 'text-red-700' : 'text-slate-900'}`}>{fmtNum(kernel)}</b>
          <span className="text-slate-600">건 위반 행위</span>
        </div>
        <div className="text-[11px] text-slate-400">설치 중 실제로 한 일</div>
      </div>
    </div>
  );
}

const KIND_LABEL = { exec: '실행', open: '파일', connect: '통신' } as const;

function Activity({ s }: { s: InstallSession }) {
  const a = s.activity;
  if (!a) return <p className="text-xs text-slate-400">활동 요약 없음</p>;
  return (
    <div className="grid gap-3 text-sm">
      <div className="grid grid-cols-3 gap-2">
        {(['exec', 'open', 'connect'] as const).map((k) => (
          <div key={k} className="rounded-md border border-slate-200 px-3 py-2">
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
