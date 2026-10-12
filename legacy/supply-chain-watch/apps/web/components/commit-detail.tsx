'use client';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import type { WsEnvelope } from '@scw/shared-types';
import { useWebSocket } from '@/lib/ws';
import { cn } from '@/lib/utils';
import { LEVEL_LABEL, levelClass, levelIcon, tagGroups } from '@/lib/risk';
import {
  LLM_STATUS_LABEL,
  SEVERITY_LABEL,
  getCommit,
  reanalyze,
  setVerdict,
  type CommitDetail as Detail,
} from '@/lib/commits';
import { DiffView, markId, type Mark } from './diff-view';

function fmtTime(iso: string | null | undefined) {
  return iso ? new Date(iso).toLocaleString('ko-KR', { hour12: false }) : '—';
}

export function CommitDetail({ id }: { id: string }) {
  const [d, setD] = useState<Detail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(() => {
    getCommit(id).then((x) => { setD(x); setErr(null); }).catch((e: Error) => setErr(e.message));
  }, [id]);
  useEffect(load, [load]);

  // 이 커밋의 분석이 시작·완료되면 다시 읽는다
  useWebSocket((e: WsEnvelope) => {
    const p = e.payload as { commitId?: number };
    if ((e.type === 'analysis.completed' || e.type === 'analysis.started' || e.type === 'analysis.failed') && String(p.commitId) === id) load();
  });

  if (err) return <div className="rounded-xl border border-line bg-surface p-6 text-[13px] text-crit-ink">{err}</div>;
  if (!d) return <div className="p-6 text-[13px] text-fg-3">불러오는 중…</div>;

  const c = d.commit;
  const a = d.analysis;
  const analyzing = c.status === 'QUEUED' || c.status === 'ANALYZING';
  const marks: Mark[] = [
    ...(a?.llm?.evidence ?? []).map((ev, i) => ({ file: ev.file, hint: ev.lineHint, kind: 'llm' as const, key: `llm-${i}` })),
    ...(a?.matchedRules ?? []).map((m, i) => ({ file: m.file, hint: m.snippet, kind: 'rule' as const, key: `rule-${i}` })),
  ];
  const jump = (key: string) => document.getElementById(markId(key))?.scrollIntoView({ behavior: 'smooth', block: 'center' });

  const doReanalyze = async () => {
    setBusy(true);
    try {
      await reanalyze(c.id);
      setNotice('AI 정밀 분석을 다시 요청했습니다. 끝나면 이 화면이 자동으로 바뀝니다.');
      load();
    } catch (e) {
      setNotice(`요청 실패: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  };
  const doVerdict = async (v: 'TRUE_POSITIVE' | 'FALSE_POSITIVE') => {
    try {
      await setVerdict(c.id, a?.verdict === v ? null : v);
      load();
    } catch (e) {
      setNotice(`저장 실패: ${(e as Error).message}`);
    }
  };

  return (
    <section className="flex flex-col gap-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-3">Commit Analysis</div>
          <h1 className="truncate text-[19px] font-semibold tracking-tight">{c.message.split('\n')[0] || '(메시지 없음)'}</h1>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12.5px] text-fg-2">
            <Link href="/targets" className="font-semibold hover:underline">{c.repoFullName}</Link>
            <a href={c.htmlUrl} target="_blank" rel="noreferrer" className="font-mono hover:underline">{c.shortSha}</a>
            {c.branch && <span className="font-mono text-fg-3">{c.branch}</span>}
            <span>{c.authorLogin ?? c.authorName ?? '—'}</span>
            <span className="text-fg-3">{fmtTime(c.committedAt)}</span>
            <span className="text-fg-3">{c.source === 'webhook' ? '즉시 수신' : c.source === 'backfill' ? '최근 커밋 가져오기' : '주기 확인'}</span>
          </div>
        </div>
        <div className="flex shrink-0 gap-2">
          <button onClick={() => void doReanalyze()} disabled={busy || analyzing} className="rounded-lg bg-accent px-3.5 py-2 text-[12.5px] font-bold text-white disabled:opacity-40">
            {analyzing ? '분석 중…' : '다시 분석 (AI 정밀)'}
          </button>
        </div>
      </div>

      {notice && <div role="status" aria-live="polite" className="rounded-lg bg-info-soft px-3.5 py-2 text-[12.5px]">{notice}</div>}

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_380px]">
        {/* 좌: 변경 내용 */}
        <div className="flex min-w-0 flex-col gap-3 rounded-xl border border-line bg-surface p-3 shadow-card">
          <div className="flex flex-wrap items-center justify-between gap-2 px-1 text-[12.5px]">
            <b>변경 내용 <span className="font-normal text-fg-3">{d.files.length}개 파일 · +{c.additions} -{c.deletions}</span></b>
            <span className="flex items-center gap-3 text-[11.5px] text-fg-3">
              <span className="inline-flex items-center gap-1"><i className="inline-block h-2.5 w-1 bg-crit" />AI 근거</span>
              <span className="inline-flex items-center gap-1"><i className="inline-block h-2.5 w-1 bg-warn" />정적 검사 근거</span>
            </span>
          </div>
          {d.diffTruncated && <div className="rounded-md bg-warn-soft px-3 py-1.5 text-[12px] text-warn-ink">변경이 커서 일부만 표시·분석했습니다 (파일당 20KB, 전체 120KB).</div>}
          <DiffView text={d.diffText ?? ''} marks={marks} />
        </div>

        {/* 우: 분석 결과 */}
        <aside className="flex min-w-0 flex-col gap-3">
          <div className="rounded-xl border border-line bg-surface p-4 shadow-card">
            {analyzing || !a ? (
              <div className="text-[13px] text-fg-2">{analyzing ? '분석 대기·진행 중입니다…' : '아직 분석 결과가 없습니다.'}</div>
            ) : (
              <>
                <div className="flex items-end justify-between gap-3">
                  <div>
                    <div className="text-[12px] text-fg-3">위험 점수</div>
                    <div className={cn('text-[42px] font-bold leading-none', a.riskLevel === 'HIGH' ? 'text-crit' : a.riskLevel === 'MEDIUM' ? 'text-[var(--warn-ink)]' : 'text-[var(--good-ink)]')}>
                      {a.riskScore}
                    </div>
                  </div>
                  <span className={cn('inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[13px] font-bold', levelClass(a.riskLevel))}>
                    {levelIcon(a.riskLevel)} {LEVEL_LABEL[a.riskLevel] ?? a.riskLevel}
                  </span>
                </div>
                <div className="mt-2 h-2 overflow-hidden rounded-full bg-surface-2">
                  <div className={cn('h-full', a.riskLevel === 'HIGH' ? 'bg-crit' : a.riskLevel === 'MEDIUM' ? 'bg-warn' : 'bg-good')} style={{ width: `${a.riskScore}%` }} />
                </div>
                <dl className="mt-3 grid grid-cols-3 gap-2 text-center text-[11.5px]">
                  <div className="rounded-lg bg-surface-2 py-1.5"><dt className="text-fg-3">정적 검사</dt><dd className="text-[14px] font-bold">{a.staticScore}</dd></div>
                  <div className="rounded-lg bg-surface-2 py-1.5"><dt className="text-fg-3">AI 확신도</dt><dd className="text-[14px] font-bold">{a.llm ? `${a.llm.confidence}%` : '—'}</dd></div>
                  <div className="rounded-lg bg-surface-2 py-1.5"><dt className="text-fg-3">걸린 시간</dt><dd className="text-[14px] font-bold">{(((a.staticLatencyMs ?? 0) + (a.llmLatencyMs ?? 0)) / 1000).toFixed(1)}s</dd></div>
                </dl>
                {tagGroups(a.tags).length > 0 && <div className="mt-2 text-[12px] text-fg-2">의심 행위: <b>{tagGroups(a.tags).join(' · ')}</b></div>}
                <div className="mt-1 text-[11.5px] text-fg-3">{LLM_STATUS_LABEL[a.llmStatus] ?? a.llmStatus}{a.llmModel ? ` · ${a.llmModel}` : ''}{a.promptVersion ? ` · 지침 v${a.promptVersion}` : ''}</div>
              </>
            )}
          </div>

          {a?.llm && (
            <div className="flex flex-col gap-2 rounded-xl border border-line bg-surface p-4 shadow-card">
              <b className="text-[13.5px]">AI 요약</b>
              <p className="whitespace-pre-wrap text-[13px] leading-relaxed">{a.llm.attackNarrativeKo}</p>
              {a.llm.benignExplanationKo && (
                <div className="rounded-lg bg-good-soft px-3 py-2 text-[12.5px] text-good-ink"><b>정상일 가능성 · </b>{a.llm.benignExplanationKo}</div>
              )}
              <div className="rounded-lg bg-accent-soft px-3 py-2 text-[12.5px]"><b>권장 조치 · </b>{a.llm.recommendedActionKo}</div>
            </div>
          )}

          {a && (a.llm?.evidence?.length || a.matchedRules.length) ? (
            <div className="flex flex-col gap-1.5 rounded-xl border border-line bg-surface p-4 shadow-card">
              <b className="text-[13.5px]">근거 <span className="font-normal text-fg-3">누르면 해당 줄로 이동</span></b>
              {(a.llm?.evidence ?? []).map((ev, i) => (
                <button key={`e${i}`} onClick={() => jump(`llm-${i}`)} className="rounded-lg border-l-[3px] border-crit bg-surface-2 px-2.5 py-1.5 text-left hover:bg-crit-soft">
                  <div className="truncate font-mono text-[11.5px] text-fg-3">{ev.file}</div>
                  <div className="truncate font-mono text-[12px]">{ev.lineHint}</div>
                  <div className="text-[12px] text-fg-2">{ev.reasonKo}</div>
                </button>
              ))}
              {a.matchedRules.map((m, i) => (
                <button key={`r${i}`} onClick={() => jump(`rule-${i}`)} className="rounded-lg border-l-[3px] border-warn bg-surface-2 px-2.5 py-1.5 text-left hover:bg-warn-soft">
                  <div className="flex items-center gap-1.5 text-[12px]">
                    <span className="rounded bg-warn-soft px-1.5 text-[11px] font-bold text-warn-ink">{SEVERITY_LABEL[m.severity] ?? m.severity}</span>
                    <span className="font-semibold">{m.descriptionKo || m.ruleId}</span>
                  </div>
                  <div className="truncate font-mono text-[11.5px] text-fg-3">{m.file}{m.count && m.count > 1 ? ` · ${m.count}곳` : ''}</div>
                  <div className="truncate font-mono text-[12px]">{m.snippet}</div>
                </button>
              ))}
            </div>
          ) : null}

          {a && (
            <div className="flex flex-col gap-2 rounded-xl border border-line bg-surface p-4 shadow-card">
              <b className="text-[13.5px]">처리 과정</b>
              <ol className="flex flex-col gap-1.5 border-l border-line pl-3 text-[12px]">
                <li>수집 · {fmtTime(c.receivedAt)}</li>
                <li>정적 검사 · {a.staticScore}점 · {a.staticLatencyMs ?? 0}ms</li>
                {a.gateReasons.length > 0 && <li className="text-fg-2">AI 분석으로 넘긴 이유 · {a.gateReasons.join(' / ')}</li>}
                {a.stages.map((s, i) => (
                  <li key={i}>
                    AI {i + 1}단계 · {s.model} · {LLM_STATUS_LABEL[s.status] ? s.status === 'OK' ? `${s.riskScore ?? '—'}점` : LLM_STATUS_LABEL[s.status] : s.status}
                    {s.latencyMs ? ` · ${(s.latencyMs / 1000).toFixed(1)}s` : ''}
                  </li>
                ))}
                <li>결과 저장 · {fmtTime(a.createdAt)}{d.attempts.length > 1 ? ` · ${d.attempts.length}번째 분석` : ''}</li>
              </ol>
              {a.usage.inputTokens > 0 && (
                <div className="text-[11.5px] text-fg-3">AI 사용량 · 입력 {a.usage.inputTokens.toLocaleString()} · 출력 {a.usage.outputTokens.toLocaleString()} 토큰</div>
              )}
            </div>
          )}

          {a && (
            <div className="flex items-center justify-between gap-2 rounded-xl border border-line bg-surface px-4 py-3 shadow-card">
              <span className="text-[12.5px]">이 판정이 맞나요?</span>
              <span className="flex gap-1.5">
                <button onClick={() => void doVerdict('TRUE_POSITIVE')} aria-pressed={a.verdict === 'TRUE_POSITIVE'} className={cn('rounded-md border border-line-strong px-2.5 py-1 text-[12px] font-semibold', a.verdict === 'TRUE_POSITIVE' && 'border-good bg-good-soft text-good-ink')}>맞음</button>
                <button onClick={() => void doVerdict('FALSE_POSITIVE')} aria-pressed={a.verdict === 'FALSE_POSITIVE'} className={cn('rounded-md border border-line-strong px-2.5 py-1 text-[12px] font-semibold', a.verdict === 'FALSE_POSITIVE' && 'border-crit bg-crit-soft text-crit-ink')}>잘못 판정</button>
              </span>
            </div>
          )}
        </aside>
      </div>
    </section>
  );
}
