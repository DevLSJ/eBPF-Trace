import { Copy, Printer } from 'lucide-react';
import { useCallback, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { DecisionBadge, StatusBadge } from '../../components/Badges';
import { ActionButton } from '../../components/ActionButton';
import { KindBadge } from '../../components/KindBadge';
import { TimeText } from '../../components/list/cells';
import { PageActions } from '../../components/PageActions';
import { Empty, LoadError } from '../../components/Panel';
import { TimelineBar } from '../../components/TimelineBar';
import { LevelBadge, VerdictBadge } from '../../components/VerdictBadge';
import { useAuth } from '../../hooks/auth-context';
import { useToast } from '../../hooks/toast-context';
import { useLoad } from '../../hooks/useLoad';
import { screenCopy } from '../../lib/screenCopy';
import { fmtDateTime } from '../../lib/format';
import { SOURCE_LABEL } from '../../lib/guide';
import { installDest, topologyDest } from '../../lib/nav';
import { changeText, LIST_LABEL } from '../../lib/proposal';
import { evidenceCounts, loadReport, reportMarkdown, summaryLines, type ReportData } from '../../lib/report';
import { detailOf } from '../../lib/types';

// 건 보고서 1장(10/30 계약 §5) — /report?case=<건> 또는 /report?install=<설치 세션>(주소에는 id 만).
// 내용 순서 고정: 제목 → 요약 3줄 → 격리 타임라인 → 위반 표 → 증거 요약 → 판정 → 정책 변경 · 차단 목록 → 작성. 읽기 전용(조회자도)
export function ReportPage() {
  const [params] = useSearchParams();
  const caseId = params.get('case');
  const installId = params.get('install');
  const load = useCallback(() => loadReport({ caseId, installId }), [caseId, installId]);
  const r = useLoad(load);
  const { me } = useAuth();
  const toast = useToast();
  const author = me?.user.displayName ?? '';
  const [at] = useState(() => new Date());
  const d = r.data;

  const copy = () => {
    if (!d) return;
    const md = reportMarkdown(d, author, at);
    const ok = () => toast('보고서를 Markdown으로 복사했습니다.', { key: 'report-copy', tone: 'ok' });
    const fail = () => toast('보고서를 복사하지 못했습니다. 브라우저의 클립보드 권한을 허용하거나 인쇄로 저장하세요.', { key: 'report-copy', tone: 'warn' });
    try {
      navigator.clipboard.writeText(md).then(ok, fail);
    } catch {
      fail();
    }
  };

  return (
    <div data-fill="" className="h-full min-h-0 overflow-y-auto" data-part="report-scroll">
      <p data-part="screen-copy" data-screen="report" className="m-0 shrink-0 truncate text-[length:var(--fs-sm)] text-text-3">
        {screenCopy('report')}
      </p>
      <PageActions>
        <ActionButton onClick={() => window.print()} reason={!d && '보고서를 불러온 뒤 쓸 수 있습니다'} className="sg-btn sg-btn-sm sg-btn-secondary flex items-center gap-1.5">
          <Printer className="size-3.5" aria-hidden /> 인쇄
        </ActionButton>
        <ActionButton onClick={copy} reason={!d && '보고서를 불러온 뒤 쓸 수 있습니다'} className="sg-btn sg-btn-sm sg-btn-secondary flex items-center gap-1.5">
          <Copy className="size-3.5" aria-hidden /> Markdown 복사
        </ActionButton>
        <span className="hidden truncate text-xs text-slate-400 lg:inline">A4 1~2장 · 읽기 전용</span>
      </PageActions>
      {r.error && !d ? (
        <div className="mx-auto max-w-3xl">
          <LoadError error={r.error} what="건 보고서" />
        </div>
      ) : !d ? (
        <Empty>불러오는 중…</Empty>
      ) : (
        <Report d={d} author={author} at={at} />
      )}
    </div>
  );
}

function Report({ d, author, at }: { d: ReportData; author: string; at: Date }) {
  const c = d.case;
  const s = d.session;
  const ev = d.evidence;
  const counts = ev ? evidenceCounts(ev) : null;
  const back = s ? installDest(s.id) : c ? topologyDest(c.container) : null;
  return (
    <article data-testid="report" className="sg-card mx-auto grid max-w-3xl gap-5 p-5 text-sm text-slate-800 md:p-8 print:max-w-none print:border-0 print:p-0 print:shadow-none">
      <header data-section="title" className="grid gap-2 border-b border-slate-200 pb-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded bg-indigo-50 px-1.5 py-0.5 text-xs font-medium text-accent-text">{SOURCE_LABEL[d.source]}</span>
          {s ? <StatusBadge status={s.status} /> : c ? <LevelBadge level={c.level} /> : null}
          {c && <DecisionBadge decision={c.decision} />}
        </div>
        <h2 className="font-mono text-xl font-semibold text-slate-900">{d.label}</h2>
        <p className="text-xs text-slate-500">
          건 보고서{c ? ` · 건 ${c.id}` : ''}
          {s ? ` · 세션 ${s.id}` : ''}
          {back && (
            <>
              {' '}
              ·{' '}
              <Link {...back} className="text-indigo-600 hover:underline print:hidden">
                {s ? '설치 검사에서 보기' : '토폴로지에서 보기'} →
              </Link>
            </>
          )}
        </p>
      </header>

      <section data-section="summary" className="grid gap-1.5">
        <H>요약</H>
        <ul className="grid gap-1">
          {summaryLines(d).map(([k, v]) => (
            <li key={k} className="grid grid-cols-[5rem_1fr] gap-2">
              <b className="text-slate-500">{k}</b>
              <span className="break-all">{v}</span>
            </li>
          ))}
        </ul>
      </section>

      <section data-section="timeline" className="grid gap-1.5">
        <H>격리 타임라인</H>
        <TimelineBar timeline={d.timeline} />
        {!d.timeline && <p className="text-xs text-slate-400">타임라인 기록 없음(격리되지 않았거나 기록이 생기기 전의 건)</p>}
      </section>

      <section data-section="violations" className="grid gap-1.5">
        <H>
          위반 <span className="num font-normal text-slate-400">{d.violations.length}</span>
        </H>
        <div className="overflow-x-auto">
          <table className="sg-table">
            <thead>
              <tr>
                {['시각', '종류', '규칙', '상세', '판정'].map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {d.violations.map((v, i) => (
                <tr key={i}>
                  <td className="tk-short text-slate-600">
                    <TimeText value={v.event.timestamp} kind="log" />
                  </td>
                  <td className="tk-short">
                    <KindBadge kind={v.event.kind} />
                  </td>
                  <td className="tk-short font-mono">{v.ruleId ?? ''}</td>
                  <td className="font-mono break-all">{detailOf(v.event)}</td>
                  <td className="tk-short">
                    <VerdictBadge v={v} />
                  </td>
                </tr>
              ))}
              {!d.violations.length && (
                <tr>
                  <td colSpan={5} className="text-slate-400">
                    위반 없음
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section data-section="evidence" className="grid gap-1.5">
        <H>증거 요약</H>
        {ev && counts ? (
          <p>
            로그 {counts.logs}줄 · 파일 변경 {counts.changes} · 프로세스 {counts.processes} <span className="text-xs text-slate-500">({fmtDateTime(ev.collectedAt)} · {ev.durationMs}ms)</span>
            {ev.partial && (
              <span className="ml-2 rounded bg-amber-100 px-1.5 py-0.5 text-xs text-amber-800" data-part="evidence-partial">
                일부만 모음{ev.error ? `(${ev.error})` : ''}
              </span>
            )}
          </p>
        ) : (
          <p className="text-xs text-slate-400">증거 없음, 증거(로그 · 파일 변경 · 프로세스)는 격리(kill) 직전에만 모읍니다</p>
        )}
      </section>

      <section data-section="decision" className="grid gap-1.5">
        <H>판정</H>
        {c ? (
          <p className="flex flex-wrap items-center gap-2">
            <DecisionBadge decision={c.decision} />
            {c.decidedBy && (
              <span className="text-xs text-slate-500">
                {c.decidedBy} · {c.decidedAt ? fmtDateTime(c.decidedAt) : ''}
              </span>
            )}
            {c.note && <span className="text-xs text-slate-700">메모: {c.note}</span>}
            {c.decision === 'pending' && <span className="text-xs text-slate-500">판정 대기(설치 검사 · 토폴로지에서 판정)</span>}
          </p>
        ) : (
          <p className="text-xs text-slate-400">판정할 건 없음 (격리 · 경고가 아님)</p>
        )}
      </section>

      <section data-section="changes" className="grid gap-1.5">
        <H>정책 변경 · 차단 목록</H>
        {d.proposal || d.blocks.length ? (
          <ul className="grid gap-1 text-xs">
            {d.proposal && (
              <li>
                제안 <span className="font-mono">{d.proposal.id}</span>
                {' · '}
                {d.proposal.state === 'applied'
                  ? ['적용됨', d.proposal.appliedBy, d.proposal.appliedAt && fmtDateTime(d.proposal.appliedAt)].filter(Boolean).join(' · ')
                  : d.proposal.state === 'discarded'
                    ? '버림(변경 없음)'
                    : '초안(정책에서 미리보기 후 적용)'}
                <ul className="mt-1 grid gap-0.5 pl-4 font-mono">
                  {d.proposal.changes.map((ch, i) => (
                    <li key={i} className="list-disc">
                      {changeText(ch)}
                    </li>
                  ))}
                </ul>
              </li>
            )}
            {d.blocks.map((b) => (
              <li key={`${b.list}:${b.value}`} className="font-mono">
                차단 목록 {LIST_LABEL[b.list]} {b.value} <span className="font-sans text-slate-500">({b.by} · {fmtDateTime(b.at)})</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-slate-400">없음, 판정 · 제안 적용 뒤에 여기에 남습니다</p>
        )}
      </section>

      <footer data-section="meta" className="border-t border-slate-200 pt-3 text-xs text-slate-500">
        작성 <span className="num">{fmtDateTime(at.toISOString())}</span>{author && ` · 작성자 ${author}`} · SupplyGuard 건 보고서
      </footer>
    </article>
  );
}

function H({ children }: { children: React.ReactNode }) {
  return <h3 className="text-sm font-semibold text-slate-800">{children}</h3>;
}
