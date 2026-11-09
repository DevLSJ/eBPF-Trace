import { api } from './api';
import { FIELD } from './fieldNames';
import { fmtDateTime } from './format';
import { SOURCE_LABEL } from './guide';
import { sessionLabel } from './pkg';
import { changeText, LIST_LABEL } from './proposal';
import { fmtMs, fmtSec, isolationMs, segmentsOf } from './timeline';
import { caseLabel, DECISION_LABEL, detailOf, INSTALL_STATUS_LABEL, LEVEL_LABEL, levelOf, type BlockEntry, type BlockList, type Case, type Evidence, type InstallSession, type Proposal, type Timeline, type Verdict } from './types';

// 건 보고서 1장(10/30 계약 §5) — 데이터 모으기 · Markdown 만들기(화면은 features/report/ReportPage.tsx)

export interface ReportData {
  label: string;
  source: Case['source'];
  session: InstallSession | null;
  case: Case | null;
  container: string;
  image: string;
  startedAt: string;
  finishedAt: string | null;
  ruleIds: string[];
  violations: Verdict[];
  timeline: Timeline | null;
  evidence: Evidence | null;
  proposal: Proposal | null;
  blocks: (BlockEntry & { list: BlockList })[];
}

export async function loadReport(q: { caseId: string | null; installId: string | null }): Promise<ReportData> {
  let session: InstallSession | null = null;
  let c: Case | null = null;
  if (q.installId) {
    session = await api.install(q.installId);
    if (session.caseId) c = await api.case(session.caseId).catch(() => null);
  } else if (q.caseId) {
    c = await api.case(q.caseId);
    if (c.installId) session = await api.install(c.installId).catch(() => null);
  } else throw new Error('보고서는 ?case=<건> 또는 ?install=<설치 세션> 으로 엽니다');
  let violations: Verdict[] = session?.violations ?? [];
  if (!session && c) {
    const rows = await api.audit({ container: c.container, limit: 500 }).catch(() => []);
    const mine = rows.filter((a) => a.caseId === c!.id);
    violations = mine.length ? mine : rows.filter((a) => a.event.containerName === c!.container);
  }
  const container = session?.container || c?.container || '';
  const evidence = container ? await api.evidence(container).then((xs) => xs[0] ?? null).catch(() => null) : null;
  const proposal = c?.proposalId ? await api.proposals().then((ps) => ps.find((p) => p.id === c!.proposalId) ?? null).catch(() => null) : null;
  const blocks = c
    ? await api
        .blocklist()
        .then((b) => (['packages', 'images', 'hosts'] as const).flatMap((l) => (b[l] ?? []).filter((e) => e.caseId === c!.id).map((e) => ({ ...e, list: l }))))
        .catch(() => [] as (BlockEntry & { list: BlockList })[])
    : [];
  const ruleIds = c?.ruleIds?.length ? c.ruleIds : [...new Set(violations.map((v) => v.ruleId).filter((x): x is string => !!x))];
  return {
    label: session ? `${session.manager} ${sessionLabel(session)}` : c ? caseLabel(c) : '',
    source: c?.source ?? 'install',
    session,
    case: c,
    container,
    image: session?.image || c?.image || '',
    startedAt: session?.startedAt ?? c?.openedAt ?? new Date().toISOString(),
    finishedAt: session?.finishedAt ?? session?.containerExitedAt ?? null,
    ruleIds,
    violations: [...violations].sort((a, b) => a.event.timestamp.localeCompare(b.event.timestamp)),
    timeline: session?.isolation?.timeline ?? c?.isolation?.timeline ?? null,
    evidence,
    proposal,
    blocks,
  };
}

export const statusText = (d: ReportData) => (d.session ? INSTALL_STATUS_LABEL[d.session.status] : d.case ? LEVEL_LABEL[d.case.level] : '');
export const evidenceCounts = (e: Evidence) => ({
  logs: e.logs ? e.logs.split('\n').filter((l) => l.trim()).length : 0,
  changes: e.changes?.length ?? 0,
  processes: e.processes?.length ?? 0,
});
export const violationCount = (d: ReportData) => d.violations.reduce((n, v) => n + ((v as { count?: number }).count || 1), 0);

// 요약 3줄(무엇이 · 언제 · 어떤 정책 — 이름은 lib/fieldNames.ts)
export function summaryLines(d: ReportData): [string, string][] {
  const when = `시작 ${fmtDateTime(d.startedAt)}${d.finishedAt ? ` · 끝 ${fmtDateTime(d.finishedAt)}` : ''}${d.case ? ` · 건 열림 ${fmtDateTime(d.case.openedAt)}` : ''}`;
  return [
    ['무엇이', `${d.label}${d.image ? ` (${d.image})` : ''}${d.container ? ` · 컨테이너 ${d.container}` : ''}`],
    ['언제', when],
    [`어떤 ${FIELD.policy}`, `${d.ruleIds.length ? `${d.ruleIds.join(', ')} · ` : ''}위반 ${violationCount(d)}건`],
  ];
}

export function reportMarkdown(d: ReportData, author: string, at = new Date()): string {
  const segs = segmentsOf(d.timeline);
  const total = isolationMs(d.timeline);
  const out: string[] = [];
  out.push(`# ${d.label} 건 보고서`);
  out.push(`${SOURCE_LABEL[d.source]} · ${statusText(d)}${d.case ? ` · 건 ${d.case.id}` : ''}${d.session ? ` · 세션 ${d.session.id}` : ''}`);
  out.push('', '## 요약');
  for (const [k, v] of summaryLines(d)) out.push(`- ${k}: ${v}`);
  out.push('', '## 격리 타임라인');
  out.push(`${segs.map((s) => `${s.label} ${fmtMs(s.ms)}`).join(' · ')} · 격리까지 ${total === null ? '' : fmtSec(total)}`);
  out.push('', '## 위반', `| 시각 | 종류 | ${FIELD.policy} | 상세 | 판정 |`, '|---|---|---|---|---|');
  for (const v of d.violations) out.push(`| ${fmtDateTime(v.event.timestamp)} | ${v.event.kind} | ${v.ruleId ?? ''} | ${detailOf(v.event).replace(/\|/g, '\\|')} | ${LEVEL_LABEL[levelOf(v)]} |`);
  if (!d.violations.length) out.push('|  |  |  | 위반 없음 |  |');
  out.push('', '## 증거');
  if (d.evidence) {
    const n = evidenceCounts(d.evidence);
    out.push(`로그 ${n.logs}줄 · 파일 변경 ${n.changes} · 프로세스 ${n.processes}${d.evidence.partial ? ` · 일부만 모음${d.evidence.error ? `(${d.evidence.error})` : ''}` : ''} · 모은 시각 ${fmtDateTime(d.evidence.collectedAt)}`);
  } else out.push('증거 없음, 격리(kill) 직전에만 모읍니다');
  out.push('', '## 판정');
  if (d.case) {
    out.push(`${DECISION_LABEL[d.case.decision]}${d.case.decidedBy ? ` · ${d.case.decidedBy}` : ''}${d.case.decidedAt ? ` · ${fmtDateTime(d.case.decidedAt)}` : ''}${d.case.note ? ` · 메모: ${d.case.note}` : ''}`);
  } else out.push('판정할 건 없음');
  out.push('', '## 정책 변경 · 차단 목록');
  if (d.proposal) {
    out.push(`제안 ${d.proposal.id}: ${d.proposal.state === 'applied' ? `적용됨${d.proposal.appliedBy ? `(${d.proposal.appliedBy})` : ''}` : d.proposal.state === 'discarded' ? '버림' : '초안'}`);
    for (const ch of d.proposal.changes) out.push(`- ${changeText(ch)}`);
  }
  for (const b of d.blocks) out.push(`- 차단 목록 ${LIST_LABEL[b.list]} ${b.value} (${b.by} · ${fmtDateTime(b.at)})`);
  if (!d.proposal && !d.blocks.length) out.push('없음');
  out.push('', `작성 ${fmtDateTime(at.toISOString())} · 작성자 ${author}`);
  return out.join('\n');
}
