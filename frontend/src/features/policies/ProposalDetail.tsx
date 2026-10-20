import { Eye } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { DecisionBadge } from '../../components/Badges';
import { ConfirmButton } from '../../components/ConfirmButton';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { useCases } from '../../hooks/cases-context';
import { useToast } from '../../hooks/toast-context';
import { api, errorText } from '../../lib/api';
import { fmtDateTime, fmtNum } from '../../lib/format';
import { changeText, LIST_LABEL } from '../../lib/proposal';
import { caseLabel, LEVEL_LABEL, type Level, type Preview, type Proposal } from '../../lib/types';

const levelText = (v: string) => LEVEL_LABEL[v as Level] ?? (v === 'kill' ? '격리' : v === 'alert' ? '경고' : v);

// 제안 상세: 근거(판정) → 변경 내용 → 미리보기(과거 위반 중 결과가 바뀌는 건) → 적용 / 버림
// 초안을 열면 미리보기를 바로 한 번 계산한다(결정 2026-10-15) — 다시 계산은 「미리보기」 버튼
export function ProposalDetail({
  proposal: p,
  loading,
  error,
  canWrite,
  onDone,
}: {
  proposal: Proposal | undefined;
  loading: boolean;
  error: unknown;
  canWrite: boolean;
  onDone: () => void;
}) {
  const { cases } = useCases();
  const toast = useToast();
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewError, setPreviewError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const id = p?.id;
  const draft = p?.state === 'draft';
  const runPreview = useCallback(async () => {
    if (!id) return;
    setBusy(true);
    try {
      setPreview(await api.preview(id));
      setPreviewError(null);
    } catch (e) {
      setPreviewError(e);
    } finally {
      setBusy(false);
    }
  }, [id]);
  // StrictMode 의 이중 실행에도 제안마다 한 번만 자동 계산
  const autoFor = useRef<string | null>(null);
  useEffect(() => {
    if (!id || !draft || autoFor.current === id) return;
    autoFor.current = id;
    void runPreview();
  }, [id, draft, runPreview]);

  if (!p) {
    return (
      <Panel title="제안" testId="proposal">
        {error ? <LoadError error={error} what="제안" /> : <Empty>{loading ? '불러오는 중…' : '제안을 찾을 수 없습니다'}</Empty>}
      </Panel>
    );
  }
  const c = cases?.find((x) => x.id === p.caseId);
  const target = c ? caseLabel(c) : p.caseId;
  // 옛 백엔드(nextOnly 없음)는 제안의 패키지 · 이미지 차단으로 대신한다
  const nextOnly =
    preview?.nextOnly ?? p.changes.flatMap((x) => (x.op === 'block' && x.list !== 'hosts' ? [{ list: x.list, value: x.value }] : []));
  const act = async (kind: 'apply' | 'discard') => {
    setBusy(true);
    try {
      if (kind === 'apply') await api.applyProposal(p.id);
      else await api.discardProposal(p.id);
      toast(kind === 'apply' ? `제안 적용 — ${target} 건 종결, 변경 이력에 기록` : `제안 버림 — ${target} 건 종결(변경 없음)`, {
        key: `proposal:${p.id}`,
        tone: 'ok',
      });
      onDone();
    } catch (e) {
      toast(`${kind === 'apply' ? '적용' : '버림'} 실패: ${errorText(e)}`, { key: `proposal:${p.id}`, tone: 'danger' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      className="min-h-0"
      testId="proposal"
      title={
        <span className="flex items-center gap-2">
          제안 · <DecisionBadge decision={p.decision} /> <span className="font-mono">{target}</span>
        </span>
      }
      actions={<span className="text-xs text-slate-400">{p.state === 'draft' ? '초안' : p.state === 'applied' ? '적용됨' : '버림'}</span>}
    >
      <div className="flex h-full flex-col">
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4 text-sm">
          <section className="mb-4">
            <h3 className="mb-1.5 text-xs font-semibold text-slate-700">근거</h3>
            <p className="text-slate-600">
              {c ? (
                <>
                  {c.source === 'install' ? '설치 검사' : '런타임'} <span className="font-mono">{target}</span> · 위반 {fmtNum(c.violations)}건 ({c.ruleIds.join(', ')}) ·{' '}
                  {c.decidedBy ?? p.createdBy} 판정 {c.decidedAt ? fmtDateTime(c.decidedAt) : fmtDateTime(p.createdAt)}
                  {c.note && <> · 메모 「{c.note}」</>}{' '}
                  {c.source === 'install' && c.installId && (
                    <Link to={`/installs?status=all&id=${encodeURIComponent(c.installId)}`} className="text-indigo-600 hover:underline">
                      세션 보기
                    </Link>
                  )}
                </>
              ) : (
                <>건 {p.caseId} · {p.createdBy} · {fmtDateTime(p.createdAt)}</>
              )}
            </p>
          </section>
          <section className="mb-4">
            <h3 className="mb-1.5 text-xs font-semibold text-slate-700">변경 내용 {p.changes.length}</h3>
            {p.changes.length === 0 ? (
              <p className="text-xs text-slate-500">자동으로 만들 변경이 없습니다 — 실행 규칙은 정책을 직접 수정하세요.</p>
            ) : (
              <ul className="grid gap-1" data-testid="proposal-changes">
                {p.changes.map((x, i) => (
                  <li key={i} className="flex items-center gap-2 rounded-md bg-slate-50 px-3 py-1.5 font-mono text-xs">
                    <span className={`rounded px-1.5 py-0.5 font-sans text-[11px] ${x.op === 'block' ? 'bg-red-100 text-red-800' : 'bg-sky-100 text-sky-800'}`}>
                      {x.op === 'block' ? '차단' : '예외'}
                    </span>
                    {changeText(x)}
                  </li>
                ))}
              </ul>
            )}
            {!!p.notes?.length && (
              <ul className="mt-2 grid gap-1 text-xs text-amber-800" data-testid="proposal-notes">
                {p.notes.map((n, i) => (
                  <li key={i} className="rounded-md bg-amber-50 px-3 py-1.5">
                    {n}
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section data-testid="preview">
            <h3 className="mb-1.5 text-xs font-semibold text-slate-700">미리보기</h3>
            {previewError ? (
              <LoadError error={previewError} what="미리보기" compact />
            ) : !preview ? (
              <p className="text-xs text-slate-500">이 변경을 적용한 정책으로 저장된 감사 로그를 다시 평가해 결과가 바뀌는 위반을 보여 줍니다.</p>
            ) : (
              <div className="grid gap-2">
                <p data-testid="preview-summary">
                  감사 로그 <b className="num">{fmtNum(preview.evaluated)}</b>건 재평가 — 통과로 바뀜{' '}
                  <b className="num text-emerald-700" data-to-normal={preview.counts.toNormal}>
                    {fmtNum(preview.counts.toNormal)}
                  </b>{' '}
                  · 차단으로 바뀜{' '}
                  <b className="num text-red-700" data-to-blocked={preview.counts.toBlocked}>
                    {fmtNum(preview.counts.toBlocked)}
                  </b>
                </p>
                {preview.changed.length > 0 && (
                  <table className="w-full text-xs">
                    <thead className="text-left text-slate-500">
                      <tr>
                        <th className="py-1 font-medium">#</th>
                        <th className="py-1 font-medium">컨테이너</th>
                        <th className="py-1 font-medium">규칙</th>
                        <th className="py-1 font-medium">탐지 결과</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.changed.slice(0, 50).map((r) => (
                        <tr key={r.auditId} className="border-t border-slate-100">
                          <td className="num py-1 text-slate-400">{r.auditId}</td>
                          <td className="py-1">{r.container}</td>
                          <td className="py-1 font-mono">{r.ruleId}</td>
                          <td className="py-1">
                            {levelText(String(r.before))} → <b>{levelText(String(r.after))}</b>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {nextOnly.length > 0 && (
                  <div className="rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800" data-testid="next-only">
                    <p className="mb-1 font-medium">다음 설치 · 기동부터 적용 — 과거 이벤트는 바뀌지 않습니다</p>
                    <ul className="grid gap-0.5 font-mono">
                      {nextOnly.map((x) => (
                        <li key={`${x.list}:${x.value}`}>
                          {LIST_LABEL[x.list] ?? x.list} {x.value}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>
        <div className="flex shrink-0 items-center gap-2 border-t border-slate-100 px-5 py-3">
          {p.state === 'draft' ? (
            <>
              <button
                type="button"
                onClick={() => void runPreview()}
                disabled={busy}
                className="flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-40"
              >
                <Eye className="size-4" aria-hidden /> 미리보기
              </button>
              {!canWrite && <span className="text-xs text-amber-700">관리자 토큰을 머리 칸에 입력하세요</span>}
              <ConfirmButton
                onConfirm={() => void act('discard')}
                confirmLabel="버림 확정"
                disabled={busy || !canWrite}
                className="ml-auto rounded-md px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-100 disabled:opacity-40"
              >
                버림
              </ConfirmButton>
              <button
                type="button"
                onClick={() => void act('apply')}
                disabled={busy || !canWrite || !preview}
                title={preview ? undefined : '먼저 미리보기로 무엇이 바뀌는지 확인하세요'}
                className="rounded-md bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-40"
              >
                적용
              </button>
            </>
          ) : (
            <span className="text-xs text-slate-500" data-testid="proposal-state">
              {p.state === 'applied' ? `적용됨 · ${p.appliedBy ?? '—'} · ${p.appliedAt ? fmtDateTime(p.appliedAt) : ''}` : '버림 — 변경 없이 건 종결'}
            </span>
          )}
        </div>
      </div>
    </Panel>
  );
}
