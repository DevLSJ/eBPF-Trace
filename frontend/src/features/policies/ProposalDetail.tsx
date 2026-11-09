import { Eye } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { DecisionBadge } from '../../components/Badges';
import { ConfirmDialog } from '../../components/Modal';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { useCases } from '../../hooks/cases-context';
import { useToast } from '../../hooks/toast-context';
import { api, errorText } from '../../lib/api';
import { fmtDateTime, fmtNum } from '../../lib/format';
import { scanHref, SOURCE_LABEL } from '../../lib/guide';
import { installDest } from '../../lib/nav';
import { applyEffects, changeText, LIST_LABEL } from '../../lib/proposal';
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
  bare,
}: {
  proposal: Proposal | undefined;
  loading: boolean;
  error: unknown;
  canWrite: boolean;
  onDone: () => void;
  // 11/09: 시트 안(제목은 시트 머리) — 테두리 있는 칸 없이
  bare?: boolean;
}) {
  const { cases } = useCases();
  const toast = useToast();
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewError, setPreviewError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  // 적용 · 버림은 확인 대화상자(10/20 B) — 사유는 변경 이력 reason
  const [ask, setAsk] = useState<'apply' | 'discard' | null>(null);

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
    const body = error ? <LoadError error={error} what="제안" /> : <Empty>{loading ? '불러오는 중…' : '제안을 찾을 수 없습니다'}</Empty>;
    return bare ? (
      <div data-testid="proposal" className="h-full">
        {body}
      </div>
    ) : (
      <Panel title="제안" testId="proposal">
        {body}
      </Panel>
    );
  }
  const c = cases?.find((x) => x.id === p.caseId);
  const target = c ? caseLabel(c) : p.caseId;
  // 옛 백엔드(nextOnly 없음)는 제안의 패키지 · 이미지 차단으로 대신한다
  const nextOnly =
    preview?.nextOnly ?? p.changes.flatMap((x) => (x.op === 'block' && x.list !== 'hosts' ? [{ list: x.list, value: x.value }] : []));
  const act = async (kind: 'apply' | 'discard', reason: string) => {
    setBusy(true);
    try {
      if (kind === 'apply') await api.applyProposal(p.id, reason);
      else await api.discardProposal(p.id, reason);
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

  const inner = (
    <>
      <div className="flex h-full flex-col">
        <div data-fill="" className="min-h-0 flex-1 overflow-y-auto px-5 py-4 text-sm">
          <section className="mb-4">
            <h3 className="mb-1.5 text-xs font-semibold text-slate-700">근거</h3>
            <p className="text-slate-600">
              {c ? (
                <>
                  {SOURCE_LABEL[c.source] ?? c.source} <span className="font-mono">{target}</span> · 위반 {fmtNum(c.violations)}건 ({c.ruleIds.join(', ')}) ·{' '}
                  {c.decidedBy ?? p.createdBy} 판정 {c.decidedAt ? fmtDateTime(c.decidedAt) : fmtDateTime(p.createdAt)}
                  {c.note && <> · 메모 「{c.note}」</>}{' '}
                  {c.source === 'install' && c.installId && (
                    <Link {...installDest(c.installId)} className="text-indigo-600 hover:underline">
                      세션 보기
                    </Link>
                  )}
                  {scanHref(c) && (
                    <Link to={scanHref(c)!} className="text-indigo-600 hover:underline">
                      검사 결과 보기
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
                    <span className={`rounded px-1.5 py-0.5 font-sans text-xs ${x.op === 'block' ? 'bg-red-100 text-red-800' : 'bg-sky-100 text-sky-800'}`}>
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
                  <table className="sg-table">
                    <thead>
                      <tr>
                        <th className="tk-short">#</th>
                        <th>컨테이너</th>
                        <th>규칙</th>
                        <th>탐지 결과</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.changed.slice(0, 50).map((r) => (
                        <tr key={r.auditId}>
                          <td className="num tk-short text-slate-400">{r.auditId}</td>
                          <td>{r.container}</td>
                          <td className="font-mono">{r.ruleId}</td>
                          <td>
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
                className="sg-btn sg-btn-secondary"
              >
                <Eye className="size-4" aria-hidden /> 미리보기
              </button>
              {/* 조회자는 적용 · 버림을 그리지 않는다(W16) — 미리보기는 조회자도 */}
              {canWrite && (
                <button
                  type="button"
                  onClick={() => setAsk('discard')}
                  disabled={busy}
                  className="sg-btn ml-auto text-text-2 hover:bg-surface-2"
                >
                  버림
                </button>
              )}
              {canWrite && <button
                type="button"
                onClick={() => setAsk('apply')}
                disabled={busy || !preview}
                title={preview ? undefined : '먼저 미리보기로 무엇이 바뀌는지 확인하세요'}
                className="sg-btn sg-btn-primary"
              >
                적용
              </button>}
              {!canWrite && <span className="ml-auto text-xs text-slate-500">적용 · 버림은 관리자만 합니다</span>}
            </>
          ) : (
            <span className="text-xs text-slate-500" data-testid="proposal-state">
              {p.state === 'applied' ? `적용됨 · ${p.appliedBy ?? '—'} · ${p.appliedAt ? fmtDateTime(p.appliedAt) : ''}` : '버림 — 변경 없이 건 종결'}
            </span>
          )}
        </div>
      </div>
      {ask && (
        <ConfirmDialog
          key={ask}
          title={ask === 'apply' ? '제안 적용' : '제안 버림'}
          target={`${target} · 제안 ${p.id}`}
          tone={ask === 'apply' ? 'primary' : 'danger'}
          okLabel={ask === 'apply' ? '적용' : '버림'}
          reason
          effects={
            ask === 'apply'
              ? applyEffects(p, preview)
              : ['정책 · 차단 목록은 바뀌지 않습니다', `건 ${p.caseId} 은 판정(${p.decision === 'malicious' ? '악성' : '오탐'})만 남기고 종결`, '판정 · 변경 이력에 「제안 버림」으로 남습니다']
          }
          undo={
            ask === 'apply'
              ? p.decision === 'malicious'
                ? '정책 › 차단 목록에서 「해제」하면 다음 설치 · 기동부터 풀립니다'
                : '정책 편집에서 더한 예외 값을 지우고 저장하면 됩니다'
              : '버린 제안은 되살리지 않습니다 — 같은 대상이 다시 걸리면 새 건으로 판정합니다'
          }
          onCancel={() => setAsk(null)}
          onConfirm={(reason) => {
            const k = ask;
            setAsk(null);
            void act(k, reason);
          }}
        />
      )}
    </>
  );
  if (bare)
    return (
      <div data-testid="proposal" className="flex h-full min-h-0 flex-col">
        <header className="flex shrink-0 items-center gap-2 border-b border-border px-5 py-2.5 text-sm">
          <DecisionBadge decision={p.decision} /> <span className="min-w-0 truncate font-mono text-text">{target}</span>
          <span className="ml-auto shrink-0 text-xs text-text-3" data-part="proposal-badge">
            {p.state === 'draft' ? '적용 대기' : p.state === 'applied' ? '적용됨' : '버림'}
          </span>
        </header>
        {inner}
      </div>
    );
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
      {inner}
    </Panel>
  );
}
