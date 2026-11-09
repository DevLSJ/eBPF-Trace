import { Link } from 'react-router-dom';
import { useState } from 'react';
import { useCases } from '../hooks/cases-context';
import { useToast } from '../hooks/toast-context';
import { useAuth } from '../hooks/auth-context';
import { api, ApiError, errorText } from '../lib/api';
import { FIELD } from '../lib/fieldNames';
import { fmtDateTime } from '../lib/format';
import { caseLabel, type Case, type Decision } from '../lib/types';
import { DecisionBadge } from './Badges';
import { ConfirmDialog } from './Modal';

const STATE_LABEL: Record<Case['state'], string> = { open: '판정 대기', decided: '판정됨 · 제안 적용 대기', closed: '종결' };

// 판정 — 설치 검사 시트와 토폴로지가 같은 부품을 쓴다.
// 악성 확정 → 차단 제안(설치: 패키지 · 도메인 / 런타임: 이미지 · 도메인), 오탐 → 걸린 규칙에 예외 제안.
// 10/20 B: 두 버튼은 확인 대화상자를 연다 — 영향 범위는 서버 판정 미리보기(POST /api/cases/{id}/preview)의 effects 그대로, 사유 = 판정 메모(note)
// 11/09 G19 · G20: 확인 창 제목 「[대상] 건을 ~할까요?」 + 본문 + 영향 범위 줄, 실패 알림 「판정하지 못했습니다(사유).」 + 할 일
export function DecisionBox({ caseId }: { caseId: string | null | undefined }) {
  const { cases, error, upsert, reload } = useCases();
  const { isAdmin } = useAuth();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [ask, setAsk] = useState<Exclude<Decision, 'pending'> | null>(null);

  if (!caseId) return <p className="text-xs text-slate-500">판정할 건이 없습니다 (격리 · 경고가 아님).</p>;
  const c = cases?.find((x) => x.id === caseId);
  if (!c) {
    if (error) return <p className="text-xs text-slate-500">건 정보를 불러오지 못했습니다{' '}<span className="text-slate-400">({errorText(error)})</span></p>;
    return <p className="text-xs text-slate-400">건 정보를 불러오는 중…</p>;
  }

  const canWrite = isAdmin; // 조회자는 판정 버튼을 그리지 않는다(W16)
  const what = caseLabel(c);
  const decide = async (d: Exclude<Decision, 'pending'>, note: string) => {
    setBusy(true);
    try {
      const r = await api.decide(c.id, d, note);
      upsert(r.case);
      toast(
        d === 'malicious' ? `${what} 악성 확정, 차단 제안을 만들었습니다.` : `${what} 오탐, 예외 제안을 만들었습니다.`,
        {
          key: `decide:${c.id}`,
          tone: 'ok',
          action: r.proposal ? { label: '제안 보기', to: `/policies?proposal=${encodeURIComponent(r.proposal.id)}` } : undefined,
        },
      );
    } catch (e) {
      const conflict = e instanceof ApiError && e.status === 409;
      if (conflict) reload();
      toast(`판정하지 못했습니다(${errorText(e)}). ${conflict ? '건 상태를 다시 불러왔으니 판정 결과를 확인하세요.' : '잠시 뒤 다시 시도하세요.'}`, { key: `decide:${c.id}`, tone: 'danger' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-2 text-sm" data-testid="decision" data-state={c.state}>
      {c.decision !== 'pending' && (
        <div className="flex items-center gap-2">
          <DecisionBadge decision={c.decision} />
          <span className="text-xs text-slate-500">{STATE_LABEL[c.state]}</span>
        </div>
      )}
      {c.decision === 'pending' && !canWrite ? (
        <p className="text-xs text-slate-500">[판정 대기] 판정은 관리자가 합니다(지금 계정은 조회자).</p>
      ) : c.decision === 'pending' ? (
        <>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={() => setAsk('malicious')}
              className="sg-btn sg-btn-danger flex-1"
            >
              악성 확정
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => setAsk('false_positive')}
              className="sg-btn sg-btn-secondary flex-1"
            >
              오탐
            </button>
          </div>
          <p className="text-xs text-slate-500">
            악성 확정 → {c.source === 'install' ? '패키지' : '이미지'} · 도메인 차단 제안 / 오탐 → 걸린 규칙에 예외 제안 (정책에서 미리보기 후 적용)
          </p>
          {ask && (
            <ConfirmDialog
              key={ask}
              title={`${what} 건을 ${ask === 'malicious' ? '악성으로 확정' : '오탐으로 판정'}할까요?`}
              body={
                ask === 'malicious'
                  ? `건 ${c.id}에 「악성」 판정을 남기고 ${c.source === 'install' ? '패키지' : '이미지'} · 도메인 차단 제안을 만듭니다.`
                  : `건 ${c.id}에 「오탐」 판정을 남기고 걸린 규칙에 예외 제안을 만듭니다.`
              }
              loadEffects={() => api.previewDecision(c.id, ask).then((r) => r.effects ?? [])}
              danger={ask === 'malicious'}
              confirmLabel={ask === 'malicious' ? '악성 확정' : '오탐으로 판정'}
              reason
              undo={
                ask === 'malicious'
                  ? '판정은 이력에 남습니다. 정책 화면에서 제안을 「버림」하면 차단 없이 건만 종결됩니다'
                  : '정책 화면에서 제안을 「버림」하면 예외 없이 건만 종결됩니다'
              }
              onCancel={() => setAsk(null)}
              onConfirm={(note) => {
                const d = ask;
                setAsk(null);
                void decide(d, note);
              }}
            />
          )}
        </>
      ) : (
        <dl className="grid grid-cols-[3.5rem_1fr] gap-x-2 gap-y-1 text-xs">
          <dt className="text-slate-500">{FIELD.by}</dt>
          <dd data-testid="decided-by">{c.decidedBy ?? ''}</dd>
          <dt className="text-slate-500">시각</dt>
          <dd className="num">{c.decidedAt ? fmtDateTime(c.decidedAt) : ''}</dd>
          {c.note && (
            <>
              <dt className="text-slate-500">메모</dt>
              <dd>{c.note}</dd>
            </>
          )}
          {c.proposalId && (
            <>
              <dt className="text-slate-500">제안</dt>
              <dd>
                <Link to={`/policies?proposal=${encodeURIComponent(c.proposalId)}`} className="text-indigo-600 hover:underline">
                  {c.state === 'closed' ? '적용 결과 보기' : '정책에서 미리보기 · 적용'} →
                </Link>
              </dd>
            </>
          )}
        </dl>
      )}
    </div>
  );
}
