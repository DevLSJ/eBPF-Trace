import { Link } from 'react-router-dom';
import { useState } from 'react';
import { useCases } from '../hooks/cases-context';
import { useStream } from '../hooks/stream-context';
import { useToast } from '../hooks/toast-context';
import { useAdminToken } from '../hooks/useLoad';
import { api, ApiError, errorText } from '../lib/api';
import { fmtDateTime } from '../lib/format';
import { caseLabel, type Case, type Decision } from '../lib/types';
import { DecisionBadge } from './Badges';

const STATE_LABEL: Record<Case['state'], string> = { open: '판정 대기', decided: '판정됨 · 제안 적용 대기', closed: '종결' };

// 판정 — 설치 검사 시트와 토폴로지가 같은 부품을 쓴다.
// 악성 확정 → 차단 제안(설치: 패키지 · 도메인 / 런타임: 이미지 · 도메인), 오탐 → 걸린 규칙에 예외 제안.
export function DecisionBox({ caseId }: { caseId: string | null | undefined }) {
  const { cases, error, upsert, reload } = useCases();
  const { info } = useStream();
  const [token] = useAdminToken();
  const toast = useToast();
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);

  if (!caseId) return <p className="text-xs text-slate-500">판정할 건이 없습니다 (격리 · 경고가 아님).</p>;
  const c = cases?.find((x) => x.id === caseId);
  if (!c) {
    if (error) return <p className="text-xs text-slate-500">건 정보를 불러오지 못했습니다{' '}<span className="text-slate-400">({errorText(error)})</span></p>;
    return <p className="text-xs text-slate-400">건 정보를 불러오는 중…</p>;
  }

  const canWrite = !info?.authRequired || token !== '';
  const what = caseLabel(c);
  const decide = async (d: Exclude<Decision, 'pending'>) => {
    setBusy(true);
    try {
      const r = await api.decide(c.id, d, note.trim());
      upsert(r.case);
      toast(
        d === 'malicious' ? `${what} 악성 확정 — 차단 제안을 만들었습니다` : `${what} 오탐 — 예외 제안을 만들었습니다`,
        {
          key: `decide:${c.id}`,
          tone: 'ok',
          action: r.proposal ? { label: '제안 보기', to: `/policies?proposal=${encodeURIComponent(r.proposal.id)}` } : undefined,
        },
      );
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) reload();
      toast(`판정 실패: ${errorText(e)}`, { key: `decide:${c.id}`, tone: 'danger' });
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
      {c.decision === 'pending' ? (
        <>
          <label className="flex items-center gap-2 text-xs text-slate-600">
            <span className="shrink-0">메모 (선택)</span>
            <input
              className="h-8 min-w-0 flex-1 rounded-md border border-slate-300 px-2 text-sm focus:border-indigo-500 focus:outline-none"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="판단 근거"
            />
          </label>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={busy || !canWrite}
              onClick={() => void decide('malicious')}
              className="flex-1 rounded-md bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-40"
            >
              악성 확정
            </button>
            <button
              type="button"
              disabled={busy || !canWrite}
              onClick={() => void decide('false_positive')}
              className="flex-1 rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-40"
            >
              오탐
            </button>
          </div>
          {/* 토큰이 없으면 안내 한 줄만 — 아래 고정 칸이 길어져 시트 본문을 가리지 않게 (10/16 sg-vm 실측) */}
          {canWrite && (
            <p className="text-xs text-slate-500">
              악성 확정 → {c.source === 'install' ? '패키지' : '이미지'} · 도메인 차단 제안 / 오탐 → 걸린 규칙에 예외 제안 (정책에서 미리보기 후 적용)
            </p>
          )}
          {!canWrite && (
            <p className="text-xs text-amber-700">
              관리자 토큰이 필요합니다 — <Link to="/policies" className="underline">정책</Link> 화면 머리에 입력하세요.
            </p>
          )}
        </>
      ) : (
        <dl className="grid grid-cols-[3.5rem_1fr] gap-x-2 gap-y-1 text-xs">
          <dt className="text-slate-500">처리자</dt>
          <dd data-testid="decided-by">{c.decidedBy ?? '—'}</dd>
          <dt className="text-slate-500">시각</dt>
          <dd className="num">{c.decidedAt ? fmtDateTime(c.decidedAt) : '—'}</dd>
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
