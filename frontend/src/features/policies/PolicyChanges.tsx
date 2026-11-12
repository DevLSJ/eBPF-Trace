import { ChevronDown, ChevronRight, RotateCcw } from 'lucide-react';
import { useCallback, useState } from 'react';
import { ActionButton, IconAction } from '../../components/ActionButton';
import { TablePager } from '../../components/DataTable';
import { fmtLog } from '../../components/list/cell-format';
import { TimeText } from '../../components/list/cells';
import { EmptyState, ListError, PagerSlot, Skeleton } from '../../components/list/ListStates';
import { Modal } from '../../components/Modal';
import { useToast } from '../../hooks/toast-context';
import { useLoad } from '../../hooks/useLoad';
import { api, failText } from '../../lib/api';
import { SYSTEM_RULES, type Change, type Rule } from '../../lib/types';
import { ActionTag, ChangeDiff } from './ChangeParts';
import { changeHasDiff, ruleDiff } from './changeView';

// 정책 시트 「변경 이력」 탭(11/09): GET /api/changes?rule=<id>&offset=&limit= — 이 정책을 다룬 기록만(전후 값도 이 정책 것만).
//   줄 = 시각(초까지) · 동작 태그(끝말 색) · 처리자 · 요약 · 사유, 펼치면 바뀐 값 「이전 → 새 값」.
//   「되돌리기」는 이 탭 한 곳(변경 이력 화면에는 없음) — 그 변경 전 값(before[id])이 있을 때만 · 관리자 · 시스템 규칙 제외
export function PolicyChanges({ ruleId, current, canWrite, onReverted }: { ruleId: string; current: Rule | undefined; canWrite: boolean; onReverted: () => void }) {
  const toast = useToast();
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const [ask, setAsk] = useState<Change | null>(null);
  const load = useCallback(() => api.changesPage({ rule: ruleId, offset: (page - 1) * size, limit: size }), [ruleId, page, size]);
  const res = useLoad(load);
  const items = res.data?.items ?? [];
  const total = res.data?.total ?? 0;
  const system = SYSTEM_RULES.has(ruleId);
  const toggle = (id: string) => setOpen((s) => (s.has(id) ? new Set([...s].filter((x) => x !== id)) : new Set([...s, id])));

  const revert = async (c: Change, reason: string) => {
    try {
      await api.revertPolicy(ruleId, c.id, reason);
      toast(`정책 ${ruleId} 을(를) 되돌렸습니다.`, { key: `revert:${c.id}`, tone: 'ok' });
      setPage(1);
      res.reload();
      onReverted();
    } catch (e) {
      // 서버 오류 문장은 바꾸지 않고 그대로(괄호 없이 「되돌리지 못했습니다.」 뒤 한 문장)
      toast(failText('되돌리지 못했습니다.', e), { key: `revert-fail:${c.id}`, tone: 'danger' });
    }
  };

  if (res.error && !res.data) return <ListError error={res.error} what="변경 이력" onRetry={res.reload} />;
  if (!res.data) return <Skeleton rows={4} />;
  return (
    <div className="flex min-h-full flex-col" data-testid="policy-changes">
      {!items.length ? (
        <EmptyState what="변경 이력" hint="이 정책을 저장하거나 제안을 적용하면 여기에 남습니다." />
      ) : (
        <ul className="divide-y divide-[var(--line-soft)]">
          {items.map((c) => {
            const can = canWrite && !system && !!c.before?.[ruleId];
            const diff = changeHasDiff(c, ruleId);
            const on = open.has(c.id);
            return (
              <li key={c.id} data-change={c.id} className="grid gap-1.5 px-5 py-3 text-[13.5px]">
                <div className="flex min-w-0 items-center gap-2">
                  <TimeText value={c.at} kind="log" className="text-xs text-text-2" />
                  <ActionTag change={c} ruleId={ruleId} />
                  <span className="min-w-0 truncate text-xs text-text-3">{c.by}</span>
                  <span className="ml-auto flex shrink-0 items-center gap-1">
                    {diff && (
                      <button
                        type="button"
                        data-action="change-expand"
                        aria-expanded={on}
                        onClick={() => toggle(c.id)}
                        className="inline-flex items-center gap-1 rounded-[var(--r-sm)] px-1.5 py-1 text-xs text-text-2 hover:bg-surface-2"
                      >
                        {on ? <ChevronDown className="size-3.5" aria-hidden /> : <ChevronRight className="size-3.5" aria-hidden />} 바뀐 값
                      </button>
                    )}
                    {can && <IconAction icon={RotateCcw} label="되돌리기" target={c.id} onClick={() => setAsk(c)} />}
                  </span>
                </div>
                <p className="min-w-0 break-words text-text-2" title={c.summary}>
                  {c.summary}
                  {c.reason && (
                    <span className="text-text-3" data-reason="">
                      {' '}
                      · 사유: {c.reason}
                    </span>
                  )}
                </p>
                {on && diff && (
                  <div className="rounded-[var(--r-md)] bg-surface-2 px-3 py-2">
                    <ChangeDiff change={c} ruleId={ruleId} />
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {total > 0 && (
        <div className="mt-auto">
          <PagerSlot>
            <TablePager name="policy-changes" total={total} from={(page - 1) * size + 1} to={(page - 1) * size + items.length} page={page} size={size} onPage={setPage} onSize={(n) => (setSize(n), setPage(1))} />
          </PagerSlot>
        </div>
      )}
      {ask && (
        <RevertDialog
          ruleId={ruleId}
          change={ask}
          current={current}
          onCancel={() => setAsk(null)}
          onConfirm={(reason) => {
            const c = ask;
            setAsk(null);
            void revert(c, reason);
          }}
        />
      )}
    </div>
  );
}

// 되돌리기 확인 창(11/09 SPEC-1109 §7): 제목 「~할까요?」 · 본문 · 영향 범위(바뀌는 칸마다 「지금 → 되돌린 뒤」) · 사유(필수) · 확인 체크.
// 공통 ConfirmDialog 는 사유가 선택이라(필수 칸 없음) 같은 모양으로 여기서 만든다 — data-part 이름은 공통 확인 창과 같다
function RevertDialog({ ruleId, change, current, onCancel, onConfirm }: { ruleId: string; change: Change; current: Rule | undefined; onCancel: () => void; onConfirm: (reason: string) => void }) {
  const [text, setText] = useState('');
  const [checked, setChecked] = useState(false);
  const restored = change.before?.[ruleId];
  const rows = ruleDiff(current, restored);
  const impact = !current ? ['지금 없는 정책을 그 변경 전 값으로 다시 만듭니다.'] : rows.map((r) => `${r.label}: ${r.before} → ${r.after}`);
  const blocked = current && !rows.length ? '이미 그 변경 전 값과 같습니다' : null;
  const off = blocked || (!text.trim() ? '사유를 입력하세요' : !checked ? '확인 칸을 먼저 고르세요' : null);
  return (
    <Modal
      title={`정책 ${ruleId} 을(를) 되돌릴까요?`}
      kind="confirm"
      wide
      onClose={onCancel}
      guard={() => text.trim() !== ''}
      foot={
        <>
          <button type="button" data-confirm="cancel" onClick={onCancel} className="sg-btn text-text-2 hover:bg-surface-3">
            취소
          </button>
          <ActionButton data-confirm="ok" reason={off} onClick={() => onConfirm(text.trim())} className="sg-btn sg-btn-primary">
            되돌리기
          </ActionButton>
        </>
      }
    >
      <p className="text-sm text-text-2" data-part="confirm-body">
        {fmtLog(change.at)} 변경 이전 값으로 정책 전체를 되돌립니다. 되돌리면 엔진에 바로 적용되고 변경 이력에 「정책 되돌림」으로 남습니다.
      </p>
      {blocked && (
        <p role="alert" className="rounded-[var(--r-sm)] bg-danger-soft px-3 py-2 text-sm text-danger-text" data-part="confirm-blocked">
          {blocked}.
        </p>
      )}
      {!!impact.length && (
        <div className="text-sm">
          <div className="font-medium">영향 범위</div>
          <ul className="mt-1 grid max-h-[168px] list-disc gap-0.5 overflow-y-auto pl-5" data-part="confirm-impact">
            {impact.map((x) => (
              <li key={x} className="text-text-2">
                {x}
              </li>
            ))}
          </ul>
        </div>
      )}
      <label className="grid gap-1 text-sm">
        <span>
          <b>사유</b>{' '}
          <span aria-hidden className="text-danger-text">
            *
          </span>{' '}
          <small className="text-text-3">변경 이력에 남습니다 (500자까지)</small>
        </span>
        <textarea
          name="reason"
          aria-label="사유"
          aria-required="true"
          rows={2}
          maxLength={500}
          value={text}
          placeholder="예: 경고로 낮춘 뒤 놓친 위반이 생김"
          onChange={(e) => setText(e.target.value)}
          className="rounded-[var(--r-md)] border border-[var(--field-line)] bg-field px-2 py-1.5 text-sm"
        />
      </label>
      {!blocked && (
        <label className="flex items-center gap-2 text-sm" data-part="confirm-check">
          <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} />
          <span>되돌리면 엔진에 바로 적용됨을 확인했습니다</span>
        </label>
      )}
    </Modal>
  );
}
