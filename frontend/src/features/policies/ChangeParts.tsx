import { StatusPill } from '../../components/DataTable';
import type { Change } from '../../lib/types';
import { changeName, changeTone, ruleDiff } from './changeView';

// 변경 이력 공통 조각(정책 시트 「변경 이력」 탭 · 변경 이력 화면): 동작 태그 · 바뀐 값 표
export function ActionTag({ change, ruleId }: { change: Change; ruleId?: string }) {
  return (
    <StatusPill tone={changeTone(change, ruleId)} data-part="action-tag" data-kind={change.kind}>
      {changeName(change, ruleId)}
    </StatusPill>
  );
}

// 정책별 바뀐 칸 — 칸 이름 · 「이전 → 새 값」. ruleId 를 주면 그 정책만
export function ChangeDiff({ change: c, ruleId, forId }: { change: Change; ruleId?: string; forId?: string }) {
  const ids = (ruleId ? [ruleId] : (c.ruleIds ?? [])).filter((id) => c.before?.[id] || c.after?.[id]);
  return (
    <div className="grid gap-2 text-[13px]" data-part="change-diff" data-for={forId}>
      {ids.map((id) => {
        const b = c.before?.[id];
        const a = c.after?.[id];
        const rows = ruleDiff(b, a);
        return (
          <div key={id} className="grid gap-1" data-rule-diff={id}>
            {!ruleId && <b className="font-mono text-xs text-text-2">{id}</b>}
            {!b && <span className="text-xs text-text-3">새로 만든 정책</span>}
            {!a && <span className="text-xs text-text-3">지운 정책 — 지우기 전 값</span>}
            {rows.length ? (
              <dl className="grid grid-cols-[minmax(6rem,auto)_1fr] gap-x-3 gap-y-0.5">
                {rows.map((r) => (
                  <div key={r.field} className="contents" data-field={r.field}>
                    <dt className="text-text-3">{r.label}</dt>
                    <dd className="min-w-0 break-words font-mono text-xs text-text">
                      {b && a ? `${r.before} → ${r.after}` : a ? r.after : r.before}
                    </dd>
                  </div>
                ))}
              </dl>
            ) : (
              <span className="text-xs text-text-3">바뀐 칸 없음</span>
            )}
          </div>
        );
      })}
    </div>
  );
}
