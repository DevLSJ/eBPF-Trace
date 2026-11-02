import type { ChainStepView } from '../lib/chain';
import type { Kind } from '../lib/types';
import { LevelBadge } from './VerdictBadge';

// 공격 체인 — 설치 검사 시트와 토폴로지가 같은 부품을 쓴다. 1 실행 → 2 파일 → 3 통신 순서. dns 는 「3 통신」 단계(connect 와 같은 단계, 정렬은 dns 먼저 — 10/30)

const KIND_STEP: Record<Kind, string> = { exec: '1 실행', open: '2 파일', connect: '3 통신', dns: '3 통신' };
const stepTone: Record<Kind, string> = { exec: 'bg-violet-50 text-violet-700', open: 'bg-sky-50 text-sky-700', connect: 'bg-teal-50 text-teal-700', dns: 'bg-amber-50 text-amber-800' };

export function AttackChain({
  steps,
  selectedId,
  onSelect,
}: {
  steps: ChainStepView[];
  selectedId?: string | null;
  onSelect?: (id: string) => void;
}) {
  if (steps.length === 0) return <p className="text-xs text-slate-400">위반 없음</p>;
  return (
    <ol className="grid gap-1" data-testid="attack-chain">
      {steps.map((st) => {
        const body = (
          <>
            <span className={`rounded py-0.5 text-center text-[11px] font-semibold ${stepTone[st.kind]}`} data-step={st.kind}>
              {KIND_STEP[st.kind]}
            </span>
            <span className="truncate font-mono text-slate-700" title={st.label}>
              {st.label}
            </span>
            <span className="max-w-28 truncate text-slate-500" title={st.rule}>
              {st.rule ?? ''}
            </span>
            <LevelBadge level={st.level} />
          </>
        );
        const cls = `grid w-full grid-cols-[3.25rem_minmax(0,1fr)_auto_auto] items-center gap-2 rounded-md border px-2 py-1 text-left text-xs ${
          selectedId === st.id ? 'border-indigo-500 bg-indigo-50' : 'border-transparent'
        }`;
        return (
          <li key={st.id}>
            {onSelect ? (
              <button type="button" onClick={() => onSelect(st.id)} className={`${cls} hover:bg-slate-50`}>
                {body}
              </button>
            ) : (
              <div className={cls}>{body}</div>
            )}
          </li>
        );
      })}
    </ol>
  );
}
