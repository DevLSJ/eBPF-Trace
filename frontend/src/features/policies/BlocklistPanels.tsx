import { ConfirmButton } from '../../components/ConfirmButton';
import { LoadError, Panel } from '../../components/Panel';
import { useToast } from '../../hooks/toast-context';
import { api, errorText } from '../../lib/api';
import { fmtDateTime } from '../../lib/format';
import type { Blocklist, BlockList, Change } from '../../lib/types';

const LISTS: { key: BlockList; label: string }[] = [
  { key: 'packages', label: '패키지' },
  { key: 'images', label: '이미지' },
  { key: 'hosts', label: '도메인' },
];

// 차단 목록 — 악성 확정으로 막은 대상. 패키지는 sg-install 이 설치 전에, 이미지는 기동 시, 도메인은 blocklist-hosts 규칙이 막는다.
export function BlocklistPanel({ data, error, canWrite, onChanged }: { data: Blocklist | undefined; error: unknown; canWrite: boolean; onChanged: () => void }) {
  const toast = useToast();
  const total = data ? LISTS.reduce((n, l) => n + (data[l.key]?.length ?? 0), 0) : 0;
  const unblock = async (list: BlockList, value: string) => {
    try {
      await api.unblock(list, value);
      toast(`차단 해제 — ${value}`, { key: `unblock:${value}`, tone: 'ok' });
      onChanged();
    } catch (e) {
      toast(`차단 해제 실패: ${errorText(e)}`, { key: `unblock:${value}`, tone: 'danger' });
    }
  };
  return (
    <Panel
      testId="blocklist"
      title={
        <span>
          차단 목록 <span className="num ml-1 font-normal text-slate-400">{data ? total : ''}</span>
        </span>
      }
    >
      {error && !data ? (
        <LoadError error={error} what="차단 목록" compact />
      ) : total === 0 ? (
        <p className="px-4 py-3 text-xs text-slate-400">{data ? '차단한 패키지 · 이미지 · 도메인 없음' : '불러오는 중…'}</p>
      ) : (
        <ul className="h-full overflow-y-auto px-4 py-2 text-xs">
          {LISTS.flatMap((l) =>
            (data?.[l.key] ?? []).map((e) => (
              <li key={`${l.key}:${e.value}`} className="flex items-center gap-2 border-b border-slate-100 py-1.5 last:border-b-0" data-block={`${l.key}:${e.value}`}>
                <span className="w-12 shrink-0 text-slate-500">{l.label}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-slate-800" title={`${e.by} · ${fmtDateTime(e.at)}`}>
                  {e.value}
                </span>
                <ConfirmButton
                  onConfirm={() => void unblock(l.key, e.value)}
                  confirmLabel="해제 확정"
                  disabled={!canWrite}
                  className="shrink-0 rounded px-1.5 py-0.5 text-slate-500 hover:bg-slate-100 disabled:opacity-40"
                >
                  해제
                </ConfirmButton>
              </li>
            )),
          )}
        </ul>
      )}
    </Panel>
  );
}

const KIND_LABEL: Record<string, string> = {
  proposal_applied: '제안 적용',
  policy_edit: '정책 편집',
  policy_replace: 'YAML 교체',
  blocklist_remove: '차단 해제',
};

// 변경 이력 — 누가 · 언제 · 어느 판정에서
export function ChangesPanel({ data, error }: { data: Change[] | undefined; error: unknown }) {
  return (
    <Panel
      testId="changes"
      title={
        <span>
          변경 이력 <span className="num ml-1 font-normal text-slate-400">{data ? data.length : ''}</span>
        </span>
      }
    >
      {error && !data ? (
        <LoadError error={error} what="변경 이력" compact />
      ) : !data?.length ? (
        <p className="px-4 py-3 text-xs text-slate-400">{data ? '변경 기록 없음' : '불러오는 중…'}</p>
      ) : (
        <ul className="h-full overflow-y-auto px-4 py-2 text-xs">
          {data.map((c) => (
            <li key={c.id} className="border-b border-slate-100 py-1.5 last:border-b-0" data-change={c.id}>
              <div className="flex items-center gap-2">
                <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-600">{KIND_LABEL[c.kind] ?? c.kind}</span>
                <span className="num text-slate-400">{fmtDateTime(c.at)}</span>
                <span className="ml-auto text-slate-500">{c.by}</span>
              </div>
              <div className="mt-0.5 truncate text-slate-700" title={c.summary}>
                {c.summary}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
