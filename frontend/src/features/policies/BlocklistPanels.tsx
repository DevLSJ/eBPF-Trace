import { useState } from 'react';
import { ConfirmDialog } from '../../components/Modal';
import { LoadError, Panel } from '../../components/Panel';
import { useToast } from '../../hooks/toast-context';
import { api, errorText } from '../../lib/api';
import { fmtDateTime } from '../../lib/format';
import { CHANGE_KIND_LABEL, type Blocklist, type BlockList, type Change } from '../../lib/types';

const LISTS: { key: BlockList; label: string }[] = [
  { key: 'packages', label: '패키지' },
  { key: 'images', label: '이미지' },
  { key: 'hosts', label: '도메인' },
];

// 해제 확인 대화상자의 「함께 일어나는 일」(10/20 B)
const UNBLOCK_EFFECTS: Record<BlockList, (v: string) => string> = {
  packages: (v) => `다음 설치부터 ${v} 를 다시 설치할 수 있습니다(설치 검사는 그대로 감시)`,
  images: (v) => `이미지 ${v} 로 시작하는 컨테이너가 다음 재기동부터 다시 뜹니다`,
  hosts: (v) => `시스템 규칙 blocklist-hosts 에서 ${v} 를 빼 바로 통신을 허용합니다`,
};

// 차단 목록 — 악성 확정으로 막은 대상. 패키지는 sg-install 이 설치 전에, 이미지는 기동 시, 도메인은 blocklist-hosts 규칙이 막는다.
export function BlocklistPanel({ data, error, canWrite, onChanged }: { data: Blocklist | undefined; error: unknown; canWrite: boolean; onChanged: () => void }) {
  const toast = useToast();
  const [ask, setAsk] = useState<{ list: BlockList; label: string; value: string } | null>(null);
  const total = data ? LISTS.reduce((n, l) => n + (data[l.key]?.length ?? 0), 0) : 0;
  const unblock = async (list: BlockList, value: string, reason: string) => {
    try {
      await api.unblock(list, value, reason);
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
        <ul data-fill="" className="h-full overflow-y-auto px-4 py-2 text-xs">
          {LISTS.flatMap((l) =>
            (data?.[l.key] ?? []).map((e) => (
              <li key={`${l.key}:${e.value}`} className="flex items-center gap-2 border-b border-slate-100 py-1.5 last:border-b-0" data-block={`${l.key}:${e.value}`}>
                <span className="w-12 shrink-0 text-slate-500">{l.label}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-slate-800" title={`${e.by} · ${fmtDateTime(e.at)}`}>
                  {e.value}
                </span>
                {canWrite && (
                  <button
                    type="button"
                    onClick={() => setAsk({ list: l.key, label: l.label, value: e.value })}
                    className="shrink-0 rounded px-1.5 py-0.5 text-slate-500 hover:bg-red-50 hover:text-red-700"
                  >
                    해제
                  </button>
                )}
              </li>
            )),
          )}
        </ul>
      )}
      {ask && (
        <ConfirmDialog
          title="차단 해제"
          target={`${ask.label} ${ask.value}`}
          okLabel="해제"
          reason
          effects={[UNBLOCK_EFFECTS[ask.list](ask.value), '변경 이력에 「차단 해제」로 남습니다']}
          undo="다시 막으려면 설치 검사 · 토폴로지에서 악성 판정하거나 공급망 검사에서 차단 목록에 올리세요"
          onCancel={() => setAsk(null)}
          onConfirm={(reason) => {
            const a = ask;
            setAsk(null);
            void unblock(a.list, a.value, reason);
          }}
        />
      )}
    </Panel>
  );
}

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
        <ul data-fill="" className="h-full overflow-y-auto px-4 py-2 text-xs">
          {data.map((c) => (
            <li key={c.id} className="border-b border-slate-100 py-1.5 last:border-b-0" data-change={c.id}>
              <div className="flex items-center gap-2">
                <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-600">{CHANGE_KIND_LABEL[c.kind] ?? c.kind}</span>
                <span className="num text-slate-400">{fmtDateTime(c.at)}</span>
                <span className="ml-auto text-slate-500">{c.by}</span>
              </div>
              <div className="mt-0.5 truncate text-slate-700" title={c.summary}>
                {c.summary}
              </div>
              {c.reason && (
                <div className="mt-0.5 truncate text-slate-500" title={c.reason} data-reason="">
                  사유: {c.reason}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
