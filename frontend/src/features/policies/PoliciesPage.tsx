import { FileCode, KeyRound, Plus } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ConfirmButton } from '../../components/ConfirmButton';
import { KindBadge } from '../../components/KindBadge';
import { Empty, Panel } from '../../components/Panel';
import { PolicyEditor } from '../../components/PolicyEditor';
import { useStream } from '../../hooks/stream-context';
import { adminToken, api, ApiError } from '../../lib/api';
import type { Rule } from '../../lib/types';

const NEW = '__new__';
const BULK = '__yaml__';
const blank: Rule = { id: '', kind: 'open', action: 'alert' };

export function PoliciesPage() {
  const { info } = useStream();
  const [params, setParams] = useSearchParams();
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [loadError, setLoadError] = useState('');
  const [token, setToken] = useState(adminToken.get);
  const selected = params.get('id') ?? '';

  const select = (id: string) => setParams(id ? { id } : {}, { replace: true });

  const load = useCallback(() => {
    api
      .listRules()
      .then((rs) => {
        setRules(rs);
        setLoadError('');
      })
      .catch((e: Error) => setLoadError(e.message));
  }, []);
  useEffect(load, [load]);

  const canWrite = !info?.authRequired || token !== '';
  const current = rules?.find((r) => r.id === selected);

  return (
    <div className="flex h-full min-h-[560px] gap-4">
      <Panel
        className="w-80 shrink-0"
        title={`정책 ${rules ? rules.length : ''}`}
        actions={
          <div className="flex gap-1">
            <button
              type="button"
              onClick={() => select(BULK)}
              className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-600 hover:bg-slate-100"
              title="전체 정책을 YAML로 보기·일괄 적용"
            >
              <FileCode className="size-3.5" aria-hidden /> YAML
            </button>
            <button
              type="button"
              onClick={() => select(NEW)}
              className="flex items-center gap-1 rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700"
            >
              <Plus className="size-3.5" aria-hidden /> 새 정책
            </button>
          </div>
        }
      >
        <div className="flex h-full flex-col">
          {loadError && <p className="p-4 text-sm text-red-600">불러오기 실패: {loadError}</p>}
          {rules?.length === 0 && <Empty>정책 없음</Empty>}
          <ul className="min-h-0 flex-1 overflow-y-auto">
            {rules?.map((r) => (
              <li key={r.id}>
                <button
                  type="button"
                  onClick={() => select(r.id)}
                  className={`flex w-full items-center gap-2.5 border-b border-slate-100 px-4 py-2.5 text-left text-sm hover:bg-slate-50 ${
                    r.id === selected ? 'bg-indigo-50' : ''
                  }`}
                >
                  <span
                    className={`size-2 shrink-0 rounded-full ${r.disabled ? 'border border-slate-400' : 'bg-emerald-500'}`}
                    title={r.disabled ? '비활성' : '활성'}
                  />
                  <span className={`min-w-0 flex-1 truncate font-medium ${r.disabled ? 'text-slate-400' : 'text-slate-800'}`}>{r.id}</span>
                  <span
                    className={`rounded px-1.5 py-0.5 text-xs font-medium ${
                      r.action === 'kill' && !r.dryRun ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-800'
                    }`}
                  >
                    {r.action}
                    {r.dryRun && ' · dry'}
                  </span>
                  <KindBadge kind={r.kind} />
                </button>
              </li>
            ))}
          </ul>
          {info?.authRequired && (
            <label className="flex shrink-0 items-center gap-2 border-t border-slate-100 px-4 py-3 text-xs text-slate-500">
              <KeyRound className="size-4 shrink-0" aria-hidden />
              <input
                type="password"
                autoComplete="off"
                placeholder="관리자 토큰 (변경 시 필요)"
                className="h-7 min-w-0 flex-1 rounded border border-slate-300 px-2 text-xs"
                value={token}
                onChange={(e) => {
                  setToken(e.target.value);
                  adminToken.set(e.target.value);
                }}
              />
            </label>
          )}
        </div>
      </Panel>

      <Panel
        className="min-w-0 flex-1"
        title={selected === NEW ? '새 정책' : selected === BULK ? '전체 정책 YAML' : current ? `정책 편집 · ${current.id}` : '정책 편집'}
      >
        {selected === BULK ? (
          <BulkYaml canWrite={canWrite} onApplied={setRules} />
        ) : selected === NEW || current ? (
          <PolicyEditor
            key={selected}
            rule={current ?? blank}
            isNew={selected === NEW}
            canWrite={canWrite}
            onSaved={(r) => {
              load();
              select(r.id);
            }}
            onDeleted={() => {
              load();
              select('');
            }}
          />
        ) : (
          <Empty>왼쪽에서 정책을 고르거나 새 정책을 만드세요</Empty>
        )}
      </Panel>
    </div>
  );
}

// 전체 교체: PUT /api/policies (YAML 원클릭 적용)
function BulkYaml({ canWrite, onApplied }: { canWrite: boolean; onApplied: (rs: Rule[]) => void }) {
  const [text, setText] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .exportYaml()
      .then(setText)
      .catch((e: Error) => setMsg({ ok: false, text: e.message }));
  }, []);

  const apply = async () => {
    if (text === null) return;
    setBusy(true);
    try {
      const rs = await api.applyYaml(text);
      onApplied(rs);
      setMsg({ ok: true, text: `${rs.length}개 정책을 엔진에 적용함` });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof ApiError ? `${e.status} · ${e.message}` : (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="min-h-0 flex-1 p-4">
        <textarea
          className="h-full w-full rounded-md border border-slate-300 p-3 font-mono text-xs leading-relaxed focus:border-indigo-500 focus:outline-none"
          value={text ?? '불러오는 중…'}
          disabled={text === null}
          spellCheck={false}
          onChange={(e) => setText(e.target.value)}
          aria-label="전체 정책 YAML"
        />
      </div>
      <div className="flex shrink-0 items-center gap-3 border-t border-slate-100 px-5 py-3">
        {msg && <span className={`min-w-0 flex-1 truncate text-sm ${msg.ok ? 'text-emerald-600' : 'text-red-600'}`}>{msg.text}</span>}
        <ConfirmButton
          onConfirm={apply}
          confirmLabel="기존 정책을 모두 교체 — 확정"
          disabled={busy || !canWrite || text === null}
          className="ml-auto rounded-md bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-40"
        >
          전체 교체 후 적용 ▶
        </ConfirmButton>
      </div>
    </div>
  );
}
