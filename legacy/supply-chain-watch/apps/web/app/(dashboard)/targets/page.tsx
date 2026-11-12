'use client';
import { useEffect, useRef, useState } from 'react';
import type { WsEnvelope } from '@scw/shared-types';
import { useWebSocket } from '@/lib/ws';
import { cn } from '@/lib/utils';
import {
  MODE_LABEL,
  deleteRepo,
  inspectRepo,
  listRepos,
  looksLikeRepo,
  registerRepo,
  repoStatusView,
  setRepoPaused,
  splitRepoInputs,
  type Repo,
  type RepoMode,
  type RepoPreview,
} from '@/lib/repos';

const TONE: Record<string, string> = {
  good: 'bg-good-soft text-good-ink',
  warn: 'bg-warn-soft text-warn-ink',
  crit: 'bg-crit-soft text-crit-ink',
  muted: 'bg-surface-2 text-fg-2',
};

function ago(iso: string | null): string {
  if (!iso) return '—';
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}초 전`;
  if (s < 3600) return `${Math.round(s / 60)}분 전`;
  if (s < 86400) return `${Math.round(s / 3600)}시간 전`;
  return `${Math.round(s / 86400)}일 전`;
}

export default function TargetsPage() {
  const [repos, setRepos] = useState<Repo[] | null>(null);
  const [input, setInput] = useState('');
  const [mode, setMode] = useState<RepoMode>('polling');
  const [preview, setPreview] = useState<RepoPreview | null>(null);
  const [previewErr, setPreviewErr] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ text: string; err: boolean } | null>(null);
  const [confirmId, setConfirmId] = useState<number | null>(null);
  const previewSeq = useRef(0);

  const reload = () => listRepos().then(setRepos).catch(() => setRepos((r) => r ?? []));
  useEffect(() => { void reload(); }, []);
  useWebSocket((e: WsEnvelope) => { if (e.type === 'repo.status') void reload(); });

  const flash = (text: string, err = false) => {
    setNotice({ text, err });
    setTimeout(() => setNotice(null), 5000);
  };

  // 레포 1개를 입력하면 0.6초 뒤 GitHub 정보를 미리 보여준다
  const inputs = splitRepoInputs(input);
  const single = inputs.length === 1 && looksLikeRepo(inputs[0]) ? inputs[0] : null;
  useEffect(() => {
    setPreview(null);
    setPreviewErr(null);
    if (!single) return;
    const seq = ++previewSeq.current;
    const t = setTimeout(() => {
      setPreviewing(true);
      inspectRepo(single)
        .then((p) => { if (seq === previewSeq.current) setPreview(p); })
        .catch((e: Error) => { if (seq === previewSeq.current) setPreviewErr(e.message); })
        .finally(() => { if (seq === previewSeq.current) setPreviewing(false); });
    }, 600);
    return () => clearTimeout(t);
  }, [single]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (inputs.length === 0 || busy) return;
    setBusy(true);
    const ok: string[] = [];
    const failed: string[] = [];
    for (const url of inputs) {
      try {
        const r = await registerRepo(url, mode);
        ok.push(r.fullName);
      } catch (err) {
        failed.push(`${url} (${(err as Error).message})`);
      }
    }
    setBusy(false);
    if (ok.length) setInput('');
    if (failed.length) flash(`${ok.length}개 등록, ${failed.length}개 실패: ${failed.join(', ')}`, true);
    else flash(ok.length === 1 ? `${ok[0]} 검사를 시작했습니다. 최근 커밋 5개를 먼저 가져옵니다.` : `${ok.length}개 레포 검사를 시작했습니다.`);
    void reload();
  };

  const togglePause = async (r: Repo) => {
    try {
      await setRepoPaused(r.id, r.status !== 'PAUSED');
      void reload();
    } catch (err) {
      flash((err as Error).message, true);
    }
  };

  const remove = async (r: Repo) => {
    setConfirmId(null);
    try {
      await deleteRepo(r.id);
      flash(`${r.fullName} 검사를 중단하고 목록에서 뺐습니다.`);
      void reload();
    } catch (err) {
      flash((err as Error).message, true);
    }
  };

  return (
    <section className="flex flex-col gap-3">
      <div>
        <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-3">Repository Inspection</div>
        <h1 className="text-[20px] font-semibold tracking-tight">검사 레포지토리</h1>
      </div>

      <form onSubmit={submit} className="flex flex-col gap-3 rounded-xl border border-line bg-surface p-4 shadow-card">
        <div className="flex flex-col gap-2 md:flex-row">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="레포지토리 URL 링크를 입력해주세요 (예: github.com/owner/repo)"
            aria-label="레포지토리 URL"
            className="min-w-0 flex-1 rounded-lg border border-line-strong bg-surface px-3 py-2 text-[13.5px] outline-none focus:border-accent"
          />
          <div className="flex shrink-0 flex-wrap gap-2">
            <div role="radiogroup" aria-label="수집 방식" className="flex rounded-lg border border-line-strong p-0.5">
              {(['polling', 'webhook'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  role="radio"
                  aria-checked={mode === m}
                  onClick={() => setMode(m)}
                  className={cn('whitespace-nowrap rounded-md px-3 py-1.5 text-[12.5px] font-medium text-fg-2', mode === m && 'bg-accent-soft text-accent-ink')}
                >
                  {MODE_LABEL[m]}
                </button>
              ))}
            </div>
            <button
              type="submit"
              disabled={inputs.length === 0 || busy}
              className="flex-1 whitespace-nowrap rounded-lg bg-accent px-4 py-2 text-[13px] font-bold text-white disabled:opacity-40 md:flex-none"
            >
              {busy ? '등록 중…' : inputs.length > 1 ? `${inputs.length}개 검사 시작` : '검사 시작'}
            </button>
          </div>
        </div>
        <p className="text-[12px] text-fg-3">
          여러 개는 쉼표나 줄바꿈으로 구분합니다. {mode === 'polling'
            ? '주기 확인: 15초마다 새 커밋을 확인합니다. 어떤 공개 레포든 쓸 수 있습니다.'
            : '즉시 수신: 커밋이 올라오는 순간 받습니다. 그 레포의 GitHub 설정에 Webhook 등록이 필요합니다.'}
        </p>

        {(previewing || preview || previewErr) && (
          <div className="rounded-lg border border-line bg-surface-2 px-3.5 py-3 text-[13px]">
            {previewing && <span className="text-fg-3">GitHub에서 레포 정보를 확인하는 중…</span>}
            {!previewing && previewErr && <span className="text-crit-ink">{previewErr}</span>}
            {!previewing && preview && (
              <div className="flex flex-col gap-1">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="font-semibold">{preview.repo.fullName}</span>
                  <span className="text-fg-2">★ {preview.repo.stars.toLocaleString()}</span>
                  <span className="font-mono text-[12px] text-fg-3">{preview.repo.defaultBranch}</span>
                </div>
                {preview.repo.description && <div className="truncate text-fg-2">{preview.repo.description}</div>}
                <div className="text-[12px] text-fg-3">
                  최근 커밋 {preview.commits.length}개 확인됨
                  {preview.commits[0] && ` · 최신: ${preview.commits[0].message.split('\n')[0].slice(0, 60)}`}
                </div>
              </div>
            )}
          </div>
        )}
      </form>

      {notice && (
        <div role="status" aria-live="polite" className={cn('rounded-lg px-3.5 py-2.5 text-[13px]', notice.err ? 'bg-crit-soft text-crit-ink' : 'bg-good-soft text-good-ink')}>
          {notice.text}
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-line bg-surface shadow-card">
        <div className="flex items-center border-b border-line px-4 py-2.5 text-[13px] font-semibold">
          검사 중인 레포 <span className="ml-1.5 text-fg-3">{repos?.length ?? 0}</span>
        </div>
        {repos === null ? (
          <div className="px-4 py-6 text-[13px] text-fg-3">불러오는 중…</div>
        ) : repos.length === 0 ? (
          <div className="px-4 py-8 text-center text-[13px] text-fg-2">
            아직 등록한 레포가 없습니다. 위 입력창에 GitHub 주소를 넣고 <b>검사 시작</b>을 누르세요.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-[13px]">
              <thead>
                <tr className="border-b border-line bg-surface-2 text-left text-[12px] text-fg-3">
                  <th className="px-4 py-2 font-medium">레포</th>
                  <th className="px-3 py-2 font-medium">방식</th>
                  <th className="px-3 py-2 font-medium">상태</th>
                  <th className="px-3 py-2 text-right font-medium">마지막 확인</th>
                  <th className="px-4 py-2 text-right font-medium">관리</th>
                </tr>
              </thead>
              <tbody>
                {repos.map((r) => {
                  const st = repoStatusView(r.status);
                  return (
                    <tr key={r.id} className="border-b border-line last:border-0">
                      <td className="whitespace-nowrap px-4 py-2.5">
                        <a href={`https://github.com/${r.fullName}`} target="_blank" rel="noreferrer" className="font-semibold hover:underline">
                          {r.fullName}
                        </a>
                        {r.stars != null && <span className="ml-2 text-[12px] text-fg-3">★ {r.stars.toLocaleString()}</span>}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2.5 text-fg-2" title={r.mode === 'polling' ? `${r.pollIntervalS}초마다 확인` : 'GitHub Webhook으로 수신'}>
                        {MODE_LABEL[r.mode]}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2.5">
                        <span className={cn('rounded-full px-2 py-0.5 text-[12px] font-semibold', TONE[st.tone])} title={r.lastError ?? undefined}>
                          {st.label}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-3 py-2.5 text-right text-fg-2">{ago(r.lastSyncAt)}</td>
                      <td className="whitespace-nowrap px-4 py-2.5 text-right">
                        {confirmId === r.id ? (
                          <span className="inline-flex items-center gap-2">
                            <span className="text-[12px] text-fg-2">검사를 중단할까요?</span>
                            <button onClick={() => void remove(r)} className="rounded-md bg-crit px-2.5 py-1 text-[12px] font-bold text-white">삭제</button>
                            <button onClick={() => setConfirmId(null)} className="rounded-md border border-line-strong px-2.5 py-1 text-[12px]">취소</button>
                          </span>
                        ) : (
                          <span className="inline-flex gap-2">
                            <button onClick={() => void togglePause(r)} className="rounded-md border border-line-strong px-2.5 py-1 text-[12px] font-medium">
                              {r.status === 'PAUSED' ? '다시 시작' : '일시정지'}
                            </button>
                            <button onClick={() => setConfirmId(r.id)} className="rounded-md border border-line-strong px-2.5 py-1 text-[12px] font-medium hover:border-crit hover:text-crit-ink">
                              삭제
                            </button>
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
