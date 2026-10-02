'use client';
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import type { WsEnvelope } from '@scw/shared-types';
import { api, type CommitFeedItem, type Overview } from '@/lib/api';
import { useWebSocket } from '@/lib/ws';
import { cn } from '@/lib/utils';
import { levelClass, levelIcon, statusLabel } from '@/lib/risk';

const MAX = 200;

export function OverviewFeed() {
  const [items, setItems] = useState<CommitFeedItem[]>([]);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [filter, setFilter] = useState<string>('ALL');
  const byId = useRef(new Map<number, CommitFeedItem>());

  function upsert(it: Partial<CommitFeedItem> & { id: number }) {
    const prev = byId.current.get(it.id);
    const merged = { ...(prev ?? ({} as CommitFeedItem)), ...it } as CommitFeedItem;
    byId.current.set(it.id, merged);
    setItems(() => {
      const arr = [...byId.current.values()].sort(
        (a, b) => new Date(b.receivedAt ?? 0).getTime() - new Date(a.receivedAt ?? 0).getTime(),
      );
      return arr.slice(0, MAX);
    });
  }

  async function reload() {
    try {
      const [feed, ov] = await Promise.all([api<CommitFeedItem[]>('/api/commits?limit=100'), api<Overview>('/api/stats/overview')]);
      byId.current = new Map(feed.map((f) => [f.id, f]));
      setItems(feed);
      setOverview(ov);
    } catch { /* gateway down */ }
  }

  useEffect(() => { void reload(); }, []);

  const state = useWebSocket((e: WsEnvelope) => {
    const p = e.payload as Record<string, unknown>;
    if (e.type === 'commit.received') upsert({ id: p.id as number, repoFullName: p.repoFullName as string, sha: p.sha as string, shortSha: p.shortSha as string, branch: (p.branch as string) ?? null, status: 'QUEUED', receivedAt: new Date().toISOString(), message: '', riskLevel: null } as CommitFeedItem);
    else if (e.type === 'analysis.started') upsert({ id: p.commitId as number, status: 'ANALYZING' });
    else if (e.type === 'analysis.completed') upsert({ id: p.commitId as number, status: 'DONE', riskScore: p.riskScore as number, riskLevel: p.riskLevel as string, tags: (p.tags as string[]) ?? [], llmStatus: p.llmStatus as string });
    else if (e.type === 'stats.tick') void reloadStats();
  });

  async function reloadStats() {
    try { setOverview(await api<Overview>('/api/stats/overview')); } catch { /* */ }
  }
  // WS 복구 시 갭 보정
  useEffect(() => { if (state === 'open') void reload(); }, [state]);

  const shown = items.filter((c) => filter === 'ALL' || c.riskLevel === filter || (filter === 'ANALYZING' && (c.status === 'QUEUED' || c.status === 'ANALYZING')));
  const high = items.filter((c) => c.riskLevel === 'HIGH');

  return (
    <div className="flex h-full flex-col gap-3.5">
      {overview && (
        <div className="grid grid-cols-2 gap-3.5 lg:grid-cols-4">
          <Kpi label="검사 레포" value={`${overview.repos.total}`} foot={`${overview.repos.active} 활성`} />
          <Kpi label="오늘 커밋" value={`${overview.today.commits}`} foot="실시간" />
          <Kpi label="위협 감지" value={`${overview.today.high} HIGH`} foot={`${overview.today.medium} MEDIUM`} accent={overview.today.high > 0} />
          <Kpi label="LLM 호출" value={`${overview.today.llm_calls}`} foot={overview.engine.healthy ? overview.engine.model ?? '' : 'engine 꺼짐'} />
        </div>
      )}

      <div className="flex min-h-0 flex-1 flex-col rounded-xl border border-line bg-surface shadow-card">
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2.5">
          {(['ALL', 'HIGH', 'MEDIUM', 'ANALYZING'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn('rounded-lg border border-line-strong bg-surface px-2.5 py-1 text-[12.5px] font-medium', filter === f && 'border-accent bg-accent text-white')}
            >
              {f === 'ALL' ? `전체 ${items.length}` : f === 'ANALYZING' ? '분석중' : f}
            </button>
          ))}
          <span className="ml-auto inline-flex items-center gap-1.5 rounded-full border border-line px-2.5 py-1 text-[12px] text-fg-2">
            <span className={cn('h-[7px] w-[7px] rounded-full', state === 'open' ? 'bg-good' : 'bg-warn')} />
            LIVE
          </span>
        </div>

        <div className="min-h-0 flex-1 overflow-auto">
          {high.length > 0 && (
            <div className="sticky top-0 z-10 bg-surface-2 px-4 py-1.5 text-[12px] font-semibold text-fg-2">
              즉시 확인 · HIGH {high.length}
            </div>
          )}
          {high.map((c) => <FeedRow key={c.id} c={c} pinned />)}
          <div className="sticky top-0 bg-surface-2 px-4 py-1.5 text-[12px] font-semibold text-fg-2">최근 수집 · 최신순</div>
          {shown.filter((c) => c.riskLevel !== 'HIGH').map((c) => <FeedRow key={c.id} c={c} />)}
          {shown.length === 0 && <div className="p-6 text-[13px] text-fg-3">수집된 커밋이 없습니다. 검사 레포지토리에서 레포를 등록하세요.</div>}
        </div>
      </div>
    </div>
  );
}

function Kpi({ label, value, foot, accent }: { label: string; value: string; foot: string; accent?: boolean }) {
  return (
    <div className="flex flex-col gap-1.5 rounded-xl border border-line bg-surface p-4 shadow-card">
      <div className="text-[12px] text-fg-2">{label}</div>
      <div className={cn('text-[26px] font-semibold leading-none tracking-tight', accent && 'text-crit')}>{value}</div>
      <div className="text-[11.5px] text-fg-3">{foot}</div>
    </div>
  );
}

function FeedRow({ c, pinned }: { c: CommitFeedItem; pinned?: boolean }) {
  const analyzing = c.status === 'QUEUED' || c.status === 'ANALYZING';
  return (
    <Link href={`/commits/${c.id}`} className={cn('grid grid-cols-[1fr_auto] items-center gap-3 border-t border-line px-4 py-2.5 hover:bg-surface-2', pinned && 'border-l-[3px] border-l-crit bg-crit-soft')}>
      <div className="min-w-0">
        <div className="flex items-center gap-2 text-[13px] font-medium">
          <span className="truncate">{c.repoFullName}</span>
          <span className="font-mono text-[11.5px] text-fg-3">{c.shortSha}</span>
          {c.branch && <span className="font-mono text-[11px] text-fg-3">{c.branch}</span>}
        </div>
        <div className="truncate text-[12.5px] text-fg-2">{c.message || (analyzing ? '분석 대기 중…' : '—')}</div>
        {c.tags?.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-1">
            {c.tags.slice(0, 4).map((t) => <span key={t} className="rounded-[6px] bg-surface-2 px-1.5 text-[11px] text-fg-2">{t}</span>)}
          </div>
        )}
      </div>
      <div className="flex flex-col items-end gap-1 whitespace-nowrap text-[11.5px] text-fg-3">
        {!analyzing && c.riskScore != null && <span className={cn('font-mono text-[15px] font-bold', c.riskLevel === 'HIGH' ? 'text-crit' : c.riskLevel === 'MEDIUM' ? 'text-[var(--warn-ink)]' : 'text-[var(--good-ink)]')}>{c.riskScore}</span>}
        <span className={cn('inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11.5px] font-semibold', levelClass(analyzing ? null : c.riskLevel))}>
          {levelIcon(analyzing ? null : c.riskLevel)} {statusLabel(c.status, c.riskLevel)}
        </span>
      </div>
    </Link>
  );
}
