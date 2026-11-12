'use client';
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import type { WsEnvelope } from '@scw/shared-types';
import { api, type CommitFeedItem, type Overview } from '@/lib/api';
import { useWebSocket } from '@/lib/ws';
import { cn } from '@/lib/utils';
import { levelClass, levelIcon, statusLabel, tagGroups } from '@/lib/risk';

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

  // 카드 수치는 집계 API 재조회로 맞춘다. 이벤트가 몰려도 0.5초에 1번만
  const statsTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  function scheduleStats() {
    if (statsTimer.current) return;
    statsTimer.current = setTimeout(() => {
      statsTimer.current = null;
      void reloadStats();
    }, 500);
  }
  useEffect(() => () => { if (statsTimer.current) clearTimeout(statsTimer.current); }, []);

  const state = useWebSocket((e: WsEnvelope) => {
    const p = e.payload as Record<string, unknown>;
    if (e.type === 'commit.received') {
      upsert({
        id: p.id as number, repoId: p.repoId as number, repoFullName: p.repoFullName as string,
        sha: p.sha as string, shortSha: p.shortSha as string, branch: (p.branch as string) ?? null,
        source: p.source as string, status: 'QUEUED', receivedAt: new Date().toISOString(),
        message: (p.message as string) ?? '', authorLogin: (p.authorLogin as string) ?? null,
        authorName: (p.authorName as string) ?? null, committedAt: (p.committedAt as string) ?? null,
        htmlUrl: (p.htmlUrl as string) ?? '', filesChanged: (p.filesChanged as number) ?? 0,
        additions: (p.additions as number) ?? 0, deletions: (p.deletions as number) ?? 0,
        riskLevel: null, riskScore: null, tags: [],
      });
      scheduleStats();
    } else if (e.type === 'analysis.started') upsert({ id: p.commitId as number, status: 'ANALYZING' });
    else if (e.type === 'analysis.completed') {
      upsert({ id: p.commitId as number, status: 'DONE', riskScore: p.riskScore as number, riskLevel: p.riskLevel as string, tags: (p.tags as string[]) ?? [], llmStatus: p.llmStatus as string });
      scheduleStats();
    } else if (e.type === 'analysis.failed') {
      upsert({ id: p.commitId as number, status: 'FAILED' });
      scheduleStats();
    } else if (e.type === 'repo.status' || e.type === 'stats.tick') scheduleStats();
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
          <Kpi label="위협 감지" value={`위험 ${overview.today.high}`} foot={`주의 ${overview.today.medium}`} accent={overview.today.high > 0} />
          <Kpi label="AI 정밀 분석" value={`${overview.today.llm_calls}`} foot={overview.engine.healthy ? overview.engine.model ?? '' : 'engine 꺼짐'} />
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
              {f === 'ALL' ? `전체 ${items.length}` : f === 'ANALYZING' ? '분석중' : f === 'HIGH' ? '위험' : '주의'}
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
              즉시 확인 · 위험 {high.length}
            </div>
          )}
          {high.map((c) => <FeedRow key={c.id} c={c} pinned />)}
          <div className="sticky top-0 bg-surface-2 px-4 py-1.5 text-[12px] font-semibold text-fg-2">최근 수집 · 최신순</div>
          {shown.filter((c) => c.riskLevel !== 'HIGH').map((c) => <FeedRow key={c.id} c={c} />)}
          {shown.length === 0 && (overview?.repos.total === 0 ? <FirstRunGuide /> : (
            <div className="p-6 text-[13px] text-fg-3">
              {filter === 'ALL' ? '아직 들어온 커밋이 없습니다. 새 커밋이 올라오면 여기에 바로 표시됩니다.' : '이 조건에 맞는 커밋이 없습니다.'}
            </div>
          ))}
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
        <div className="truncate text-[12.5px] text-fg-2">{c.message?.split('\n')[0] || (analyzing ? '분석 대기 중…' : '—')}</div>
        {tagGroups(c.tags).length > 0 && (
          <div className="truncate text-[11.5px] text-fg-3">의심 행위: {tagGroups(c.tags).join(' · ')}</div>
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

// 처음 로그인해 검사할 레포가 하나도 없을 때: 무엇을 하면 되는지 바로 안내
function FirstRunGuide() {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
      <div className="text-[15px] font-semibold">아직 검사할 레포가 없습니다</div>
      <p className="max-w-[440px] text-[13px] leading-relaxed text-fg-2">
        GitHub 레포 주소를 등록하면 새 커밋이 올라올 때마다 자동으로 검사해 이 화면에 보여줍니다.
        등록하면 최근 커밋 5개를 먼저 가져옵니다.
      </p>
      <Link href="/targets" className="rounded-lg bg-accent px-4 py-2 text-[13px] font-bold text-white">
        레포 추가하기
      </Link>
    </div>
  );
}
