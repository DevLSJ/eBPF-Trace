'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { listCommits } from '@/lib/commits';
import type { CommitFeedItem } from '@/lib/api';
import { LEVEL_LABEL, levelClass, levelIcon, statusLabel, tagGroups } from '@/lib/risk';
import { cn } from '@/lib/utils';

export default function CommitsPage() {
  const [items, setItems] = useState<CommitFeedItem[] | null>(null);
  useEffect(() => { listCommits(100).then(setItems).catch(() => setItems([])); }, []);
  return (
    <section className="flex flex-col gap-3">
      <div>
        <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-3">Commit Analysis</div>
        <h1 className="text-[20px] font-semibold tracking-tight">커밋 상세 분석</h1>
        <p className="mt-0.5 text-[12.5px] text-fg-2">커밋을 누르면 AI 요약·근거 줄·변경 내용을 볼 수 있습니다.</p>
      </div>
      <div className="overflow-hidden rounded-xl border border-line bg-surface shadow-card">
        {items === null ? (
          <div className="p-6 text-[13px] text-fg-3">불러오는 중…</div>
        ) : items.length === 0 ? (
          <div className="p-6 text-[13px] text-fg-2">아직 분석한 커밋이 없습니다. <Link href="/targets" className="font-semibold text-accent-ink underline">레포를 추가</Link>하면 여기에 쌓입니다.</div>
        ) : (
          items.map((c) => {
            const analyzing = c.status === 'QUEUED' || c.status === 'ANALYZING';
            return (
              <Link key={c.id} href={`/commits/${c.id}`} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 border-b border-line px-4 py-2.5 last:border-0 hover:bg-surface-2">
                <div className="min-w-0">
                  <div className="truncate text-[13px] font-medium">{c.message?.split('\n')[0] || '—'}</div>
                  <div className="truncate text-[12px] text-fg-3">
                    {c.repoFullName} · <span className="font-mono">{c.shortSha}</span>
                    {tagGroups(c.tags).length > 0 && ` · 의심 행위: ${tagGroups(c.tags).join(' · ')}`}
                  </div>
                </div>
                <span className={cn('inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11.5px] font-semibold', levelClass(analyzing ? null : c.riskLevel))}>
                  {levelIcon(analyzing ? null : c.riskLevel)} {analyzing ? statusLabel(c.status, null) : `${LEVEL_LABEL[c.riskLevel ?? ''] ?? '—'} ${c.riskScore ?? ''}`}
                </span>
              </Link>
            );
          })
        )}
      </div>
    </section>
  );
}
