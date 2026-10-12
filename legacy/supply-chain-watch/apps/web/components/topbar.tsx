'use client';
import { useState } from 'react';
import { useWebSocket } from '@/lib/ws';
import { cn } from '@/lib/utils';

const labels = { connecting: '연결 중…', open: '연결됨', closed: '끊김' } as const;
const dot = { connecting: 'bg-warn', open: 'bg-good', closed: 'bg-crit' } as const;

export function Topbar({ crumb }: { crumb: string }) {
  const [last, setLast] = useState<string>('');
  const state = useWebSocket((e) => setLast(e.type));
  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-2.5 md:px-6 md:py-3">
      <span className="hidden text-[12.5px] text-fg-3 sm:inline">{crumb}</span>
      <span className="flex-1" />
      <span className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-2.5 py-1 text-[12px] text-fg-2">
        <span className={cn('h-[7px] w-[7px] rounded-full', dot[state])} />
        WebSocket {labels[state]}
        {last && <span className="hidden text-fg-3 sm:inline">· {last}</span>}
      </span>
    </div>
  );
}
