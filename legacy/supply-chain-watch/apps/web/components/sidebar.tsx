'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutGrid,
  Target,
  GitCommitHorizontal,
  ScrollText,
  Settings,
  ShieldAlert,
  Store,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const items = [
  { href: '/', label: '대시보드', icon: LayoutGrid },
  { href: '/targets', label: '검사 레포지토리', icon: Target },
  { href: '/commits', label: '커밋 상세 분석', icon: GitCommitHorizontal },
  { href: '/runtime', label: '런타임 추적·차단', icon: ShieldAlert },
  { href: '/demoshop', label: '공격 시연', icon: Store },
  { href: '/audit', label: '감사 로그', icon: ScrollText },
  { href: '/settings', label: '설정 · 백오피스', icon: Settings },
];

export function Sidebar() {
  const path = usePathname();
  return (
    <aside className="flex w-[232px] flex-col gap-4 border-r border-line bg-surface p-3">
      <div className="flex items-center gap-2.5 px-2 py-1.5">
        <div className="grid h-8 w-8 place-items-center rounded-[9px] bg-fg text-[14px] font-bold text-surface">
          SW
        </div>
        <div>
          <b className="block text-[13.5px]">Supply Chain Watch</b>
          <small className="text-[11.5px] text-fg-3">DevLSJ · 캡스톤</small>
        </div>
      </div>
      <nav className="flex flex-col gap-0.5">
        {items.map(({ href, label, icon: Icon }) => {
          const active = href === '/' ? path === '/' : path.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                'flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] font-medium text-fg-2 hover:bg-surface-2',
                active && 'bg-accent-soft font-semibold text-accent-ink',
              )}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {label}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
