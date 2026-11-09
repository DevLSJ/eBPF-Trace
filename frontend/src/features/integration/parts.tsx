import type { ReactNode } from 'react';
import { LoadError } from '../../components/Panel';
import { screenCopy } from '../../lib/screenCopy';

// 연동 세 페이지의 틀(11/09 밤): 화면 설명 한 줄 → 본문. 불러오기 실패면 설명 + 실패 안내만
//   data-part="integration" · data-page(setup · env · watch) · data-state(loading · ready · error)
export function IntFrame({ page, screen, ready, error, children }: { page: 'setup' | 'env' | 'watch'; screen: string; ready: boolean; error: unknown; children: ReactNode }) {
  const desc = (
    <p data-part="screen-copy" data-screen={screen} className="m-0 shrink-0 truncate text-[length:var(--fs-sm)] text-text-3">
      {screenCopy(screen)}
    </p>
  );
  if (error && !ready)
    return (
      <div data-part="integration" data-page={page} data-state="error" className={`int-page int-page-${page}`}>
        {desc}
        <LoadError error={error} what="연동 상태" />
      </div>
    );
  return (
    <div data-part="integration" data-page={page} data-state={ready ? 'ready' : 'loading'} className={`int-page int-page-${page}`}>
      {desc}
      {children}
    </div>
  );
}

export function Skeleton({ rows }: { rows: number }) {
  return (
    <div className="int-skel" aria-hidden>
      {Array.from({ length: rows }, (_, i) => (
        <span key={i} />
      ))}
    </div>
  );
}
