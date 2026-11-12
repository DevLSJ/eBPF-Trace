import type { ReactNode } from 'react';
import { LoadError } from '../../components/Panel';
import { ScreenHead } from '../../components/ScreenHead';

// 연동 세 페이지의 틀(11/09 밤): 화면 설명 줄(ScreenHead) → 본문. 불러오기 실패면 설명 + 실패 안내만
//   data-part="integration" · data-page(setup · env · watch) · data-state(loading · ready · error)
export function IntFrame({ page, screen, ready, error, children }: { page: 'setup' | 'env' | 'watch'; screen: string; ready: boolean; error: unknown; children: ReactNode }) {
  // 설명 줄 = 다른 화면과 같은 공통 부품(설명 + 오른쪽 끝 주 버튼 칸, 11/10 메인 통합)
  const desc = <ScreenHead screen={screen} />;
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
