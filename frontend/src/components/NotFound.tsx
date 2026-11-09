import { Link } from 'react-router-dom';
import { EmptyState } from './list/ListStates';

// 없는 주소(11/09 G04) — 예전처럼 대시보드로 몰래 옮기지 않고(주소는 그대로) 화면 상태 양식으로 알린다.
// 셸 머리의 화면 이름이 비므로 제목은 본문에 2단계 제목으로(빈 상태 제목 칸이 span 이라 role=heading). 아이콘 없음(빈 상태 · 권한 없음과 같은 모양), 1차 단추 = 「대시보드로」
const NOT_FOUND_COPY = {
  title: '화면을 찾을 수 없습니다',
  hint: '주소를 확인하거나 왼쪽 메뉴에서 화면을 고르세요.',
  home: '대시보드로',
} as const;

export function NotFound() {
  return (
    <div data-part="not-found" className="h-full">
      <EmptyState
        title={
          <span role="heading" aria-level={2} className="text-[length:var(--fs-lg)] font-bold text-text">
            {NOT_FOUND_COPY.title}
          </span>
        }
        hint={NOT_FOUND_COPY.hint}
        actions={
          <Link to="/" className="sg-btn sg-btn-sm sg-btn-primary">
            {NOT_FOUND_COPY.home}
          </Link>
        }
      />
    </div>
  );
}
