import { FIELD } from '../../lib/fieldNames';
import { josa } from '../../lib/layout';

// 화면 상태 기본 문구(11/09 SPEC-1109 §7) — 상태 부품(ListStates.tsx)이 쓰는 한 곳. 빈 상태 아이콘은 11/05 결정대로 없음
//   로딩     읽기 라벨 「불러오는 중」(줄 모양 스켈레톤) · 단추 안 진행은 「저장 중…」(… 한 글자)
//   빈       「[무엇]이 없습니다.」 + 다음 할 일 한 문장 + 1차 단추(화면이 줌)
//   결과 없음 「조건에 맞는 데이터가 없습니다」 + 「검색 조건을 바꾸거나 해제해 보세요.」 + 「조건 지우기」
//   오류     「불러오지 못했습니다」 + 「다시 시도」
//   권한 없음 「이 화면을 볼 권한이 없습니다.」
export const STATE_COPY = {
  loading: '불러오는 중',
  emptyDefault: '데이터가 없습니다.',
  noResults: '조건에 맞는 데이터가 없습니다',
  noResultsHint: '검색 조건을 바꾸거나 해제해 보세요.',
  // 필터 해제 단추 이름은 이것 하나(11/09 G40) — 결과 없음 · 거르기 줄 · 「적용된 필터」 줄 모두. 글자는 통일표(lib/fieldNames.ts)에서
  clear: FIELD.clearFilters,
  loadFailed: '불러오지 못했습니다',
  retry: '다시 시도',
  denied: '이 화면을 볼 권한이 없습니다.',
} as const;
export const emptyText = (what?: string) => (what ? `${what}${josa(what, ['이', '가'])} 없습니다.` : STATE_COPY.emptyDefault);
