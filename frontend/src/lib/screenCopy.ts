// 화면 문구 한 곳(11/09 SPEC-1109 §7). 화면은 여기서 꺼내 쓰고 문장을 따로 두지 않는다.
//   SCREEN_COPY  제목 아래 설명 한 줄 — 「[대상]을 [동작]하고 [동작]합니다.」 20~50자 한 문장 · 마침표 앞 기호 없음 · 제약 안내는 넣지 않음.
//                대시보드는 설명 없음
//   SCREEN_NOTE  표 아래 안내 한 줄 — 설명에서 뺀 제약 · 위치 안내(부품 components/ScreenNote.tsx 가 넘치면 「…」 + 마우스 올리면 전체)
// 키는 화면 경로에서 앞 「/」를 뺀 것(예: 'policies' · 'policies/blocklist'). 화면별 문장은 각 화면 작업이 채운다.
// e2e(table-kit-1109 ㉔)가 등록된 설명을 모두 checkScreenCopy 로 검사한다.
//   <p className="…">{screenCopy('policies')}</p>   ·   <ScreenNote screen="policies" />
export const SCREEN_COPY: Record<string, string> = {
  // 정책 · 차단 목록 · 변경 이력(11/09 정책 화면 분리)
  policies: '컨테이너 행동을 판정하는 정책을 만들고 적용 범위를 관리합니다.',
  'policies/blocklist': '악성 판정으로 차단한 대상을 종류별로 확인하고 해제합니다.',
  'policies/changes': '정책과 차단 목록의 변경 기록을 시각순으로 확인합니다.',
};
export const SCREEN_NOTE: Record<string, string> = {
  policies: '행을 누르면 편집 · 차단 이력 · 변경 이력을 봅니다. 저장하면 엔진에 바로 적용됩니다.',
  'policies/blocklist': '패키지 · 이미지 해제는 다음 설치 · 기동부터, 도메인 해제는 바로 적용됩니다.',
  'policies/changes': '되돌리기는 정책 상세의 변경 이력에서 합니다.',
};

export const screenCopy = (key: string): string => SCREEN_COPY[key] ?? '';
export const screenNote = (key: string): string => SCREEN_NOTE[key] ?? '';

// 설명 한 줄 검사 — 어긋난 규칙 이름 목록(맞으면 빈 배열)
//   ending  「니다.」로 끝나지 않음 · length 20~50자 밖(공백 · 마침표 포함) · symbol 끝 마침표 앞에 기호(. = — · ( ) 「 」 : ; /)
export type CopyProblem = 'ending' | 'length' | 'symbol';
const SYMBOLS = /[.=—·()「」:;/]/;
export function checkScreenCopy(text: string): CopyProblem[] {
  const out: CopyProblem[] = [];
  const t = text.trim();
  if (!t.endsWith('니다.')) out.push('ending');
  const n = [...t].length;
  if (n < 20 || n > 50) out.push('length');
  if (SYMBOLS.test(t.endsWith('.') ? t.slice(0, -1) : t)) out.push('symbol');
  return out;
}
