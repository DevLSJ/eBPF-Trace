// 화면 문구 한 곳(11/09 SPEC-1109 §7). 화면은 여기서 꺼내 쓰고 문장을 따로 두지 않는다.
//   SCREEN_COPY  제목 아래 설명 한 줄 — 「[대상]을 [동작]하고 [동작]합니다.」 20~50자 한 문장 · 마침표 앞 기호 없음 · 제약 안내는 넣지 않음.
//                대시보드는 설명 없음
//   SCREEN_NOTE  표 아래 안내 한 줄 — 설명에서 뺀 제약 · 위치 안내(부품 components/ScreenNote.tsx 가 넘치면 「…」 + 마우스 올리면 전체)
// 키는 화면 경로에서 앞 「/」를 뺀 것(예: 'policies' · 'policies/blocklist'). 화면별 문장은 각 화면 작업이 채운다.
// e2e(table-kit-1109 ㉔)가 등록된 설명을 모두 checkScreenCopy 로 검사한다.
//   <p className="…">{screenCopy('policies')}</p>   ·   <ScreenNote screen="policies" />
export const SCREEN_COPY: Record<string, string> = {};
export const SCREEN_NOTE: Record<string, string> = {};

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
