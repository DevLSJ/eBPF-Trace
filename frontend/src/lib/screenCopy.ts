// 화면 문구 한 곳(11/09 SPEC-1109 §7). 화면은 여기서 꺼내 쓰고 문장을 따로 두지 않는다.
//   SCREEN_COPY  제목 아래 설명 한 줄 — 「[대상]을 [동작]하고 [동작]합니다.」 20~50자 한 문장 · 마침표 앞 기호 없음 · 제약 안내는 넣지 않음.
//                대시보드는 설명 없음
//   SCREEN_NOTE  표 아래 안내 한 줄 — 설명에서 뺀 제약 · 위치 안내(부품 components/ScreenNote.tsx 가 넘치면 「…」 + 마우스 올리면 전체)
// 키는 화면 경로에서 앞 「/」를 뺀 것(예: 'policies' · 'policies/blocklist' · 'integration/env'). 화면별 문장은 각 화면 작업이 채운다.
// e2e(table-kit-1109 ㉔)가 등록된 설명을 모두 checkScreenCopy 로 검사한다.
//   <p className="…">{screenCopy('policies')}</p>   ·   <ScreenNote screen="policies" />
export const SCREEN_COPY: Record<string, string> = {
  // 정책 · 차단 목록 · 변경 이력(11/09 정책 화면 분리)
  policies: '컨테이너 행동을 판정하는 정책을 만들고 적용 범위를 관리합니다.',
  'policies/blocklist': '악성 판정으로 차단한 대상을 종류별로 확인하고 해제합니다.',
  'policies/changes': '정책과 차단 목록의 변경 기록을 시각순으로 확인합니다.',
  // 정책 밖 목록 · 화면(11/09 P5)
  installs: '패키지 설치를 감시 컨테이너에서 검사하고 판정 대기 건을 처리합니다.',
  scans: '설치 전 패키지와 저장소 코드를 정적으로 검사하고 위험을 판정합니다.',
  evaluation: '공급망 검사와 설치 검사의 탐지 성능을 측정하고 결과를 비교합니다.',
  events: '감시 중인 컨테이너의 실시간 위반을 살펴보고 상세 내용을 확인합니다.',
  topology: '컨테이너의 실행과 통신 관계를 그래프로 보고 위반 경로를 확인합니다.',
  audit: '지난 위반 기록과 판정 변경 이력을 기간별로 조회하고 내보냅니다.',
  settings: '서버 동작을 확인하고 계정과 라이선스 인증 기록을 관리합니다.',
  // 연동 · 환경 점검 · 감시 중 컨테이너(11/09 밤 연동 3페이지)
  integration: '내 컨테이너의 라벨 설정을 만들고 연동 결과를 확인합니다.',
  'integration/env': '이 서버의 수집 준비 상태를 점검하고 연결 테스트를 실행합니다.',
  'integration/watch': '실행 중인 컨테이너의 감시 여부와 격리 대상을 확인합니다.',
  demo: '무해한 시연 패키지로 탐지와 격리 과정을 실행하고 결과를 확인합니다.',
  report: '판정 건의 탐지 경위와 조치를 보고서로 정리하고 인쇄하거나 복사합니다.',
};
export const SCREEN_NOTE: Record<string, string> = {
  policies: '행을 누르면 편집 · 차단 이력 · 변경 이력을 봅니다. 저장하면 엔진에 바로 적용됩니다.',
  'policies/blocklist': '패키지 · 이미지 해제는 다음 설치 · 기동부터, 도메인 해제는 바로 적용됩니다.',
  'policies/changes': '되돌리기는 정책 상세의 변경 이력에서 합니다.',
  // 정책 밖 목록(11/09 P5)
  installs: '설치는 CLI(sg-install)로만 실행하며 위반이면 설치가 끝나기 전에 격리됩니다.',
  scans: '코드를 실행하지 않는 정적 검사이며 위협이 나온 파일만 30일 보관합니다.',
  events: '실시간 목록은 최근 500건까지 보이며 지난 기록은 감사 로그에서 찾습니다.',
  audit: '정상 이벤트는 저장하지 않고 위반만 남깁니다. CSV 내보내기는 기간 안 최대 10,000건입니다.',
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
