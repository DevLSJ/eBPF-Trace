import type { InstallScan, InstallSession } from '../../lib/types';

// 11/04 종합 판정(목업 main 617b658 확정) — 설치 세션의 자동 정적 검사(scan) 문구.
// 건너뛴 이유: 목록 「—」 title 과 상세 OSV 칸 부제 끝에 같은 문구
const SKIP_TEXT: Record<string, (manager: string) => string> = {
  local: () => '로컬 패키지라 정적 검사 건너뜀',
  unsupported: (m) => `${m} 는 정적 검사 미지원`,
  busy: () => '검사 대기열이 가득 차 정적 검사 건너뜀',
  off: () => '검사기가 꺼져 있어 정적 검사 건너뜀',
  invalid: () => '패키지 이름을 해석하지 못해 정적 검사 건너뜀',
};
export const skipText = (s: InstallSession) => (SKIP_TEXT[s.scan?.skip ?? ''] ?? (() => '정적 검사 건너뜀'))(s.manager);

// 엇갈릴 때만 한 줄(둘 다 빨강) — 그 밖(둘 다 위험 · 둘 다 정상 · 실행 중 · 실패)은 문장 없음
export const NOTE_RUNTIME = '정적 검사로는 악성 코드를 찾지 못했지만, 설치 중 행동을 커널에서 보고 잡았습니다.';
export const NOTE_STATIC = '설치 중 정책 위반은 없었지만, 정적 검사에서 설치 단계의 위험한 코드가 나왔습니다 — 공급망 검사에서 코드를 확인하세요.';

const runtimeHit = (s: InstallSession) => s.status === 'isolated' || s.status === 'warned';

// 런타임 격리 · 경고 + 정적 정상 · 주의 · 취약 · 건너뜀 → 커널 쪽 / 런타임 통과 + 정적 악성 → 정적 쪽. 옛 세션(scan 없음)은 없음
export function mismatchNote(s: InstallSession): string {
  const sc = s.scan;
  if (!sc) return '';
  if (sc.status === 'skipped') return runtimeHit(s) ? NOTE_RUNTIME : '';
  if (sc.status !== 'done') return '';
  if (runtimeHit(s) && sc.verdict !== 'malicious') return NOTE_RUNTIME;
  if (s.status === 'passed' && sc.verdict === 'malicious') return NOTE_STATIC;
  return '';
}

// 빨간 행 = 런타임 격리 · 경고 또는 정적 악성
export const isDangerRow = (s: InstallSession) => runtimeHit(s) || s.scan?.verdict === 'malicious';

// 건너뜀이 아니면 정적 검사 칸(GuardDog + OSV), 건너뜀 · 없음이면 지금의 OSV 이름 조회 칸
export const hasStaticCell = (sc: InstallScan | undefined): sc is InstallScan => !!sc && sc.status !== 'skipped';
