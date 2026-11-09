import type { PillTone } from '../components/DataTable';

// 동작 태그 색(11/09 SPEC-1109 §7 — 변경 이력 · 감사 표). 이름은 「[대상] [동작]」 꼴로 짓고 끝말로 색을 고른다.
// 색 → 끝말 표는 여기 한 곳(화면마다 따로 두지 않는다). 색만으로 뜻을 전하지 않도록 배지에는 늘 이름 글자가 함께 간다.
//   <StatusPill tone={actionTone('정책 되돌림')}>정책 되돌림</StatusPill>   → 주의(갈색 자리) 톤
export const ACTION_TONE_ENDINGS: { tone: PillTone; endings: readonly string[] }[] = [
  { tone: 'danger', endings: ['삭제', '해제', '정지'] },
  { tone: 'info', endings: ['적용', '내보내기', '반영'] },
  { tone: 'warn', endings: ['수정', '변경', '되돌리기', '되돌림', '초기화'] },
  { tone: 'ok', endings: ['등록', '생성', '추가'] },
];

export function actionTone(name: string): PillTone {
  const n = name.trim();
  for (const { tone, endings } of ACTION_TONE_ENDINGS) if (endings.some((e) => n.endsWith(e))) return tone;
  return 'neutral';
}
