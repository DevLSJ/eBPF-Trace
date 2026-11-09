import type { ChatEngine } from './types';

// AI 도우미 모델 안내(11/09) — 채팅 패널 머리 · 설정 화면이 같은 문구를 쓴다. 옛 백엔드(chatEngine 없음)는 예전처럼 로컬 Ollama 로 본다
export const LOCAL_ONLY = '데이터는 서버 밖으로 나가지 않음';
export const SENT_TO_ANTHROPIC = '질문과 조회한 사실이 Anthropic API 로 전송됨';

export function engineName(e?: ChatEngine): string {
  if (!e) return '로컬 모델 qwen2.5:3b';
  return e.provider === 'claude' ? `Claude ${e.model}` : `로컬 모델 ${e.model}`;
}

export function engineHeader(e?: ChatEngine): string {
  if (e?.provider !== 'claude') return `${engineName(e)} · ${LOCAL_ONLY}`;
  return `${engineName(e)} · ${SENT_TO_ANTHROPIC}${e.backup ? ' · 예비 로컬 Ollama' : ''}`;
}

export function engineFootnote(e?: ChatEngine): string {
  const ro = '읽기 전용, 판정 · 정책 변경은 하지 않습니다.';
  return e?.provider === 'claude' ? ro : `${ro} 첫 질문은 모델을 불러오느라 1분 넘게 걸릴 수 있습니다.`;
}

// 설정 화면 「밖으로 나가는 데이터」 — chat/claude.go · tools.go 가 실제로 보내는 것과 같게 유지
export const SENT_ITEMS = [
  '질문 · 이 탭의 최근 대화 6턴',
  '건 요약(컨테이너 · 패키지 이름, 판정 수준, 위반 수)',
  '위반 예시(시각 · 명령줄 · 경로 · 주소 일부, 정책 id)',
  '수집 · 위반 집계, 많이 걸린 정책 · 컨테이너',
  '공급망 검사 결과(대상, 위험 점수, 탐지 규칙 · 파일 위치)',
  '차단 목록 일부 · 정책 설명',
];
export const NOT_SENT_ITEMS = ['증거 원문(로그 · 파일 변경 · 프로세스)', '계정 · 비밀번호 · 토큰 · 서버 설정 비밀값', '전체 이벤트 기록 · 감사 로그 전체'];
