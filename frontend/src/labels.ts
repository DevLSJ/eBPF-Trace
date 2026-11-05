// 표시 레이어 전용 용어 사전. 내부 값(API·enum·option value)은 절대 바꾸지 않고, 화면 문구만 "쉬운 말(원어)"로 바꾼다.
import type { Severity } from './types';

export interface Term { label: string; original: string; description: string }
const term = (label: string, original: string, description: string): Term => ({ label, original, description });
// 화면 표기 형식: "쉬운 말(원어)". 원어가 없으면 쉬운 말만 표시한다.
export const withOriginal = (t: Term) => t.original ? `${t.label}(${t.original})` : t.label;
export const termTitle = (t: Term) => t.original ? `${t.original} · ${t.description}` : t.description;

export const SEVERITY: Record<Severity, Term> = {
  critical: term('긴급', 'Critical', '서비스 중단 위험이 있어 즉시 확인이 필요합니다'),
  high: term('높음', 'High', '공격 가능성이 높아 빠른 확인이 필요합니다'),
  medium: term('보통', 'Medium', '주의해서 지켜볼 필요가 있습니다'),
  low: term('낮음', 'Low', '참고용 기록입니다'),
};
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];
export const severityLabel = (value: string) => SEVERITY[value as Severity]?.label ?? value;

export const ATTACK_TYPE: Record<string, Term> = {
  SYN_FLOOD: term('연결 폭주', 'SYN Flood', '접속 요청만 쏟아부어 서비스를 마비시키는 공격'),
  PORT_SCAN: term('포트 스캔', 'Port Scan', '열린 문을 찾아 여러 포트를 두드리는 정찰'),
  TRAFFIC_SPIKE: term('트래픽 급증', 'Traffic Spike', '평소보다 갑자기 많은 양이 들어옴'),
  LARGE_FLOW: term('대용량 전송', 'Large Flow', '한 연결로 매우 큰 데이터가 오감'),
  ANOMALY: term('이상 징후', 'AI 탐지', '규칙엔 없지만 평소 패턴과 다름'),
  BENIGN: term('정상', 'Benign', '공격 징후가 없는 평범한 트래픽'),
};
export const ATTACK_TYPE_ORDER = ['SYN_FLOOD', 'PORT_SCAN', 'TRAFFIC_SPIKE', 'LARGE_FLOW', 'ANOMALY'];
// 백엔드가 만든 문장(사건 제목 "PORT SCAN · 자산", 시나리오 카탈로그 "LARGE FLOW 규칙 확인" 등) 안의 코드 토큰만 쉬운 말로 바꾼다.
// 이미 "쉬운 말(원어)" 형태인 부분(여는 괄호 뒤)은 건드리지 않는다. 백엔드 문자열 자체는 그대로다.
const CODE_TOKENS: [RegExp, string][] = [
  [/(?<!\()\bSYN[ _]?FLOOD\b/gi, 'SYN_FLOOD'], [/(?<!\()\bPORT[ _]?SCAN\b/gi, 'PORT_SCAN'],
  [/(?<!\()\bLARGE[ _]?FLOW\b/gi, 'LARGE_FLOW'], [/(?<!\()\bTRAFFIC[ _]?SPIKE\b/gi, 'TRAFFIC_SPIKE'], [/(?<!\()\bANOMALY\b/g, 'ANOMALY'],
];
const LEGACY_WORDS: [RegExp, string][] = [[/SYN 폭주/g, '연결 폭주'], [/포트 탐색/g, '포트 스캔'], [/대량 전송/g, '대용량 전송']];
export function humanizeCodes(text: string | null | undefined): string {
  let out = text ?? '';
  for (const [pattern, code] of CODE_TOKENS) out = out.replace(pattern, attackTypeLabel(code));
  for (const [pattern, word] of LEGACY_WORDS) out = out.replace(pattern, word);
  return out;
}
const fallbackTerm = (value: string) => term(value.replaceAll('_', ' '), '', '');
export const attackTypeTerm = (value: string) => ATTACK_TYPE[value] ?? fallbackTerm(value);
export const attackTypeLabel = (value: string) => withOriginal(attackTypeTerm(value));

// 탐지 엔진 모드: /health.detection_mode, ScenarioRun.detection_mode, ModelAnalysis.runtime.mode, ModelOverview.runtime
export const ENGINE_MODE: Record<string, Term> = {
  hybrid: term('규칙+AI', 'Hybrid', '규칙 탐지에 이상 탐지 AI 점수를 더해 판단합니다'),
  rules: term('규칙만 사용', 'Rules', '정해진 규칙(연결 폭주·포트 스캔 등)으로만 판단합니다'),
  rules_only: term('규칙만 사용', 'Rules only', '정해진 규칙(연결 폭주·포트 스캔 등)으로만 판단합니다'),
};
export const engineTerm = (mode: string | undefined | null) => mode ? ENGINE_MODE[mode] ?? term(mode, '', '') : null;
export const engineLabel = (mode: string | undefined | null) => engineTerm(mode)?.label ?? '';

export const MODEL_KIND: Record<string, Term> = {
  isolation_forest: term('이상 탐지 AI', 'Isolation Forest', '정상 패턴을 배운 뒤 거기서 벗어난 관측을 찾는 방식'),
  hgb: term('학습형 AI', 'HGB', '정답이 있는 데이터로 공격과 정상을 구분하도록 학습한 방식'),
};

// 단위·지표
export const UNIT = {
  pps: term('초당 패킷', 'pps', '1초에 들어온 데이터 조각(패킷) 수'),
  mbps: term('초당 전송량', 'Mbps', '1초에 오가는 데이터 양'),
  bps: term('초당 비트', 'bps', '1초에 오가는 데이터 양(비트)'),
  bytesPerSecond: term('초당 바이트', 'bytes/s', '1초에 오가는 데이터 양(바이트)'),
  synPerSecond: term('초당 접속 요청', 'SYN/s', '1초에 들어온 새 연결 요청(SYN) 수'),
  synRatio: term('접속 요청 비율', 'SYN ratio', '전체 패킷 중 새 연결 요청(SYN)이 차지하는 비율'),
  anomalyScore: term('AI 이상 점수', 'Anomaly Score', '0에 가까울수록 정상, −1에 가까울수록 의심'),
  precision: term('정밀도', 'Precision', '탐지한 것 중 실제 공격이었던 비율'),
  recall: term('재현율', 'Recall', '실제 공격 중 놓치지 않고 잡은 비율'),
  f1: term('F1 점수', 'F1', '정밀도와 재현율을 함께 보는 종합 점수'),
  fpr: term('오탐률', 'FPR', '정상인데 공격으로 잘못 잡은 비율'),
} as const;

// 사건 대응 워크스페이스의 코드 값
export const PRIORITY: Record<string, Term> = {
  P1: term('1순위', 'P1', '가장 먼저 처리해야 하는 사건'),
  P2: term('2순위', 'P2', '빠르게 처리해야 하는 사건'),
  P3: term('3순위', 'P3', '순서대로 처리하는 사건'),
  P4: term('4순위', 'P4', '여유를 두고 처리하는 사건'),
};
export const ENVIRONMENT: Record<string, Term> = {
  lab: term('실험실', 'lab', '직접 소유한 시험 환경'),
  production: term('운영', 'production', '실제 서비스 환경'),
  simulation: term('모의 훈련', 'simulation', '실제 네트워크를 바꾸지 않는 훈련 환경'),
};
export const POINT_MODE: Record<string, Term> = {
  lab: term('모의 실행', 'lab', '실제 방화벽을 바꾸지 않고 흐름만 검증'),
  nftables: term('방화벽', 'nftables', '현장 호스트의 리눅스 방화벽에 기한부 규칙을 적용'),
};
export const CHANNEL: Record<string, Term> = {
  in_app: term('워크스페이스', '', '이 화면의 알림 센터'),
  slack: term('슬랙', 'Slack', '슬랙 채널로 전달'),
  email: term('이메일', 'SMTP', '이메일로 전달'),
};
export const MODEL_STAGE: Record<string, Term> = {
  offline: term('대기', 'Offline', '실시간 관측에 참여하지 않음'),
  shadow: term('그림자 검증', 'Shadow', '판정에는 쓰지 않고 실시간으로 점수만 기록'),
  advisory: term('참고', 'Advisory', '운영자에게 참고 근거로만 제공'),
  production: term('실제 판정', 'Production', '탐지 판정에 실제로 사용'),
};
export const DRIFT_STATUS: Record<string, Term> = {
  insufficient_data: term('표본 부족', 'insufficient_data', '아직 판단할 만큼 관측이 쌓이지 않음'),
  review: term('검토 필요', 'review', '최근 점수 분포가 눈에 띄게 달라짐'),
  stable: term('안정', 'stable', '점수 분포가 크게 달라지지 않음'),
};
export const SHADOW_STATUS: Record<string, Term> = {
  not_configured: term('설정 안 됨', 'not_configured', '그림자 검증 모델이 등록되지 않음'),
  ready: term('준비됨', 'ready', '실시간 관측을 기록할 수 있음'),
  invalid_artifact: term('모델 파일 오류', 'invalid_artifact', '모델 묶음을 읽을 수 없음'),
  immutable_version_conflict: term('버전 충돌', 'immutable_version_conflict', '등록된 모델과 파일 해시가 다름'),
};
export const codeLabel = (table: Record<string, Term>, value: string | null | undefined, fallback = '') => value ? (table[value] ? withOriginal(table[value]) : value) : fallback;

// 사건 대응 워크스페이스 전문 용어(값은 바꾸지 않고 툴팁·병기만)
export const OPS_TERM = {
  ttl: term('자동 해제 시간', 'TTL', '이 시간이 지나면 커널이 스스로 차단을 풀어요. 사람이 잊어도 영구 차단이 되지 않는 안전장치'),
  cidr: term('주소 범위', 'CIDR', '예: 192.0.2.0/24 처럼 여러 IP를 한 번에 나타내는 표기. 여기 적힌 주소는 절대 차단하지 않아요'),
  nftables: term('방화벽', 'nftables', '현장 리눅스 호스트의 방화벽. 차단 규칙이 실제로 적용되는 곳'),
  killSwitch: term('모든 대응 멈춤', 'Kill switch', '켜면 진행 중인 모든 차단 해제를 요청하고 새 승인·자동 차단을 막아요'),
  gate: term('차단 안전 점검', 'Gate', '차단 전에 "정상 사용자까지 막을 위험"을 점수로 계산해 자동/승인 경로를 가르는 절차'),
  gateScore: term('부수 피해 위험 점수', 'risk score', '실수로 정상 사용자까지 막을 위험 점수(0~1). 낮을수록 안전'),
  gateThreshold: term('위험 기준선', 'threshold', '이 값 이상이면 자동 차단 없이 승인 경로로 보내요(기본 0.40)'),
  autoRoute: term('자동 경로', 'automatic route', '점검 결과가 저위험일 때만 승인 없이 기한부로 차단하는 경로'),
  agent: term('현장 방화벽 프로그램', 'agent', '현장 호스트에서 차단을 적용·해제하고 결과를 보고하는 프로그램'),
} as const;
// 게이트 신호 이름(backend/services/risk_gate.py의 signals 키)
export const GATE_SIGNAL: Record<string, Term> = {
  normal_fraction: term('정상 연결 비율', 'normal_fraction', '이 출발지의 연결 중 정상적으로 완료된 비율. 높을수록 정상 사용자일 가능성'),
  port_diversity: term('포트 다양성', 'port_diversity', '두드린 포트 수. 많을수록 정찰(스캔) 성격'),
  observation: term('관측 기간', 'observation', '이 출발지를 얼마나 오래 지켜봤는지. 짧으면 판단 근거가 부족'),
  proximity: term('보호 주소 근접도', 'proximity', '보호할 주소 범위(CIDR)와 얼마나 가까운지. 가까우면 내부 장비일 수 있음'),
};

// 백엔드가 보내는 영문 오류 메시지의 표시용 번역. 백엔드 원문은 그대로 두고(감사 로그·API 호환), 모르는 메시지는 원문을 노출한다.
const ERROR_MESSAGES: [RegExp, (match: RegExpMatchArray) => string][] = [
  [/^Administrator token required$/i, () => '관리자 비밀키가 필요합니다. 설정에서 키를 입력해 주세요.'],
  [/^Session expired; sign in again$/i, () => '로그인이 만료되었습니다. 다시 로그인해 주세요.'],
  [/^Permission required: (.+)$/i, m => `권한이 부족합니다(필요 권한: ${m[1]}).`],
  [/^A scenario is already running; wait or stop it first$/i, () => '다른 시나리오(훈련)가 아직 실행 중이에요. 끝나기를 기다리거나 먼저 중지하세요.'],
];
export function translateError(message: string): string {
  const raw = message.trim();
  for (const [pattern, render] of ERROR_MESSAGES) { const match = raw.match(pattern); if (match) return render(match); }
  return message;
}

// 상태 신호등: 색·아이콘·문구를 항상 함께 쓴다.
export type StatusLevel = 'ok' | 'warn' | 'error';
export const STATUS_LEVEL: Record<StatusLevel, { name: string; symbol: string }> = {
  ok: { name: '정상', symbol: '🟢' }, warn: { name: '주의', symbol: '🟡' }, error: { name: '문제', symbol: '🔴' },
};
