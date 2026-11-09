// 대응 가이드(10/20 확정, 목업 mock/shared/guide.js 이식) — 건(격리 · 경고)마다 5단계.
// 1 탐지 · 2 격리 확인 · 4 판정은 건 데이터로, 3 공격 체인 · 5 후속 조치는 이 브라우저(localStorage supplyguard.guide.<caseId>)에.
import { installDest, topologyDest, type Dest } from './nav';
import type { Case, Info } from './types';

export const GUIDE_TOTAL = 5;
// 건의 출처 표기(목업 SRC) — 대시보드 판정 대기 · 정책 제안 근거 · 감사 판정 이력 · 가이드가 같이 쓴다
export const SOURCE_LABEL: Record<Case['source'], string> = { install: '설치 검사', runtime: '런타임', scan: '공급망 검사' };
// 공급망 검사 건(「차단 목록에 올리기」)의 검사 결과 화면
export const scanHref = (c: Case) => (c.source === 'scan' && c.scanId ? `/scans?id=${encodeURIComponent(c.scanId)}` : null);

// 규칙별 후속 조치 문구 — 같은 묶음(group)이면 한 줄로 합친다
export interface FollowItem {
  group: string;
  rules: string[];
  text: string;
}
export const FOLLOW: FollowItem[] = [
  { group: 'secrets', rules: ['sensitive-files', 'sandbox-secrets'], text: '노출됐을 수 있는 키 · 토큰 교체, 같은 볼륨을 쓰는 컨테이너 확인' },
  // 10/30: dns 질의 규칙(runtime-dns-exfil · sandbox-dns)도 외부 유출 묶음
  { group: 'egress', rules: ['reverse-shell-ports', 'runtime-direct-ip', 'sandbox-egress', 'egress-allowlist', 'runtime-dns-exfil', 'sandbox-dns'], text: '목적지 IP · 도메인을 차단 목록에 올리기, 같은 이미지를 쓰는 다른 컨테이너 확인' },
  { group: 'download', rules: ['no-shell-download', 'pipe-to-shell'], text: '설치 스크립트 출처 확인, 패키지 버전 고정 · 차단' },
  { group: 'blocked-image', rules: ['blocked-image'], text: '차단된 이미지가 다시 기동된 경로(배포 파이프라인 · 이미지 태그) 확인' },
  { group: 'hosts', rules: ['blocklist-hosts'], text: '차단 도메인으로 나간 프로세스와 그 이미지 확인' },
];
const FOLLOW_DEFAULT = '같은 이미지 · 패키지를 쓰는 다른 컨테이너 확인';

export function followFor(c: Case): (FollowItem & { hit: string[] })[] {
  const out = FOLLOW.map((f) => ({ ...f, hit: f.rules.filter((r) => c.ruleIds.includes(r)) })).filter((f) => f.hit.length);
  return out.length ? out : [{ group: 'default', rules: [], hit: c.ruleIds.slice(), text: FOLLOW_DEFAULT }];
}

// 건을 보고 판정하는 곳 — 설치 = 설치 시트, 런타임 = 토폴로지(컨테이너 노드 선택 → 판정 칸), 검사 = 검사 결과
export function caseHref(c: Case): Dest {
  if (c.source === 'install' && c.installId) return installDest(c.installId);
  if (c.source === 'scan' && c.scanId) return { to: `/scans?id=${encodeURIComponent(c.scanId)}` };
  return topologyDest(c.container);
}

// ── 이 브라우저의 저장값(저장이 막혀 있어도 화면은 그대로 동작) ──
export interface GuidePref {
  chain: boolean;
  follow: Record<string, boolean>;
}
export interface SetupPref {
  off: boolean;
  visitedPolicies: boolean;
}
export const guideKey = (id: string) => `supplyguard.guide.${id}`;
export const SETUP_KEY = 'supplyguard.guide.setup';

function load<T>(k: string, d: T): T {
  try {
    const v = JSON.parse(localStorage.getItem(k) || 'null') as T | null;
    return v ? { ...d, ...v } : d;
  } catch {
    return d;
  }
}
function store(k: string, v: unknown) {
  try {
    localStorage.setItem(k, JSON.stringify(v));
  } catch {
    /* 저장 차단 */
  }
}
export const loadGuide = (id: string): GuidePref => {
  const p = load<GuidePref>(guideKey(id), { chain: false, follow: {} });
  return { chain: !!p.chain, follow: { ...(p.follow ?? {}) } };
};
export const saveGuide = (id: string, p: GuidePref) => store(guideKey(id), p);
export const loadSetup = (): SetupPref => load<SetupPref>(SETUP_KEY, { off: false, visitedPolicies: false });
export const saveSetup = (p: SetupPref) => store(SETUP_KEY, p);

// ── 단계 판정 ──
export function stepsOf(c: Case) {
  const p = loadGuide(c.id);
  const follows = followFor(c);
  const followDone = follows.length > 0 && follows.every((f) => p.follow[f.group]);
  return { p, follows, done: [true, true, p.chain, c.decision !== 'pending', followDone] };
}
export const progressOf = (c: Case) => stepsOf(c).done.filter(Boolean).length;

// 드롭다운: 최근 5건(종결 건 포함). 기본 선택은 종결되지 않은 최근 건
export const recentCases = (cases: Case[]) => [...cases].sort((a, b) => Date.parse(b.openedAt) - Date.parse(a.openedAt)).slice(0, 5);
export const pickCase = (list: Case[], selectedId: string | null): Case | undefined =>
  (selectedId ? list.find((x) => x.id === selectedId) : undefined) ?? list.find((x) => x.state !== 'closed') ?? list[0];
// 배지 = 종결되지 않은 건 가운데 5단계가 다 끝나지 않은 수
export const pendingGuides = (cases: Case[]) => cases.filter((c) => c.state !== 'closed' && progressOf(c) < GUIDE_TOTAL).length;

// ── 알림 상태(/api/info notify) — 발송됨 · 미설정 · 실패 · 미확인 ──
export type NotifyState = 'sent' | 'off' | 'failed' | 'unknown';
export function notifyState(info: Info | null): { state: NotifyState; text: string } {
  const n = info?.notify;
  if (!n) return { state: 'unknown', text: '알림 발송 미확인 (백엔드가 알려 주지 않음)' };
  if (!n.enabled || n.channels.length === 0) return { state: 'off', text: '웹훅 미설정, 알림을 받으려면 NOTIFY_WEBHOOK_URL(또는 NOTIFY_SLACK_URL)을 설정하세요' };
  const names = n.channels.map((c) => `${c.name} ${c.host}`).join(', ');
  // 한 번도 보내지 못하고 실패만 쌓인 채널이 있으면 실패로 본다(마지막 오류를 함께)
  const broken = n.channels.filter((c) => c.failed > 0 && c.sent === 0);
  if (broken.length) {
    const err = broken.map((c) => `${c.name} ${c.host}${c.lastError ? `: ${c.lastError}` : ''}`).join(' · ');
    return { state: 'failed', text: `알림 발송 실패: ${err}` };
  }
  const extra = n.failed > 0 ? ` · 실패 ${n.failed}건${n.lastError ? ` (${n.lastError})` : ''}` : '';
  return { state: 'sent', text: `알림 발송됨: ${names}${extra}` };
}

export const INSTALL_CMD = 'sg-install pip requests';
