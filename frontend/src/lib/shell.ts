import { licenseText, licenseTone } from './auth';
import { dest, FRESH, installDest, type Dest } from './nav';
import type { Blocklist, Case, Info, InstallSession, License, Proposal, Rule, Scan, Verdict } from './types';
import { caseLabel, INSTALL_STATUS_LABEL } from './types';

// 셸 2차(10/20 W10 → React W19) — 목업 shared/shell-plus.js 의 계산 부분. 화면 없이 테스트 가능한 순수 함수만 둔다.

// ── 저장소(이 브라우저) ──
export function loadJSON<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v === null ? fallback : (JSON.parse(v) as T);
  } catch {
    return fallback;
  }
}
export function saveJSON(key: string, v: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(v));
  } catch {
    /* 저장 차단 */
  }
}

// 키보드 단축키를 받지 않을 때: 입력 중 · 대화상자가 열려 있음
export function typingTarget(e: KeyboardEvent) {
  const t = e.target as HTMLElement | null;
  return !!t && (/^(input|textarea|select)$/i.test(t.tagName) || t.isContentEditable);
}
export const dialogOpen = () => !!document.querySelector('dialog[open]');

// ── C. 알림 센터 ──
// 읽음은 「알림 id → 그때의 서명」. 서명이 바뀌면(건이 늘면 · 실패 수가 오르면) 다시 안 읽음
export const NOTICE_READ_KEY = 'supplyguard.notices.read';
export type NoticeTone = 'danger' | 'warn' | 'info';
export interface Notice {
  id: 'pending' | 'proposals' | 'conn' | 'dns' | 'dryrun' | 'webhook' | 'license' | 'violations';
  sig: string;
  tone: NoticeTone;
  title: string;
  text: string;
  to: string;
}
export interface NoticeInput {
  cases: Case[] | null;
  proposals: Proposal[] | null;
  down: boolean; // 실시간 연결 끊김(한 번 붙은 뒤)
  info: Info | null;
  enforceKill: boolean | undefined; // stats 가 있으면 stats 값
  license: License | null;
  noAuth: boolean;
  unseen: number; // 새 위반(목업 C 의 「새 위반」 — 종의 이벤트 바로가기를 옮긴 것)
  now?: number;
}
export function computeNotices(x: NoticeInput): Notice[] {
  const out: Notice[] = [];
  const open = (x.cases ?? []).filter((c) => c.state === 'open');
  if (open.length)
    out.push({ id: 'pending', sig: open.map((c) => c.id).join(','), tone: 'danger', title: `판정 대기 ${open.length}건`, text: open.slice(0, 3).map(caseLabel).join(' · '), to: '/' });
  const drafts = (x.proposals ?? []).filter((p) => p.state === 'draft');
  if (drafts.length)
    out.push({ id: 'proposals', sig: drafts.map((p) => p.id).join(','), tone: 'warn', title: `적용하지 않은 제안 ${drafts.length}건`, text: '정책에서 미리보기 후 적용하거나 버리세요', to: `/policies?proposal=${encodeURIComponent(drafts[0].id)}` });
  if (x.down) out.push({ id: 'conn', sig: 'down', tone: 'danger', title: '실시간 연결 끊김', text: '다시 연결하는 중, 끊긴 동안의 이벤트는 다시 붙으면 채웁니다', to: '/events' });
  if (x.info?.dnsResolve === 'off')
    out.push({ id: 'dns', sig: 'off', tone: 'warn', title: '도메인 판단 꺼짐', text: '도메인 조회 감시가 뜨지 않아 도메인 기준 규칙과 DNS 질의 규칙이 통과 처리됩니다', to: '/settings' });
  // 11/09 G38: 설정 이름(ENFORCE_KILL)은 설정 화면 보조 글로만 — 여기는 쉬운 말
  if (x.enforceKill === false)
    out.push({ id: 'dryrun', sig: 'off', tone: 'warn', title: '격리 꺼짐 · 알림만(dry-run)', text: '「즉시 격리」 정책도 알림만 보냅니다(서버 설정 「자동 격리」)', to: '/settings' });
  const n = x.info?.notify;
  if (n?.enabled && n.failed > 0)
    out.push({ id: 'webhook', sig: String(n.failed), tone: 'danger', title: `알림 발송 실패 ${n.failed}건`, text: n.lastError || '설정 › 서버 설정 › 알림에서 마지막 오류를 확인하세요', to: '/settings' });
  if (!x.noAuth && x.license) {
    const tone = licenseTone(x.license, x.now);
    if (tone === 'warn' || tone === 'danger')
      out.push({
        id: 'license',
        sig: `${tone}:${x.license.expiresAt}`,
        tone: tone === 'danger' ? 'danger' : 'warn',
        title: tone === 'danger' ? '라이선스 만료' : licenseText(x.license, x.now).replace(/^.* · /, '라이선스 '),
        text: tone === 'danger' ? '관리자가 새 라이선스를 등록해야 합니다' : '만료 전에 새 라이선스를 등록하세요',
        to: '/settings?tab=license',
      });
  }
  if (x.unseen > 0)
    out.push({ id: 'violations', sig: String(x.unseen), tone: 'info', title: `새 위반 ${x.unseen > 99 ? '99+' : x.unseen}건`, text: '이벤트에서 실시간 위반 보기', to: '/events' });
  return out;
}

// ── 화면 이름(11/09) — 머리 제목 · 하위 화면 위치(G17 「정책 ›」 · 11/09 밤 「연동 ›」) · 통합 검색 「화면」(G07)이 같은 표를 쓴다. 이름은 사이드바와 같다 ──
// where = 사이드바 묶음, parent = 하위 화면의 상위, search: false = 검색에 넣지 않음(건 보고서는 건을 골라 연다), demo = 관리자 + 시연 켜짐일 때만
export interface ScreenInfo {
  to: string;
  label: string;
  where?: string;
  parent?: string;
  search?: false;
  demo?: true;
}
export const SCREENS: ScreenInfo[] = [
  { to: '/', label: '대시보드' },
  { to: '/integration', label: '연동' },
  { to: '/integration/env', label: '환경 점검', parent: '/integration' },
  { to: '/integration/watch', label: '감시 중 컨테이너', parent: '/integration' },
  { to: '/demo', label: '시연', demo: true },
  { to: '/installs', label: '설치 검사', where: '설치 검사' },
  { to: '/scans', label: '공급망 검사', where: '설치 검사' },
  { to: '/evaluation', label: '평가', where: '설치 검사' },
  { to: '/events', label: '이벤트', where: '런타임 감시' },
  { to: '/topology', label: '토폴로지', where: '런타임 감시' },
  { to: '/policies', label: '정책', where: '설정 · 기록' },
  { to: '/policies/blocklist', label: '차단 목록', where: '설정 · 기록', parent: '/policies' },
  { to: '/policies/changes', label: '변경 이력', where: '설정 · 기록', parent: '/policies' },
  { to: '/audit', label: '감사 로그', where: '설정 · 기록' },
  { to: '/settings', label: '설정', where: '설정 · 기록' },
  { to: '/report', label: '건 보고서', search: false },
];
export const screenOf = (path: string) => SCREENS.find((x) => x.to === path);
// 검색 결과 보조 줄 = 사이드바 위치(묶음 › 상위)
const screenWhere = (x: ScreenInfo) => [x.where, x.parent && screenOf(x.parent)?.label].filter(Boolean).join(' › ');

// ── E. 통합 검색 — 화면 · 패키지 · 컨테이너 · 규칙 id · 도메인 · 검사(화면이 이미 쓰는 목록 API 로 클라이언트 검색) ──
// 종류 순서 = 결과 순서 — 화면 이름이 맨 앞(11/09 G07)
export type SearchType = 'screen' | 'package' | 'container' | 'rule' | 'domain' | 'scan';
export const SEARCH_TYPE_KO: Record<SearchType, string> = { screen: '화면', package: '패키지', container: '컨테이너', rule: '규칙', domain: '도메인', scan: '검사' };
// to · state(그 화면의 초기 필터 — 주소에 남기지 않는다, 10/21)
export interface SearchItem extends Dest {
  type: SearchType;
  label: string;
  sub: string;
}
export interface SearchSources {
  screens?: ScreenInfo[]; // 보여 줄 화면(권한 · 시연 켜짐은 부르는 쪽이 거른다)
  installs?: InstallSession[] | null;
  scans?: Scan[] | null;
  rules?: Rule[] | null;
  blocklist?: Blocklist | null;
  containers?: string[];
  verdicts?: Verdict[];
}
const enc = encodeURIComponent;
export const searchKey = (x: Pick<SearchItem, 'type' | 'label' | 'to' | 'state'>) => `${x.type}|${x.label}|${x.to}|${JSON.stringify(x.state?.filters ?? {})}`;
export function buildIndex(s: SearchSources): SearchItem[] {
  const out: SearchItem[] = [];
  const seen = new Set<string>();
  const add = (type: SearchType, label: string, sub: string, d: Dest | string) => {
    const x = typeof d === 'string' ? { to: d } : d;
    const k = searchKey({ type, label, ...x });
    if (!label || seen.has(k)) return;
    seen.add(k);
    out.push({ type, label, sub, ...x });
  };
  for (const sc of s.screens ?? []) if (sc.search !== false) add('screen', sc.label, screenWhere(sc), { to: sc.to, state: FRESH });
  for (const i of s.installs ?? []) for (const p of i.packages) add('package', `${i.manager} ${p}`, `설치 검사 ${i.id} · ${INSTALL_STATUS_LABEL[i.status] ?? i.status}`, installDest(i.id));
  for (const b of s.blocklist?.packages ?? []) add('package', b.value, '차단 목록', '/policies/blocklist');
  for (const sc of s.scans ?? []) if (sc.target.name) add('package', `${sc.target.manager ?? ''} ${sc.target.name}`.trim(), `공급망 검사 ${sc.id}`, `/scans?id=${enc(sc.id)}`);
  for (const c of s.containers ?? []) add('container', c, '런타임 · 토폴로지', dest('/topology', { container: c }));
  for (const i of s.installs ?? []) if (i.container) add('container', i.container, `설치 검사 · ${i.manager} ${i.packages.join(' ')}`, installDest(i.id));
  for (const r of s.rules ?? []) add('rule', r.id, r.description ?? '', `/policies?id=${enc(r.id)}`);
  for (const b of s.blocklist?.hosts ?? []) add('domain', b.value, '차단 목록', '/policies/blocklist');
  for (const r of s.rules ?? [])
    for (const [f, ko] of [['allowHosts', '허용'], ['denyHosts', '금지']] as const) for (const d of r[f] ?? []) add('domain', d, `${r.id} · ${ko} 도메인`, `/policies?id=${enc(r.id)}`);
  for (const v of s.verdicts ?? []) if (v.event.dstHost) add('domain', v.event.dstHost, `이벤트 · ${v.event.containerName}`, dest('/events', { container: v.event.containerName }));
  for (const sc of s.scans ?? []) add('scan', `${sc.id} · ${sc.target.label}`, sc.status === 'done' ? '공급망 검사 결과' : sc.status === 'failed' ? '검사 실패' : '검사 중', `/scans?id=${enc(sc.id)}`);
  return out;
}
// 종류 순서대로, 종류마다 6개까지 · 앞에서 맞는 것 먼저
export function searchIndex(index: SearchItem[], query: string, per = 6): SearchItem[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const hit = index.filter((x) => x.label.toLowerCase().includes(q) || x.sub.toLowerCase().includes(q));
  const starts = (x: SearchItem) => (x.label.toLowerCase().startsWith(q) ? 0 : 1);
  return (Object.keys(SEARCH_TYPE_KO) as SearchType[]).flatMap((t) =>
    hit
      .filter((x) => x.type === t)
      .sort((a, b) => starts(a) - starts(b))
      .slice(0, per),
  );
}

// ── D. 끊긴 구간 채우기 — 같은 이벤트(시각 · 컨테이너 · 종류 · 상세 · pid)는 한 번만 ──
export function verdictKey(v: Verdict) {
  const e = v.event;
  // dns(10/30)는 질의 이름 · 유형으로 구분한다(네임서버 IP:53 은 모두 같다)
  const detail = e.kind === 'dns' ? `${e.dstHost ?? ''}/${e.qtype ?? ''}` : (e.args ?? e.path ?? (e.dstIp ? `${e.dstIp}:${e.dstPort ?? ''}` : ''));
  return `${e.timestamp}|${e.containerId || e.containerName}|${e.kind}|${detail}|${e.pid}`;
}
// recent(최신 먼저)에서 이미 가진 것(have)을 빼고, 가진 것 중 가장 오래된 것보다 새 것만 — 오래된 기록을 다시 끌어오지 않는다
export function gapOf(recent: Verdict[], have: Verdict[]): Verdict[] {
  const keys = new Set(have.map(verdictKey));
  const oldest = have.length ? Math.min(...have.map((v) => Date.parse(v.event.timestamp))) : -Infinity;
  const out: Verdict[] = [];
  for (const v of recent) {
    const k = verdictKey(v);
    if (keys.has(k) || Date.parse(v.event.timestamp) < oldest) continue;
    keys.add(k);
    out.push(v);
  }
  return out;
}
// 최신 먼저로 합친다(같은 시각이면 원래 순서)
export function mergeByTime<T extends Verdict>(a: T[], b: T[], max: number): T[] {
  const keys = new Set(a.map(verdictKey));
  const all = [...a, ...b.filter((v) => !keys.has(verdictKey(v)))];
  return all
    .map((v, i) => ({ v, i, t: Date.parse(v.event.timestamp) }))
    .sort((x, y) => y.t - x.t || x.i - y.i)
    .map((x) => x.v)
    .slice(0, max);
}
