import { dest, type Dest } from './nav';
import type { DirectIp, Event, Kind, Rule, RuleKind, SingleRule } from './types';

// 정책 「쉬운 설정」 로직(목업 mock/shared/policy-easy.js 확정, 2026-10-16) — 화면은 components/PolicyEasy.tsx
// draft 는 고급 폼과 같은 모양(목록 필드 = 한 줄에 하나)이라 쉬운 설정 · 폼 · YAML 을 오가도 값이 그대로다.

export type ListField =
  | 'containers'
  | 'denyComms'
  | 'denyArgs'
  | 'denyPaths'
  | 'allowPaths'
  | 'allowPorts'
  | 'allowCidrs'
  | 'denyPorts'
  | 'denyCidrs'
  | 'allowHosts'
  | 'denyHosts'
  | 'denyQtypes';

// dns(10/30) 숫자 조건 — 입력 칸 값은 문자열('' = 쓰지 않음)
export type NumField = 'maxLabelLength' | 'maxNameLength';
export const NUM_FIELDS: { field: NumField; label: string; max: number; hint: string }[] = [
  { field: 'maxLabelLength', label: '라벨 길이 상한', max: 63, hint: '1~63 · 점으로 나뉜 한 덩어리가 넘으면 위반(유출 의심)' },
  { field: 'maxNameLength', label: '이름 길이 상한', max: 253, hint: '1~253 · 전체 이름이 넘으면 위반' },
];

export interface Draft {
  id: string;
  description: string;
  kind: Kind;
  action: Rule['action'];
  // 도메인 조회 없는 IP 직접 연결(connect, 10/20) — '' = 쓰지 않음(옛 동작). 고급 폼 · YAML 에서 고친다
  directIp: DirectIp | '';
  dryRun: boolean;
  disabled: boolean;
  lists: Record<ListField, string>;
  // dns 만(10/30) — 라벨 · 이름 길이 상한
  maxLabelLength: string;
  maxNameLength: string;
}

export const KIND_FIELDS: Record<Kind, ListField[]> = {
  exec: ['denyComms', 'denyArgs'],
  open: ['denyPaths', 'allowPaths'],
  connect: ['allowPorts', 'allowCidrs', 'allowHosts', 'denyPorts', 'denyCidrs', 'denyHosts'],
  // dns(10/30): 도메인 목록은 connect 와 같은 필드를 재사용(접미사 일치), 질의 유형은 대문자 목록
  dns: ['allowHosts', 'denyHosts', 'denyQtypes'],
};
export const ALL_LIST_FIELDS: ListField[] = ['containers', ...new Set(Object.values(KIND_FIELDS).flat())];
const PORT_FIELDS: ListField[] = ['allowPorts', 'denyPorts'];

// 단일 규칙만(연쇄 규칙은 단계가 있어 YAML 로만 편집한다 — 11/04)
export function toDraft(r: SingleRule): Draft {
  const lists = {} as Record<ListField, string>;
  for (const f of ALL_LIST_FIELDS) lists[f] = ((r[f] as (string | number)[] | undefined) ?? []).join('\n');
  return {
    id: r.id, description: r.description ?? '', kind: r.kind, action: r.action, directIp: r.directIp ?? '', dryRun: !!r.dryRun, disabled: !!r.disabled, lists,
    maxLabelLength: r.maxLabelLength == null ? '' : String(r.maxLabelLength),
    maxNameLength: r.maxNameLength == null ? '' : String(r.maxNameLength),
  };
}

export const listOf = (d: Draft, f: ListField) =>
  d.lists[f]
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
export const withList = (d: Draft, f: ListField, xs: string[]): Draft => ({ ...d, lists: { ...d.lists, [f]: xs.join('\n') } });

// draft → Rule. 지금 종류에 해당하지 않는 조건은 버린다
export function toRule(d: Draft): Rule {
  const rule: Rule = { id: d.id.trim(), kind: d.kind, action: d.action };
  if (d.description.trim()) rule.description = d.description.trim();
  if (d.directIp && d.kind === 'connect') rule.directIp = d.directIp;
  if (d.dryRun) rule.dryRun = true;
  if (d.disabled) rule.disabled = true;
  for (const f of ['containers' as ListField, ...KIND_FIELDS[d.kind]]) {
    const items = listOf(d, f);
    if (!items.length) continue;
    if (PORT_FIELDS.includes(f)) {
      const ports = items.map(Number);
      const bad = items.find((_, i) => !Number.isInteger(ports[i]) || ports[i] < 1 || ports[i] > 65535);
      if (bad) throw new Error(`포트 값 오류: ${bad}`);
      (rule[f] as number[]) = ports;
    } else {
      (rule[f] as string[]) = items;
    }
  }
  // dns 만(10/30): 길이 상한은 1..max 정수. 비우면 쓰지 않는다
  if (d.kind === 'dns') {
    for (const { field, label, max } of NUM_FIELDS) {
      const raw = d[field].trim();
      if (!raw) continue;
      const n = Number(raw);
      if (!Number.isInteger(n) || n < 1 || n > max) throw new Error(`${label}은 1~${max} 사이 정수로 써 주세요`);
      rule[field] = n;
    }
  }
  return rule;
}

export const ID_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

// ── 값 분류 · 형식 검사 ──
export type ChipType = 'port' | 'cidr' | 'host' | 'path' | 'prog' | 'args' | 'name' | 'qtype';
// value: 저장할 값으로 고친 것(질의 유형은 대문자). 없으면 입력 그대로
type Classified = { type: ChipType; value?: string; error?: undefined } | { type?: undefined; value?: undefined; error: string };

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/;
const IPV6 = /^[0-9a-f:]+:[0-9a-f:]*(\/\d{1,3})?$/i;
const HOST = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$/i;

export function classifyConnect(v: string): Classified {
  if (/^\d+$/.test(v)) {
    const n = Number(v);
    return n >= 1 && n <= 65535 ? { type: 'port' } : { error: '포트는 1~65535 사이 숫자로 써 주세요' };
  }
  const m = v.match(IPV4);
  if (m) {
    if ([1, 2, 3, 4].some((i) => Number(m[i]) > 255) || (m[6] && Number(m[6]) > 32)) return { error: 'IP는 0~255 네 덩어리, 대역은 /0~/32 로 써 주세요(예: 10.0.0.0/8)' };
    return { type: 'cidr' };
  }
  if (IPV6.test(v)) return { type: 'cidr' };
  if (HOST.test(v)) return { type: 'host' };
  return { error: '포트(예: 443) · IP나 대역(예: 10.0.0.0/8) · 도메인(예: pypi.org) 중 하나로 써 주세요' };
}
const classifyPath = (v: string): Classified => (v.startsWith('/') ? { type: 'path' } : { error: '/ 로 시작하는 전체 경로로 써 주세요(예: /root/.ssh/)' });
const classifyExec = (v: string): Classified =>
  /[\s|;&>]/.test(v) ? { type: 'args' } : /^[\w.+-]{1,64}$/.test(v) ? { type: 'prog' } : { error: '프로그램 이름(예: curl)이나 명령에 들어갈 글자(예: | sh)로 써 주세요' };
export const classifyName = (v: string): Classified => (/^[\w.*?[\]:/-]+$/.test(v) ? { type: 'name' } : { error: '컨테이너 이름이나 이미지 패턴으로 써 주세요(예: pkg-*)' });
// dns(10/30): 점 없는 영문 토큰은 질의 유형(대문자로 저장), 점 있는 이름은 도메인(접미사 일치)
const QTYPE = /^[a-z][a-z0-9]{0,9}$/i;
export function classifyDns(v: string): Classified {
  if (QTYPE.test(v)) return { type: 'qtype', value: v.toUpperCase() };
  if (HOST.test(v)) return { type: 'host' };
  return { error: '도메인(예: attacker.test) 또는 질의 유형(예: TXT) 으로 써 주세요' };
}
const classifyDnsHost = (v: string): Classified => (HOST.test(v) ? { type: 'host' } : { error: '도메인(예: pypi.org)으로 써 주세요 — *.pypi.org 도 포함됩니다' });

export interface ChipGroupDef {
  label: string;
  hint: string;
  classify: (v: string) => Classified;
  fields: Partial<Record<ChipType, ListField>>;
  suggest: string[];
}

// 종류별 「막을 값」(block) · 「허용 · 예외」(allow). type → 저장 필드
export const GROUPS: Record<Kind, { block: ChipGroupDef; allow?: ChipGroupDef }> = {
  open: {
    block: { label: '막을 파일 · 폴더', hint: '폴더는 끝에 / (예: /root/.ssh/), * 로 여러 개(예: /home/*/.ssh/*)', classify: classifyPath, fields: { path: 'denyPaths' }, suggest: ['/etc/shadow', '/root/.ssh/', '/home/*/.ssh/*', '/root/.aws/credentials'] },
    allow: { label: '예외 — 열어도 되는 파일', hint: '막을 목록보다 먼저 봅니다', classify: classifyPath, fields: { path: 'allowPaths' }, suggest: [] },
  },
  exec: {
    block: { label: '막을 프로그램 · 명령 모양', hint: '프로그램 이름(curl) 또는 명령에 들어간 글자(| sh)', classify: classifyExec, fields: { prog: 'denyComms', args: 'denyArgs' }, suggest: ['curl', 'wget', 'nc', '| sh', '| bash', 'base64 -d'] },
  },
  connect: {
    block: { label: '항상 막을 곳', hint: '포트 · IP나 대역 · 도메인. 허용 목록과 상관없이 위반', classify: classifyConnect, fields: { port: 'denyPorts', cidr: 'denyCidrs', host: 'denyHosts' }, suggest: ['4444', '1337', '31337'] },
    allow: { label: '허용할 곳', hint: '하나라도 넣으면 여기 없는 곳으로 가는 연결은 모두 위반', classify: classifyConnect, fields: { port: 'allowPorts', cidr: 'allowCidrs', host: 'allowHosts' }, suggest: ['443', '80', '53', '10.0.0.0/8', 'pypi.org', 'registry.npmjs.org'] },
  },
  // 10/30 계약 §1 「② 어떤 값」 문구 그대로
  dns: {
    block: { label: '막을 도메인 · 질의 유형', hint: '도메인(예: attacker.test) 또는 질의 유형(TXT) — 허용 목록과 상관없이 위반', classify: classifyDns, fields: { host: 'denyHosts', qtype: 'denyQtypes' }, suggest: ['TXT', 'ALL'] },
    allow: { label: '허용할 도메인', hint: '하나라도 넣으면 여기 없는 도메인 질의는 모두 위반 — 점 없는 이름 · *.arpa 는 제외', classify: classifyDnsHost, fields: { host: 'allowHosts' }, suggest: ['pypi.org', 'registry.npmjs.org', 'github.com'] },
  },
};
export const CONTAINERS_GROUP: ChipGroupDef = { label: '컨테이너', hint: '이름 또는 패턴(예: pkg-*)', classify: classifyName, fields: { name: 'containers' }, suggest: [] };
export const TYPE_LABEL: Record<ChipType, string> = { port: '포트', cidr: '대역', host: '도메인', path: '경로', prog: '프로그램', args: '명령', name: '이름', qtype: '질의 유형' };
export const KIND_TEXT: Record<Kind, [string, string]> = {
  open: ['파일 열기', '어떤 파일 · 폴더를 여는지 봅니다'],
  exec: ['프로그램 실행', '어떤 프로그램 · 명령을 실행하는지 봅니다'],
  connect: ['외부 통신', '어디로 연결하는지 봅니다'],
  dns: ['도메인 조회', '어떤 도메인을 조회하는지 봅니다'],
};
// sequence(11/04): 연쇄 규칙 배지 — 목업 app.js KIND_SHORT 와 같게
export const KIND_SHORT: Record<RuleKind, string> = { open: '파일', exec: '실행', connect: '통신', dns: '조회', sequence: '연쇄' };

export interface Chip {
  type: ChipType;
  value: string;
  field: ListField;
}
export const chipsOf = (d: Draft, g: ChipGroupDef): Chip[] =>
  (Object.entries(g.fields) as [ChipType, ListField][]).flatMap(([type, field]) => listOf(d, field).map((value) => ({ type, value, field })));

export type Act = 'alert' | 'kill' | 'dry';
export const actOf = (d: Pick<Draft, 'action' | 'dryRun'>): Act => (d.action === 'kill' ? (d.dryRun ? 'dry' : 'kill') : 'alert');
export const SANDBOX_SCOPE = 'sg-install-*';
export type Scope = 'all' | 'sandbox' | 'some';
export function scopeOf(d: Draft): Scope {
  const cs = listOf(d, 'containers');
  return !cs.length ? 'all' : cs.every((c) => c === SANDBOX_SCOPE) ? 'sandbox' : 'some';
}
export const actionLabel = (r: Pick<Rule, 'action' | 'dryRun'>) => ({ alert: '알림', kill: '격리', dry: '시험' })[actOf({ action: r.action, dryRun: !!r.dryRun })];

// ── 한 줄 요약 ──
const fmtConn = (xs: Chip[]) => xs.map((c) => (c.type === 'port' ? `포트 ${c.value}` : c.value)).join(' · ');
export function summarize(d: Draft): string {
  const scope = { all: '모든 컨테이너에서', sandbox: '설치 검사 컨테이너에서', some: `${listOf(d, 'containers').join(', ')} 컨테이너에서` }[scopeOf(d)];
  const act = { alert: '알림을 보냅니다', kill: '즉시 격리합니다', dry: '격리 대상으로 표시만 합니다(시험 운영)' }[actOf(d)];
  const g = GROUPS[d.kind];
  const block = chipsOf(d, g.block);
  const allow = g.allow ? chipsOf(d, g.allow) : [];
  let what: string | null = null;
  if (d.kind === 'open') {
    if (block.length) what = `${block.map((c) => c.value).join(', ')} 를 열면${allow.length ? ` (예외: ${allow.map((c) => c.value).join(', ')})` : ''}`;
  } else if (d.kind === 'exec') {
    const p = block.filter((c) => c.type === 'prog').map((c) => c.value);
    const a = block.filter((c) => c.type === 'args').map((c) => `「${c.value}」`);
    if (p.length || a.length) what = [p.length ? `${p.join(', ')} 를 실행하거나` : '', a.length ? `${a.join(', ')} 가 든 명령을 실행하면` : ''].filter(Boolean).join(' ').replace(/하거나$/, '하면');
  } else if (d.kind === 'dns') {
    const hosts = block.filter((c) => c.type === 'host').map((c) => c.value);
    const qts = block.filter((c) => c.type === 'qtype').map((c) => c.value);
    const limits = [d.maxLabelLength.trim() ? `라벨 ${d.maxLabelLength.trim()}자` : '', d.maxNameLength.trim() ? `이름 ${d.maxNameLength.trim()}자` : ''].filter(Boolean);
    const parts = [
      hosts.length ? `${hosts.join(', ')} 을 조회하거나` : '',
      qts.length ? `${qts.join(', ')} 질의를 보내거나` : '',
      limits.length ? `${limits.join(' · ')}를 넘는 이름을 조회하거나` : '',
      allow.length ? `허용한 도메인(${allow.map((c) => c.value).join(', ')}) 밖을 조회하거나` : '',
    ].filter(Boolean);
    if (parts.length) what = parts.join(' ').replace(/거나$/, '면');
  } else {
    const parts = [block.length ? `${fmtConn(block)} 에 연결하${allow.length ? '거나' : '면'}` : '', allow.length ? `허용한 곳(${fmtConn(allow)}) 밖으로 연결하면` : ''].filter(Boolean);
    if (parts.length) what = parts.join(', ');
  }
  const s = what ? `${scope} ${what} ${act}.` : '② 에 값을 넣으면 이 정책이 무엇을 하는지 여기에 보입니다.';
  return d.disabled ? `[꺼짐] ${s}` : s;
}

// ── 목적별 템플릿 ──
export interface Template {
  key: string;
  title: string;
  desc: string;
  rule: SingleRule;
}
export const TEMPLATES: Template[] = [
  { key: 'protect-secrets', title: '비밀 파일 보호', desc: '계정 · SSH 키 · 클라우드 자격 증명 파일을 열면 격리', rule: { id: 'protect-secrets', description: '비밀 파일 보호', kind: 'open', action: 'kill', denyPaths: ['/etc/shadow', '/root/.ssh/', '/home/*/.ssh/*', '/root/.aws/credentials'] } },
  { key: 'no-downloader', title: '내려받기 도구 실행 차단', desc: 'curl · wget · nc 로 무언가를 받아 오면 격리', rule: { id: 'no-downloader', description: '내려받기 도구 실행 차단', kind: 'exec', action: 'kill', denyComms: ['curl', 'wget', 'nc'] } },
  { key: 'pipe-shell', title: '받은 스크립트 바로 실행 차단', desc: '「| sh」 처럼 받은 내용을 바로 셸로 넘기면 격리', rule: { id: 'no-pipe-shell', description: '받은 스크립트 바로 실행 차단', kind: 'exec', action: 'kill', denyArgs: ['| sh', '| bash'] } },
  { key: 'reverse-shell', title: '리버스 셸 포트 차단', desc: '공격자가 흔히 쓰는 포트로 연결하면 격리', rule: { id: 'block-reverse-shell', description: '리버스 셸 포트 차단', kind: 'connect', action: 'kill', denyPorts: [4444, 1337, 31337] } },
  { key: 'egress-allow', title: '허용한 곳만 통신', desc: '웹 · DNS 포트와 내부망이 아닌 연결을 알림', rule: { id: 'egress-allow', description: '허용한 곳만 통신', kind: 'connect', action: 'alert', allowPorts: [80, 443, 53], allowCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] } },
  { key: 'install-registry', title: '설치 중엔 패키지 저장소만', desc: '설치 검사에서 pypi · npm · crates 밖으로 연결하면 격리', rule: { id: 'install-registry-only', description: '설치 중엔 패키지 저장소만', kind: 'connect', action: 'kill', containers: [SANDBOX_SCOPE], allowHosts: ['pypi.org', 'pythonhosted.org', 'registry.npmjs.org', 'crates.io', 'github.com'] } },
  // 10/30 계약 §1 템플릿 — runtime-dns-exfil 값 그대로
  { key: 'dns-exfil', title: 'DNS 유출 패턴 차단', desc: '긴 라벨 · 긴 이름 · TXT 질의를 알림', rule: { id: 'runtime-dns-exfil', description: 'DNS 질의로 데이터를 실어 보내는 패턴(긴 라벨 · 긴 이름 · TXT 질의). 런타임은 경고만', kind: 'dns', action: 'alert', maxLabelLength: 40, maxNameLength: 120, denyQtypes: ['TXT'] } },
  { key: 'blank', title: '빈 정책에서 시작', desc: '무엇을 · 어떤 값을 직접 고릅니다', rule: { id: 'new-policy', description: '', kind: 'open', action: 'alert' } },
];

// 이미 있는 id 면 뒤에 -2, -3 …
export function uniqueId(base: string, existing: string[]): string {
  let id = base;
  for (let n = 2; existing.includes(id); n++) id = `${base}-${n}`;
  return id;
}
export function fromTemplate(key: string, existing: string[]): SingleRule {
  const t = TEMPLATES.find((x) => x.key === key) ?? TEMPLATES[TEMPLATES.length - 1];
  return { ...structuredClone(t.rule), id: uniqueId(t.rule.id, existing) };
}

// ── 이벤트 · 감사 행에서 시작 ── 막기 = 그 행동을 막는 새 정책, 허용 = 걸린 정책에 가장 좁은 예외(오탐 제안과 같은 규칙)
// 미리 채우기(intent · kind · value)는 state 로 넘긴다(10/21) — 주소에는 정책 id 만
export function blockLink(e: Event): Dest | null {
  // dns(10/30): 질의 이름을 금지 도메인으로
  const value = e.kind === 'open' ? e.path : e.kind === 'exec' ? e.comm : e.kind === 'dns' ? e.dstHost : e.dstHost || e.dstIp;
  return value ? dest('/policies?id=__new__', { intent: 'block', kind: e.kind, value }) : null;
}
export function allowLink(rule: Rule | undefined, e: Event): Dest | null {
  // 연쇄 규칙(11/04)은 예외 칸이 단계 안에 있어 「이 행동 허용」을 만들지 않는다(목업 policy-easy.js 와 같게)
  if (!rule || rule.kind === 'exec' || rule.kind === 'sequence' || rule.id === 'blocklist-hosts') return null;
  // dns 규칙은 허용 도메인 목록이 있을 때만(없는 규칙에 첫 allowHosts 를 넣으면 허용 목록 모드로 바뀐다 — 계약 §1 매칭 ⑥)
  if (e.kind === 'dns') return e.dstHost && rule.allowHosts?.length ? dest(`/policies?id=${encodeURIComponent(rule.id)}`, { intent: 'allow', value: e.dstHost }) : null;
  const value = e.kind === 'open' ? e.path : e.dstHost && rule.allowHosts?.length ? e.dstHost : e.dstIp ? `${e.dstIp}/32` : undefined;
  return value ? dest(`/policies?id=${encodeURIComponent(rule.id)}`, { intent: 'allow', value }) : null;
}
export function ruleFromBlock(kind: Kind, value: string, existing: string[]): SingleRule {
  const base = { open: 'block-file', exec: 'block-program', connect: 'block-destination', dns: 'block-domain-query' }[kind];
  const r: SingleRule = { id: uniqueId(base, existing), description: `${value} 막기`, kind, action: 'kill' };
  if (kind === 'open') r.denyPaths = [value];
  else if (kind === 'exec') r.denyComms = [value];
  else if (kind === 'dns') r.denyHosts = [value];
  else if (classifyConnect(value).type === 'host') r.denyHosts = [value];
  else r.denyCidrs = [value.includes('/') ? value : `${value}/32`];
  return r;
}
// 허용 값을 정책의 알맞은 예외 필드에 더한 사본과 그 값(강조용)
export function ruleWithAllow(rule: Rule, value: string): { rule: Rule; fresh: { field: ListField; value: string } | null } {
  if (rule.kind === 'sequence') return { rule, fresh: null }; // 연쇄 규칙(11/04): 예외를 더하지 않는다
  const g = GROUPS[rule.kind].allow;
  if (!g) return { rule, fresh: null };
  const c = g.classify(value);
  if (!c.type) return { rule, fresh: null };
  const f = g.fields[c.type]!;
  const r = structuredClone(rule);
  const cur = (r[f] as (string | number)[] | undefined) ?? [];
  const val = c.value ?? value;
  const v = PORT_FIELDS.includes(f) ? Number(val) : val;
  if (!cur.includes(v)) (r[f] as (string | number)[]) = [...cur, v];
  return { rule: r, fresh: { field: f, value: val } };
}
