// 런타임 허용 목록 편집 (ADR-020 U4). 필드 의미는 apps/agent/whitelist.default.yaml과 같다.

export interface Whitelist {
  service_comms: string[];
  shell_names: string[];
  tool_names: string[];
  benign_comms: string[];
  allowed_dest_cidrs: string[];
  allowed_dest_ports: number[];
}

export type WlKey = keyof Whitelist;
type Kind = 'name' | 'cidr' | 'port';

export interface WlField {
  key: WlKey;
  kind: Kind;
  title: string;
  help: string;
  placeholder: string;
}

// 화면 순서·쉬운 설명. group: 정상으로 볼 것 / 의심으로 볼 것
export const WL_GROUPS: { title: string; help: string; fields: WlField[] }[] = [
  {
    title: '정상으로 볼 것',
    help: '여기 있는 프로그램·접속은 경보를 울리지 않습니다.',
    fields: [
      { key: 'benign_comms', kind: 'name', title: '정상 프로그램', help: '혼자 실행될 때는 문제없는 프로그램 이름 (예: 헬스체크, DB)', placeholder: '예: nginx' },
      { key: 'allowed_dest_cidrs', kind: 'cidr', title: '허용 접속 주소', help: '접속해도 되는 주소나 주소 범위. 주소 하나만 넣으면 그 주소만 허용합니다', placeholder: '예: 10.77.0.0/28 또는 10.77.0.5' },
      { key: 'allowed_dest_ports', kind: 'port', title: '허용 포트', help: '주소와 상관없이 허용할 포트 번호 (예: DNS 53)', placeholder: '예: 53' },
    ],
  },
  {
    title: '의심으로 볼 것',
    help: '아래 조건에 맞으면 경보를 만듭니다.',
    fields: [
      { key: 'service_comms', kind: 'name', title: '앱 실행 프로그램', help: '이 프로그램이 셸을 띄우면 의심합니다', placeholder: '예: node' },
      { key: 'shell_names', kind: 'name', title: '셸 프로그램', help: '셸로 취급할 프로그램 이름', placeholder: '예: bash' },
      { key: 'tool_names', kind: 'name', title: '주의할 도구', help: '서비스 안에서 실행되면 경보를 울릴 도구', placeholder: '예: curl' },
    ],
  },
];

const KINDS: Record<WlKey, Kind> = {
  service_comms: 'name', shell_names: 'name', tool_names: 'name', benign_comms: 'name',
  allowed_dest_cidrs: 'cidr', allowed_dest_ports: 'port',
};

const NAME_RE = /^[A-Za-z0-9._+-]{1,64}$/;

// 입력 1개를 검사·정규화. 문제가 있으면 error에 쉬운 사유.
export function normalizeEntry(kind: Kind, raw: string): { value?: string | number; error?: string } {
  const s = raw.trim();
  if (!s) return { error: '값을 입력하세요' };
  if (kind === 'name') {
    if (!NAME_RE.test(s)) return { error: '프로그램 이름은 영문·숫자·. _ + - 만 쓸 수 있습니다 (경로 없이 이름만)' };
    return { value: s };
  }
  if (kind === 'port') {
    if (!/^\d+$/.test(s)) return { error: '포트는 숫자만 입력하세요' };
    const n = Number(s);
    if (n < 1 || n > 65535) return { error: '포트는 1~65535 사이여야 합니다' };
    return { value: n };
  }
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!m) return { error: '주소는 10.77.0.5 또는 10.77.0.0/28 형태로 입력하세요' };
  if (m.slice(1, 5).some((o) => Number(o) > 255)) return { error: '주소의 각 숫자는 0~255여야 합니다' };
  const prefix = m[5] === undefined ? 32 : Number(m[5]);
  if (prefix > 32) return { error: '/ 뒤의 숫자는 0~32여야 합니다' };
  return { value: `${m.slice(1, 5).map(Number).join('.')}/${prefix}` };
}

// 전체 객체 검사 — 「고급」 글자 편집 저장 때도 같은 규칙을 쓴다.
export function validateWhitelist(input: unknown): { value?: Whitelist; errors: string[] } {
  const errors: string[] = [];
  if (!input || typeof input !== 'object' || Array.isArray(input)) return { errors: ['전체가 { } 로 감싼 객체여야 합니다'] };
  const obj = input as Record<string, unknown>;
  for (const k of Object.keys(obj)) if (!(k in KINDS)) errors.push(`알 수 없는 항목: ${k}`);
  const out = {} as Record<WlKey, (string | number)[]>;
  for (const key of Object.keys(KINDS) as WlKey[]) {
    const list = obj[key];
    if (!Array.isArray(list)) { errors.push(`${fieldTitle(key)}(${key}) 목록이 없습니다`); continue; }
    const seen = new Set<string>();
    out[key] = [];
    for (const item of list) {
      const r = normalizeEntry(KINDS[key], String(item));
      if (r.error) { errors.push(`${fieldTitle(key)} "${String(item)}": ${r.error}`); continue; }
      const id = String(r.value);
      if (seen.has(id)) { errors.push(`${fieldTitle(key)} "${id}"가 중복됐습니다`); continue; }
      seen.add(id);
      out[key].push(r.value!);
    }
  }
  return errors.length ? { errors } : { value: out as unknown as Whitelist, errors };
}

export function fieldTitle(key: WlKey): string {
  for (const g of WL_GROUPS) for (const f of g.fields) if (f.key === key) return f.title;
  return key;
}
