import type { AuditEntry, Evidence, EvidenceFile } from '../../lib/types';

// 11/10 증거 파일 등급 — 정상 A · 비정상 F 를 화면에서 계산한다.
//   위반 대상(targets): open 의 경로 · exec 인자 중 / 로 시작하는 토큰(connect · dns 는 없음)
//   위반 토큰(tokens): 대상 경로 + exec 명령 조각(셸 · 인터프리터 · 옵션 제외) · URL 과 그 호스트 + connect 의 IP · 포트 · 도메인 + dns 질의 이름
//   F = 위반 대상이거나, 저장된 설치 스크립트 중 위반 토큰이 든 줄이 있는 파일
export interface Marks {
  targets: Set<string>;
  tokens: string[];
}

// 어디에나 흔한 명령 · 경로는 토큰으로 쓰지 않는다(정상 줄까지 빨개지지 않게)
const STOP = new Set(['sh', 'bash', 'dash', 'zsh', 'ash', 'busybox', 'env', 'exec', 'python', 'python3', 'node', 'npm', 'npx', 'pip', 'pip3', 'cargo', 'sudo', 'nohup', 'true', 'false']);
const IGNORE_PATHS = new Set(['/dev/null', '/dev/stdout', '/dev/stderr', '/dev/stdin', '/']);
const IP = /^\d{1,3}(\.\d{1,3}){3}$/;
const norm = (p: string) => (p.length > 1 ? p.replace(/\/+$/, '') : p);

export function violationMarks(vs: AuditEntry[]): Marks {
  const targets = new Set<string>();
  const tokens = new Set<string>();
  const addTarget = (p?: string) => {
    if (!p) return;
    const n = norm(p);
    if (IGNORE_PATHS.has(n)) return;
    targets.add(n);
    tokens.add(n);
  };
  for (const v of vs) {
    const e = v.event;
    if (e.kind === 'open') addTarget(e.path);
    else if (e.kind === 'exec') {
      const base = (e.comm ?? '').split('/').pop() ?? '';
      if (base.length >= 3 && !STOP.has(base)) tokens.add(base);
      for (const t of (e.args ?? '').split(/[\s|;&<>()'"`]+/)) {
        if (!t) continue;
        if (t.startsWith('/')) addTarget(t);
        else if (t.includes('://')) {
          tokens.add(t);
          try {
            const h = new URL(t).hostname;
            if (h) tokens.add(h);
          } catch {
            /* 주소 모양이 아니면 조각 그대로만 */
          }
        } else if (IP.test(t)) tokens.add(t);
        else if (!t.startsWith('-') && t.length >= 3 && !t.includes('=') && !STOP.has(t.split('/').pop() ?? t)) tokens.add(t);
      }
    } else if (e.kind === 'connect') {
      if (e.dstIp) tokens.add(e.dstIp);
      if (e.dstPort) tokens.add(String(e.dstPort));
      if (e.dstHost) tokens.add(e.dstHost);
    } else if (e.kind === 'dns') {
      if (e.dstHost) tokens.add(e.dstHost);
    }
  }
  // 긴 토큰부터(한 줄 강조 표시는 가장 긴 조각)
  return { targets, tokens: [...tokens].sort((a, b) => b.length - a.length) };
}

// 앞뒤가 이어진 글자(영숫자 · _ · . · -)이면 조각이 아니다 — 4444 가 14444 에, curl 이 libcurl 에 걸리지 않게
const JOIN_BEFORE = /[\w.-]/;
const JOIN_AFTER = /[\w-]/;
// 줄에서 가장 앞에 나온 위반 토큰 — 없으면 null
export function findToken(line: string, tokens: string[]): { at: number; token: string } | null {
  let best: { at: number; token: string } | null = null;
  for (const t of tokens) {
    for (let i = line.indexOf(t); i >= 0; i = line.indexOf(t, i + 1)) {
      if (i > 0 && JOIN_BEFORE.test(line[i - 1])) continue;
      const after = line[i + t.length];
      if (after && JOIN_AFTER.test(after)) continue;
      if (!best || i < best.at) best = { at: i, token: t };
      break;
    }
  }
  return best;
}

export const hitLines = (f: EvidenceFile, tokens: string[]) => {
  const out = new Set<number>();
  if (!tokens.length) return out;
  f.content.split('\n').forEach((ln, i) => {
    if (findToken(ln, tokens)) out.add(i + 1);
  });
  return out;
};

const KIND_TITLE: Record<string, string> = { A: '추가된 파일', C: '변경된 파일', D: '삭제된 파일' };
export const TARGET_TITLE = '위반 대상(읽기 · 실행)';

export interface GradedRow {
  path: string;
  kind?: string; // docker diff 종류(A · C · D) — diff 에 없던 새 줄은 없음
  grade: 'A' | 'F';
  title: string;
  saved?: EvidenceFile;
  hits: number;
}

// diff + diff 에 없는 위반 대상 + diff 에 없는 저장 스크립트를 한 목록으로(F 먼저, 그 안은 원래 순서)
export function gradeRows(ev: Evidence, m: Marks): GradedRow[] {
  const files = new Map((ev.files ?? []).map((f) => [f.path, f]));
  const rows = new Map<string, GradedRow>();
  const make = (path: string, kind?: string): GradedRow => {
    const saved = files.get(path);
    const hits = saved ? hitLines(saved, m.tokens).size : 0;
    const target = m.targets.has(norm(path));
    const why = [kind ? (KIND_TITLE[kind] ?? kind) : saved ? '저장된 설치 스크립트' : '', target ? TARGET_TITLE : '', hits ? '위반 관련 줄 있음' : ''].filter(Boolean);
    return { path, kind, grade: target || hits ? 'F' : 'A', title: why.join(' · '), saved, hits };
  };
  for (const c of ev.changes ?? []) if (!rows.has(c.path)) rows.set(c.path, make(c.path, c.kind));
  for (const p of m.targets) if (!rows.has(p)) rows.set(p, make(p));
  for (const p of files.keys()) if (!rows.has(p)) rows.set(p, make(p));
  const list = [...rows.values()];
  return [...list.filter((r) => r.grade === 'F'), ...list.filter((r) => r.grade === 'A')];
}
