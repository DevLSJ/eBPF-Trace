'use client';
import { cn } from '@/lib/utils';

// gateway 전처리 형식(diff --- path (status, +a -d) + GitHub patch)을 파일별로 그린다.
// 근거 줄 강조: AI 근거 = 적색, 정적 룰 = 황색 (docs/06 §4). 강조된 줄에는 id를 달아 근거 클릭 시 스크롤.

export interface Mark { file: string; hint: string; kind: 'llm' | 'rule'; key: string }

interface Line { kind: 'add' | 'del' | 'ctx' | 'hunk' | 'note'; text: string; newNo?: number; oldNo?: number }
interface FileBlock { path: string; meta: string; lines: Line[] }

const HDR = /^diff --- (.+?) \((\w+), (\+\d+ -\d+)\)$/;

export function parseDiff(text: string): FileBlock[] {
  const files: FileBlock[] = [];
  let cur: FileBlock | null = null;
  let oldNo = 0;
  let newNo = 0;
  for (const raw of text.split('\n')) {
    const m = raw.match(HDR);
    if (m) {
      cur = { path: m[1], meta: `${m[2]} · ${m[3]}`, lines: [] };
      files.push(cur);
      continue;
    }
    if (!cur) continue;
    const h = raw.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (h) {
      oldNo = Number(h[1]);
      newNo = Number(h[2]);
      cur.lines.push({ kind: 'hunk', text: raw });
    } else if (raw.startsWith('…[')) {
      cur.lines.push({ kind: 'note', text: raw });
    } else if (raw.startsWith('+')) {
      cur.lines.push({ kind: 'add', text: raw.slice(1), newNo: newNo++ });
    } else if (raw.startsWith('-')) {
      cur.lines.push({ kind: 'del', text: raw.slice(1), oldNo: oldNo++ });
    } else if (raw.length) {
      cur.lines.push({ kind: 'ctx', text: raw.slice(1), oldNo: oldNo++, newNo: newNo++ });
    }
  }
  return files;
}

const norm = (s: string) => s.replace(/…$/, '').replace(/\s+/g, ' ').trim();

// 근거 문자열이 이 줄을 가리키는가: 공백을 줄여 서로 포함 관계면 일치
function matches(line: string, hint: string): boolean {
  const a = norm(line);
  const b = norm(hint);
  if (b.length < 4 || !a) return false;
  return a.includes(b) || (b.includes(a) && a.length >= 12);
}

export function markId(key: string) {
  return `mark-${key}`;
}

export function DiffView({ text, marks }: { text: string; marks: Mark[] }) {
  const files = parseDiff(text);
  if (!files.length) return <div className="p-6 text-[13px] text-fg-3">표시할 변경 내용이 없습니다.</div>;
  const placed = new Set<string>(); // 근거마다 첫 일치 줄에만 id
  return (
    <div className="flex flex-col gap-3">
      {files.map((f) => {
        const fileMarks = marks.filter((mk) => mk.file === f.path || f.path.endsWith(mk.file) || mk.file.endsWith(f.path));
        return (
          <div key={f.path} className="overflow-hidden rounded-lg border border-line">
            <div className="flex items-center justify-between gap-2 border-b border-line bg-surface-2 px-3 py-1.5 text-[12px]">
              <span className="truncate font-mono font-semibold">{f.path}</span>
              <span className="shrink-0 text-fg-3">{f.meta}</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse font-mono text-[12px] leading-[1.55]">
                <tbody>
                  {f.lines.map((ln, i) => {
                    if (ln.kind === 'hunk' || ln.kind === 'note') {
                      return (
                        <tr key={i} className="bg-info-soft/40 text-fg-3">
                          <td colSpan={3} className="px-3 py-0.5">{ln.text}</td>
                        </tr>
                      );
                    }
                    const hit = ln.kind !== 'del' ? fileMarks.filter((mk) => matches(ln.text, mk.hint)) : fileMarks.filter((mk) => mk.kind === 'rule' && matches(ln.text, mk.hint));
                    const llm = hit.some((h) => h.kind === 'llm');
                    const rule = hit.some((h) => h.kind === 'rule');
                    const anchors = hit.filter((h) => !placed.has(h.key));
                    anchors.forEach((h) => placed.add(h.key));
                    return (
                      <tr
                        key={i}
                        id={anchors[0] ? markId(anchors[0].key) : undefined}
                        className={cn(
                          ln.kind === 'add' && 'bg-good-soft/50',
                          ln.kind === 'del' && 'bg-crit-soft/40',
                          rule && 'bg-warn-soft',
                          llm && 'bg-crit-soft',
                        )}
                      >
                        <td className={cn('w-1 p-0', llm ? 'bg-crit' : rule ? 'bg-warn' : '')} />
                        <td className="w-12 select-none px-2 text-right align-top text-fg-3">{ln.newNo ?? ln.oldNo}</td>
                        <td className="whitespace-pre px-2">
                          <span className="select-none text-fg-3">{ln.kind === 'add' ? '+' : ln.kind === 'del' ? '-' : ' '}</span>
                          {ln.text}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        );
      })}
    </div>
  );
}
