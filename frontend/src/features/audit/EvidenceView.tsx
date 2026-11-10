import { FileSearch } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useAutoRetry } from '../../components/list/hooks';
import { EmptyState, ListError, Skeleton } from '../../components/list/ListStates';
import { Section } from '../../components/Sheet';
import { useLoad } from '../../hooks/useLoad';
import { api } from '../../lib/api';
import { shortId } from '../../lib/format';
import { TimeText } from '../../components/list/cells';
import { CodeWindow, CW_BODY } from '../../components/CodeWindow';
import { FileTree, type TreeItem } from '../../components/FileTree';
import type { AuditEntry, Evidence, EvidenceFile } from '../../lib/types';
import { findToken, gradeRows, hitLines, violationMarks, type GradedRow, type Marks } from './evidenceGrade';

const NOT_SAVED = '이 파일 내용은 저장되지 않았습니다(설치 스크립트만 격리 직전에 저장합니다).';
const gradeLabel = (r: GradedRow) => `${r.grade === 'F' ? '비정상(F)' : '정상(A)'}, ${r.title}`;

// 감사 상세 「증거」 탭(10/20 I) — GET /api/evidence?container=<이름>(최근 것부터). 같은 이름으로 여러 번 뜬 컨테이너는 ID 별로 묶고,
// 이 행의 컨테이너 ID 묶음을 맨 위에 둔다. 증거는 격리(kill) 직전에만 모은다 — 로그 마지막 200줄 · docker diff · docker top · 설치 스크립트(11/10)
export function EvidenceView({ a }: { a: AuditEntry }) {
  const name = a.event.containerName;
  const load = useCallback(() => api.evidence(name), [name]);
  const r = useLoad(load);
  // 11/10 등급 계산용 — 이 컨테이너의 위반 기록(백엔드 필터는 부분 일치라 이름이 완전히 같은 것만). 못 받으면 이 행 하나로
  const loadV = useCallback(() => api.audit({ container: name, limit: 500 }), [name]);
  const v = useLoad(loadV);
  const marks = useMemo(() => {
    const vs = new Map<number, AuditEntry>([[a.id, a]]);
    for (const x of v.data ?? []) if (x.event.containerName === name) vs.set(x.id, x);
    return violationMarks([...vs.values()]);
  }, [a, v.data, name]);
  useAutoRetry(!!r.error && !r.data, r.error, r.reload); // 오류 칸의 「30초마다」 문구대로
  if (r.error && !r.data) return <ListError error={r.error} what="증거" onRetry={r.reload} retrying={r.loading} />;
  if (!r.data || (!v.data && !v.error)) return <Skeleton rows={4} />;
  if (!r.data.length)
    return (
      <div data-part="evidence-empty">
        <EmptyState icon={FileSearch} title="이 컨테이너의 증거가 없습니다." hint="증거(로그 · 파일 변경 · 프로세스)는 격리(kill) 직전에만 모읍니다. 경고만 있었거나 격리 전에 컨테이너가 끝났으면 없습니다." />
      </div>
    );
  const groups = new Map<string, Evidence[]>();
  for (const ev of r.data) groups.set(ev.containerId, [...(groups.get(ev.containerId) ?? []), ev]);
  const mine = a.event.containerId;
  const order = [...groups.keys()].sort((x, y) => Number(sameId(y, mine)) - Number(sameId(x, mine)));
  return (
    <div className="text-sm" data-part="evidence">
      {order.map((cid) => {
        const current = sameId(cid, mine);
        return (
          <Section
            key={cid}
            title={
              <span className="flex items-center gap-2">
                컨테이너 <span className="font-mono">{shortId(cid)}</span>
                {current ? <span className="rounded bg-indigo-50 px-1.5 py-0.5 text-xs text-accent-text">이 기록</span> : <span className="text-xs font-normal text-slate-400">같은 이름 · 다른 실행</span>}
              </span>
            }
          >
            <div className="grid gap-3" data-evidence-group={cid} data-current={String(current)}>
              {groups.get(cid)!.map((ev) => (
                <EvidenceCard key={ev.id} ev={ev} marks={marks} />
              ))}
            </div>
          </Section>
        );
      })}
    </div>
  );
}

const sameId = (a: string, b: string) => !!a && !!b && (a.startsWith(b) || b.startsWith(a));

function EvidenceCard({ ev, marks }: { ev: Evidence; marks: Marks }) {
  const procs = ev.processes ?? [];
  return (
    <article className="grid gap-2 rounded-md border border-slate-200 p-3" data-evidence={ev.id}>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-slate-600">
          <TimeText value={ev.collectedAt} kind="log" />
        </span>
        <span className="text-slate-400">· {ev.durationMs}ms</span>
        {ev.partial ? (
          <span className="rounded bg-amber-100 px-1.5 py-0.5 text-amber-800" data-part="evidence-partial" title={ev.error}>
            일부만 모음
          </span>
        ) : (
          <span className="rounded bg-emerald-50 px-1.5 py-0.5 text-emerald-700">모두 모음</span>
        )}
      </div>
      {ev.error && (
        <p className="rounded bg-amber-50 px-2 py-1 text-xs text-amber-800" data-part="evidence-error">
          빠진 부분: {ev.error}
        </p>
      )}
      <div>
        <h4 className="mb-1 text-xs font-semibold text-slate-700">
          로그 <span className="font-normal text-slate-400">(마지막 200줄)</span>
        </h4>
        {/* 11/04f 코드 창(R1 11/04) — 파일명 없음 · log · 줄바꿈 */}
        <CodeWindow lang="log" wrap bodyClassName="ev-logs">
          <span data-part="evidence-logs">{ev.logs || '(비어 있음)'}</span>
        </CodeWindow>
      </div>
      <div>
        <h4 className="mb-1 text-xs font-semibold text-slate-700">
          파일 변경 <span className="font-normal text-slate-400">(docker diff · A 정상 · F 비정상)</span>
        </h4>
        <FileChanges ev={ev} marks={marks} />
      </div>
      <div>
        <h4 className="mb-1 text-xs font-semibold text-slate-700">
          프로세스 <span className="font-normal text-slate-400">(docker top)</span>
        </h4>
        {procs.length ? (
          <table className="sg-table" data-part="evidence-procs">
            <thead>
              <tr>
                <th className="tk-short">PID</th>
                <th className="tk-short">사용자</th>
                <th>명령</th>
              </tr>
            </thead>
            <tbody>
              {procs.map((p, i) => (
                <tr key={i}>
                  <td className="num tk-short">{p.pid}</td>
                  <td className="tk-short">{p.user}</td>
                  <td className="font-mono break-all">{p.cmd}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-xs text-slate-400" data-part="evidence-procs">
            {ev.partial ? '모으지 못함, 위 안내 참고' : '없음'}
          </p>
        )}
      </div>
    </article>
  );
}

// 11/10 파일 변경 — 등급 A(정상) · F(비정상). docker diff 종류(A 추가 · C 변경 · D 삭제)는 툴팁 · aria · data-change-kind 로만.
//   트리: 여러 폴더에 걸치거나 저장된 설치 스크립트(files)가 있을 때. 폴더는 접힌 채 시작, F 가 든 폴더만 펼침 · F 가 같은 층에서 먼저
//   files 가 있으면 파일을 눌러 오른쪽(좁으면 아래) 코드 창으로 — 처음은 내용이 있는 F 파일(없으면 첫 저장 파일). 없으면 트리만(옛 증거)
//   한 폴더 안 몇 줄이면 예전 표(F 먼저)
function FileChanges({ ev, marks }: { ev: Evidence; marks: Marks }) {
  const rows = useMemo(() => gradeRows(ev, marks), [ev, marks]);
  const files = ev.files ?? [];
  const bad = rows.filter((r) => r.grade === 'F');
  const [sel, setSel] = useState<string | null>(() => (bad.find((r) => r.saved) ?? rows.find((r) => r.saved))?.path ?? null);
  const items = useMemo<TreeItem[]>(
    () =>
      rows.map((r) => ({
        path: r.path,
        diff: r.kind,
        rank: r.grade === 'F' ? 1 : 0,
        badge: {
          text: r.grade,
          cls: r.grade === 'F' ? 'ev-bad' : 'ev-ok',
          title: r.title,
          attrs: { 'aria-label': gradeLabel(r), 'data-grade': r.grade, ...(r.kind ? { 'data-change-kind': r.kind } : {}) },
        },
      })),
    [rows],
  );
  if (!rows.length)
    return (
      <p className="text-xs text-slate-400" data-part="evidence-changes">
        없음
      </p>
    );
  const sum = (
    <p className="mb-1 text-xs text-slate-600" data-part="evidence-grade-sum">
      <span className={bad.length ? 'font-semibold text-danger-text' : ''}>비정상 {bad.length.toLocaleString('ko-KR')}개</span> · 정상 {(rows.length - bad.length).toLocaleString('ko-KR')}개
    </p>
  );
  // 표 · 트리 기준은 diff · 저장 파일 경로(위반 대상만인 새 줄은 어느 쪽이든 함께 나온다)
  const own = rows.filter((r) => r.kind || r.saved);
  const dirs = new Set(own.map((r) => r.path.slice(0, r.path.lastIndexOf('/'))));
  if (!files.length && (own.length < 2 || dirs.size < 2))
    return (
      <>
        {sum}
        <table className="sg-table" data-part="evidence-changes">
          <tbody>
            {rows.map((r) => (
              <tr key={r.path} data-grade={r.grade}>
                <td className="tk-short">
                  <span className={`ft-badge ${r.grade === 'F' ? 'ev-bad' : 'ev-ok'}`} title={r.title} aria-label={gradeLabel(r)} data-grade={r.grade} {...(r.kind ? { 'data-change-kind': r.kind } : {})}>
                    {r.grade}
                  </span>
                </td>
                <td className={`font-mono break-all ${r.grade === 'F' ? 'text-danger-text' : ''}`}>{r.path}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </>
    );
  const badPaths = bad.map((r) => r.path);
  const tree = (
    <FileTree
      label="파일 변경"
      part="evidence-changes"
      selectable={files.length > 0}
      selected={sel}
      onSelect={setSel}
      defaultOpen={(dir) => badPaths.some((p) => p.startsWith(`${dir}/`))}
      items={items}
    />
  );
  if (!files.length)
    return (
      <>
        {sum}
        {tree}
      </>
    );
  const cur = files.find((f) => f.path === sel) ?? null;
  return (
    <>
      {sum}
      <div className="ev-files" data-part="evidence-files">
        <div className="ev-split">
          {tree}
          <div className="ev-code min-w-0">{cur ? <SavedFile key={cur.path} f={cur} tokens={marks.tokens} /> : sel ? <p className="text-xs text-slate-500" data-part="evidence-no-content">{NOT_SAVED}</p> : null}</div>
        </div>
      </div>
    </>
  );
}

// 저장된 설치 스크립트 — 공통 코드 창 · 줄 번호 · 위반 토큰이 든 줄은 빨간 줄(첫 조각은 표시), 처음 위반 줄로 스크롤
function SavedFile({ f, tokens }: { f: EvidenceFile; tokens: string[] }) {
  const hits = useMemo(() => hitLines(f, tokens), [f, tokens]);
  const box = useRef<HTMLDivElement>(null);
  const first = hits.size ? Math.min(...hits) : 0;
  useEffect(() => {
    const el = box.current?.querySelector<HTMLElement>(`[data-line="${first}"]`);
    if (box.current && el && first > 3) box.current.scrollTop = el.offsetTop - box.current.clientHeight / 3;
  }, [first]);
  return (
    <div className="grid gap-1">
      <p className={`text-xs ${hits.size ? 'font-semibold text-danger-text' : 'text-slate-500'}`} data-part="evidence-hit-count">
        {hits.size ? `위반 관련 줄 ${hits.size.toLocaleString('ko-KR')}개` : '위반 관련 줄 없음'}
      </p>
      <CodeWindow name={f.path} body="raw">
        <div ref={box} className={`${CW_BODY} code-view`} role="region" aria-label={`${f.path} 코드`}>
          {f.content.split('\n').map((ln, i) => {
            const n = i + 1;
            const hit = hits.has(n);
            const m = hit ? findToken(ln, tokens) : null;
            return (
              <div key={n} data-line={n} data-hit={hit ? '1' : undefined} className={`code-line ${hit ? 'hl-threat' : ''}`} title={hit ? '위반 기록과 같은 조각이 있는 줄' : undefined}>
                <span className="ln">{n}</span>
                <code>
                  {m ? (
                    <>
                      {ln.slice(0, m.at)}
                      <mark>{m.token}</mark>
                      {ln.slice(m.at + m.token.length)}
                    </>
                  ) : (
                    ln || ' '
                  )}
                </code>
              </div>
            );
          })}
        </div>
      </CodeWindow>
      {f.truncated && (
        <p className="text-xs text-slate-500" data-part="evidence-truncated">
          64KB 까지만 저장됨
        </p>
      )}
    </div>
  );
}
