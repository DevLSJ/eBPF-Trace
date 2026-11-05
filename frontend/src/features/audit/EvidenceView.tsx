import { FileSearch } from 'lucide-react';
import { useCallback } from 'react';
import { useAutoRetry } from '../../components/list/hooks';
import { EmptyState, ListError, Skeleton } from '../../components/list/ListStates';
import { Section } from '../../components/Sheet';
import { useLoad } from '../../hooks/useLoad';
import { api } from '../../lib/api';
import { fmtDateTime, shortId } from '../../lib/format';
import { CodeWindow } from '../../components/CodeWindow';
import { FileTree } from '../../components/FileTree';
import type { AuditEntry, Evidence } from '../../lib/types';

const CHANGE_TONE: Record<string, [string, string]> = {
  A: ['bg-emerald-100 text-emerald-800', '추가'],
  C: ['bg-amber-100 text-amber-800', '변경'],
  D: ['bg-red-100 text-red-700', '삭제'],
};

// 감사 상세 「증거」 탭(10/20 I) — GET /api/evidence?container=<이름>(최근 것부터). 같은 이름으로 여러 번 뜬 컨테이너는 ID 별로 묶고,
// 이 행의 컨테이너 ID 묶음을 맨 위에 둔다. 증거는 격리(kill) 직전에만 모은다 — 로그 마지막 200줄 · docker diff · docker top
export function EvidenceView({ a }: { a: AuditEntry }) {
  const name = a.event.containerName;
  const load = useCallback(() => api.evidence(name), [name]);
  const r = useLoad(load);
  useAutoRetry(!!r.error && !r.data, r.error, r.reload); // 오류 칸의 「30초마다」 문구대로
  if (r.error && !r.data) return <ListError error={r.error} what="증거" onRetry={r.reload} retrying={r.loading} />;
  if (!r.data) return <Skeleton rows={4} />;
  if (!r.data.length)
    return (
      <div data-part="evidence-empty">
        <EmptyState icon={FileSearch} title="이 컨테이너의 증거가 없습니다" hint="증거(로그 · 파일 변경 · 프로세스)는 격리(kill) 직전에만 모읍니다. 경고만 있었거나 격리 전에 컨테이너가 끝났으면 없습니다." />
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
                {current ? <span className="rounded bg-indigo-50 px-1.5 py-0.5 text-xs text-indigo-700">이 기록</span> : <span className="text-xs font-normal text-slate-400">같은 이름 · 다른 실행</span>}
              </span>
            }
          >
            <div className="grid gap-3" data-evidence-group={cid} data-current={String(current)}>
              {groups.get(cid)!.map((ev) => (
                <EvidenceCard key={ev.id} ev={ev} />
              ))}
            </div>
          </Section>
        );
      })}
    </div>
  );
}

const sameId = (a: string, b: string) => !!a && !!b && (a.startsWith(b) || b.startsWith(a));

function EvidenceCard({ ev }: { ev: Evidence }) {
  const changes = ev.changes ?? [];
  const procs = ev.processes ?? [];
  return (
    <article className="grid gap-2 rounded-md border border-slate-200 p-3" data-evidence={ev.id}>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="num text-slate-600">{fmtDateTime(ev.collectedAt)}</span>
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
          로그 <span className="font-normal text-slate-400">— 마지막 200줄</span>
        </h4>
        {/* 11/04f 코드 창(R1 11/04) — 파일명 없음 · log · 줄바꿈 */}
        <CodeWindow lang="log" wrap bodyClassName="ev-logs">
          <span data-part="evidence-logs">{ev.logs || '(비어 있음)'}</span>
        </CodeWindow>
      </div>
      <div>
        <h4 className="mb-1 text-xs font-semibold text-slate-700">
          파일 변경 <span className="font-normal text-slate-400">— docker diff (A 추가 · C 변경 · D 삭제)</span>
        </h4>
        {/* 11/04f 파일 트리(R1 11/04) — 여러 폴더에 걸치면 트리 + A · C · D 배지(폴더 모두 펼침 · 선택 없음), 1개이거나 한 폴더면 예전 표 */}
        {changes.length > 1 && new Set(changes.map((c) => c.path.slice(0, c.path.lastIndexOf('/')))).size > 1 ? (
          <FileTree
            label="파일 변경"
            part="evidence-changes"
            selectable={false}
            items={changes.map((c) => ({ path: c.path, diff: c.kind, badge: { text: c.kind, cls: `ev-${c.kind}`, title: CHANGE_TONE[c.kind]?.[1] ?? c.kind, attrs: { 'data-change-kind': '' } } }))}
          />
        ) : changes.length ? (
          <table className="sg-table" data-part="evidence-changes">
            <tbody>
              {changes.map((c, i) => (
                <tr key={i}>
                  <td className="tk-short">
                    <span className={`rounded px-1 font-mono ${CHANGE_TONE[c.kind]?.[0] ?? 'bg-slate-100'}`} title={CHANGE_TONE[c.kind]?.[1]} data-change-kind="">
                      {c.kind}
                    </span>
                  </td>
                  <td className="font-mono break-all">{c.path}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-xs text-slate-400" data-part="evidence-changes">
            없음
          </p>
        )}
      </div>
      <div>
        <h4 className="mb-1 text-xs font-semibold text-slate-700">
          프로세스 <span className="font-normal text-slate-400">— docker top</span>
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
            {ev.partial ? '모으지 못함 — 위 안내 참고' : '없음'}
          </p>
        )}
      </div>
    </article>
  );
}
