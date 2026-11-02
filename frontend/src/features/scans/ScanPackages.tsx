import { OctagonX } from 'lucide-react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ConfirmDialog } from '../../components/Modal';
import { Section } from '../../components/Sheet';
import { useAuth } from '../../hooks/auth-context';
import { useToast } from '../../hooks/toast-context';
import { useLoad } from '../../hooks/useLoad';
import { api, errorText } from '../../lib/api';
import type { Scan } from '../../lib/types';

// 패키지 골라 차단(10/20 G) — 저장소 · 파일 검사 결과의 패키지(잠금 파일마다 한 행)를 (매니저, 이름, 버전)으로 묶어 한 줄 + 출처 파일 나열.
// 고르면 「선택한 N개 차단 목록에 올리기」 → 확인 대화상자(사유) → POST /api/scans/{id}/block {packages, reason} → 정책 제안.
// 차단 목록이 다루지 않는 생태계(manager 없음) · 이미 차단된 것(매니저:이름)은 체크 칸이 없다
interface Group {
  key: string; // 매니저:이름@버전 (생태계 미지원은 생태계:이름@버전)
  blockKey: string; // 차단 목록 값 — 매니저:이름(버전 무관)
  manager: string;
  name: string;
  version: string;
  ecosystem: string;
  sources: string[];
  direct: boolean;
  vulns: number;
}

function groupsOf(s: Scan): Group[] {
  const m = new Map<string, Group>();
  for (const p of s.packages ?? []) {
    const head = p.manager ? `${p.manager}:${p.name}` : `${p.ecosystem ?? '?'}:${p.name}`;
    const key = `${head}@${p.version}`;
    const g = m.get(key) ?? { key, blockKey: `${p.manager}:${p.name.toLowerCase()}`, manager: p.manager, name: p.name, version: p.version, ecosystem: p.ecosystem ?? '', sources: [], direct: false, vulns: 0 };
    if (p.source && !g.sources.includes(p.source)) g.sources.push(p.source);
    g.direct ||= p.direct;
    g.vulns = Math.max(g.vulns, p.vulns ?? 0);
    m.set(key, g);
  }
  return [...m.values()].sort((a, b) => b.vulns - a.vulns || a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

export function ScanPackages({ s }: { s: Scan }) {
  const { isAdmin } = useAuth();
  const toast = useToast();
  const nav = useNavigate();
  const blocklist = useLoad(api.blocklist);
  const [picked, setPicked] = useState<Set<string>>(() => new Set());
  const [ask, setAsk] = useState(false);
  const list = groupsOf(s);
  if (!list.length)
    return (
      <Section title="패키지 0" testId="packages">
        <p className="text-xs text-slate-500" data-part="packages">
          잠금 · 의존성 파일(requirements.txt · package-lock.json · Cargo.lock)을 찾지 못했습니다.
        </p>
      </Section>
    );
  const blocked = new Set((blocklist.data?.packages ?? []).map((x) => x.value.toLowerCase()));
  const canPick = (g: Group) => isAdmin && !!g.manager && !blocked.has(g.blockKey);
  const pickable = list.filter(canPick);
  const sel = list.filter((g) => picked.has(g.key) && canPick(g));
  const toggle = (k: string, on: boolean) =>
    setPicked((cur) => {
      const next = new Set(cur);
      if (on) next.add(k);
      else next.delete(k);
      return next;
    });
  const submit = async (reason: string) => {
    try {
      const r = await api.blockScanPackages(
        s.id,
        sel.map((g) => ({ manager: g.manager, name: g.name, version: g.version })),
        reason,
      );
      nav(`/policies?proposal=${encodeURIComponent(r.proposalId)}`);
    } catch (e) {
      toast(`차단 제안 실패: ${errorText(e)}`, { key: 'scan-block', tone: 'danger' });
    }
  };
  return (
    <Section title={`패키지 ${list.length} — 잠금 · 의존성 파일에서 읽음, 같은 패키지 · 버전은 한 줄`}>
      <div data-part="packages" className="grid gap-2">
        <div className="max-h-72 overflow-auto rounded-md border border-slate-200">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-slate-50 text-left text-slate-500">
              <tr>
                {isAdmin && (
                  <th className="w-8 px-2 py-1">
                    <input
                      type="checkbox"
                      aria-label="모두 고르기"
                      className="accent-indigo-600"
                      disabled={!pickable.length}
                      checked={pickable.length > 0 && pickable.every((g) => picked.has(g.key))}
                      onChange={(e) => setPicked(e.target.checked ? new Set(pickable.map((g) => g.key)) : new Set())}
                    />
                  </th>
                )}
                {['패키지', '버전', '취약', '의존', '출처 파일'].map((h) => (
                  <th key={h} className="px-2 py-1 font-semibold">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {list.map((g) => (
                <tr key={g.key} data-pkg={g.key} data-sources={g.sources.length} className={`border-t border-slate-100 ${picked.has(g.key) ? 'bg-indigo-50' : ''}`}>
                  {isAdmin && (
                    <td className="px-2 py-1">
                      {canPick(g) ? (
                        <input type="checkbox" className="accent-indigo-600" aria-label={`${g.key} 고르기`} checked={picked.has(g.key)} onChange={(e) => toggle(g.key, e.target.checked)} />
                      ) : (
                        <span className="text-[11px] text-slate-400" title={g.manager ? '이미 차단 목록에 있음' : '차단 목록이 다루지 않는 생태계'}>
                          {g.manager ? '차단됨' : '—'}
                        </span>
                      )}
                    </td>
                  )}
                  <td className="px-2 py-1 font-mono">{g.manager ? `${g.manager}:${g.name}` : <span title="차단 목록이 다루지 않는 생태계">{`${g.ecosystem} ${g.name}`}</span>}</td>
                  <td className="px-2 py-1 font-mono">{g.version}</td>
                  <td className={`num px-2 py-1 ${g.vulns ? 'font-semibold text-amber-700' : 'text-slate-400'}`}>{g.vulns}</td>
                  <td className="px-2 py-1">{g.direct ? '직접' : '간접'}</td>
                  <td className="px-2 py-1 font-mono text-[11px] text-slate-600">
                    <ul>
                      {g.sources.map((x) => (
                        <li key={x}>{x}</li>
                      ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {isAdmin &&
          (sel.length ? (
            <button
              type="button"
              data-action="block-selected"
              onClick={() => setAsk(true)}
              className="flex items-center gap-1.5 justify-self-start rounded-md bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700"
            >
              <OctagonX className="size-3.5" aria-hidden /> 선택한 {sel.length}개 차단 목록에 올리기
            </button>
          ) : (
            <span className="text-xs text-slate-500">차단할 패키지를 고르세요 — 취약점이 많은 것부터 위에 있습니다</span>
          ))}
      </div>
      {ask && (
        <ConfirmDialog
          title="고른 패키지 차단 목록에 올리기"
          target={`${s.target.label} · ${s.id}`}
          okLabel={`${sel.length}개 올리기`}
          reason
          effects={[
            `차단 제안 초안 — 패키지 ${sel.length}개: ${[...new Set(sel.map((g) => `${g.manager}:${g.name}`))].join(' · ')} (정책에서 미리보기 후 적용)`,
            '적용하면 다음 sg-install 부터 이 패키지는 설치 전 거부(컨테이너를 띄우지 않음) — 차단은 버전과 무관',
            '공급망 검사 건을 「악성」으로 판정한 기록이 남습니다(사유는 판정 메모)',
          ]}
          undo="정책에서 제안을 「버림」하면 차단 없이 끝납니다. 적용한 뒤에는 차단 목록에서 「해제」"
          onCancel={() => setAsk(false)}
          onConfirm={(reason) => {
            setAsk(false);
            void submit(reason);
          }}
        />
      )}
    </Section>
  );
}
