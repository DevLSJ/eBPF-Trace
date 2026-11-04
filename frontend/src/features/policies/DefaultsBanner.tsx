import { ChevronDown, ChevronUp, Sparkles } from 'lucide-react';
import { useState } from 'react';
import { defaultItems, diffText, hiddenDefaults, hideDefault, hideSig, type DefaultItem } from '../../lib/policyDefaults';
import type { PolicyDefaults } from '../../lib/types';

// 정책 화면 맨 위 「새 기본 규칙 있음」 띠(10/20 F) — GET /api/policies/defaults. 라우트가 없거나(404 · 405) 읽지 못하면 그리지 않는다.
// 규칙별 「미리보기 후 추가」(관리자, 바로 저장 전 확인) · 「이번엔 숨기기」(이 브라우저)
export function DefaultsBanner({ data, canWrite, onPreview }: { data: PolicyDefaults | undefined; canWrite: boolean; onPreview: (x: DefaultItem) => void }) {
  const [open, setOpen] = useState(false);
  const [, setHid] = useState(0); // 숨긴 뒤 다시 그리기
  const hid = hiddenDefaults();
  const items = defaultItems(data).filter((x) => hid[x.id] !== hideSig(x.rule));
  if (!items.length) return null;
  const nM = items.filter((x) => x.kind === 'missing').length;
  const nD = items.length - nM;
  const what = [nM ? `새 규칙 ${nM}개` : '', nD ? `바뀐 규칙 ${nD}개` : ''].filter(Boolean).join(' · ');
  return (
    <section className="shrink-0 rounded-lg border border-indigo-200 bg-indigo-50/60 text-sm" data-part="defaults-banner">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 px-4 py-2">
        <Sparkles className="size-4 shrink-0 text-indigo-600" aria-hidden />
        <b className="text-slate-800">기본 정책에 {what}가 있습니다</b>
        <span className="text-xs text-slate-500">— 업데이트로 생긴 규칙은 저절로 들어가지 않습니다. 사용자가 바꾼 규칙은 덮어쓰지 않습니다.</span>
        <button
          type="button"
          data-action="defaults-toggle"
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
          className="ml-auto flex items-center gap-1 rounded-md px-2 py-1 text-xs text-indigo-700 hover:bg-indigo-100"
        >
          {open ? (
            <>
              접기 <ChevronUp className="size-3.5" aria-hidden />
            </>
          ) : (
            <>
              펼치기 <ChevronDown className="size-3.5" aria-hidden />
            </>
          )}
        </button>
      </div>
      {open && (
        <ul data-fill="" className="grid max-h-48 gap-1 overflow-y-auto border-t border-indigo-100 px-4 py-2">
          {items.map((x) => (
            <li key={`${x.kind}:${x.id}`} data-default={x.id} className="flex items-center gap-2">
              <span className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] ${x.kind === 'missing' ? 'bg-sky-100 text-sky-800' : 'bg-amber-100 text-amber-800'}`}>
                {x.kind === 'missing' ? '새 규칙' : '바뀐 규칙'}
              </span>
              <span className="grid min-w-0 flex-1">
                <span className="truncate text-slate-800">{x.rule.description || x.id}</span>
                <small className="truncate font-mono text-[11px] text-slate-500" title={x.current ? diffText(x.current, x.rule) : x.id}>
                  {x.kind === 'missing' || !x.current ? x.id : `${x.id} — ${diffText(x.current, x.rule)}`}
                </small>
              </span>
              {canWrite && (
                <button
                  type="button"
                  data-action="default-preview"
                  onClick={() => onPreview(x)}
                  className="shrink-0 rounded-md border border-indigo-300 bg-white px-2 py-1 text-xs text-indigo-700 hover:bg-indigo-50"
                >
                  미리보기 후 추가
                </button>
              )}
              <button
                type="button"
                data-action="default-hide"
                title="이 브라우저에서 이번 기본 규칙은 숨깁니다(기본 규칙 내용이 바뀌면 다시 보입니다)"
                onClick={() => {
                  hideDefault(x);
                  setHid((n) => n + 1);
                }}
                className="shrink-0 rounded-md px-2 py-1 text-xs text-slate-600 hover:bg-white"
              >
                이번엔 숨기기
              </button>
            </li>
          ))}
          <li className="text-xs text-slate-500">
            목록에 없던 규칙은 그대로, 바뀐 규칙은 지금 규칙에 없는 값만 더해 「저장 전 확인」(최근 감사 로그 재평가)을 거쳐 저장합니다.
          </li>
        </ul>
      )}
    </section>
  );
}
