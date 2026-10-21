import { Search } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useStream } from '../../hooks/stream-context';
import { api } from '../../lib/api';
import { buildIndex, dialogOpen, searchIndex, searchKey, SEARCH_TYPE_KO, typingTarget, type SearchSources } from '../../lib/shell';

// E. 사이드바 통합 검색(10/20 확정) — 목업 shared/shell-plus.js searchBox.
// 패키지 · 컨테이너 · 규칙 id · 도메인 · 검사를 화면이 이미 쓰는 목록 API(설치 검사 · 공급망 검사 · 정책 · 차단 목록)와
// 실시간 피드 · 토폴로지로 클라이언트에서 찾는다. 목록은 검색 칸에 들어올 때 읽는다(15초 안에는 다시 읽지 않음).
// `/` 로 포커스, ↑↓ 고르고 Enter 이동, Esc 닫기. 사이드바가 접혀 있으면 아이콘 → 옆으로 뜨는 칸

const RELOAD_MS = 15_000;

export function SearchBox({ collapsed }: { collapsed: boolean }) {
  const { verdicts, topology, topologyVersion } = useStream();
  const navigate = useNavigate();
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const [focused, setFocused] = useState(false);
  const [src, setSrc] = useState<SearchSources>({});
  const loadedAt = useRef(0);
  const input = useRef<HTMLInputElement>(null);
  const wrap = useRef<HTMLDivElement>(null);

  const load = () => {
    if (Date.now() - loadedAt.current < RELOAD_MS) return;
    loadedAt.current = Date.now();
    // 없는 API(옛 백엔드) · 오류는 그 출처만 빼고 찾는다
    void Promise.allSettled([api.installs(), api.scans(), api.listRules(), api.blocklist()]).then(([i, s, r, b]) =>
      setSrc({
        installs: i.status === 'fulfilled' ? i.value : null,
        scans: s.status === 'fulfilled' ? s.value : null,
        rules: r.status === 'fulfilled' ? r.value : null,
        blocklist: b.status === 'fulfilled' ? b.value : null,
      }),
    );
  };

  const index = useMemo(
    () => buildIndex({ ...src, containers: topology.containers(), verdicts }),
    // topologyVersion: 토폴로지 저장소는 같은 객체라 판 번호로 다시 계산한다
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [src, verdicts, topology, topologyVersion],
  );
  const items = useMemo(() => searchIndex(index, q), [index, q]);
  const sel = Math.min(active, Math.max(0, items.length - 1));
  const showResults = focused && q.trim() !== '';

  const focus = () => {
    setFocused(true);
    // 접힌 사이드바에서는 칸이 그려진 뒤에 포커스
    requestAnimationFrame(() => {
      input.current?.focus();
      input.current?.select();
    });
  };
  const reset = () => {
    setQ('');
    setActive(0);
    setFocused(false);
    input.current?.blur();
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey || typingTarget(e) || dialogOpen()) return;
      e.preventDefault();
      focus();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  const box = (
    <div className={collapsed ? `absolute top-0 left-full z-50 ml-2 w-80 ${focused ? '' : 'hidden'}` : 'relative'}>
      <div className="relative">
        <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-slate-500" aria-hidden />
        <input
          ref={input}
          type="search"
          role="combobox"
          aria-label="통합 검색 (패키지 · 컨테이너 · 규칙 id · 도메인 · 검사)"
          aria-expanded={showResults}
          aria-controls="shell-search-results"
          autoComplete="off"
          placeholder="검색"
          value={q}
          onFocus={() => {
            setFocused(true);
            load();
          }}
          onChange={(e) => {
            setQ(e.target.value);
            setActive(0);
          }}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
              e.preventDefault();
              if (!items.length) return;
              setActive((sel + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length);
            } else if (e.key === 'Enter') {
              e.preventDefault();
              const x = items[sel];
              if (x && showResults) {
                navigate(x.to, { state: x.state });
                reset();
              }
            } else if (e.key === 'Escape') {
              e.preventDefault();
              e.stopPropagation();
              reset();
            }
          }}
          className={`w-full rounded-md border py-1.5 pr-7 pl-8 text-sm focus:outline-none ${
            collapsed ? 'border-slate-300 bg-white text-slate-900 shadow-lg' : 'border-slate-700 bg-slate-800 text-slate-100 placeholder:text-slate-500 focus:border-indigo-400'
          }`}
        />
        {!q && (
          <kbd className="pointer-events-none absolute top-1/2 right-2 -translate-y-1/2 rounded border border-slate-600 px-1 text-[10px] text-slate-400" aria-hidden>
            /
          </kbd>
        )}
      </div>
      {showResults && (
        <div
          id="shell-search-results"
          data-part="search-results"
          role="listbox"
          className="absolute top-full right-0 left-0 z-50 mt-1 max-h-[min(26rem,calc(100vh-8rem))] min-w-72 overflow-y-auto rounded-lg border border-slate-200 bg-white py-1 text-slate-800 shadow-xl"
        >
          {items.length === 0 ? (
            <p className="px-3 py-2 text-xs text-slate-400">찾는 것이 없습니다</p>
          ) : (
            items.map((x, i) => (
              <div key={searchKey(x)}>
                {(i === 0 || items[i - 1].type !== x.type) && <div className="px-3 pt-2 pb-1 text-[11px] font-medium text-slate-400">{SEARCH_TYPE_KO[x.type]}</div>}
                <Link
                  to={x.to}
                  state={x.state}
                  role="option"
                  aria-selected={i === sel}
                  data-result=""
                  data-type={x.type}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => reset()}
                  className={`grid gap-0.5 px-3 py-1.5 ${i === sel ? 'bg-indigo-50' : 'hover:bg-slate-50'}`}
                >
                  <span className="truncate font-mono text-[13px]">{x.label}</span>
                  {x.sub && <span className="truncate text-[11px] text-slate-500">{x.sub}</span>}
                </Link>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );

  return (
    <div
      ref={wrap}
      className={`relative ${collapsed ? 'flex justify-center' : ''}`}
      onBlur={(e) => {
        if (wrap.current?.contains(e.relatedTarget as Node)) return;
        window.setTimeout(() => {
          if (!wrap.current?.contains(document.activeElement)) setFocused(false);
        }, 150);
      }}
    >
      {collapsed && (
        <button type="button" onClick={focus} aria-label="검색 (/)" title="검색 (/)" className="grid size-9 place-items-center rounded-md text-slate-400 hover:bg-slate-800 hover:text-white">
          <Search className="size-4" aria-hidden />
        </button>
      )}
      {box}
    </div>
  );
}
