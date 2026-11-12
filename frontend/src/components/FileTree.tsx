import { useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';

// 파일 트리(11/04f 목업 U.fileTree, R1 11/04) — 경로 목록을 폴더 트리로. 카드 안 role=tree, 하위는 들여쓰기 11 + 세로 연결선 · 항목 앞 가로 연결선.
//   폴더 먼저 · 이름순, 절대 경로는 맨 위 폴더에 「/」. 아이콘 ▸ 닫힌 폴더 · ▾ 열린 폴더 · ▤ 파일(목업 글리프 체계)
//   펼침/접힘: 자리에서 aria-expanded 만 바꾸고 CSS(grid-template-rows 0fr ↔ 1fr, --t-slow)가 움직인다. 접힌 그룹은 끝난 뒤 visibility hidden
//   선택이 바뀌면(딥링크 포함) 그 파일의 부모를 펼친다 — 같은 선택으로 다시 그릴 때는 사용자가 접은 그대로
//   키보드(roving tabindex): ↑↓ 보이는 항목 · → 펼침/첫 자식 · ← 접힘/부모 · Home/End · Enter/Space 폴더 토글 · 파일 선택
//   rank(선택, 11/10 증거): 큰 값이 같은 층에서 먼저 — 폴더는 안에 든 항목의 가장 큰 값. 없으면 0(예전 순서 그대로)
export interface TreeItem {
  path: string;
  badge?: { text: string; cls?: string; title?: string; attrs?: Record<string, string> };
  diff?: string;
  rank?: number;
}
interface Node {
  name: string;
  path: string;
  kids: Map<string, Node>;
  item: TreeItem | null;
  rank: number;
}

function build(items: TreeItem[]): Node {
  const root: Node = { name: '', path: '', kids: new Map(), item: null, rank: 0 };
  for (const it of items) {
    const abs = it.path.startsWith('/');
    const segs = it.path.replace(/^\/+/, '').split('/').filter(Boolean);
    const rank = it.rank ?? 0;
    let node = root;
    let acc = '';
    segs.forEach((seg, i) => {
      acc = abs ? `${acc}/${seg}` : acc ? `${acc}/${seg}` : seg;
      if (!node.kids.has(seg)) node.kids.set(seg, { name: i === 0 && abs ? `/${seg}` : seg, path: acc, kids: new Map(), item: null, rank: 0 });
      node = node.kids.get(seg)!;
      node.rank = Math.max(node.rank, rank);
    });
    node.item = it;
  }
  return root;
}
const sorted = (m: Map<string, Node>) => [...m.values()].sort((a, b) => b.rank - a.rank || Number(b.kids.size > 0) - Number(a.kids.size > 0) || a.name.localeCompare(b.name, 'en'));
const parents = (p: string) => {
  const out: string[] = [];
  let x = p;
  while (x.includes('/')) {
    x = x.slice(0, x.lastIndexOf('/'));
    if (x) out.push(x);
  }
  return out;
};

export function FileTree({
  label,
  items,
  selected,
  selectable = true,
  defaultOpen,
  onSelect,
  className = '',
  part = 'file-tree',
}: {
  label: string;
  items: TreeItem[];
  selected?: string | null;
  selectable?: boolean;
  defaultOpen?: (dir: string) => boolean;
  onSelect?: (path: string) => void;
  className?: string;
  part?: string;
}) {
  const root = useMemo(() => build(items), [items]);
  const sel = selectable ? (selected ?? null) : null;
  const [open, setOpen] = useState<Map<string, boolean>>(() => new Map());
  const [seenSel, setSeenSel] = useState<string | null>(null);
  const [focus, setFocus] = useState<string | null>(null);
  // 선택이 바뀌면 그 파일의 부모를 펼친다(렌더 중 한 번 — 같은 선택이면 그대로)
  if (sel && sel !== seenSel) {
    setSeenSel(sel);
    setFocus(null);
    const next = new Map(open);
    for (const p of parents(sel)) next.set(p, true);
    setOpen(next);
  }
  const isOpen = (p: string) => (open.has(p) ? open.get(p)! : defaultOpen ? defaultOpen(p) : true);
  const toggle = (p: string, to?: boolean) => setOpen((m) => new Map(m).set(p, to ?? !(m.has(p) ? m.get(p) : defaultOpen ? defaultOpen(p) : true)));
  const first = sorted(root.kids)[0]?.path ?? null;
  // Tab 한 칸 = 선택 항목(없으면 마지막으로 포커스한 항목 · 첫 항목)
  const tabStop = focus ?? sel ?? first;
  const tree = useRef<HTMLUListElement>(null);

  const all = () => [...(tree.current?.querySelectorAll<HTMLElement>('[role="treeitem"]') ?? [])];
  const shown = () => all().filter((li) => !li.parentElement?.closest('[aria-expanded="false"]'));
  const go = (li: HTMLElement | null | undefined) => {
    if (!li) return;
    setFocus(li.dataset.path!);
    li.focus();
  };
  const activate = (li: HTMLElement) => {
    const p = li.dataset.path!;
    if (li.dataset.kind === 'dir') return toggle(p);
    if (selectable) onSelect?.(p);
  };
  const onKey = (e: KeyboardEvent<HTMLUListElement>) => {
    const li = (e.target as HTMLElement).closest<HTMLElement>('[role="treeitem"]');
    if (!li) return;
    const vis = shown();
    const i = vis.indexOf(li);
    const dir = li.dataset.kind === 'dir';
    const on = li.getAttribute('aria-expanded') === 'true';
    switch (e.key) {
      case 'ArrowDown':
        go(vis[i + 1]);
        break;
      case 'ArrowUp':
        go(vis[i - 1]);
        break;
      case 'Home':
        go(vis[0]);
        break;
      case 'End':
        go(vis[vis.length - 1]);
        break;
      case 'ArrowRight':
        if (dir && !on) toggle(li.dataset.path!, true);
        else if (dir) go(li.querySelector<HTMLElement>(':scope > .ft-kids [role="treeitem"]'));
        break;
      case 'ArrowLeft':
        if (dir && on) toggle(li.dataset.path!, false);
        else go(li.parentElement?.closest<HTMLElement>('[role="treeitem"]'));
        break;
      case 'Enter':
      case ' ':
        activate(li);
        break;
      default:
        return;
    }
    e.preventDefault();
  };

  const itemEl = (n: Node, lvl: number): ReactNode => {
    const dir = n.kids.size > 0;
    const on = dir && isOpen(n.path);
    const b = n.item?.badge;
    return (
      <li
        key={n.path}
        role="treeitem"
        className={`ft-item ${dir ? 'ft-dir' : 'ft-file'}`}
        data-path={n.path}
        data-kind={dir ? 'dir' : 'file'}
        data-diff={n.item?.diff}
        aria-level={lvl}
        aria-expanded={dir ? on : undefined}
        aria-selected={!dir && selectable ? n.path === sel : undefined}
        tabIndex={n.path === tabStop ? 0 : -1}
        title={n.path}
      >
        <div
          className="ft-row"
          onClick={(e) => {
            const li = (e.currentTarget.parentElement as HTMLElement) ?? null;
            go(li);
            activate(li);
          }}
        >
          <i className="ft-ico" aria-hidden data-icon={dir ? (on ? '▾' : '▸') : '▤'} />
          <span className="ft-name">{n.name}</span>
          {b && (
            <span className={`ft-badge ${b.cls ?? ''}`} title={b.title} {...b.attrs}>
              {b.text}
            </span>
          )}
        </div>
        {dir && (
          <div className="ft-kids">
            <ul role="group">{sorted(n.kids).map((k) => itemEl(k, lvl + 1))}</ul>
          </div>
        )}
      </li>
    );
  };

  return (
    <div className={`ftree ${className}`} data-part={part}>
      <ul ref={tree} role="tree" className="ft-tree" aria-label={label} onKeyDown={onKey}>
        {sorted(root.kids).map((n) => itemEl(n, 1))}
      </ul>
    </div>
  );
}
