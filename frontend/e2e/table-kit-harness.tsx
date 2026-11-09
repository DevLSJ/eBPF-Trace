// 11/09 P2 — 공통 부품(표 도구줄 · 칸 고르기/폭/순서 · 필터 Select · 검색칸 · 주소 쿼리 목록 상태 · 시트 탭 · 큰 2단 창 · 미저장 경고)을
// 앱 화면 위 무대에서 띄워 본다(r1-harness.tsx 와 같은 방식 — 앱을 연 뒤 page.evaluate(() => import('/e2e/table-kit-harness.tsx'))).
// window.__tk.mount('list' | 'modal', props) → Promise<{ unmount() }>. 무대는 화면 전체를 덮는 고정 상자 [data-tk-stage](z 65 — 도우미 60 위, 펼침 상자 70 아래).
// 'list' 는 BrowserRouter 로 진짜 주소 쿼리를 쓴다(앱 라우터는 popstate 만 듣기에 서로 건드리지 않는다).
/* eslint-disable react-refresh/only-export-components */
import { createElement, useState, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { GridCells, SortHead, StatusPill, TablePager } from '../src/components/DataTable';
import { FilterBar, SearchField } from '../src/components/list/SearchField';
import { downloadCSV } from '../src/components/list/csv';
import { Modal } from '../src/components/Modal';
import { Select } from '../src/components/Select';
import { Sheet } from '../src/components/Sheet';
import { sheetNav } from '../src/components/sheet-nav';
import { TableToolbar } from '../src/components/TableToolbar';
import { useListQuery } from '../src/hooks/useListQuery';
import { useTableKit, type Column } from '../src/hooks/useTableKit';
import { useUnsaved } from '../src/hooks/useUnsaved';

const K = { GridCells, SortHead, StatusPill, TablePager, FilterBar, SearchField, downloadCSV, Modal, Select, Sheet, sheetNav, TableToolbar, useListQuery, useTableKit, useUnsaved };
const ready = async () => K;

// ── 목록 무대 ──
const KINDS = ['exec', 'open', 'connect', 'dns', 'sequence'];
const ACTIONS = ['allow', 'alert', 'kill'];
const OWNERS = 'abcdefghijkl'.split('').map((c) => `owner-${c}`);
interface Row {
  id: string;
  name: string;
  kind: string;
  action: string;
  owner: string;
  hits: number;
  note: string;
}
const pad = (n: number) => String(n).padStart(2, '0');
const ROWS: Row[] = Array.from({ length: 45 }, (_, i) => ({
  id: `r${pad(i + 1)}`,
  name: `policy-${pad(i + 1)}`,
  kind: KINDS[i % 5],
  action: ACTIONS[i % 3],
  owner: OWNERS[i % 12],
  hits: (i * 7) % 23,
  note: `메모 ${pad(i + 1)}`,
}));

function columns(): Column<Row>[] {
  return [
    { key: 'pick', label: '', fixed: true, cell: (r: Row) => <input type="checkbox" aria-label={`${r.name} 고르기`} onClick={(e) => e.stopPropagation()} /> },
    { key: 'name', label: '정책', sort: (r: Row) => r.name, cell: (r: Row) => r.name },
    { key: 'kind', label: '종류', sort: (r: Row) => r.kind, cell: (r: Row) => r.kind },
    { key: 'action', label: '판정', sort: (r: Row) => r.action, cell: (r: Row) => r.action },
    { key: 'owner', label: '담당', sort: (r: Row) => r.owner, cell: (r: Row) => r.owner, maxWidth: 240 },
    { key: 'hits', label: '위반', num: true, sort: (r: Row) => r.hits, cell: (r: Row) => r.hits },
    { key: 'note', label: '메모', hidden: true, cell: (r: Row) => r.note, csv: (r: Row) => r.note },
    { key: 'act', label: '', fixed: true, cell: () => <button type="button" aria-label="행 동작" onClick={(e) => e.stopPropagation()}>…</button> },
  ];
}
const COLS = columns();
const TABS = [
  { key: 'detail', label: '상세' },
  { key: 'blocks', label: '차단 이력', count: 3 },
  { key: 'changes', label: '변경 이력' },
];

function ListDemo({ grid }: { grid: string }) {
  const lq = K.useListQuery({
    filters: { q: '', kind: '', action: '', owner: '' },
    validate: { kind: (v) => KINDS.includes(v), action: (v) => ACTIONS.includes(v), owner: (v) => OWNERS.includes(v) },
    sort: { key: 'name', dir: 'asc' as const },
    sortKeys: ['name', 'kind', 'action', 'owner', 'hits'],
    tabs: TABS.map((t) => t.key),
  });
  const kit = K.useTableKit({ columns: COLS, grid, query: lq.table });
  const [refreshes, setRefreshes] = useState(0);
  const f = lq.filters;
  const list = ROWS.filter((r) => (!f.q || r.name.includes(f.q)) && (!f.kind || r.kind === f.kind) && (!f.action || r.action === f.action) && (!f.owner || r.owner === f.owner));
  const view = kit.view(list);
  const cur = lq.id ? ROWS.find((r) => r.id === lq.id) : undefined;
  const ids = view.rows.map((r) => r.id);
  return (
    <div className="flex h-full min-h-0 flex-col gap-3 p-4" data-tk-refreshes={refreshes}>
      <K.FilterBar name="demo" active={lq.active} onClear={lq.clearFilters}>
        <K.SearchField label="정책 검색" placeholder="정책 이름" value={f.q} onApply={(q) => lq.setFilters({ q })} />
        <K.Select name="kind" label="종류" value={f.kind} options={KINDS.map((v) => ({ value: v, label: v }))} onChange={(kind) => lq.setFilters({ kind })} />
        <K.Select name="action" label="판정" value={f.action} options={ACTIONS.map((v) => ({ value: v, label: v }))} onChange={(action) => lq.setFilters({ action })} />
        <K.Select name="owner" label="담당" value={f.owner} options={OWNERS.map((v) => ({ value: v, label: v }))} onChange={(owner) => lq.setFilters({ owner })} />
      </K.FilterBar>
      <div className="sg-card flex min-h-0 flex-1 flex-col overflow-hidden">
        <K.TableToolbar name="demo" total={list.length} kit={kit} onRefresh={() => setRefreshes((n) => n + 1)} onExport={() => K.downloadCSV('tk-demo.csv', kit.csv(list))} />
        <div className="min-h-0 flex-1 overflow-auto" data-testid="tk-scroll">
          <table className="sg-table" data-table="demo">
            <K.SortHead kit={kit} />
            <tbody>
              {view.rows.map((r) => (
                <tr key={r.id} data-row={r.id} tabIndex={0} aria-selected={r.id === lq.id} onClick={() => lq.open(r.id)} className="cursor-pointer">
                  <K.GridCells kit={kit} row={r} />
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <K.TablePager name="demo" total={view.total} from={view.from} to={view.to} page={view.page} size={kit.size} onPage={kit.setPage} onSize={kit.setSize} />
      </div>
      {cur && (
        <K.Sheet
          kind="demo"
          title={cur.name}
          subtitle={cur.id}
          badges={<K.StatusPill tone={cur.action === 'kill' ? 'danger' : 'neutral'}>{cur.action}</K.StatusPill>}
          tabs={TABS}
          tab={lq.tab}
          onTab={lq.setTab}
          nav={K.sheetNav(ids, cur.id, (id) => lq.open(id))}
          onClose={lq.close}
        >
          <div data-part="tab-body" data-tab-body={lq.tab}>
            <p>{lq.tab} 내용</p>
            <button type="button" data-testid="inside-1">안쪽 단추 1</button>
            <input aria-label="안쪽 칸" />
            <button type="button" data-testid="inside-2">안쪽 단추 2</button>
          </div>
        </K.Sheet>
      )}
    </div>
  );
}

// ── 큰 2단 창 무대 ──
const tall = (n: number, what: string): ReactNode => Array.from({ length: n }, (_, i) => <p key={i} className="py-2">{`${what} 줄 ${i + 1}`}</p>);
function ModalDemo({ onClosed }: { onClosed: () => void }) {
  const [v, setV] = useState({ name: 'policy-01', note: '' });
  const unsaved = K.useUnsaved(v);
  return (
    <K.Modal
      size="xl"
      kind="tk-form"
      title="정책 생성"
      guard={() => unsaved.dirty}
      onClose={onClosed}
      side={<div data-testid="side-content">{tall(40, '오른쪽')}</div>}
      foot={(close) => (
        <>
          <button type="button" className="sg-btn sg-btn-secondary" data-action="form-cancel" onClick={close}>
            취소
          </button>
          <button type="button" className="sg-btn sg-btn-primary" data-action="form-save" onClick={onClosed}>
            저장
          </button>
        </>
      )}
    >
      <label className="grid gap-1">
        <span>이름</span>
        <input name="name" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} />
      </label>
      <div data-testid="main-content">{tall(40, '왼쪽')}</div>
    </K.Modal>
  );
}

function Closed({ n }: { n: number }) {
  return <div data-tk-closed={n} />;
}

async function mount(kind: string, props: { grid?: string } = {}) {
  await ready();
  const host = document.createElement('div');
  Object.assign(host.style, { position: 'fixed', inset: '0', zIndex: '65', background: 'var(--bg)', display: 'flex', flexDirection: 'column' });
  host.dataset.tkStage = kind;
  document.body.append(host);
  const root = createRoot(host);
  if (kind === 'list') root.render(createElement(BrowserRouter, null, createElement(ListDemo, { grid: props.grid ?? 'tk-demo' })));
  else {
    let closed = 0;
    const draw = () => root.render(closed ? createElement(Closed, { n: closed }) : createElement(ModalDemo, { onClosed: () => ((closed += 1), draw()) }));
    draw();
  }
  return {
    unmount: () => {
      root.unmount();
      host.remove();
    },
  };
}

(window as unknown as { __tk: unknown }).__tk = { mount };
