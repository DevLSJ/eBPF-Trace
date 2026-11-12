import { useEffect, useMemo, useState } from 'react';
import { rowKeys, rowState } from '../../components/list/hooks';
import { Empty, Panel } from '../../components/Panel';
import { sheetNav } from '../../components/sheet-nav';
import { useListQuery } from '../../hooks/useListQuery';
import { sentence } from '../../lib/api';
import { fmtNum } from '../../lib/format';
import type { IntegrationContainer, IntegrationStatus } from '../../lib/types';
import { WATCH_TABS } from './model';
import { IntFrame, Skeleton } from './parts';
import { useIntegration } from './useIntegration';
import { WatchSheet, WatchTags } from './WatchSheet';
import './integration.css';

// 「연동 › 감시 중 컨테이너」(11/09 밤 — 연동 페이지 오른쪽 목록을 페이지로): 실행 중인 컨테이너의 감시 · 격리 여부(3초마다)
// 11/10: 행 클릭 · Enter → 오른쪽 상세 시트(정보 · 위반 이력 · 최근 이벤트) — 주소 ?id=<컨테이너 id>&tab=…, 열린 채 다른 행은 내용만 교체 · ↑↓
const NO_FILTERS = {};

export function IntegrationWatchPage() {
  const { data, error } = useIntegration();
  const q = useListQuery({ filters: NO_FILTERS, tabs: WATCH_TABS });
  const rows = data?.containers ?? [];
  const ids = rows.map((r) => r.id);
  return (
    <IntFrame page="watch" screen="integration/watch" ready={!!data} error={error}>
      <WatchList data={data} openId={q.id} onOpen={(id) => q.open(id)} />
      {q.id && (
        <WatchSheet
          id={q.id}
          row={rows.find((r) => r.id === q.id)}
          tab={q.tab}
          onTab={q.setTab}
          nav={sheetNav(ids, q.id, (x) => q.open(x))}
          onClose={q.close}
        />
      )}
    </IntFrame>
  );
}

// 감시 목록 — 새로 들어온 행은 강조하며 미끄러져 들어오고, 사라진 행은 잠깐 흐려진 뒤 빠진다
function WatchList({ data, openId, onOpen }: { data?: IntegrationStatus; openId: string | null; onOpen: (id: string) => void }) {
  const rows = useMemo(() => data?.containers ?? [], [data]);
  const [prevRows, setPrevRows] = useState<IntegrationContainer[]>([]);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const [gone, setGone] = useState<IntegrationContainer[]>([]);
  if (rows !== prevRows) {
    const before = new Set(prevRows.map((r) => r.id));
    const now = new Set(rows.map((r) => r.id));
    setFresh(new Set(rows.filter((r) => !before.has(r.id)).map((r) => r.id)));
    const left = prevRows.filter((r) => !now.has(r.id));
    if (left.length) setGone(left);
    setPrevRows(rows);
  }
  useEffect(() => {
    if (!gone.length) return;
    const t = window.setTimeout(() => setGone([]), 700);
    return () => window.clearTimeout(t);
  }, [gone]);
  const watched = rows.filter((r) => r.watched);
  const enforced = rows.filter((r) => r.enforce);
  return (
    <Panel
      className="int-watch min-h-0"
      testId="int-watch"
      title="실행 중인 컨테이너"
      sub="3초마다 갱신"
      actions={
        <span className="int-sum" data-part="watch-sum">
          <b>{fmtNum(watched.length)}</b> 감시 · <b className="danger">{fmtNum(enforced.length)}</b> 격리 대상 · {fmtNum(rows.length - watched.length)} 감시 밖
        </span>
      }
    >
      <div className="int-watch-body">
        {data?.listError && <p className="int-points warn" role="alert">컨테이너 목록을 읽지 못했습니다. {sentence(data.listError)}</p>}
        {!data ? (
          <Skeleton rows={6} />
        ) : rows.length + gone.length === 0 ? (
          <div data-part="watch-empty">
            <Empty>실행 중인 컨테이너가 없습니다.</Empty>
          </div>
        ) : (
          <ul className="int-rows" data-part="watch-rows">
            {rows.map((r) => (
              <li
                key={r.id}
                data-container={r.name}
                data-watched={String(r.watched)}
                data-enforce={String(r.enforce)}
                className={`int-row int-row-open ${r.watched ? '' : 'out'} ${fresh.has(r.id) ? 'in' : ''}`}
                {...rowState({ open: r.id === openId })}
                {...rowKeys(() => onOpen(r.id))}
                onClick={() => onOpen(r.id)}
              >
                <span className={`int-row-dot ${r.enforce ? 'danger' : r.watched ? 'ok' : ''}`} aria-hidden />
                <span className="int-row-name" title={r.name}>
                  {r.name}
                </span>
                <span className="int-row-image" title={r.image}>
                  {r.image}
                </span>
                <span className="int-row-tags">
                  <WatchTags c={r} />
                </span>
              </li>
            ))}
            {gone.map((r) => (
              <li key={`gone-${r.id}`} className="int-row gone" aria-hidden>
                <span className="int-row-dot" />
                <span className="int-row-name">{r.name}</span>
                <span className="int-row-image">{r.image}</span>
                <span className="int-row-tags">
                  <span className="sg-pill sg-pill-neutral">종료</span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
}
