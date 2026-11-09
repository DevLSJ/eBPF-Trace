import { useEffect, useMemo, useState } from 'react';
import { Empty, Panel } from '../../components/Panel';
import { sentence } from '../../lib/api';
import { fmtNum } from '../../lib/format';
import type { IntegrationContainer, IntegrationStatus } from '../../lib/types';
import { IntFrame, Skeleton } from './parts';
import { useIntegration } from './useIntegration';
import './integration.css';

// 「연동 › 감시 중 컨테이너」(11/09 밤 — 연동 페이지 오른쪽 목록을 페이지로): 실행 중인 컨테이너의 감시 · 격리 여부(3초마다)
const WATCH_BY: Record<string, string> = { all: '전체 감시', name: '이름', label: '라벨' };
const ENFORCE_BY: Record<string, string> = { all: '전체', name: '이름', label: '라벨', sandbox: '설치 검사', demo: '시연' };

export function IntegrationWatchPage() {
  const { data, error } = useIntegration();
  return (
    <IntFrame page="watch" screen="integration/watch" ready={!!data} error={error}>
      <WatchList data={data} />
    </IntFrame>
  );
}

// 감시 목록 — 새로 들어온 행은 강조하며 미끄러져 들어오고, 사라진 행은 잠깐 흐려진 뒤 빠진다
function WatchList({ data }: { data?: IntegrationStatus }) {
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
              <li key={r.id} data-container={r.name} data-watched={String(r.watched)} data-enforce={String(r.enforce)} className={`int-row ${r.watched ? '' : 'out'} ${fresh.has(r.id) ? 'in' : ''}`}>
                <span className={`int-row-dot ${r.enforce ? 'danger' : r.watched ? 'ok' : ''}`} aria-hidden />
                <span className="int-row-name" title={r.name}>
                  {r.name}
                </span>
                <span className="int-row-image" title={r.image}>
                  {r.image}
                </span>
                <span className="int-row-tags">
                  {r.watched ? <span className="sg-pill sg-pill-ok" data-tag="watch">{WATCH_BY[r.watchBy ?? ''] ?? '감시'}</span> : <span className="sg-pill sg-pill-neutral" data-tag="watch">감시 밖</span>}
                  {r.watched &&
                    (r.enforce ? (
                      <span className="sg-pill sg-pill-danger" data-tag="enforce">
                        격리 · {ENFORCE_BY[r.enforceBy ?? ''] ?? ''}
                      </span>
                    ) : (
                      <span className="sg-pill sg-pill-warn" data-tag="enforce" title="supplyguard.enforce=true 라벨이 있어야 격리됨">
                        격리 보류
                      </span>
                    ))}
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
