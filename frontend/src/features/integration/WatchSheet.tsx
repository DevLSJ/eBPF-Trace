import { Copy } from 'lucide-react';
import { useCallback, useMemo, type ReactNode } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { GridCells, SortHead, TableScroll } from '../../components/DataTable';
import { KindBadge } from '../../components/KindBadge';
import { fmtLog } from '../../components/list/cell-format';
import { TimeText } from '../../components/list/cells';
import { rowKeys, rowState } from '../../components/list/hooks';
import { EmptyState, ListError, Skeleton } from '../../components/list/ListStates';
import { Section, Sheet, type SheetTab } from '../../components/Sheet';
import type { SheetNav } from '../../components/sheet-nav';
import { VerdictBadge } from '../../components/VerdictBadge';
import { useStream } from '../../hooks/stream-context';
import { useLoad } from '../../hooks/useLoad';
import { COL_W, useTableKit, type Column } from '../../hooks/useTableKit';
import { useToast } from '../../hooks/toast-context';
import type { StreamVerdict } from '../../hooks/useEventStream';
import { api } from '../../lib/api';
import { FIELD } from '../../lib/fieldNames';
import { fmtDateTime, fmtNum, shortId } from '../../lib/format';
import { dest } from '../../lib/nav';
import { WATCH_TABS } from './model';
import { detailOf, LEVEL_LABEL, levelOf, type AuditEntry, type IntegrationContainer, type IntegrationContainerDetail } from '../../lib/types';

// 감시 중 컨테이너 상세 시트(11/10 사용자 결정): 행 클릭 · Enter → 오른쪽 시트(공통 Sheet), 주소 ?id=<컨테이너 id>&tab=violations|events
//   정보 = 읽기 전용 GET /api/integration/containers/{id}(상태 · 시작 시각 · 재시작 · 포트 · 라벨, 환경 변수는 서버가 보내지 않음) + 감시 · 격리 이유
//   위반 이력 = GET /api/audit?container=<이름> 은 부분 일치라 이름이 완전히 같은 것만 남긴다(최근 200건 안) · 시각 먼저 · 행 → 감사 로그 그 기록
//   최근 이벤트 = 실시간 수집 흐름(셸이 받는 최근 500건) 중 이 컨테이너 것만 최근 순 50건
const AUDIT_FETCH = 200;
const SHOW_MAX = 50;

const WATCH_BY: Record<string, string> = { all: '전체 감시', name: '이름', label: '라벨' };
const ENFORCE_BY: Record<string, string> = { all: '전체', name: '이름', label: '라벨', sandbox: '설치 검사', demo: '시연' };
const WATCH_WHY: Record<string, string> = {
  all: '전체 감시(감시 범위를 따로 정하지 않아 모든 컨테이너를 감시합니다)',
  name: '이름 규칙(서버의 감시 이름 규칙에 맞습니다)',
  label: '라벨 supplyguard.watch=true',
};
const ENFORCE_WHY: Record<string, string> = {
  all: '전체 격리',
  name: '이름 규칙(서버의 격리 이름 규칙에 맞습니다)',
  label: '라벨 supplyguard.enforce=true',
  sandbox: '설치 검사 컨테이너(sg-install)',
  demo: '시연 컨테이너',
};
const STATE_LABEL: Record<string, string> = {
  running: '실행 중',
  created: '생성됨',
  restarting: '다시 시작 중',
  paused: '일시 중지',
  exited: '종료됨',
  removing: '삭제 중',
  dead: '중지됨',
};

export function WatchTags({ c }: { c: IntegrationContainer }) {
  return (
    <>
      {c.watched ? (
        <span className="sg-pill sg-pill-ok" data-tag="watch">
          {WATCH_BY[c.watchBy ?? ''] ?? '감시'}
        </span>
      ) : (
        <span className="sg-pill sg-pill-neutral" data-tag="watch">
          감시 밖
        </span>
      )}
      {c.watched &&
        (c.enforce ? (
          <span className="sg-pill sg-pill-danger" data-tag="enforce">
            격리 · {ENFORCE_BY[c.enforceBy ?? ''] ?? ''}
          </span>
        ) : (
          <span className="sg-pill sg-pill-warn" data-tag="enforce" title="supplyguard.enforce=true 라벨이 있어야 격리됨">
            격리 보류
          </span>
        ))}
    </>
  );
}

export function WatchSheet({
  id,
  row,
  tab,
  onTab,
  nav,
  onClose,
}: {
  id: string;
  // 목록의 그 줄(3초마다 갱신) — 목록에서 빠졌으면(종료) undefined, 시트는 상세 응답 값으로 그린다
  row: IntegrationContainer | undefined;
  tab: string | null;
  onTab: (t: string) => void;
  nav?: SheetNav;
  onClose: () => void;
}) {
  const load = useCallback(() => api.integrationContainer(id), [id]);
  const detail = useLoad<IntegrationContainerDetail>(load);
  const c: IntegrationContainer | undefined = row ?? detail.data;
  const name = c?.name ?? '';
  const cur = tab && (WATCH_TABS as readonly string[]).includes(tab) ? tab : 'info';
  const tabs: SheetTab[] = [
    { key: 'info', label: '정보' },
    { key: 'violations', label: '위반 이력' },
    { key: 'events', label: '최근 이벤트' },
  ];
  return (
    <Sheet
      kind="watch"
      title={name || shortId(id)}
      subtitle={c?.image || undefined}
      badges={c && <WatchTags c={c} />}
      tabs={tabs}
      tab={cur}
      onTab={onTab}
      nav={nav}
      onClose={onClose}
      loading={!c && detail.loading}
    >
      {cur === 'violations' ? (
        name ? <WatchViolations key={name} name={name} /> : <WatchInfo id={id} c={c} detail={detail} />
      ) : cur === 'events' ? (
        name ? <WatchEvents key={name} id={id} name={name} /> : <WatchInfo id={id} c={c} detail={detail} />
      ) : (
        <WatchInfo id={id} c={c} detail={detail} />
      )}
    </Sheet>
  );
}

function Row({ field, label, children }: { field: string; label: string; children: ReactNode }) {
  return (
    <div className="watch-dl-row" data-field={field}>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function WatchInfo({ id, c, detail }: { id: string; c: IntegrationContainer | undefined; detail: { data?: IntegrationContainerDetail; error: unknown; loading: boolean; reload: () => void } }) {
  const toast = useToast();
  const d = detail.data;
  const copy = () => {
    const ok = () => toast('컨테이너 ID 를 복사했습니다.', { key: 'copy', tone: 'ok' });
    const fail = () => toast('컨테이너 ID 를 복사하지 못했습니다. 직접 선택해 복사하세요.', { key: 'copy', tone: 'warn' });
    try {
      navigator.clipboard.writeText(id).then(ok, fail);
    } catch {
      fail();
    }
  };
  if (detail.error && !d)
    return (
      <div data-testid="watch-info">
        <ListError error={detail.error} what="컨테이너 상세" onRetry={detail.reload} />
      </div>
    );
  if (!d) return <Skeleton rows={5} />;
  // 감시 · 격리 판정은 목록(3초 갱신)이 더 새롭다 — 없으면 상세 응답 값
  const s = c ?? d;
  const labels = Object.entries(d.labels).sort(([a], [b]) => a.localeCompare(b));
  return (
    <div className="text-sm" data-testid="watch-info">
      {d.detailError && (
        <p className="int-points warn mt-4" data-part="detail-note" role="status">
          {d.detailError}
        </p>
      )}
      <Section title="컨테이너">
        <dl className="watch-dl">
          <Row field="name" label="이름">
            <span className="font-mono">{d.name}</span>
          </Row>
          <Row field="id" label="ID">
            <span className="inline-flex items-center gap-1.5">
              <span className="font-mono" data-part="id-short" title={id}>
                {shortId(id)}
              </span>
              <button type="button" className="sg-btn sg-btn-sm sg-btn-secondary" data-action="copy-id" onClick={copy} aria-label="전체 ID 복사" title="전체 ID 복사">
                <Copy className="size-3.5" aria-hidden />
                복사
              </button>
            </span>
          </Row>
          <Row field="image" label="이미지">
            <span className="font-mono break-all" title={d.imageId || undefined}>
              {d.image}
            </span>
          </Row>
          <Row field="state" label="상태">
            {STATE_LABEL[d.state] ?? d.state}
          </Row>
          <Row field="started" label="시작 시각">
            {d.startedAt ? <span className="num">{fmtDateTime(d.startedAt)}</span> : ''}
          </Row>
          <Row field="restarts" label="재시작 횟수">
            <span className="num">{fmtNum(d.restartCount)}</span>
          </Row>
          <Row field="ports" label="포트">
            {d.ports.length ? (
              <ul className="watch-list">
                {d.ports.map((p, i) => (
                  <li key={`${p.port}-${i}`} className="font-mono">
                    {p.hostPort ? `${p.port} → ${p.hostIp ? `${p.hostIp}:` : ''}${p.hostPort}` : p.port}
                  </li>
                ))}
              </ul>
            ) : (
              ''
            )}
          </Row>
        </dl>
      </Section>
      <Section title="감시 · 격리">
        <dl className="watch-dl">
          <Row field="watch" label="감시">
            {s.watched ? WATCH_WHY[s.watchBy ?? ''] ?? '감시' : '감시 밖(감시 범위에 들지 않습니다)'}
          </Row>
          <Row field="enforce" label="격리">
            {!s.watched ? (
              ''
            ) : s.enforce ? (
              ENFORCE_WHY[s.enforceBy ?? ''] ?? '격리'
            ) : (
              <>
                격리 보류
                <span className="mt-0.5 block text-xs text-text-3">정책이 격리여도 격리하지 않고 경고만 남깁니다. 격리하려면 supplyguard.enforce=true 라벨을 붙입니다.</span>
              </>
            )}
          </Row>
        </dl>
      </Section>
      <Section title={`라벨(${fmtNum(labels.length)})`}>
        {labels.length ? (
          <ul className="watch-list watch-labels">
            {labels.map(([k, v]) => (
              <li key={k} className="font-mono" data-label={k} title={`${k}=${v}`}>
                {k}={v}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-text-3">라벨이 없습니다.</p>
        )}
      </Section>
    </div>
  );
}

const VIO_COLS: Column<AuditEntry>[] = [
  { key: 'at', label: '시각', width: COL_W.log, cell: (a) => <TimeText value={a.event.timestamp} kind="log" />, csv: (a) => fmtLog(a.event.timestamp) },
  { key: 'policy', label: FIELD.policy, cell: (a) => <span className="font-mono text-[13px] whitespace-nowrap">{a.ruleId ?? ''}</span> },
  { key: 'result', label: '결과', width: COL_W.status, cell: (a) => <VerdictBadge v={a} />, csv: (a) => LEVEL_LABEL[levelOf(a)] },
  { key: 'detail', label: '요약', fill: true, cell: (a) => <span title={a.reason || detailOf(a.event)}>{a.reason ? `${a.reason}(${detailOf(a.event)})` : detailOf(a.event)}</span> },
];

function WatchViolations({ name }: { name: string }) {
  const navigate = useNavigate();
  const kit = useTableKit({ columns: VIO_COLS });
  const load = useCallback(() => api.audit({ container: name, limit: AUDIT_FETCH }), [name]);
  const res = useLoad(load);
  // 백엔드 container 필터는 부분 일치 — 이름이 완전히 같은 기록만, 최근 순
  const rows = useMemo(
    () =>
      (res.data ?? [])
        .filter((a) => a.event.containerName === name)
        .sort((a, b) => b.event.timestamp.localeCompare(a.event.timestamp) || b.id - a.id)
        .slice(0, SHOW_MAX),
    [res.data, name],
  );
  if (res.error && !res.data) return <ListError error={res.error} what="위반 이력" onRetry={res.reload} />;
  if (!res.data) return <Skeleton rows={4} />;
  const open = (a: AuditEntry) => navigate(`/audit?id=${a.id}`);
  return (
    <div className="flex min-h-full flex-col" data-testid="watch-violations">
      {!rows.length ? (
        <EmptyState what="위반 이력" hint="이 컨테이너에서 위반으로 탐지된 기록이 없습니다." />
      ) : (
        <TableScroll className="min-w-0 overflow-x-auto">
          <table className="sg-table min-w-[560px]" data-table="watch-violations">
            <SortHead kit={kit} />
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} data-audit={a.id} {...rowState({})} {...rowKeys(() => open(a))} onClick={() => open(a)} className="cursor-pointer">
                  <GridCells kit={kit} row={a} />
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      )}
      <p className="mt-auto px-5 py-3 text-xs">
        <Link {...dest('/audit', { container: name })} className="text-accent-text hover:underline" data-action="violations-all">
          감사 로그에서 이 컨테이너 기록 모두 보기 ›
        </Link>
      </p>
    </div>
  );
}

const target = (v: StreamVerdict) => {
  const e = v.event;
  if (e.kind === 'connect') return e.dstHost ? `${e.dstHost} (${e.dstIp}:${e.dstPort})` : `${e.dstIp ?? ''}${e.dstPort ? `:${e.dstPort}` : ''}`;
  if (e.kind === 'dns') return e.qtype ? `${e.dstHost ?? ''} (${e.qtype})` : e.dstHost ?? '';
  return detailOf(e);
};
const EV_COLS: Column<StreamVerdict>[] = [
  { key: 'at', label: '시각', width: COL_W.log, cell: (v) => <TimeText value={v.event.timestamp} kind="log" /> },
  { key: 'kind', label: '종류', width: 96, cell: (v) => <KindBadge kind={v.event.kind} /> },
  { key: 'comm', label: '프로세스', width: 120, cell: (v) => <span className="font-mono text-[13px]">{v.event.comm}</span> },
  { key: 'target', label: '대상', fill: true, cell: (v) => <span className="font-mono text-[13px] break-all" title={target(v)}>{target(v)}</span> },
];

function WatchEvents({ id, name }: { id: string; name: string }) {
  const { verdicts, recentLoading, recentError, retryLoad } = useStream();
  const kit = useTableKit({ columns: EV_COLS });
  const rows = useMemo(
    () =>
      verdicts
        .filter((v) => v.event.containerName === name || v.event.containerId === id)
        .sort((a, b) => b.event.timestamp.localeCompare(a.event.timestamp) || b.key - a.key)
        .slice(0, SHOW_MAX),
    [verdicts, name, id],
  );
  if (!verdicts.length && recentError != null) return <ListError error={recentError} what="최근 이벤트" onRetry={retryLoad} />;
  if (!verdicts.length && recentLoading) return <Skeleton rows={4} />;
  return (
    <div className="flex min-h-full flex-col" data-testid="watch-events">
      {!rows.length ? (
        <EmptyState what="최근 이벤트" hint="실시간 수집 흐름(최근 500건)에 이 컨테이너의 이벤트가 없습니다." />
      ) : (
        <TableScroll className="min-w-0 overflow-x-auto">
          <table className="sg-table min-w-[560px]" data-table="watch-events">
            <SortHead kit={kit} />
            <tbody>
              {rows.map((v) => (
                <tr key={v.key} data-event={v.key} data-container={v.event.containerName} data-level={levelOf(v)}>
                  <GridCells kit={kit} row={v} />
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      )}
      <p className="mt-auto px-5 py-3 text-xs text-text-3">실시간 수집 흐름 중 이 컨테이너의 최근 {fmtNum(SHOW_MAX)}건까지 보입니다.</p>
    </div>
  );
}
