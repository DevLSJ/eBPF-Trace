import { OctagonX, Play } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useFilters } from '../../hooks/useFilters';
import { dest } from '../../lib/nav';
import { FilterChips } from '../../components/FilterChips';
import { rowKeys, rowState, useAutoRetry, useBusy } from '../../components/list/hooks';
import { GridCells, SortHead, TablePager, TableScroll } from '../../components/DataTable';
import { useTableKit, type Column } from '../../hooks/useTableKit';
import { fmtStatus } from '../../components/list/cell-format';
import { downloadCSV } from '../../components/list/csv';
import { ScreenNote } from '../../components/ScreenNote';
import { TableToolbar } from '../../components/TableToolbar';
import { screenCopy } from '../../lib/screenCopy';
import { AppliedFilters, EmptyState, ListError, NoResults, PagerSlot, Skeleton } from '../../components/list/ListStates';
import { TimeText } from '../../components/list/cells';
import { ActionButton } from '../../components/ActionButton';
import { CodeWindow, CW_BODY } from '../../components/CodeWindow';
import { FileTree, type TreeItem } from '../../components/FileTree';
import { ConfirmDialog } from '../../components/Modal';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { Section, Sheet } from '../../components/Sheet';
import { sheetNav, type SheetNav } from '../../components/sheet-nav';
import { useAuth } from '../../hooks/auth-context';
import { useToast } from '../../hooks/toast-context';
import { useInterval, useLoad } from '../../hooks/useLoad';
import { api, errorText, failText, sentence } from '../../lib/api';
import { FIELD } from '../../lib/fieldNames';
import { fmtNum } from '../../lib/format';
import { SCAN_VERDICT_LABEL, type Scan, type ScanFinding } from '../../lib/types';
import { ScanVerdictBadge } from '../../components/Badges';
import { ScanPackages } from './ScanPackages';

// 공급망 검사(10/16, 목업 확정) — 「설치하기 전에, 이 패키지 · 저장소 · 파일에 위험한 코드나 알려진 취약점이 있나?」
// 실제 오픈소스로 정적 검사: GuardDog(악성 코드 패턴 — 파일:줄) · OSV-Scanner(의존성의 알려진 취약점). 코드를 실행하지 않는다.
const VERDICT = SCAN_VERDICT_LABEL; // 판정 이름 · 배지는 components/Badges ScanVerdictBadge 와 공유(11/04 설치 목록 「정적 검사」 열)
const RISK: Record<string, string> = { high_risk: '높음', medium_risk: '보통', low_risk: '낮음', no_risks_detected: '없음' };
const MAX_UPLOAD = 50 * 1024 * 1024;
// GuardDog 규칙 → 쉬운 설명(없으면 GuardDog 원문). 원문은 마우스를 올리면 보인다
const RULE_KO: Record<string, string> = {
  'threat-network-exfiltration': '의심 도메인 · IP 로 보내는 주소(정보 유출 · 원격 조종에 흔함)',
  'threat-filesystem-read': '민감 파일(계정 · 키 · 설정) 접근',
  'threat-setup-suspicious-imports': 'setup.py 에서 네트워크 · 시스템 모듈을 불러옴',
  'threat-process-hooks': '설치 단계(훅)에서 프로그램 실행 · 네트워크 사용',
  'threat-process-download-exec': '내려받아 바로 실행',
  'threat-network-reverse-shell': '리버스 셸(공격자에게 셸 연결)',
  'threat-process-cryptomining': '암호화폐 채굴',
  'threat-npm-preinstall-script': 'npm 설치 전 스크립트 실행',
  'threat-filesystem-autostart': '자동 실행 등록',
  'threat-runtime-dynamic-loader': '동적으로 코드를 불러와 실행',
  'capability-process-spawn': '프로세스 실행',
  'capability-network-lolbas': '시스템 도구로 내려받기',
  'capability-network-outbound': '외부로 연결',
  'capability-network-download': '파일 내려받기',
  'capability-filesystem-read': '파일 읽기',
  'capability-filesystem-delete': '파일 · 폴더 삭제',
  'capability-filesystem-write-executable': '실행 파일 쓰기',
};
// 입력 글자 13.5 · 포커스 링은 전역 규칙(index.css) 하나 — 화면 쪽 focus · 글자 크기 유틸리티를 두지 않는다(11/09 SPEC §1)
const input = 'h-8 min-w-0 rounded-[var(--r-md)] border border-slate-300 bg-field px-2';

// GitHub 주소(W4) — 백엔드 scan.ParseGitHubURL 과 같은 형식(공개 저장소만): 저장소 · …/tree/<ref>[/<폴더>] · …/commit/<sha> · …/releases/tag/<태그>.
// ?쿼리 · #조각은 무시. ref 에 / 가 든 브랜치(feature/x)는 지원하지 않는다(첫 조각이 브랜치로 읽힌다)
const GH_HINT = '저장소 주소는 https://github.com/<소유자>/<저장소> 모양으로 입력하세요. 브랜치 · 폴더는 …/tree/<브랜치>/<폴더>, 커밋은 …/commit/<sha>, 릴리스는 …/releases/tag/<태그>.';
const GH_RE = /^https:\/\/(?:www\.)?github\.com\/[\w.-]+\/[\w.-]+?(?:\.git)?(?:\/(?:tree\/[\w.+-]+(?:\/[\w.@+~-]+)*|commit\/[\w.+-]+|releases\/tag\/[\w.+-]+))?\/?$/;
function repoUrlError(raw: string): string {
  const url = raw.trim().replace(/[?#].*$/, '');
  if (/^https:\/\/(?:www\.)?github\.com\/[\w.-]+\/[\w.-]+\/(?:blob|raw)\//.test(url)) return '파일 하나는 「파일 올리기」로 검사하세요. 저장소 주소는 …/tree/<브랜치>/<폴더>까지입니다.';
  if (!GH_RE.test(url)) return GH_HINT;
  if (/\/\.{1,2}(?:\/|$)/.test(url.slice('https://'.length))) return '하위 경로에 . 또는 .. 조각은 쓸 수 없습니다.';
  return '';
}

type VerdictFilter = '' | 'malicious' | 'vulnerable' | 'caution' | 'clean';

// 표 칸(R4 11/04 — 목업 11/04e U.tableKit): 머리 클릭 정렬 · 기본은 시작 내림(목록 순서 그대로). 결과는 위험한 것부터(검사 중이 맨 앞).
// 11/09 SPEC §4: 현황 표 — 상태(결과)가 맨 앞, 시작은 MM-DD HH:mm + 전체 시각 툴팁
const VERDICT_RANK: Record<string, number> = { malicious: 0, vulnerable: 1, caution: 2, clean: 3 };
// 11/09 표 도구: 칸 보이기 · 폭 · 순서는 이 브라우저에(supplyguard.grid.scans.v1), CSV = 보이는 칸 · 화면 글
const verdictText = (x: Scan) => (x.status === 'running' ? '검사 중…' : x.status === 'failed' ? '실패' : VERDICT[x.verdict ?? 'clean']);
const vulnText = (x: Scan) => (x.status === 'done' ? (x.vulnCount ? `${fmtNum(x.vulnCount)} (최고 ${x.vulnMax})` : '0') : null);
const COLUMNS: Column<Scan>[] = [
  { key: 'verdict', label: '결과', sort: (x) => (x.status === 'running' ? -1 : x.verdict ? VERDICT_RANK[x.verdict] : null), short: true, cell: (x) => <StatusBadge s={x} />, csv: verdictText },
  { key: 'started', label: '시작', sort: (x) => Date.parse(x.startedAt), short: true, cell: (x) => <TimeText value={x.startedAt} kind="status" />, csv: (x) => fmtStatus(x.startedAt) },
  { key: 'target', label: '대상', sort: (x) => x.target.label, fill: true, cellClass: 'font-mono', cell: (x) => <span title={x.target.label}>{x.target.label}</span>, csv: (x) => x.target.label },
  { key: 'risk', label: '위험 점수', num: true, sort: (x) => x.risk?.score ?? null, short: true, cellClass: 'num', cell: (x) => (x.risk ? x.risk.score.toFixed(1) : null) },
  {
    key: 'threats',
    label: '위협',
    num: true,
    sort: (x) => (x.status === 'done' ? x.threats : null),
    short: true,
    cellClass: 'num',
    cell: (x) => (x.status === 'done' ? <span className={x.threats ? 'text-red-600' : 'text-slate-400'}>{fmtNum(x.threats)}</span> : null),
    csv: (x) => (x.status === 'done' ? x.threats : null),
  },
  {
    key: 'vulns',
    label: '취약점',
    num: true,
    sort: (x) => (x.status === 'done' ? x.vulnCount : null),
    short: true,
    cellClass: 'num',
    cell: (x) => (x.status === 'done' ? <span className={x.vulnCount ? 'text-amber-700' : 'text-slate-400'}>{vulnText(x)}</span> : null),
    csv: vulnText,
  },
];

export function ScansPage() {
  const { isAdmin } = useAuth();
  const [params, setParams] = useSearchParams();
  const selId = params.get('id') ?? '';
  // 결과 필터(10/20 D) — 화면 상태로만(10/21, 주소에 남기지 않음)
  const [filters, setFilters] = useFilters('/scans');
  const vf = filters.verdict as VerdictFilter;
  const list = useLoad(api.scans);
  const running = list.data?.some((s) => s.status === 'running');
  // 첫 로드가 실패한 동안은 갱신을 멈추고 30초마다 조용히 한 번 다시 부른다
  const failing = !!list.error && !list.data;
  const { reload } = list;
  const poll = useCallback(() => {
    if (!failing) reload();
  }, [failing, reload]);
  useInterval(poll, running ? 2000 : 15000);
  useAutoRetry(failing, list.error, reload);
  const canWrite = isAdmin; // 조회자는 검사 시작 · 차단 버튼을 그리지 않는다(W16)
  const kit = useTableKit({ columns: COLUMNS, sort: { key: 'started', dir: 'desc' }, grid: 'scans' });
  const busy = useBusy(list.loading && !!list.data);
  const setQ = (k: 'id' | 'verdict', v: string) => {
    if (k === 'verdict') {
      kit.setPage(1); // 필터를 바꾸면 첫 쪽부터(11/04e)
      return setFilters({ verdict: v });
    }
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };
  const select = (id: string) => setQ('id', id);
  const rows = (list.data ?? []).filter((x) => !vf || x.verdict === vf);
  // 주소 ?id= 로 들어오면 그 행이 있는 쪽(첫 데이터 한 번)
  const [revealed, setRevealed] = useState(false);
  if (!revealed && selId && list.data) {
    setRevealed(true);
    kit.reveal(rows, (x) => x.id === selId);
  }
  const view = kit.view(rows);
  const vOptions = [
    { value: '' as VerdictFilter, label: '전체', count: list.data?.length },
    ...(['malicious', 'vulnerable', 'caution', 'clean'] as const).map((k) => ({ value: k as VerdictFilter, label: VERDICT[k], count: list.data?.filter((x) => x.verdict === k).length })),
  ];

  return (
    <div className="grid h-full min-h-0 grid-cols-[minmax(0,1fr)_auto] gap-4">
      <div className="flex min-h-0 flex-col gap-3">
        <p data-part="screen-copy" data-screen="scans" className="m-0 shrink-0 truncate text-[length:var(--fs-sm)] text-text-3">
          {screenCopy('scans')}
        </p>
        <ScanForm canWrite={canWrite} onStarted={() => { select(''); list.reload(); }} />
        <Panel title="검사 기록" testId="scans" className="min-h-0 flex-1" actions={list.data?.length ? <FilterChips label="결과" options={vOptions} value={vf} onChange={(v) => setQ('verdict', v)} /> : undefined}>
          <div className="flex h-full flex-col">
          <AppliedFilters items={[!!vf && { key: 'verdict', label: `결과: ${(vf && VERDICT[vf]) || vf}`, clear: () => setQ('verdict', '') }]} onClearAll={() => setQ('verdict', '')} />
          {failing ? (
            <ListError error={list.error} what="공급망 검사" onRetry={list.reload} retrying={list.loading} />
          ) : !list.data ? (
            <Skeleton rows={5} />
          ) : !list.data.length ? (
            <EmptyState
              what="공급망 검사"
              hint={canWrite ? '위 칸에 패키지 이름 · 저장소 주소 · 파일을 넣어 첫 검사를 시작하세요. 예: pip reqeusts(requests 의 오타, 타이포스쿼팅 시연)' : '관리자가 검사를 시작하면 여기에 쌓입니다.'}
            />
          ) : !rows.length ? (
            <NoResults onClear={() => setQ('verdict', '')} />
          ) : (
            <>
              <TableToolbar name="scans" total={rows.length} kit={kit} onRefresh={list.reload} refreshing={busy} onExport={() => downloadCSV('supplyguard-scans.csv', kit.csv(rows))} />
              <TableScroll data-fill="" className="min-h-0 flex-1 overflow-auto">
                <table className="sg-table" data-table="scans">
                  <SortHead kit={kit} />
                  <tbody>
                    {view.rows.map((s) => (
                      <tr key={s.id} {...rowKeys(() => select(s.id))} {...rowState({ open: s.id === selId })} data-scan={s.id} data-status={s.status} onClick={() => select(s.id)} className="cursor-pointer">
                        {/* 11/04e 막대: 악성 의심 행만(위험색) — 첫 칸 */}
                        <GridCells kit={kit} row={s} bar={s.verdict === 'malicious' && 'danger'} />
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableScroll>
              <PagerSlot edge={!selId}>
                <TablePager name="scans" total={view.total} from={view.from} to={view.to} page={view.page} size={kit.size} onPage={kit.setPage} onSize={kit.setSize} />
              </PagerSlot>
            </>
          )}
          </div>
        </Panel>
        <ScreenNote screen="scans" />
      </div>
      {selId && <ScanSheet key={selId} id={selId} canWrite={canWrite} done={list.data?.find((s) => s.id === selId)?.status !== 'running'} onClose={() => select('')} nav={sheetNav(view.rows.map((s) => s.id), selId, select)} />}
    </div>
  );
}

function StatusBadge({ s }: { s: Scan }) {
  return <ScanVerdictBadge status={s.status} verdict={s.verdict} error={s.error} />;
}

function ScanForm({ canWrite, onStarted }: { canWrite: boolean; onStarted: () => void }) {
  const toast = useToast();
  const [kind, setKind] = useState<'package' | 'repo' | 'file'>('package');
  const [manager, setManager] = useState('pip');
  const [name, setName] = useState('');
  const [version, setVersion] = useState('');
  const [url, setUrl] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const start = async () => {
    setErr('');
    if (kind === 'repo') {
      const e = repoUrlError(url);
      if (e) return setErr(e);
    }
    if (kind === 'package' && !name.trim()) return setErr('패키지 이름을 입력하세요.');
    if (kind === 'file' && !file) return setErr('파일을 먼저 고르세요.');
    if (kind === 'file' && file && file.size > MAX_UPLOAD) return setErr(`파일은 50MB까지입니다(「${file.name}」).`);
    setBusy(true);
    try {
      const r = await api.startScan(kind === 'file' ? file! : kind === 'repo' ? { kind, url: url.trim() } : { kind, manager, name: name.trim(), version: version.trim() });
      toast(`검사 ${r.id}을(를) 시작했습니다.`, { key: 'scan', tone: 'info' });
      onStarted();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  const tabs: [typeof kind, string][] = [['package', '패키지 이름'], ['repo', '저장소 주소'], ['file', '파일 올리기']];
  return (
    <section className="shrink-0 rounded-[var(--r-lg)] border border-card-line bg-surface shadow-[var(--sh-1)]" data-part="scan-form">
      <header className="flex items-center justify-between border-b border-slate-100 px-4 py-2.5">
        <h2 className="text-sm font-semibold text-slate-800">검사할 대상</h2>
        <span className="text-xs text-slate-400">설치하기 전에 정적 검사(코드를 실행하지 않음)</span>
      </header>
      <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2.5 px-4 py-3">
        <div className="col-span-2 flex rounded-md border border-slate-300 p-0.5 text-xs font-medium justify-self-start" role="group" aria-label="입력">
          {tabs.map(([k, ko]) => (
            <button key={k} type="button" data-input={k} aria-pressed={kind === k} onClick={() => { setKind(k); setErr(''); }}
              className={`rounded px-3 py-1 ${kind === k ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-100'}`}>{ko}</button>
          ))}
        </div>
        <div className="flex min-w-0 gap-2">
          {kind === 'package' ? (
            <>
              <select className={`${input} w-20`} data-field="manager" aria-label={FIELD.manager} value={manager} onChange={(e) => setManager(e.target.value)}>
                <option>pip</option>
                <option>npm</option>
              </select>
              <input className={`${input} flex-1 font-mono`} data-field="name" aria-label="패키지 이름" placeholder="예: requests" value={name} onChange={(e) => setName(e.target.value)} />
              <input className={`${input} w-32 font-mono`} data-field="version" aria-label="버전" placeholder="비우면 최신 버전" value={version} onChange={(e) => setVersion(e.target.value)} />
            </>
          ) : kind === 'repo' ? (
            <span key="repo" className="flex min-w-0 flex-1 flex-col gap-1">
              <input className={`${input} w-full font-mono`} data-field="url" aria-label="저장소 주소" placeholder="예: https://github.com/소유자/저장소" value={url} onChange={(e) => setUrl(e.target.value)} />
              <span className="truncate text-xs text-slate-400" data-part="repo-hint">공개 저장소만 · 기본 브랜치 전체, 또는 …/tree/&lt;브랜치&gt;/&lt;폴더&gt; · …/commit/&lt;sha&gt; · …/releases/tag/&lt;태그&gt; (브랜치 이름의 / 는 지원하지 않음)</span>
            </span>
          ) : (
            // 파일 칸은 비제어 입력 — 다른 칸과 자리를 나눠 쓰지 않게 key 로 분리(파일 → 저장소 전환 때 React 경고)
            <span key="file" className="flex min-w-0 items-center gap-2">
              <input type="file" aria-label="파일" accept=".tar.gz,.tgz,.whl,.zip,.py,.js,.txt,.json,.lock,.yaml" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" />
              <span className="truncate text-xs text-slate-400">패키지 압축 · 소스 · 의존성 파일(requirements.txt · package-lock.json), 50MB 까지</span>
            </span>
          )}
        </div>
        {canWrite ? (
          <ActionButton aria-label="검사 시작" reason={busy && '검사를 시작하는 중입니다'} onClick={() => void start()} className="sg-btn sg-btn-primary">
            {busy ? '시작 중…' : '검사 시작'}
          </ActionButton>
        ) : (
          <span className="self-center text-xs text-slate-500">검사 시작은 관리자만 할 수 있습니다.</span>
        )}
        {err && <p className="col-span-2 text-xs text-red-600" data-form-error="" role="alert">{err}</p>}
      </div>
    </section>
  );
}

function ScanSheet({ id, canWrite, done, onClose, nav }: { id: string; canWrite: boolean; done: boolean; onClose: () => void; nav?: SheetNav }) {
  const load = useCallback(() => api.scan(id), [id]);
  const r = useLoad(load);
  const { reload } = r;
  useEffect(() => { if (done) reload(); }, [done, reload]);
  const s = r.data;
  return (
    <Sheet kind="scan" size="wide" nav={nav} title={s?.target.label ?? '공급망 검사'} onClose={onClose}>
      {!s ? (r.error ? <LoadError error={r.error} what="검사" /> : <Empty>불러오는 중…</Empty>) : <ScanDetail s={s} canWrite={canWrite} />}
    </Sheet>
  );
}

function ScanDetail({ s, canWrite }: { s: Scan; canWrite: boolean }) {
  const toast = useToast();
  const nav = useNavigate();
  const [focus, setFocus] = useState('');
  const [askBlock, setAskBlock] = useState(false);
  const findings = s.findings ?? [];
  // 테스트 코드 탐지(11/02)는 위협 · 기능과 따로 — 위험 점수 · 판정 · 위협 수에 넣지 않는다
  const threats = findings.filter((f) => f.category === 'threat' && !f.test);
  const caps = findings.filter((f) => f.category === 'capability' && !f.test);
  const tests = findings.filter((f) => f.test);
  // 11/02: 패키지 검사는 자기 버전(direct) 취약점과 OSV-Scanner 가 푼 의존성(간접) 취약점을 나눠 말한다(목업 UI.scanVerdictText 와 같은 문구)
  const vulnText = () => {
    const own = (s.vulns ?? []).filter((v) => v.direct).reduce((n, v) => n + v.count, 0);
    const dep = (s.vulns ?? []).filter((v) => !v.direct).reduce((n, v) => n + v.count, 0);
    if (s.target.kind === 'package' && own) return `이 버전에 알려진 취약점이 ${fmtNum(own)}건${dep ? ` · 의존성에 ${fmtNum(dep)}건` : ''} 있습니다. 고쳐진 버전으로 올리세요.`;
    return `의존성에 알려진 취약점이 ${fmtNum(own + dep || s.vulnCount)}건 있습니다. 고쳐진 버전으로 올리세요.`;
  };
  const vulns = s.vulns ?? [];
  const t = s.target;
  const cmd = t.kind === 'package' ? `sg-install ${t.manager} ${t.name}${t.version ? (t.manager === 'pip' ? '==' : '@') + t.version : ''}` : '';
  // 설치 검사 명령 복사 — 문구는 hooks/useCopyCommand 와 같게(11/09), 성공 알림에는 「설치 검사」 이동 단추
  const copyCmd = (c: string) => {
    const ok = () => toast(`「${c}」 명령을 복사했습니다.`, { key: 'copy', tone: 'ok', action: { label: '설치 검사', ...dest('/installs', { status: 'all' }) } });
    const fail = () => toast(`명령을 복사하지 못했습니다. 「${c}」을(를) 직접 입력하세요.`, { key: 'copy', tone: 'warn' });
    try {
      navigator.clipboard.writeText(c).then(ok, fail);
    } catch {
      fail();
    }
  };
  const block = async (reason: string) => {
    try {
      const r = await api.scanBlock(s.id, reason);
      nav(`/policies?proposal=${encodeURIComponent(r.proposalId)}`);
    } catch (e) {
      toast(failText('차단 제안을 만들지 못했습니다.', e), { key: 'scan-block', tone: 'danger' });
    }
  };
  const item = (f: ScanFinding) => {
    const loc = `${f.file}:${f.line}`;
    return (
      <li key={`${f.rule}:${loc}`}>
        <button type="button" data-finding="" data-category={f.category} data-test={f.test ? 'true' : undefined} data-loc={loc} onClick={() => setFocus(loc)}
          className={`grid w-full grid-cols-[minmax(0,12rem)_minmax(0,1fr)] gap-x-2 rounded-md border border-l-4 px-2.5 py-1.5 text-left text-xs hover:bg-slate-50 ${f.test ? 'border-l-slate-300' : f.category === 'threat' ? 'border-l-red-500' : 'border-l-amber-400'} ${focus === loc ? 'bg-slate-50' : ''}`}>
          <span className="truncate font-mono" title={loc}>{`${f.file.split('/').pop()}:${f.line}`}</span>{/* 11/04f: 폴더 안 파일은 이름:줄만(줄 번호가 잘리지 않게) — 전체 경로는 툴팁 · 트리 · 코드 창 이름 */}
          <b className="font-medium text-slate-800" title={f.message}>{RULE_KO[f.rule] ?? f.message}</b>
          <span className="col-start-2 font-mono text-slate-400">
            {f.rule}
            {f.test && <span className="ml-1.5 rounded-full bg-slate-100 px-1.5 py-0.5 font-sans text-xs text-slate-600">테스트 코드</span>}
          </span>
        </button>
      </li>
    );
  };
  return (
    <div className="text-sm">
      <Section title="결과">
        <div className={`grid gap-2 rounded-lg border p-3 ${s.verdict === 'malicious' ? 'border-red-200 bg-red-50' : s.verdict === 'vulnerable' || s.verdict === 'caution' ? 'border-amber-200 bg-amber-50' : 'border-slate-200'}`} data-part="verdict">
          <div className="flex items-center gap-2">
            <ScanVerdictBadge status={s.status} verdict={s.verdict} className="font-medium" />
            {s.risk && <span className="text-xs">위험 점수 <b className="num">{s.risk.score.toFixed(1)}</b> / 10 · {RISK[s.risk.label] ?? s.risk.label}</span>}
          </div>
          <p className="text-xs text-slate-700">
            {s.status === 'failed' ? `검사하지 못했습니다. ${sentence(s.error ?? '')}`.trim() : s.status === 'running' ? '검사 중입니다…'
              : s.verdict === 'malicious' ? `설치 단계에서 위험한 행동을 하는 코드가 ${s.installThreats || threats.length}곳 있습니다. 설치하지 말고 차단 목록에 올리세요.`
              : s.verdict === 'vulnerable' ? vulnText()
              : s.verdict === 'caution' ? `설치 단계의 위험한 행동은 없고, 실행 중 동작 규칙(동적 로딩 · 환경 변수 읽기 등)에 ${threats.length}곳 걸렸습니다. 정상 라이브러리에도 흔한 패턴이니 코드 보기로 확인하세요.`
              : '정적 검사에서 위험한 코드 · 알려진 취약점을 찾지 못했습니다. 설치 검사(eBPF)로 실제 행동도 확인할 수 있습니다.'}
          </p>
          {t.kind === 'repo' && t.url && (
            <p className="flex flex-wrap items-center gap-1.5 text-xs text-slate-600" data-part="repo-ref">
              <a href={t.url} target="_blank" rel="noreferrer" className="truncate font-mono text-indigo-600 hover:underline">{t.url}</a>
              <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono" data-ref={t.ref ?? ''}>{t.ref ? `브랜치/태그 ${t.ref}` : '기본 브랜치'}</span>
              {t.subpath && <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono" data-subpath={t.subpath}>폴더 {t.subpath}</span>}
            </p>
          )}
          {s.status === 'done' && t.kind === 'package' && (
            <div className="flex flex-wrap gap-2">
              <button type="button" aria-label="설치 검사로 실제 설치해 보기" onClick={() => copyCmd(cmd)}
                className="flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1 text-xs hover:bg-white"><Play className="size-3.5" aria-hidden /> 설치 검사로 실제 설치해 보기</button>
              {canWrite && <button type="button" aria-label="차단 목록에 올리기" onClick={() => setAskBlock(true)}
                className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-xs disabled:opacity-40 ${s.verdict === 'malicious' ? 'bg-red-600 text-white hover:bg-red-700' : 'border border-slate-300 hover:bg-white'}`}><OctagonX className="size-3.5" aria-hidden /> 차단 목록에 올리기</button>}
            </div>
          )}
        </div>
      </Section>
      {s.status === 'done' && t.kind !== 'package' && <ScanPackages s={s} />}
      {askBlock && (
        <ConfirmDialog
          title={`${t.manager}:${t.name}을(를) 차단 목록에 올릴까요?`}
          target={`${t.label} · ${s.id}`}
          okLabel="올리기"
          reason
          effects={[
            `패키지 ${t.manager}:${t.name} 차단 제안 초안(정책에서 미리보기 후 적용)`,
            '적용하면 다음 sg-install 부터 이 패키지는 설치 전 거부(컨테이너를 띄우지 않음)',
            '공급망 검사 건을 「악성」으로 판정한 기록이 남습니다(사유는 판정 메모)',
          ]}
          undo="정책에서 제안을 「버림」하면 차단 없이 끝납니다. 적용한 뒤에는 차단 목록에서 「해제」"
          onCancel={() => setAskBlock(false)}
          onConfirm={(reason) => {
            setAskBlock(false);
            void block(reason);
          }}
        />
      )}
      <Section title={`위협 ${threats.length}(GuardDog, 누르면 코드에서 그 줄)`}>
        <div data-part="findings" className="grid gap-2">
          {threats.length ? <ul className="grid gap-1">{threats.map(item)}</ul> : <p className="text-xs text-slate-500">없음</p>}
          {caps.length > 0 && (
            <details>
              <summary className="cursor-pointer text-xs text-slate-500">기능 {caps.length}(정보, 위협은 아니지만 코드가 할 수 있는 일)</summary>
              <ul className="mt-1 grid gap-1">{caps.map(item)}</ul>
            </details>
          )}
          {tests.length > 0 && (
            <details data-part="tests">
              <summary className="cursor-pointer text-xs text-slate-500">테스트 코드 {tests.length}(위험 점수 · 판정에 넣지 않음)</summary>
              <ul className="mt-1 grid gap-1">{tests.map(item)}</ul>
            </details>
          )}
        </div>
      </Section>
      <Section title="코드 보기(빨강 = 위협 줄, 노랑 = 기능)">
        <CodeView s={s} focus={focus} setFocus={setFocus} />
      </Section>
      {vulns.length > 0 && (
        <Section title={`알려진 취약점 ${fmtNum(s.vulnCount)}(OSV-Scanner, ${t.kind === 'package' ? '이 패키지 버전 · 의존성 포함' : '간접 의존성 포함'})`}>
          <table className="sg-table" data-part="vulns">
            <thead>
              <tr>{['패키지', '버전', '의존', '건수', '최고', 'ID'].map((x) => <th key={x}>{x}</th>)}</tr>
            </thead>
            <tbody>
              {vulns.map((v) => (
                <tr key={`${v.package}@${v.version}`} data-vpkg={v.package} data-count={v.count} data-max={v.maxSeverity} data-direct={String(v.direct)}>
                  <td className="font-mono">{v.package}</td>
                  <td className="font-mono">{v.version}</td>
                  <td>{v.direct ? '직접' : '간접'}</td>
                  <td className="num">{v.count}</td>
                  <td>{v.maxSeverity ? <span className={`rounded px-1.5 py-0.5 ${Number(v.maxSeverity) >= 9 ? 'bg-red-900 text-white' : Number(v.maxSeverity) >= 7 ? 'bg-red-100 text-red-700' : Number(v.maxSeverity) >= 4 ? 'bg-amber-100 text-amber-800' : 'bg-slate-100'}`}>{v.maxSeverity}</span> : null}</td>
                  <td>{v.ids.slice(0, 2).map((x) => <a key={x} href={`https://osv.dev/vulnerability/${x}`} target="_blank" rel="noreferrer" className="mr-1 font-mono text-indigo-600 hover:underline">{x}</a>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}
      <p className="px-4 pb-3 text-xs text-slate-400">{(s.engines ?? []).map((e) => `${e.name} ${e.version}`).join(' · ')}</p>
    </div>
  );
}

// 코드 보기(11/04f, R1 11/04) — 왼쪽 위협 파일 트리 · 오른쪽 코드 창(파일명 = 경로, 줄 번호 · 위협 줄 · 기능 줄 · mark 그대로). 768 미만은 트리가 위
// 위협 파일이 든 폴더는 처음부터 펼침, 파일마다 위협 개수 배지. 위협 목록 → 그 파일 · 그 줄(딥링크)이면 부모 폴더를 펼친다
const NO_FILES: Record<string, string> = {};
function CodeView({ s, focus, setFocus }: { s: Scan; focus: string; setFocus: (v: string) => void }) {
  const files = s.files ?? NO_FILES;
  const paths = Object.keys(files);
  const box = useRef<HTMLDivElement>(null);
  const cur = paths.includes(focus.split(':')[0]) ? focus.split(':')[0] : paths[0];
  const focusLine = focus.startsWith(`${cur}:`) ? Number(focus.split(':')[1]) : 0;
  const findings = s.findings;
  const threatsIn = useCallback((p: string) => (findings ?? []).filter((f) => f.file === p && f.category === 'threat').length, [findings]);
  const items = useMemo<TreeItem[]>(() => Object.keys(files).map((p) => { const n = threatsIn(p); return { path: p, badge: n ? { text: String(n), cls: 'ft-threat', title: `위협 ${n}곳` } : undefined }; }), [files, threatsIn]);
  useEffect(() => { box.current?.querySelector(`[data-line="${focusLine}"]`)?.scrollIntoView({ block: 'center' }); }, [focusLine, cur]);
  if (!paths.length) return <p className="text-xs text-slate-500" data-part="code">{s.status !== 'done' ? '검사 중…' : '위협이 나온 파일이 없어 코드를 보관하지 않았습니다(걸린 파일만 30일 보관).'}</p>;
  const at = (cat: string) => new Map((s.findings ?? []).filter((f) => f.file === cur && f.category === cat).map((f) => [f.line, f]));
  const thr = at('threat');
  const cap = at('capability');
  const mark = (text: string, f?: ScanFinding) => {
    const i = f?.match ? text.indexOf(f.match) : -1;
    if (!f || i < 0) return text;
    return (<>{text.slice(0, i)}<mark>{f.match}</mark>{text.slice(i + f.match.length)}</>);
  };
  return (
    <div data-part="code" className="code-split">
      <FileTree label="위협 파일" items={items} selected={cur} defaultOpen={(dir) => paths.some((p) => p.startsWith(`${dir}/`) && threatsIn(p) > 0)} onSelect={(p) => p !== cur && setFocus(`${p}:0`)} />
      <CodeWindow name={cur} body="raw">
        <div ref={box} className={`${CW_BODY} code-view`} role="region" aria-label={`${cur} 코드`}>
          {files[cur].split('\n').map((ln, i) => {
            const n = i + 1;
            const tf = thr.get(n);
            const cf = cap.get(n);
            return (
              <div key={n} data-line={n} title={tf ? `${tf.rule} · ${tf.message}` : cf ? `${cf.rule} · ${cf.message}` : undefined}
                className={`code-line ${tf ? 'hl-threat' : cf ? 'hl-cap' : ''} ${n === focusLine ? 'focus' : ''}`}>
                <span className="ln">{n}</span>
                <code>{mark(ln || ' ', tf ?? cf)}</code>
              </div>
            );
          })}
        </div>
      </CodeWindow>
    </div>
  );
}
