import { KeyRound, OctagonX, Play } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { PageActions } from '../../components/PageActions';
import { Empty, LoadError, Panel } from '../../components/Panel';
import { Section, Sheet } from '../../components/Sheet';
import { useStream } from '../../hooks/stream-context';
import { useToast } from '../../hooks/toast-context';
import { useAdminToken, useInterval, useLoad } from '../../hooks/useLoad';
import { api, errorText } from '../../lib/api';
import { fmtDateTime, fmtNum } from '../../lib/format';
import type { Scan, ScanFinding } from '../../lib/types';

// 공급망 검사(10/16, 목업 확정) — 「설치하기 전에, 이 패키지 · 저장소 · 파일에 위험한 코드나 알려진 취약점이 있나?」
// 실제 오픈소스로 정적 검사: GuardDog(악성 코드 패턴 — 파일:줄) · OSV-Scanner(의존성의 알려진 취약점). 코드를 실행하지 않는다.
const VERDICT: Record<string, [string, string]> = {
  malicious: ['악성 의심', 'bg-red-100 text-red-700'],
  vulnerable: ['취약점 있음', 'bg-amber-100 text-amber-800'],
  clean: ['위협 없음', 'bg-emerald-50 text-emerald-700'],
};
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
const input = 'h-8 min-w-0 rounded-md border border-slate-300 px-2 text-sm focus:border-indigo-500 focus:outline-none';

export function ScansPage() {
  const { info } = useStream();
  const [token, setToken] = useAdminToken();
  const [params, setParams] = useSearchParams();
  const selId = params.get('id') ?? '';
  const list = useLoad(api.scans);
  const running = list.data?.some((s) => s.status === 'running');
  useInterval(list.reload, running ? 2000 : 15000);
  const canWrite = !info?.authRequired || token !== '';
  const select = (id: string) => setParams(id ? { id } : {}, { replace: true });

  return (
    <div className="grid h-full min-h-0 grid-cols-[minmax(0,1fr)_auto] gap-4">
      <PageActions>
        {info?.authRequired && (
          <label className="flex items-center gap-2 text-xs text-slate-500">
            <KeyRound className="size-4 shrink-0" aria-hidden />
            관리자 토큰
            <input type="password" autoComplete="off" placeholder="검사 시작 · 차단 시 필요" className={`${input} w-56`} value={token} onChange={(e) => setToken(e.target.value)} />
          </label>
        )}
      </PageActions>
      <div className="flex min-h-0 flex-col gap-4">
        <ScanForm canWrite={canWrite} onStarted={() => { select(''); list.reload(); }} />
        <Panel title="검사 기록" className="min-h-0 flex-1">
          {list.error && !list.data ? (
            <LoadError error={list.error} what="공급망 검사" />
          ) : !list.data?.length ? (
            <Empty>아직 검사가 없습니다. 위에서 패키지 이름 · 저장소 주소 · 파일로 시작하세요.</Empty>
          ) : (
            <div className="h-full overflow-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-slate-50 text-left text-xs text-slate-500">
                  <tr>{['시작', '대상', '결과', '위험 점수', '위협', '취약점'].map((t) => <th key={t} className={`px-3 py-2 font-medium ${t === '대상' ? 'w-[38%]' : ''}`}>{t}</th>)}</tr>
                </thead>
                <tbody>
                  {list.data.map((s) => (
                    <tr key={s.id} data-scan={s.id} data-status={s.status} onClick={() => select(s.id)}
                      className={`cursor-pointer border-t border-slate-100 hover:bg-slate-50 ${s.id === selId ? 'bg-indigo-50' : ''} ${s.verdict === 'malicious' ? 'shadow-[inset_3px_0_0_#dc2626]' : ''}`}>
                      <td className="num px-3 py-2 font-mono text-xs whitespace-nowrap">{fmtDateTime(s.startedAt)}</td>
                      <td className="max-w-0 truncate px-3 py-2 font-mono" title={s.target.label}>{s.target.label}</td>
                      <td className="px-3 py-2"><StatusBadge s={s} /></td>
                      <td className="num px-3 py-2">{s.risk ? s.risk.score.toFixed(1) : '—'}</td>
                      <td className={`num px-3 py-2 ${s.threats ? 'text-red-600' : 'text-slate-400'}`}>{s.status === 'done' ? s.threats : '—'}</td>
                      <td className={`num px-3 py-2 ${s.vulnCount ? 'text-amber-700' : 'text-slate-400'}`}>{s.status === 'done' ? (s.vulnCount ? `${fmtNum(s.vulnCount)} (최고 ${s.vulnMax})` : 0) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
      {selId && <ScanSheet key={selId} id={selId} canWrite={canWrite} done={list.data?.find((s) => s.id === selId)?.status !== 'running'} onClose={() => select('')} />}
    </div>
  );
}

function StatusBadge({ s }: { s: Scan }) {
  if (s.status === 'running') return <span className="rounded bg-indigo-50 px-1.5 py-0.5 text-xs text-indigo-700">검사 중…</span>;
  if (s.status === 'failed') return <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-600" title={s.error}>실패</span>;
  const [ko, cls] = VERDICT[s.verdict ?? 'clean'];
  return <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>{ko}</span>;
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
    if (kind === 'repo' && !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/.test(url.trim())) return setErr('https://github.com/<소유자>/<저장소> 형식으로 써 주세요');
    if (kind === 'file' && !file) return setErr('파일을 고르세요');
    if (kind === 'file' && file && file.size > MAX_UPLOAD) return setErr(`「${file.name}」 — 파일은 50MB 까지 올릴 수 있습니다`);
    setBusy(true);
    try {
      const r = await api.startScan(kind === 'file' ? file! : kind === 'repo' ? { kind, url: url.trim() } : { kind, manager, name: name.trim(), version: version.trim() });
      toast(`검사를 시작했습니다 — ${r.id}`, { key: 'scan', tone: 'info' });
      onStarted();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  const tabs: [typeof kind, string][] = [['package', '패키지 이름'], ['repo', '저장소 주소'], ['file', '파일 올리기']];
  return (
    <section className="shrink-0 rounded-lg border border-slate-200 bg-white" data-part="scan-form">
      <header className="flex items-center justify-between border-b border-slate-100 px-4 py-2.5">
        <h2 className="text-sm font-semibold text-slate-800">검사할 대상</h2>
        <span className="text-xs text-slate-400">설치하기 전에 정적 검사 — 코드를 실행하지 않습니다</span>
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
              <select className={`${input} w-20`} data-field="manager" aria-label="매니저" value={manager} onChange={(e) => setManager(e.target.value)}>
                <option>pip</option>
                <option>npm</option>
              </select>
              <input className={`${input} flex-1 font-mono`} data-field="name" aria-label="패키지 이름" placeholder="예: requests" value={name} onChange={(e) => setName(e.target.value)} />
              <input className={`${input} w-32 font-mono`} data-field="version" aria-label="버전" placeholder="버전(선택)" value={version} onChange={(e) => setVersion(e.target.value)} />
            </>
          ) : kind === 'repo' ? (
            <input className={`${input} flex-1 font-mono`} data-field="url" aria-label="저장소 주소" placeholder="https://github.com/소유자/저장소" value={url} onChange={(e) => setUrl(e.target.value)} />
          ) : (
            <span className="flex min-w-0 items-center gap-2">
              <input type="file" aria-label="파일" accept=".tar.gz,.tgz,.whl,.zip,.py,.js,.txt,.json,.lock,.yaml" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" />
              <span className="truncate text-xs text-slate-400">패키지 압축 · 소스 · 의존성 파일(requirements.txt · package-lock.json), 50MB 까지</span>
            </span>
          )}
        </div>
        <button type="button" aria-label="검사 시작" disabled={busy || !canWrite} onClick={() => void start()} title={canWrite ? undefined : '관리자 토큰을 화면 머리에 입력하세요'}
          className="rounded-md bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-40">검사 시작</button>
        {(err || !canWrite) && <p className="col-span-2 text-xs text-red-600" data-form-error="">{err || '관리자 토큰을 화면 머리에 입력하면 검사를 시작할 수 있습니다'}</p>}
      </div>
    </section>
  );
}

function ScanSheet({ id, canWrite, done, onClose }: { id: string; canWrite: boolean; done: boolean; onClose: () => void }) {
  const load = useCallback(() => api.scan(id), [id]);
  const r = useLoad(load);
  const { reload } = r;
  useEffect(() => { if (done) reload(); }, [done, reload]);
  const s = r.data;
  return (
    <Sheet kind="scan" title={s?.target.label ?? '공급망 검사'} onClose={onClose} className="w-[560px]">
      {!s ? (r.error ? <LoadError error={r.error} what="검사" /> : <Empty>불러오는 중…</Empty>) : <ScanDetail s={s} canWrite={canWrite} />}
    </Sheet>
  );
}

function ScanDetail({ s, canWrite }: { s: Scan; canWrite: boolean }) {
  const toast = useToast();
  const nav = useNavigate();
  const [focus, setFocus] = useState('');
  const findings = s.findings ?? [];
  const threats = findings.filter((f) => f.category === 'threat');
  const caps = findings.filter((f) => f.category === 'capability');
  const vulns = s.vulns ?? [];
  const t = s.target;
  const cmd = t.kind === 'package' ? `sg-install ${t.manager} ${t.name}${t.version ? (t.manager === 'pip' ? '==' : '@') + t.version : ''}` : '';
  const [vk, vcls] = s.status === 'failed' ? ['실패', 'bg-slate-100 text-slate-600'] : s.status === 'running' ? ['검사 중…', 'bg-indigo-50 text-indigo-700'] : VERDICT[s.verdict ?? 'clean'];
  const block = async () => {
    try {
      const r = await api.scanBlock(s.id);
      nav(`/policies?proposal=${encodeURIComponent(r.proposalId)}`);
    } catch (e) {
      toast(`차단 제안 실패: ${errorText(e)}`, { key: 'scan-block', tone: 'danger' });
    }
  };
  const item = (f: ScanFinding) => {
    const loc = `${f.file}:${f.line}`;
    return (
      <li key={`${f.rule}:${loc}`}>
        <button type="button" data-finding="" data-category={f.category} data-loc={loc} onClick={() => setFocus(loc)}
          className={`grid w-full grid-cols-[minmax(0,12rem)_minmax(0,1fr)] gap-x-2 rounded-md border border-l-4 px-2.5 py-1.5 text-left text-xs hover:bg-slate-50 ${f.category === 'threat' ? 'border-l-red-500' : 'border-l-amber-400'} ${focus === loc ? 'bg-slate-50' : ''}`}>
          <span className="truncate font-mono" title={loc}>{loc}</span>
          <b className="font-medium text-slate-800" title={f.message}>{RULE_KO[f.rule] ?? f.message}</b>
          <span className="col-start-2 font-mono text-slate-400">{f.rule}</span>
        </button>
      </li>
    );
  };
  return (
    <div className="text-sm">
      <Section title="결과">
        <div className={`grid gap-2 rounded-lg border p-3 ${s.verdict === 'malicious' ? 'border-red-200 bg-red-50' : s.verdict === 'vulnerable' ? 'border-amber-200 bg-amber-50' : 'border-slate-200'}`} data-part="verdict">
          <div className="flex items-center gap-2">
            <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${vcls}`}>{vk}</span>
            {s.risk && <span className="text-xs">위험 점수 <b className="num">{s.risk.score.toFixed(1)}</b> / 10 · {RISK[s.risk.label] ?? s.risk.label}</span>}
          </div>
          <p className="text-xs text-slate-700">
            {s.status === 'failed' ? `검사하지 못했습니다 — ${s.error}` : s.status === 'running' ? '검사 중입니다…'
              : s.verdict === 'malicious' ? `설치 단계에서 위험한 행동을 하는 코드가 ${threats.length}곳 있습니다. 설치하지 말고 차단 목록에 올리세요.`
              : s.verdict === 'vulnerable' ? `의존성에 알려진 취약점이 ${fmtNum(s.vulnCount)}건 있습니다. 고쳐진 버전으로 올리세요.`
              : '정적 검사에서 위험한 코드 · 알려진 취약점을 찾지 못했습니다. 설치 검사(eBPF)로 실제 행동도 확인할 수 있습니다.'}
          </p>
          {s.status === 'done' && t.kind === 'package' && (
            <div className="flex flex-wrap gap-2">
              <button type="button" aria-label="설치 검사로 실제 설치해 보기" onClick={() => { void navigator.clipboard?.writeText(cmd).catch(() => {}); toast(`명령을 복사했습니다 — ${cmd} (감시 컨테이너에서 실제 설치 · eBPF 관찰)`, { key: 'copy', tone: 'ok', action: { label: '설치 검사', to: '/installs?status=all' } }); }}
                className="flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1 text-xs hover:bg-white"><Play className="size-3.5" aria-hidden /> 설치 검사로 실제 설치해 보기</button>
              <button type="button" aria-label="차단 목록에 올리기" disabled={!canWrite} onClick={() => void block()}
                className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-xs disabled:opacity-40 ${s.verdict === 'malicious' ? 'bg-red-600 text-white hover:bg-red-700' : 'border border-slate-300 hover:bg-white'}`}><OctagonX className="size-3.5" aria-hidden /> 차단 목록에 올리기</button>
            </div>
          )}
        </div>
      </Section>
      <Section title={`위협 ${threats.length} — GuardDog, 누르면 코드에서 그 줄`}>
        <div data-part="findings" className="grid gap-2">
          {threats.length ? <ul className="grid gap-1">{threats.map(item)}</ul> : <p className="text-xs text-slate-500">없음</p>}
          {caps.length > 0 && (
            <details>
              <summary className="cursor-pointer text-xs text-slate-500">기능(정보) {caps.length} — 위협은 아니지만 코드가 할 수 있는 일</summary>
              <ul className="mt-1 grid gap-1">{caps.map(item)}</ul>
            </details>
          )}
        </div>
      </Section>
      <Section title="코드 보기 — 빨강 = 위협 줄, 노랑 = 기능">
        <CodeView s={s} focus={focus} setFocus={setFocus} />
      </Section>
      {vulns.length > 0 && (
        <Section title={`알려진 취약점 ${fmtNum(s.vulnCount)} — OSV-Scanner, 간접 의존성 포함`}>
          <table className="w-full text-xs" data-part="vulns">
            <thead className="text-left text-slate-500">
              <tr>{['패키지', '버전', '의존', '건수', '최고', 'ID'].map((x) => <th key={x} className="py-1 font-medium">{x}</th>)}</tr>
            </thead>
            <tbody>
              {vulns.map((v) => (
                <tr key={`${v.package}@${v.version}`} className="border-t border-slate-100" data-vpkg={v.package} data-count={v.count} data-max={v.maxSeverity} data-direct={String(v.direct)}>
                  <td className="py-1 font-mono">{v.package}</td>
                  <td className="py-1 font-mono">{v.version}</td>
                  <td className="py-1">{v.direct ? '직접' : '간접'}</td>
                  <td className="num py-1">{v.count}</td>
                  <td className="py-1"><span className={`rounded px-1.5 py-0.5 ${Number(v.maxSeverity) >= 9 ? 'bg-red-900 text-white' : Number(v.maxSeverity) >= 7 ? 'bg-red-100 text-red-700' : Number(v.maxSeverity) >= 4 ? 'bg-amber-100 text-amber-800' : 'bg-slate-100'}`}>{v.maxSeverity || '—'}</span></td>
                  <td className="py-1">{v.ids.slice(0, 2).map((x) => <a key={x} href={`https://osv.dev/vulnerability/${x}`} target="_blank" rel="noreferrer" className="mr-1 font-mono text-indigo-600 hover:underline">{x}</a>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}
      <p className="px-4 pb-3 text-[11px] text-slate-400">{(s.engines ?? []).map((e) => `${e.name} ${e.version}`).join(' · ')} — 오픈소스 정적 분석(Apache-2.0)</p>
    </div>
  );
}

function CodeView({ s, focus, setFocus }: { s: Scan; focus: string; setFocus: (v: string) => void }) {
  const files = s.files ?? {};
  const paths = Object.keys(files);
  const box = useRef<HTMLDivElement>(null);
  const cur = paths.includes(focus.split(':')[0]) ? focus.split(':')[0] : paths[0];
  const focusLine = focus.startsWith(`${cur}:`) ? Number(focus.split(':')[1]) : 0;
  useEffect(() => { box.current?.querySelector(`[data-line="${focusLine}"]`)?.scrollIntoView({ block: 'center' }); }, [focusLine, cur]);
  if (!paths.length) return <p className="text-xs text-slate-500" data-part="code">{s.status !== 'done' ? '검사 중…' : '위협이 나온 파일이 없어 코드를 보관하지 않았습니다(걸린 파일만 30일 보관).'}</p>;
  const at = (cat: string) => new Map((s.findings ?? []).filter((f) => f.file === cur && f.category === cat).map((f) => [f.line, f]));
  const thr = at('threat');
  const cap = at('capability');
  const mark = (text: string, f?: ScanFinding) => {
    const i = f?.match ? text.indexOf(f.match) : -1;
    if (!f || i < 0) return text;
    return (<>{text.slice(0, i)}<mark className="rounded-sm bg-red-500 px-px text-white">{f.match}</mark>{text.slice(i + f.match.length)}</>);
  };
  return (
    <div data-part="code" className="grid gap-1.5">
      {paths.length > 1 ? (
        <div className="flex flex-wrap gap-1">{paths.map((p) => <button key={p} type="button" onClick={() => setFocus(`${p}:0`)} className={`rounded-full border px-2 py-0.5 font-mono text-[11px] ${p === cur ? 'border-indigo-600 bg-indigo-600 text-white' : 'border-slate-300'}`}>{p}</button>)}</div>
      ) : (
        <span className="font-mono text-[11px] text-slate-500">{cur}</span>
      )}
      <div ref={box} className="max-h-80 overflow-auto rounded-md bg-slate-900 text-xs leading-relaxed text-slate-200" role="region" aria-label={`${cur} 코드`}>
        <pre className="m-0">
          {files[cur].split('\n').map((ln, i) => {
            const n = i + 1;
            const tf = thr.get(n);
            const cf = cap.get(n);
            return (
              <div key={n} data-line={n} title={tf ? `${tf.rule} — ${tf.message}` : cf ? `${cf.rule} — ${cf.message}` : undefined}
                className={`grid grid-cols-[2.5rem_minmax(0,1fr)] ${tf ? 'hl-threat bg-red-600/35 shadow-[inset_3px_0_0_#ef4444]' : cf ? 'hl-cap bg-amber-500/20' : ''} ${n === focusLine ? 'focus outline-2 -outline-offset-2 outline-amber-400' : ''}`}>
                <span className="pr-2.5 text-right text-slate-500 select-none">{n}</span>
                <code className="pr-3 whitespace-pre">{mark(ln || ' ', tf ?? cf)}</code>
              </div>
            );
          })}
        </pre>
      </div>
    </div>
  );
}
