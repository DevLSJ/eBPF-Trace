import { Check } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useStream } from '../hooks/stream-context';
import { useCopyCommand } from '../hooks/useCopyCommand';
import { api } from '../lib/api';
import { fmtDateTime, fmtNum, fmtTime } from '../lib/format';
import {
  caseHref,
  GUIDE_TOTAL,
  INSTALL_CMD,
  loadGuide,
  loadSetup,
  notifyState,
  pickCase,
  recentCases,
  saveGuide,
  saveSetup,
  SOURCE_LABEL,
  stepsOf,
  type GuidePref,
} from '../lib/guide';
import { isInstallContainer } from '../lib/topology';
import { caseLabel, LEVEL_LABEL, type Case } from '../lib/types';
import { DecisionBadge } from './Badges';
import { LevelBadge } from './VerdictBadge';

// 「대응 가이드」 탭 본문 (10/20 확정, 목업 shared/guide.js). 건이 있으면 건별 5단계, 하나도 없으면 「구축 순서」.
// 체크 상태는 localStorage 라 바뀌면 onChange 로 부모가 다시 그린다(배지도 같이).
export function GuidePanel({
  cases,
  selectedId,
  onSelect,
  onChange,
}: {
  cases: Case[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onChange: () => void;
}) {
  const list = recentCases(cases);
  if (!list.length) return <SetupView onChange={onChange} />;
  const c = pickCase(list, selectedId)!;
  return <CaseView key={c.id} c={c} list={list} onSelect={onSelect} onChange={onChange} />;
}

function Bar({ n, total }: { n: number; total: number }) {
  return (
    <div
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={total}
      aria-valuenow={n}
      aria-label={`${n}/${total}`}
      data-part="guide-progress"
      data-value={`${n}/${total}`}
      className="mb-3 h-1.5 overflow-hidden rounded-full bg-slate-200"
    >
      <span className="block h-full bg-indigo-600 transition-[width]" style={{ width: `${(n / total) * 100}%` }} />
    </div>
  );
}

function Step({ i, done, unknown, title, children }: { i: number; done: boolean; unknown?: boolean; title: ReactNode; children: ReactNode }) {
  return (
    <li
      data-step={i}
      data-done={unknown ? 'unknown' : String(done)}
      className={`flex gap-2.5 rounded-lg border p-2.5 ${done ? 'border-emerald-200 bg-emerald-50/60' : 'border-slate-200 bg-white'}`}
    >
      <span
        aria-hidden
        className={`grid size-[22px] shrink-0 place-items-center rounded-full text-xs font-semibold ${
          done ? 'bg-emerald-600 text-white' : unknown ? 'bg-amber-100 text-amber-800' : 'bg-indigo-50 text-indigo-700'
        }`}
      >
        {done ? <Check className="size-3.5" /> : i}
      </span>
      <div className="grid min-w-0 flex-1 gap-1">
        <b className="text-[13px] text-slate-800">{title}</b>
        {children}
      </div>
    </li>
  );
}

const linkCls = 'text-xs text-indigo-600 hover:underline';

function CaseView({ c, list, onSelect, onChange }: { c: Case; list: Case[]; onSelect: (id: string) => void; onChange: () => void }) {
  const { info } = useStream();
  const { p, follows, done } = stepsOf(c);
  const n = done.filter(Boolean).length;
  const href = caseHref(c);
  const mark = (patch: Partial<GuidePref>) => {
    saveGuide(c.id, { ...loadGuide(c.id), ...patch });
    onChange();
  };
  const isolation: [string, string, string] =
    c.level === 'killed'
      ? [
          'text-red-700',
          '격리됨',
          c.source === 'install'
            ? '감시 컨테이너를 종료했습니다(kill). 설치는 끝나기 전에 막혔습니다.'
            : '컨테이너를 종료했습니다(kill). 15초 뒤 재기동되면 차단 이미지일 때만 즉시 다시 격리됩니다.',
        ]
      : c.level === 'held'
        ? ['text-amber-700', '격리 대상', 'dry-run 이라 알림만 보냈습니다 — 컨테이너가 살아 있습니다. 필요하면 직접 멈추고, 격리 모드(ENFORCE_KILL)를 켜세요.']
        : ['text-amber-700', '경고', '격리 정책이 아니라 알림만 보냈습니다. 컨테이너는 계속 동작 중입니다.'];
  const notify = notifyState(info);
  const notifyTone = notify.state === 'sent' ? 'text-emerald-700' : notify.state === 'failed' ? 'text-red-700' : notify.state === 'off' ? 'text-amber-700' : 'text-slate-500';

  return (
    <section data-part="guide-case-view">
      {list.length > 1 && (
        <label className="mb-2.5 grid gap-1">
          <span className="text-xs text-slate-500">건</span>
          <select
            className="h-8 w-full rounded-md border border-slate-300 bg-white px-2 text-[13px]"
            data-part="guide-case"
            aria-label="건 선택 (최근 5건)"
            value={c.id}
            onChange={(e) => onSelect(e.target.value)}
          >
            {list.map((x) => (
              <option key={x.id} value={x.id}>
                {`${SOURCE_LABEL[x.source]} · ${caseLabel(x)} · ${LEVEL_LABEL[x.level]} · ${fmtTime(x.openedAt)}`}
              </option>
            ))}
          </select>
        </label>
      )}
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <b className="text-sm text-slate-900">{`${SOURCE_LABEL[c.source]} · ${caseLabel(c)}`}</b>
        <LevelBadge level={c.level} />
        <span className="num ml-auto text-xs text-slate-500">{`${n}/${GUIDE_TOTAL}`}</span>
      </div>
      <Bar n={n} total={GUIDE_TOTAL} />
      <ol className="grid gap-2">
        <Step i={1} done={done[0]} title="탐지">
          <p className="num text-xs text-slate-500">{`${fmtDateTime(c.openedAt)} · 위반 ${fmtNum(c.violations)}건`}</p>
          <ul className="flex flex-wrap gap-1">
            {c.ruleIds.map((id) => (
              <li key={id}>
                <Link to={`/policies?id=${encodeURIComponent(id)}`} className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-700 hover:bg-slate-200">
                  {id}
                </Link>
              </li>
            ))}
          </ul>
        </Step>
        <Step i={2} done={done[1]} title="격리 확인">
          <p className="text-xs">
            <b className={isolation[0]}>{isolation[1]}</b> — <span className="text-slate-500">{isolation[2]}</span>
          </p>
        </Step>
        <Step i={3} done={done[2]} title="공격 체인 보기">
          <div className="flex flex-wrap gap-x-2.5 gap-y-1">
            <Link to={href} className={linkCls} data-part="chain-link" onClick={() => mark({ chain: true })}>
              {c.source === 'install' ? '설치 검사 시트에서 공격 체인 →' : c.source === 'scan' ? '검사 결과 보기 →' : '토폴로지에서 공격 체인 →'}
            </Link>
            {c.source === 'runtime' && (
              <Link to={`/events?container=${encodeURIComponent(c.container)}`} className={linkCls} onClick={() => mark({ chain: true })}>
                이벤트 →
              </Link>
            )}
          </div>
        </Step>
        <Step i={4} done={done[3]} title="판정">
          {c.decision === 'pending' ? (
            <div className="flex flex-wrap items-center gap-2">
              <DecisionBadge decision="pending" />
              <Link to={href} className={linkCls}>
                악성 확정 / 오탐 판정하러 가기 →
              </Link>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <DecisionBadge decision={c.decision} />
              <span className="num text-xs text-slate-500">
                {c.decidedBy ?? ''}
                {c.decidedAt ? ` · ${fmtDateTime(c.decidedAt)}` : ''}
              </span>
              {c.state === 'decided' && c.proposalId ? (
                <Link to={`/policies?proposal=${encodeURIComponent(c.proposalId)}`} className={linkCls}>
                  제안 적용 →
                </Link>
              ) : (
                <span className="text-xs text-slate-500">종결</span>
              )}
            </div>
          )}
        </Step>
        <Step i={5} done={done[4]} title="후속 조치">
          <ul className="grid gap-1.5">
            {follows.map((f) => (
              <li key={f.group}>
                <label className="flex items-start gap-2 text-xs text-slate-700" data-follow={f.hit.join(' ')} data-group={f.group}>
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={!!p.follow[f.group]}
                    onChange={(e) => {
                      const q = loadGuide(c.id);
                      saveGuide(c.id, { ...q, follow: { ...q.follow, [f.group]: e.target.checked } });
                      onChange();
                    }}
                  />
                  <span>
                    {f.text} <span className="font-mono text-slate-400">({f.hit.join(', ')})</span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
          <p className={`text-xs ${notifyTone}`} data-part="notify" data-notify={notify.state}>
            {notify.text}
          </p>
        </Step>
      </ol>
    </section>
  );
}

// 건이 하나도 없을 때 — 구축 순서 3단계(데이터로 완료 판정, 모르는 것은 「미확인」)
function SetupView({ onChange }: { onChange: () => void }) {
  const { topology, topologyVersion } = useStream();
  const copy = useCopyCommand();
  const pref = loadSetup();
  // 설치 세션이 하나라도 있으면 ① 완료. 못 읽으면 null(미확인), 읽는 중은 undefined
  const [hasInstall, setHasInstall] = useState<boolean | null | undefined>(undefined);
  useEffect(() => {
    let live = true;
    api.installs({ limit: 1 }).then(
      (xs) => live && setHasInstall(xs.length > 0),
      () => live && setHasInstall(null),
    );
    return () => {
      live = false;
    };
  }, []);
  void topologyVersion; // 토폴로지가 바뀌면 다시 그려진다
  const runtime = topology.containers().filter((n) => !isInstallContainer(n)).length > 0;

  if (pref.off)
    return (
      <div className="grid justify-items-start gap-2 px-1 py-2" data-part="setup-off">
        <p className="text-sm text-slate-500">아직 격리 · 경고된 건이 없습니다.</p>
        <button
          type="button"
          className="rounded-md px-2 py-1 text-xs text-slate-600 hover:bg-slate-100"
          onClick={() => {
            saveSetup({ ...loadSetup(), off: false });
            onChange();
          }}
        >
          구축 순서 다시 보기
        </button>
      </div>
    );

  const steps: { id: string; title: string; desc: string; to: string; label: string; done: boolean | null }[] = [
    { id: 'install', title: '설치 검사 돌려 보기', desc: '터미널에서 감시 컨테이너로 패키지를 설치해 봅니다. 결과는 「설치 검사」에 쌓입니다.', to: '/installs?status=all', label: '설치 검사 →', done: hasInstall === undefined ? false : hasInstall },
    { id: 'policies', title: '정책 확인', desc: '기본 정책이 무엇을 막는지 한 번 봅니다(정책 화면을 열면 완료).', to: '/policies', label: '정책 →', done: pref.visitedPolicies },
    { id: 'runtime', title: '런타임 감시 컨테이너 확인', desc: '토폴로지에 감시 중인 컨테이너가 보이면 런타임 감시가 돌고 있는 것입니다.', to: '/topology', label: '토폴로지 →', done: runtime },
  ];
  const n = steps.filter((s) => s.done === true).length;
  return (
    <section data-part="setup-steps">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <b className="text-sm text-slate-900">{n === steps.length ? '구축 완료' : '처음이세요? 구축 순서 3단계'}</b>
        <span className="num text-xs text-slate-500">{`${n}/${steps.length}`}</span>
        <button
          type="button"
          className="ml-auto rounded-md px-2 py-1 text-xs text-slate-600 hover:bg-slate-100"
          aria-label="구축 순서 그만 보기"
          title="다시 보려면 「구축 순서 다시 보기」"
          onClick={() => {
            saveSetup({ ...loadSetup(), off: true });
            onChange();
          }}
        >
          그만 보기
        </button>
      </div>
      <Bar n={n} total={steps.length} />
      <ol className="grid gap-2">
        {steps.map((s, i) => (
          <li
            key={s.id}
            data-setup={s.id}
            data-done={s.done === null ? 'unknown' : String(s.done)}
            className={`flex gap-2.5 rounded-lg border p-2.5 ${s.done === true ? 'border-emerald-200 bg-emerald-50/60' : 'border-slate-200 bg-white'}`}
          >
            <span
              aria-hidden
              className={`grid size-[22px] shrink-0 place-items-center rounded-full text-xs font-semibold ${
                s.done === true ? 'bg-emerald-600 text-white' : s.done === null ? 'bg-amber-100 text-amber-800' : 'bg-indigo-50 text-indigo-700'
              }`}
            >
              {s.done === true ? <Check className="size-3.5" /> : i + 1}
            </span>
            <div className="grid min-w-0 flex-1 gap-1">
              <div className="flex items-center gap-2">
                <b className="text-[13px] text-slate-800">{s.title}</b>
                {s.done === null && <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[11px] text-amber-800">미확인</span>}
              </div>
              <p className="text-xs text-slate-500">{s.desc}</p>
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                {s.id === 'install' && (
                  <>
                    <button type="button" className="rounded-md bg-indigo-600 px-2 py-0.5 text-xs font-medium text-white hover:bg-indigo-700" aria-label="sg-install 명령 복사" onClick={() => copy(INSTALL_CMD)}>
                      명령 복사
                    </button>
                    <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-700">{INSTALL_CMD}</code>
                  </>
                )}
                <Link to={s.to} className={linkCls}>
                  {s.label}
                </Link>
              </div>
            </div>
          </li>
        ))}
      </ol>
      {n === steps.length && <p className="mt-2 text-xs text-slate-500">설치 검사 · 정책 · 런타임 감시까지 모두 확인했습니다. 격리 · 경고가 생기면 여기에 대응 가이드가 뜹니다.</p>}
    </section>
  );
}
