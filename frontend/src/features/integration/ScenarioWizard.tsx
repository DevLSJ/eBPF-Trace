import { Box, Check, Container, Copy, FlaskConical, Layers, Loader2, Plus, RotateCcw, ShieldCheck, SquareTerminal, Tag, Tags, TriangleAlert, WandSparkles, X, type LucideIcon } from 'lucide-react';
import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ActionButton } from '../../components/ActionButton';
import { StatusBadge } from '../../components/Badges';
import { useCopyCommand } from '../../hooks/useCopyCommand';
import { useInterval, useLoad } from '../../hooks/useLoad';
import { useStream } from '../../hooks/stream-context';
import { api } from '../../lib/api';
import { installDest } from '../../lib/nav';
import type { IntegrationContainer, IntegrationEnv } from '../../lib/types';
import {
  DEFAULT_INSTALL,
  DEFAULT_MULTI,
  DEFAULT_SINGLE,
  DEMO_INSTALL,
  detected,
  EXAMPLE_INSTALL,
  EXAMPLE_MULTI,
  EXAMPLE_SINGLE,
  EXIT_CODES,
  addedCount,
  isAdded,
  RESULT_KILL,
  resultPass,
  SCENARIO_FLOW,
  TOKEN_CMD,
  type CutIcon,
  expected,
  installCmd,
  installSessionFor,
  installValid,
  multiApply,
  multiErrors,
  multiSnippet,
  multiValid,
  outcomeOf,
  pkgError,
  SCENARIOS,
  singleApply,
  singleErrors,
  singleSnippet,
  singleValid,
  STEPS,
  testCmd,
  testVerdict,
  type InstallInput,
  type Manager,
  type MultiInput,
  type Outcome,
  type ScenarioId,
  type SingleInput,
} from './model';

// 시나리오 따라 하기(11/06 요구 1 수정): 시나리오 고르기 → 1 입력(설정 자동 생성) → 2 적용(감시 목록에서 자동 감지) → 3 확인(내 컨테이너 시험 동작).
// 카드(11/09 밤) = 제목 + 한 줄 설명 + 예 하나 — 세부는 고른 뒤 1단계 위 3컷 흐름 그림(SCENARIO_FLOW)으로
// 1단계(11/10) = 왼쪽 입력(칸마다 한 줄 도움말 · 예시로 채우기) + 오른쪽 실시간 미리보기, 설치 검사는 터미널 순서 3단계
// 진행 · 입력값은 이 브라우저에 저장(새로고침해도 이어짐, 저장이 막혀 있으면 이번 화면만). 문구 규칙: 개조식 명사형 종결
const KEY = 'supplyguard.integrate.wizard.v1';
interface Saved {
  scenario: ScenarioId | null;
  step: number;
  single: SingleInput;
  multi: MultiInput;
  install: InstallInput;
  armedAt?: string; // 3단계 시험 명령을 복사한 시각
  installSince?: string; // 설치 검사 명령을 복사한 시각
  target?: string; // 여러 컨테이너에서 시험할 컨테이너
}
const FRESH: Saved = { scenario: null, step: 1, single: DEFAULT_SINGLE, multi: DEFAULT_MULTI, install: DEFAULT_INSTALL };
function load(): Saved {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? 'null') as Partial<Saved> | null;
    return v ? { ...FRESH, ...v } : FRESH;
  } catch {
    return FRESH;
  }
}
function save(s: Saved) {
  try {
    localStorage.setItem(KEY, JSON.stringify(s));
  } catch {
    /* 저장이 막혀 있으면 이번 화면만 */
  }
}

export function ScenarioWizard({ env, containers }: { env: IntegrationEnv; containers: IntegrationContainer[] }) {
  const [st, setSt] = useState<Saved>(load);
  const set = useCallback((p: Partial<Saved>) => {
    setSt((cur) => {
      const next = { ...cur, ...p };
      save(next);
      return next;
    });
  }, []);
  const sc = st.scenario;
  const valid = sc === 'single' ? singleValid(st.single) : sc === 'multi' ? multiValid(st.multi) : sc === 'install' ? installValid(st.install) : false;
  return (
    <section className="int-wizard sg-card" data-part="wizard" data-scenario={sc ?? ''} data-step={st.step}>
      <div className="int-scn-row" role="radiogroup" aria-label="연동 시나리오">
        {SCENARIOS.map((s, i) => (
          <button
            key={s.id}
            type="button"
            role="radio"
            aria-checked={sc === s.id}
            data-scn={s.id}
            className={`int-scn ${sc === s.id ? 'on' : ''}`}
            style={{ ['--i' as string]: i }}
            onClick={() => sc !== s.id && set({ scenario: s.id, step: 1, armedAt: undefined, installSince: undefined, target: undefined })}
          >
            <b className="int-scn-title">{s.title}</b>
            <span className="int-scn-desc" data-part="int-scn-desc">
              {s.desc}
            </span>
            <span className="int-scn-ex" data-part="int-scn-example">
              예) <code>{s.example}</code>
            </span>
          </button>
        ))}
      </div>
      {!sc ? (
        <p className="int-wiz-hint" data-part="wizard-pick">
          ↑ 상황에 맞는 시나리오 선택 → 입력 · 적용 · 확인 3단계 진행됨
        </p>
      ) : (
        <>
          <ol className="int-stepper" data-part="stepper">
            {STEPS.map((label, i) => {
              const n = i + 1;
              const state = n < st.step ? 'done' : n === st.step ? 'on' : 'off';
              return (
                <li key={label} data-state={state} className={`int-stepper-item ${state}`}>
                  <ActionButton reason={n > st.step && !(n === 2 && valid) && '앞 단계를 먼저 마치세요'} onClick={() => set({ step: n })}>
                    <span className="int-stepper-n">{state === 'done' ? <Check className="size-3.5" aria-hidden /> : n}</span>
                    {label}
                  </ActionButton>
                </li>
              );
            })}
            <li className="int-stepper-reset">
              <button type="button" className="sg-btn sg-btn-sm sg-btn-secondary" data-part="wizard-reset" onClick={() => set({ ...FRESH, scenario: sc })}>
                <RotateCcw className="size-3.5" aria-hidden /> 처음부터
              </button>
            </li>
          </ol>
          <div className="int-wiz-body" key={`${sc}-${st.step}`}>
            {st.step === 1 && <FlowCuts sc={sc} />}
            {st.step === 1 && sc === 'single' && (
              <TwoCol input={<SingleForm v={st.single} onChange={(single) => set({ single })} />} out={<SinglePreview v={st.single} env={env} />} />
            )}
            {st.step === 1 && sc === 'multi' && <TwoCol input={<MultiForm v={st.multi} onChange={(multi) => set({ multi })} />} out={<MultiPreview v={st.multi} env={env} />} />}
            {st.step === 1 && sc === 'install' && (
              <TwoCol
                input={<InstallForm v={st.install} onChange={(install) => set({ install })} />}
                out={<InstallTerminal v={st.install} onCopyCmd={() => set({ installSince: new Date(Date.now() - 2000).toISOString() })} />}
              />
            )}
            {st.step === 1 && (
              <div className="int-wiz-foot">
                <ActionButton className="sg-btn sg-btn-primary" data-part="wizard-next" reason={!valid && '입력 칸의 오류를 먼저 고치세요'} onClick={() => set({ step: 2 })}>
                  {sc === 'install' ? '실행 결과 기다리기 →' : '설정 만들기 →'}
                </ActionButton>
              </div>
            )}
            {st.step === 2 && sc !== 'install' && <ApplyStep sc={sc} st={st} env={env} containers={containers} onNext={() => set({ step: 3 })} />}
            {st.step === 2 && sc === 'install' && <InstallApply st={st} set={set} />}
            {st.step === 3 && sc !== 'install' && <TestStep sc={sc} st={st} set={set} containers={containers} />}
            {st.step === 3 && sc === 'install' && <InstallApply st={st} set={set} />}
          </div>
        </>
      )}
    </section>
  );
}

// ── 1 입력 ──
// 3컷 흐름 그림 — 무엇을 → 어떻게 → 결과. 그림은 아이콘 + CSS 화살표(외부 이미지 없음)
const CUT_ICON: Record<CutIcon, LucideIcon> = { container: Container, tag: Tag, shield: ShieldCheck, layers: Layers, tags: Tags, terminal: SquareTerminal, box: Box, split: ShieldCheck };
function FlowCuts({ sc }: { sc: ScenarioId }) {
  const cuts = SCENARIO_FLOW[sc];
  return (
    <ol className="int-cuts" data-part="int-scn-notes" data-flow={sc} aria-label="이 시나리오의 흐름">
      {cuts.map((c, i) => {
        const Icon = CUT_ICON[c.icon];
        return (
          <li key={c.title} className="int-cut-wrap" style={{ ['--i' as string]: i }}>
            {i > 0 && (
              <span className="int-cut-arrow" data-part="cut-arrow" aria-hidden>
                <svg viewBox="0 0 24 24" width="22" height="22">
                  <path d="M3 12h15M13 6l6 6-6 6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </span>
            )}
            <div className={`int-cut ${i === cuts.length - 1 ? 'last' : ''}`} data-cut={i + 1}>
              <span className="int-cut-ico">
                <Icon className="size-5" aria-hidden />
                <i className="int-cut-n">{i + 1}</i>
              </span>
              <span className="int-cut-text">
                <b data-part="cut-title">{c.title}</b>
                <span data-part="cut-desc">{c.desc}</span>
                {c.icon === 'split' && (
                  <span className="int-cut-chips">
                    <span className="int-chip ok" data-outcome="pass">
                      통과
                    </span>
                    <span className="int-chip danger" data-outcome="kill">
                      격리
                    </span>
                  </span>
                )}
              </span>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

// 2단 — 1024 미만은 위아래(integration.css)
function TwoCol({ input, out }: { input: ReactNode; out: ReactNode }) {
  return (
    <div className="int-two">
      <div className="int-two-in" data-part="scn-input">
        {input}
      </div>
      {out}
    </div>
  );
}

function Field({ label, help, error, children, wide }: { label: string; help?: string; error?: string; children: ReactNode; wide?: boolean }) {
  return (
    <label className={`int-field ${wide ? 'wide' : ''} ${error ? 'bad' : ''}`}>
      <span className="int-field-label">{label}</span>
      {children}
      {error ? (
        <span className="int-field-err" role="alert">
          {error}
        </span>
      ) : (
        help && (
          <span className="int-field-help" data-part="field-help">
            {help}
          </span>
        )
      )}
    </label>
  );
}

function FillButton({ onClick, part = 'fill-example', icon = 'wand', children = '예시로 채우기' }: { onClick: () => void; part?: string; icon?: 'wand' | 'flask'; children?: ReactNode }) {
  const Icon = icon === 'flask' ? FlaskConical : WandSparkles;
  return (
    <button type="button" className="sg-btn sg-btn-sm sg-btn-secondary" data-part={part} onClick={onClick}>
      <Icon className="size-3.5" aria-hidden /> {children}
    </button>
  );
}

function SingleForm({ v, onChange }: { v: SingleInput; onChange: (v: SingleInput) => void }) {
  const e = singleErrors(v);
  return (
    <div className="int-form" data-part="form-single">
      <div className="int-form-top">
        <div className="int-tabs" role="tablist" aria-label="방식">
          {(['compose', 'run'] as const).map((k) => (
            <button key={k} type="button" role="tab" aria-selected={v.mode === k} data-mode={k} className={`int-tab ${v.mode === k ? 'on' : ''}`} onClick={() => onChange({ ...v, mode: k })}>
              {k === 'compose' ? 'docker compose' : 'docker run'}
            </button>
          ))}
        </div>
        <FillButton onClick={() => onChange({ ...v, ...EXAMPLE_SINGLE })} />
      </div>
      <Field label={v.mode === 'compose' ? '서비스(컨테이너) 이름' : '컨테이너 이름'} help="감시 목록에서 이 이름으로 자동 감지" error={e.name}>
        <input name="name" className="int-input" value={v.name} onChange={(x) => onChange({ ...v, name: x.target.value.trim() })} />
      </Field>
      <Field label="이미지" help="지금 쓰는 이미지 그대로, 이미지는 바꾸지 않음" error={e.image}>
        <input name="image" className="int-input" value={v.image} onChange={(x) => onChange({ ...v, image: x.target.value.trim() })} />
      </Field>
      <label className="int-enforce">
        <input type="checkbox" name="enforce" checked={v.enforce} onChange={(x) => onChange({ ...v, enforce: x.target.checked })} />
        격리까지 맡기기 <span className="int-muted">(정책 위반 시 증거 수집 뒤 즉시 종료됨)</span>
      </label>
    </div>
  );
}

function MultiForm({ v, onChange }: { v: MultiInput; onChange: (v: MultiInput) => void }) {
  const e = multiErrors(v);
  const upd = (k: number, p: Partial<MultiInput['services'][number]>) => onChange({ ...v, services: v.services.map((s, i) => (i === k ? { ...s, ...p, ...(p.watch === false ? { enforce: false } : {}) } : s)) });
  return (
    <div className="int-form" data-part="form-multi">
      <div className="int-form-top">
        <span className="int-field-label">compose 프로젝트</span>
        <FillButton onClick={() => onChange(EXAMPLE_MULTI)} />
      </div>
      <Field label="프로젝트 이름" help="compose 의 name, 컨테이너 이름은 「프로젝트-서비스」" error={e.project}>
        <input name="project" className="int-input" value={v.project} onChange={(x) => onChange({ ...v, project: x.target.value.trim() })} />
      </Field>
      <table className="sg-table int-svc-table" data-part="svc-table">
        <thead>
          <tr>
            <th>서비스</th>
            <th>이미지</th>
            <th className="tk-short">감시</th>
            <th className="tk-short">격리</th>
            <th className="tk-short" />
          </tr>
        </thead>
        <tbody>
          {v.services.map((s, k) => (
            <tr key={k} data-svc={k} className="int-svc-row">
              <td>
                <input aria-label={`서비스 ${k + 1} 이름`} className={`int-input ${e.services[k]?.name ? 'bad' : ''}`} value={s.name} onChange={(x) => upd(k, { name: x.target.value.trim() })} title={e.services[k]?.name || undefined} />
              </td>
              <td>
                <input aria-label={`서비스 ${k + 1} 이미지`} className={`int-input ${e.services[k]?.image ? 'bad' : ''}`} value={s.image} onChange={(x) => upd(k, { image: x.target.value.trim() })} title={e.services[k]?.image || undefined} />
              </td>
              <td className="tk-short">
                <input type="checkbox" aria-label={`서비스 ${k + 1} 감시`} checked={s.watch} onChange={(x) => upd(k, { watch: x.target.checked })} />
              </td>
              <td className="tk-short">
                <input type="checkbox" aria-label={`서비스 ${k + 1} 격리`} checked={s.enforce} disabled={!s.watch} onChange={(x) => upd(k, { enforce: x.target.checked })} />
              </td>
              <td className="tk-short">
                <ActionButton
                  className="int-icon-btn"
                  aria-label={`빼기(서비스 ${k + 1})`}
                  title={`빼기(서비스 ${k + 1})`}
                  reason={v.services.length <= 1 && '서비스는 하나 이상 있어야 합니다'}
                  onClick={() => onChange({ ...v, services: v.services.filter((_, i) => i !== k) })}
                >
                  <X className="size-3.5" aria-hidden />
                </ActionButton>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <span className="int-field-help" data-part="field-help">
        감시를 끈 서비스는 라벨 없음 · 격리는 감시 중인 서비스만
      </span>
      <div className="int-form-row">
        <ActionButton className="sg-btn sg-btn-sm sg-btn-secondary" data-part="svc-add" reason={v.services.length >= 12 && '서비스는 12개까지입니다'} onClick={() => onChange({ ...v, services: [...v.services, { name: `svc${v.services.length + 1}`, image: 'busybox:1.36', watch: true, enforce: false }] })}>
          <Plus className="size-3.5" aria-hidden /> 서비스 추가
        </ActionButton>
        {(e.none || e.services.find((x) => x.name || x.image)) && <span className="int-field-err" data-part="multi-error" role="alert">{e.none || '서비스의 이름 · 이미지를 확인하세요.'}</span>}
      </div>
    </div>
  );
}

const MANAGERS: Manager[] = ['pip', 'npm', 'cargo'];
function InstallForm({ v, onChange }: { v: InstallInput; onChange: (v: InstallInput) => void }) {
  return (
    <div className="int-form" data-part="form-install">
      <div className="int-form-top">
        <div className="int-tabs" role="tablist" aria-label="패키지 관리자">
          {MANAGERS.map((k) => (
            <button key={k} type="button" role="tab" aria-selected={v.manager === k} data-manager={k} className={`int-tab ${v.manager === k ? 'on' : ''}`} onClick={() => onChange({ ...v, manager: k })}>
              {k}
            </button>
          ))}
        </div>
        <FillButton onClick={() => onChange(EXAMPLE_INSTALL)} />
      </div>
      <Field label="패키지" help="버전 지정 가능(예: requests==2.31.0), 저장소 안 폴더는 ./ 로 시작" error={pkgError(v.pkg)} wide>
        <input name="pkg" className="int-input" value={v.pkg} onChange={(x) => onChange({ ...v, pkg: x.target.value.trim() })} />
      </Field>
      <div className="int-demo" data-part="install-demo">
        <FillButton part="fill-demo" icon="flask" onClick={() => onChange(DEMO_INSTALL)}>
          악성 흉내 패키지로 시연
        </FillButton>
        <span className="int-field-help">저장소의 무해한 시연 패키지(예약 주소만 접속 시도), 격리 결과 확인용</span>
      </div>
    </div>
  );
}

// 실시간 미리보기 — 입력하는 대로 만들어질 설정, 추가되는 라벨 줄 강조 + 줄 수
function Preview({ title, text, apply, note }: { title: string; text: string; apply?: string; note: ReactNode }) {
  const n = addedCount(text);
  return (
    <div className="int-two-out int-pv" data-part="scn-preview">
      <div className="int-pv-head">
        <h4 className="int-h4">미리보기({title})</h4>
        <span className="int-pv-badge" data-part="preview-added">
          추가되는 줄 {n}개
        </span>
      </div>
      <pre className="int-pv-code" data-part="preview-config" aria-live="polite">
        {text.split('\n').map((line, i) => {
          const add = isAdded(line);
          return (
            <span key={i} className={`int-pv-line ${add ? 'hl' : ''}`} data-added={add ? 'true' : undefined}>
              {line}
              {'\n'}
            </span>
          );
        })}
      </pre>
      {apply && (
        <div className="int-pv-apply">
          <span className="int-field-label">다시 실행</span>
          <code data-part="preview-apply">{apply}</code>
        </div>
      )}
      <p className="int-pv-note">{note}</p>
    </div>
  );
}

function SinglePreview({ v, env }: { v: SingleInput; env: IntegrationEnv }) {
  const run = v.mode === 'run';
  return (
    <Preview
      title={run ? '실행 명령' : 'docker-compose.yml'}
      text={singleSnippet(v, env)}
      apply={run ? undefined : `docker compose up -d ${v.name}`}
      note={
        <>
          적용하면 → 감시 목록에 <b>{v.name || '이름'}</b> 나타남(자동 감지){v.enforce ? ' · 위반이면 증거 수집 뒤 격리' : ' · 위반이면 경고'}
        </>
      }
    />
  );
}

function MultiPreview({ v, env }: { v: MultiInput; env: IntegrationEnv }) {
  const watched = v.services.filter((s) => s.watch).length;
  return (
    <Preview
      title="docker-compose.yml"
      text={multiSnippet(v, env)}
      apply={multiApply()}
      note={
        <>
          적용하면 → 서비스 {v.services.length}개 중 <b>{watched}개</b> 감시 시작(자동 감지)
        </>
      }
    />
  );
}

// 설치 검사 — 터미널 순서 그대로(① 토큰 준비 ② 명령 ③ 나오는 결과). 토큰 값은 화면에 두지 않고 파일에서 읽는 명령만
function InstallTerminal({ v, onCopyCmd }: { v: InstallInput; onCopyCmd: () => void }) {
  return (
    <ol className="int-two-out int-term" data-part="term-steps" aria-label="터미널에서 순서대로">
      <li className="int-term-step" data-term-step="1">
        <span className="int-term-n" data-part="term-n">
          1
        </span>
        <div className="int-term-body">
          <b>토큰 준비</b>
          <Code part="pre-token" text={TOKEN_CMD} />
          <span className="int-field-help">로컬(make dev) 기준, 저장소 폴더에서 실행 · 서버에서는 서버 .env 의 SANDBOX_TOKEN 사용 · 토큰 값은 파일에서 읽음</span>
        </div>
      </li>
      <li className="int-term-step" data-term-step="2">
        <span className="int-term-n" data-part="term-n">
          2
        </span>
        <div className="int-term-body">
          <b>설치 명령 실행</b>
          <Code part="pre-install" text={installCmd(v)} onCopy={onCopyCmd} />
          <span className="int-field-help">pip install 대신 이 명령, 입력한 패키지대로 바뀜</span>
        </div>
      </li>
      <li className="int-term-step" data-term-step="3">
        <span className="int-term-n" data-part="term-n">
          3
        </span>
        <div className="int-term-body">
          <b>나오는 결과(예)</b>
          <div className="int-term-results">
            <div className="int-term-ex ok">
              <span className="int-chip ok">통과</span>
              <pre className="int-pv-code" data-part="result-pass">
                {resultPass(v)}
              </pre>
            </div>
            <div className="int-term-ex danger">
              <span className="int-chip danger">격리</span>
              <pre className="int-pv-code" data-part="result-kill">
                {RESULT_KILL}
              </pre>
            </div>
          </div>
          <table className="int-exit" data-part="exit-codes">
            <caption className="int-field-label">종료 코드</caption>
            <tbody>
              {EXIT_CODES.map(([code, what]) => (
                <tr key={code}>
                  <td>{code}</td>
                  <td>{what}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </li>
    </ol>
  );
}

// ── 2 적용 · 자동 감지 ──
function Code({ text, part, onCopy }: { text: string; part: string; onCopy?: () => void }) {
  const copy = useCopyCommand();
  return (
    <div className="int-codebox">
      <pre className="int-code" data-part={part}>
        {text.split('\n').map((line, i) => (
          <span key={i} className={line.includes('supplyguard.') ? 'hl' : undefined}>
            {line}
            {'\n'}
          </span>
        ))}
      </pre>
      <button
        type="button"
        className="sg-btn sg-btn-sm sg-btn-secondary int-code-copy"
        data-part={`${part}-copy`}
        onClick={() => {
          copy(text);
          onCopy?.();
        }}
      >
        <Copy className="size-3.5" aria-hidden /> 복사
      </button>
    </div>
  );
}

function ApplyStep({ sc, st, env, containers, onNext }: { sc: 'single' | 'multi'; st: Saved; env: IntegrationEnv; containers: IntegrationContainer[]; onNext: () => void }) {
  const exp = expected(sc, st.single, st.multi);
  const found = detected(exp, containers);
  const n = found.filter((f) => f.row).length;
  const all = n === found.length && found.length > 0;
  return (
    <div className="int-apply" data-part="apply">
      <div className="int-apply-cols">
        <div>
          <h4 className="int-h4">① 설정({sc === 'single' && st.single.mode === 'run' ? '실행 명령' : 'docker-compose.yml'})</h4>
          <Code part="gen-config" text={sc === 'single' ? singleSnippet(st.single, env) : multiSnippet(st.multi, env)} />
          {sc === 'single' && st.single.mode === 'compose' && <p className="int-muted">기존 compose 의 같은 서비스에 labels · container_name 두 항목 추가</p>}
        </div>
        <div>
          <h4 className="int-h4">② 서버에서 실행(컨테이너 다시 만들기)</h4>
          <Code part="gen-apply" text={sc === 'single' ? singleApply(st.single, env) : multiApply()} />
          <div className="int-h4-row">
            <h4 className="int-h4">③ 자동 감지 {found.length > 1 && <span className="int-muted" data-part="detect-count">{n} / {found.length}</span>}</h4>
            <Link to="/integration/watch" className="int-link" data-part="detect-watch-link">
              감시 중 컨테이너 보기 ›
            </Link>
          </div>
          <ul className="int-detect" data-part="detect">
            {found.map((f) => (
              <li key={f.name} data-detect={f.name} data-found={String(!!f.row)} className={`int-detect-row ${f.row ? 'found' : ''}`}>
                <span className="int-detect-ico">{f.row ? <Check className="size-3.5" aria-hidden /> : <Loader2 className="size-3.5 animate-spin" aria-hidden />}</span>
                <b>{f.name}</b>
                <span className="int-muted">{f.row ? (f.row.enforce ? '감시 · 격리 대상 확인됨' : '감시 확인됨') : '감시 목록에 나타나기를 기다리는 중'}</span>
                {f.row && f.enforce !== f.row.enforce && <span className="int-field-err">격리 설정 다름, 라벨 확인 필요</span>}
              </li>
            ))}
          </ul>
        </div>
      </div>
      <div className="int-wiz-foot">
        {all ? (
          <span className="int-ok" data-part="detect-done">[감지 완료] 확인 단계 진행 가능</span>
        ) : (
          <span className="int-muted">
            감지 전에도 다음 단계로 이동 가능, 감지가 안 되면{' '}
            <Link to="/integration/env" className="int-link" data-part="detect-env-link">
              환경 점검
            </Link>{' '}
            확인
          </span>
        )}
        <button type="button" className={`sg-btn ${all ? 'sg-btn-primary' : 'sg-btn-secondary'}`} data-part="wizard-next" onClick={onNext}>
          확인 단계 →
        </button>
      </div>
    </div>
  );
}

// ── 3 확인 — 내 컨테이너에서 시험 동작 ──
const OUTCOME: Record<Outcome, { tone: string; title: string; points: string[] }> = {
  killed: { tone: 'danger', title: '[격리] 연동 · 격리 모두 동작 확인됨', points: ['/etc/shadow 읽기가 sensitive-files 정책에 걸려 컨테이너 종료됨', '조치: docker compose up -d 로 다시 시작(재시작 정책이 있으면 자동)'] },
  held: { tone: 'warn', title: '[격리 보류] 감시 동작 확인됨', points: ['위반 탐지 · 기록됨, 격리 라벨이 없어 종료하지 않음', '격리가 필요하면 supplyguard.enforce=true 추가'] },
  alert: { tone: 'ok', title: '[경고] 감시 동작 확인됨', points: ['위반 탐지 · 기록됨(정책 대응이 경고)'] },
};

function TestStep({ sc, st, set, containers }: { sc: 'single' | 'multi'; st: Saved; set: (p: Partial<Saved>) => void; containers: IntegrationContainer[] }) {
  const { verdicts } = useStream();
  const exp = expected(sc, st.single, st.multi);
  const target = exp.find((e) => e.name === st.target)?.name ?? exp[0]?.name ?? '';
  const enforce = exp.find((e) => e.name === target)?.enforce ?? false;
  const watching = containers.some((c) => c.name === target && c.watched);
  const v = testVerdict(verdicts, target, st.armedAt);
  const out = v ? OUTCOME[outcomeOf(v)] : null;
  return (
    <div className="int-test3" data-part="verify">
      {exp.length > 1 && (
        <div className="int-form-row">
          <span className="int-field-label">시험할 컨테이너</span>
          <select className="int-input" data-part="verify-target" value={target} onChange={(e) => set({ target: e.target.value, armedAt: undefined })}>
            {exp.map((e) => (
              <option key={e.name} value={e.name}>
                {e.name}
                {e.enforce ? ' (격리)' : ''}
              </option>
            ))}
          </select>
        </div>
      )}
      {!watching && <p className="int-field-err">⚠ {target} 아직 감시 목록에 없음, 2단계 적용 먼저 필요</p>}
      {enforce && (
        <p className="int-warn" data-part="verify-kill-warn">
          <TriangleAlert className="size-4" aria-hidden /> 격리 라벨 있음, 시험 동작 시 이 컨테이너가 실제로 종료됨
        </p>
      )}
      <h4 className="int-h4">서버에서 무해한 시험 동작 실행(계정 파일 읽기 시도)</h4>
      <Code part="gen-test" text={testCmd(target)} onCopy={() => set({ armedAt: new Date().toISOString() })} />
      <div className={`int-verify ${out ? out.tone : st.armedAt ? 'wait' : 'idle'}`} data-part="verify-result" data-outcome={v ? outcomeOf(v) : st.armedAt ? 'waiting' : 'idle'} key={v ? `v${v.event.timestamp}` : st.armedAt ?? 'idle'}>
        {!st.armedAt ? (
          <span className="int-muted">명령 복사 → 실행하면 결과가 여기에 자동 표시됨</span>
        ) : !v || !out ? (
          <span className="int-wait">
            <Loader2 className="size-4 animate-spin" aria-hidden /> {target} 의 위반 판정 기다리는 중
          </span>
        ) : (
          <>
            <b className="int-verify-title">
              <Check className="size-4" aria-hidden /> {out.title}
            </b>
            <ul className="int-points">
              {out.points.map((p) => (
                <li key={p}>{p}</li>
              ))}
              <li>
                규칙 {v.ruleId} · {v.reason}
              </li>
            </ul>
            <div className="int-form-row">
              <Link className="sg-btn sg-btn-sm sg-btn-secondary" to="/events">
                이벤트 보기
              </Link>
              <Link className="sg-btn sg-btn-sm sg-btn-secondary" to={`/topology?node=${encodeURIComponent(`c:${target}`)}`}>
                토폴로지에서 보기
              </Link>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── 설치 검사: 2 적용(명령) · 3 확인(세션 결과) ──
function InstallApply({ st, set }: { st: Saved; set: (p: Partial<Saved>) => void }) {
  const loadFn = useCallback(() => api.installs({ limit: 50 }), []);
  const { data, reload } = useLoad(st.installSince ? loadFn : null);
  const sess = installSessionFor(data, st.install, st.installSince);
  const finished = !!sess && sess.status !== 'running';
  // 콜백을 고정해야 타이머가 렌더마다(실시간 통계로 2초보다 자주) 다시 걸리지 않는다
  const poll = useCallback(() => {
    if (st.installSince && !finished) reload();
  }, [st.installSince, finished, reload]);
  useInterval(poll, 2000);
  useEffect(() => {
    if (sess && st.step === 2) set({ step: 3 });
  }, [sess, st.step, set]);
  return (
    <div className="int-apply" data-part="install-apply">
      <h4 className="int-h4">SupplyGuard 서버 셸에서 실행(저장소 폴더)</h4>
      <Code part="gen-install" text={installCmd(st.install)} onCopy={() => set({ installSince: new Date(Date.now() - 2000).toISOString() })} />
      <ul className="int-points">
        <li>도구 위치: 저장소의 tools/sg-install · SANDBOX_TOKEN 은 서버 .env 의 값 사용</li>
        <li>명령 복사 뒤 실행하면 설치 세션이 여기에 자동 표시됨</li>
      </ul>
      <div className={`int-verify ${finished ? (sess!.status === 'passed' ? 'ok' : 'danger') : st.installSince ? 'wait' : 'idle'}`} data-part="install-result" data-status={sess?.status ?? (st.installSince ? 'waiting' : 'idle')}>
        {!st.installSince ? (
          <span className="int-muted">명령 복사 → 실행하면 결과가 여기에 자동 표시됨</span>
        ) : !sess ? (
          <span className="int-wait">
            <Loader2 className="size-4 animate-spin" aria-hidden /> {st.install.manager} {st.install.pkg} 설치 세션 기다리는 중
          </span>
        ) : (
          <>
            <b className="int-verify-title">
              <StatusBadge status={sess.status} /> {sess.status === 'running' ? '설치 진행 중' : sess.status === 'passed' ? '위반 없이 설치 완료' : '설치 중 위반, 결과 확인 필요'}
            </b>
            <div className="int-form-row">
              <Link className="sg-btn sg-btn-sm sg-btn-secondary" data-part="install-open" to={installDest(sess.id).to} state={installDest(sess.id).state}>
                설치 상세 보기
              </Link>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
