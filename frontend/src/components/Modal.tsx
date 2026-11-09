import { X } from 'lucide-react';
import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { errorText, isUnsupported, sentence } from '../lib/api';
import { ActionButton } from './ActionButton';
import './table-kit.css';

// 모달 · 확인 대화상자 — 목업 shared/ui-kit.js 의 modal · confirmDialog 를 옮긴 것(W16).
// <dialog> + 포커스 트랩 · Esc · 연 곳으로 포커스 복귀 · 미저장 보호(guard 가 true 면 닫기 전에 묻는다)
// 11/09 size(선택 — 안 주면 wide 로 md 640 · 아니면 sm 448 그대로):
//   'xl' 큰 2단 창 — 폭 min(1180px, 100vw−40px) · 최대 높이 100vh−40px · 왼쪽 children(남는 폭) + 오른쪽 side(clamp(340px, 36%, 460px))
//        두 칸이 따로 스크롤 · 머리(제목 · ✕) · 바닥 버튼 줄(위 선) · 바깥 클릭으로 닫히지 않음(모든 크기 공통) · 768 미만은 1단으로 쌓음
//   미저장 경고: confirmClose(xl 은 기본 켬)면 노란 띠 대신 확인 창 「계속 편집 / 버리고 닫기」. 값 비교는 hooks/useUnsaved.ts
//   foot 에 함수를 주면 (close) => 단추 — 「취소」가 ✕ · Esc 와 같은 길(미저장 경고)로 닫힌다
//   busy 동안은 ✕ · Esc · 취소로 닫히지 않는다(저장 중 — ✕ 는 aria-disabled + 사유)
//   움직임(11/09 SPEC-1109 §2 · 참고 제품 B2): 뒤 어둡게만 150ms(.tk-dialog::backdrop), 창 상자는 움직이지 않는다 — 모든 크기 · 확인 창 공통

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function Modal({
  title,
  kind,
  children,
  foot,
  guard,
  onClose,
  wide,
  size,
  side,
  confirmClose,
  busy,
}: {
  title: string;
  kind?: string;
  children: ReactNode;
  foot?: ReactNode | ((close: () => void) => ReactNode);
  guard?: () => boolean;
  onClose: () => void;
  wide?: boolean;
  size?: 'sm' | 'md' | 'xl';
  side?: ReactNode;
  confirmClose?: boolean;
  busy?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [warn, setWarn] = useState(false);
  const [ask, setAsk] = useState(false);
  const closeRef = useRef(onClose);
  useEffect(() => {
    closeRef.current = onClose;
  });
  const sz = size ?? (wide ? 'md' : 'sm');
  const asking = confirmClose ?? sz === 'xl';

  useEffect(() => {
    const d = ref.current!;
    const opener = document.activeElement as HTMLElement | null;
    if (!d.open) d.showModal();
    const auto = d.querySelector<HTMLElement>('[autofocus], textarea, input, select') ?? d.querySelector<HTMLElement>('[data-confirm="ok"]');
    auto?.focus();
    return () => {
      try {
        d.close();
      } catch {
        /* 이미 닫힘 */
      }
      if (opener?.isConnected) opener.focus();
    };
  }, []);

  const tryClose = () => {
    if (busy) return;
    if (guard?.()) {
      if (asking) return setAsk(true);
      if (!warn) return setWarn(true);
    }
    onClose();
  };
  const footNode = typeof foot === 'function' ? foot(tryClose) : foot;
  const onKeyDown = (e: KeyboardEvent<HTMLDialogElement>) => {
    if (e.key !== 'Tab') return;
    const d = ref.current!;
    // 이 창 위에 겹친 창(확인 창)의 Tab 은 그 창이 맡는다
    if ((e.target as Element).closest('dialog') !== d) return;
    const els = [...d.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((x) => x.offsetParent !== null && x.closest('dialog') === d);
    if (!els.length) return;
    const first = els[0];
    const last = els[els.length - 1];
    if (e.shiftKey && (document.activeElement === first || !d.contains(document.activeElement))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (document.activeElement === last || !d.contains(document.activeElement))) {
      e.preventDefault();
      first.focus();
    }
  };
  const askBox = ask && (
    <UnsavedAsk
      onKeep={() => setAsk(false)}
      onDiscard={() => {
        setAsk(false);
        closeRef.current();
      }}
    />
  );

  if (sz === 'xl')
    return (
      <dialog
        ref={ref}
        data-part={kind ?? 'modal'}
        data-size="xl"
        aria-label={title}
        onCancel={(e) => {
          e.preventDefault();
          tryClose();
        }}
        onKeyDown={onKeyDown}
        className="tk-dialog tk-modal-xl m-auto rounded-[var(--r-xl)] border border-border bg-raised p-0 text-text shadow-[var(--sh-2)] backdrop:bg-black/50"
      >
        <div className="tk-xl">
          <header className="tk-xl-head">
            <h3 className="min-w-0 flex-1 truncate text-base font-semibold">{title}</h3>
            <ActionButton aria-label="닫기" title="닫기" reason={busy && '저장 중입니다'} onClick={tryClose} className="tk-icon-btn">
              <X className="size-4" aria-hidden />
            </ActionButton>
          </header>
          <div className="tk-xl-body" data-part="modal-body" data-two={side != null ? '' : undefined}>
            <div className="tk-xl-main" data-part="modal-main">
              {children}
            </div>
            {side != null && (
              <div className="tk-xl-side" data-part="modal-side">
                {side}
              </div>
            )}
          </div>
          {warn && !asking && <WarnStrip onKeep={() => setWarn(false)} onDiscard={() => closeRef.current()} />}
          {footNode && (
            <footer className="tk-xl-foot" data-part="modal-foot">
              {footNode}
            </footer>
          )}
        </div>
        {askBox}
      </dialog>
    );

  return (
    <dialog
      ref={ref}
      data-part={kind ?? 'modal'}
      aria-label={title}
      onCancel={(e) => {
        e.preventDefault();
        tryClose();
      }}
      onKeyDown={onKeyDown}
      className={`tk-dialog m-auto rounded-[var(--r-xl)] border border-border bg-raised p-0 text-text shadow-[var(--sh-2)] backdrop:bg-black/50 ${sz === 'md' ? 'w-[40rem]' : 'w-[28rem]'} max-w-[calc(100vw-2rem)]`}
    >
      <div className="grid gap-4 p-5">
        <div className="flex items-center justify-between gap-3">
          <h3 className="text-base font-semibold">{title}</h3>
          <button type="button" aria-label="닫기" title="닫기" onClick={tryClose} className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700">
            <X className="size-4" aria-hidden />
          </button>
        </div>
        {children}
        {warn && !asking && <WarnStrip onKeep={() => setWarn(false)} onDiscard={() => closeRef.current()} />}
        {footNode && <div className="flex justify-end gap-2">{footNode}</div>}
      </div>
      {askBox}
    </dialog>
  );
}

function WarnStrip({ onKeep, onDiscard }: { onKeep: () => void; onDiscard: () => void }) {
  return (
    <div role="alert" className="flex items-center gap-2 rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-900">
      <span className="flex-1">저장하지 않은 내용이 있습니다. 닫으면 사라집니다.</span>
      <button type="button" onClick={onKeep} className="rounded px-2 py-1 hover:bg-amber-100">
        계속 쓰기
      </button>
      <button type="button" data-action="discard-close" onClick={onDiscard} className="rounded px-2 py-1 text-red-700 hover:bg-red-50">
        버리고 닫기
      </button>
    </div>
  );
}

// 미저장 확인 창(11/09) — 창 위에 겹친 작은 창. Esc · 「계속 편집」 = 이 창만 닫고 입력은 그대로, 「버리고 닫기」 = 아래 창까지 닫음
function UnsavedAsk({ onKeep, onDiscard }: { onKeep: () => void; onDiscard: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current!;
    const opener = document.activeElement as HTMLElement | null;
    if (!d.open) d.showModal();
    d.querySelector<HTMLElement>('[data-action="keep-editing"]')?.focus();
    return () => {
      try {
        d.close();
      } catch {
        /* 이미 닫힘 */
      }
      if (opener?.isConnected) opener.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      data-part="unsaved"
      aria-label="저장하지 않은 변경"
      aria-describedby="sg-unsaved-text"
      onCancel={(e) => {
        e.preventDefault();
        e.stopPropagation(); // 아래 창의 onCancel(React 는 겹친 dialog 로도 올려 보낸다)까지 가지 않게
        onKeep();
      }}
      onKeyDown={(e) => e.stopPropagation()}
      className="tk-dialog tk-ask m-auto rounded-[var(--r-xl)] border border-border bg-raised p-0 text-text shadow-[var(--sh-2)] backdrop:bg-black/40"
    >
      <div className="grid gap-3 p-5">
        <h3 className="text-base font-semibold">저장하지 않은 변경 있음</h3>
        <p id="sg-unsaved-text" className="text-sm text-text-2">
          입력한 값이 아직 저장되지 않았습니다. 닫으면 바꾼 내용이 사라집니다.
        </p>
        <div className="flex justify-end gap-2">
          <button type="button" data-action="keep-editing" className="sg-btn sg-btn-secondary" onClick={onKeep}>
            계속 편집
          </button>
          <button type="button" data-action="discard-close" className="sg-btn sg-btn-danger" onClick={onDiscard}>
            버리고 닫기
          </button>
        </div>
      </div>
    </dialog>
  );
}

// 「함께 일어나는 일」 한 줄 — 문자열 또는 서버 판정 미리보기의 effect({kind, text, count?}) 그대로
export type EffectItem = string | { kind: string; text: string; count?: number };

const EFFECT_TONE: Record<string, string> = {
  blocklist: 'text-red-700 font-medium',
  package: 'text-slate-700',
  image: 'text-slate-700',
  host: 'text-slate-700',
  exception: 'text-sky-800',
  already_blocked: 'text-slate-500',
  none: 'text-slate-500',
  note: 'text-amber-800',
  next: 'text-slate-500',
  loading: 'text-slate-400',
  error: 'text-amber-800',
};

// 확인 대화상자(10/20 B — 두 번 누르기 대체): 대상 · 함께 일어나는 일 · (선택) 사유 · 되돌리기 안내. 확인이면 onConfirm(사유)
// effects 는 바로 아는 것, loadEffects 는 서버가 계산하는 것(판정 미리보기) — 계산 중 · 실패도 목록 안에 보인다
// 11/09 SPEC-1109 §7 양식(선택 props — 안 주면 옛 모양 그대로):
//   title 「[대상]을 [동작]할까요?」 · body 한두 문장 · impact 영향 범위 줄마다 하나(개수 포함 — 주면 옛 「함께 일어나는 일」 칸 대신)
//   blocked 막는 사유(있으면 확인이 aria-disabled + 그 사유, 확인 체크 없음) · requireCheck 위험하면 확인 체크 「~ㅁ을 확인했습니다」(체크 전엔 확인 꺼짐)
//   confirmLabel 확인 단추 동작 한 단어(삭제 · 저장 · 되돌리기, okLabel 과 같음) · danger 지우기 · 되돌릴 수 없는 일은 위험 단추(tone 과 같음)
//   새 양식에서 impact 없이 loadEffects(서버 계산 — 판정 미리보기) · effects 를 주면 그 줄이 「영향 범위」 칸에 들어간다(계산 중 · 실패도 그 칸 안, 11/09 G19)
//   <ConfirmDialog title="정책 a 를 삭제할까요?" body="…" impact={['컨테이너 3개의 판정이 바뀝니다.']} requireCheck="삭제하면 되돌릴 수 없음을 확인했습니다" confirmLabel="삭제" danger onConfirm={…} onCancel={…} />
export function ConfirmDialog({
  title,
  target,
  effects,
  loadEffects,
  undo,
  okLabel,
  tone,
  reason = false,
  body,
  impact,
  blocked,
  requireCheck,
  confirmLabel,
  danger,
  onConfirm,
  onCancel,
}: {
  title: string;
  target?: string;
  effects?: EffectItem[];
  loadEffects?: () => Promise<EffectItem[]>;
  undo?: string;
  okLabel?: string;
  tone?: 'danger' | 'primary';
  reason?: boolean;
  body?: ReactNode;
  impact?: EffectItem[];
  blocked?: string | null;
  requireCheck?: string;
  confirmLabel?: string;
  danger?: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const [text, setText] = useState('');
  const [checked, setChecked] = useState(false);
  const label = confirmLabel ?? okLabel ?? '확인';
  const isDanger = danger ?? (tone ? tone === 'danger' : true);
  const needCheck = !!requireCheck && !blocked;
  const offReason = blocked || (needCheck && !checked ? '확인 칸을 먼저 고르세요' : null);
  // 옛 「함께 일어나는 일」 칸 — 새 양식(body · impact)을 하나도 안 줄 때만. 새 양식이면 effects · loadEffects 도 「영향 범위」 칸에
  const newForm = body !== undefined || impact !== undefined;
  const legacyEffects = !newForm;
  const [loaded, setLoaded] = useState<{ items?: EffectItem[]; error?: string } | null>(null);
  // 처음 받은 계산 함수만 쓴다(부모가 다시 그려도 한 번)
  const [load] = useState(() => loadEffects);
  const started = useRef(false);
  useEffect(() => {
    if (!load || started.current) return;
    started.current = true; // 개발 모드(StrictMode) 이중 실행에도 서버 계산은 한 번
    load().then(
      (items) => setLoaded({ items }),
      (e: unknown) => setLoaded({ error: isUnsupported(e) ? '백엔드 미지원(미리보기 API 없음)' : errorText(e) }),
    );
  }, [load]);
  const items: EffectItem[] = load
    ? !loaded
      ? [{ kind: 'loading', text: '계산 중…' }]
      : loaded.error !== undefined
        ? [{ kind: 'error', text: `영향을 계산하지 못했습니다. ${sentence(loaded.error)}` }]
        : (loaded.items ?? [])
    : (effects ?? []);
  const shown = items.length ? items : ['따로 바뀌는 것 없음'];
  const impactItems: EffectItem[] = impact ?? (newForm && (load || effects) ? (items.length ? items : ['따로 바뀌는 것이 없습니다.']) : []);
  return (
    <Modal
      title={title}
      kind="confirm"
      wide
      onClose={onCancel}
      guard={() => reason && text.trim() !== ''}
      foot={
        <>
          <button type="button" data-confirm="cancel" onClick={onCancel} className="sg-btn text-text-2 hover:bg-surface-3">
            취소
          </button>
          <ActionButton data-confirm="ok" reason={offReason} onClick={() => onConfirm(text.trim())} className={`sg-btn ${isDanger ? 'sg-btn-danger' : 'sg-btn-primary'}`}>
            {label}
          </ActionButton>
        </>
      }
    >
      {target !== undefined && (
        <dl className="grid grid-cols-[3rem_1fr] gap-x-2 text-sm">
          <dt className="text-slate-500">대상</dt>
          <dd className="font-mono break-all" data-part="confirm-target">
            {target}
          </dd>
        </dl>
      )}
      {body != null && (
        <p className="text-sm text-text-2" data-part="confirm-body">
          {body}
        </p>
      )}
      {blocked && (
        <p role="alert" className="rounded-[var(--r-sm)] bg-danger-soft px-3 py-2 text-sm text-danger-text" data-part="confirm-blocked">
          {blocked}
        </p>
      )}
      {!!impactItems.length && (
        <div className="text-sm">
          <div className="font-medium">영향 범위</div>
          <ul className="mt-1 grid max-h-[168px] list-disc gap-0.5 overflow-y-auto pl-5" data-part="confirm-impact" aria-live={load ? 'polite' : undefined}>
            {impactItems.map((x, i) => {
              const kind = typeof x === 'string' ? '' : x.kind;
              return (
                <li key={i} data-kind={kind || undefined} className={EFFECT_TONE[kind] ?? 'text-text-2'}>
                  {typeof x === 'string' ? x : x.text}
                </li>
              );
            })}
          </ul>
        </div>
      )}
      {legacyEffects && (
      <div className="text-sm">
        <div className="font-medium">함께 일어나는 일</div>
        <ul className="mt-1 grid list-disc gap-0.5 pl-5" data-part="confirm-effects" aria-live="polite">
          {shown.map((x, i) => {
            const kind = typeof x === 'string' ? '' : x.kind;
            return (
              <li key={i} data-kind={kind || undefined} className={EFFECT_TONE[kind] ?? 'text-slate-700'}>
                {typeof x === 'string' ? x : x.text}
              </li>
            );
          })}
        </ul>
      </div>
      )}
      {needCheck && (
        <label className="flex items-center gap-2 text-sm" data-part="confirm-check">
          <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} />
          <span>{requireCheck}</span>
        </label>
      )}
      {reason && (
        <label className="grid gap-1 text-sm">
          <span>
            <b>사유</b> <small className="text-slate-500">선택 · 감사 로그에 남습니다 (500자까지)</small>
          </span>
          <textarea
            name="reason"
            aria-label="사유 (선택)"
            rows={2}
            maxLength={500}
            value={text}
            placeholder="예: 이름이 requests 와 한 글자 다른 타이포스쿼팅"
            onChange={(e) => setText(e.target.value)}
            className="rounded-[var(--r-md)] border border-slate-300 px-2 py-1.5 text-sm focus:border-indigo-500 focus:outline-none"
          />
        </label>
      )}
      {undo && (
        <p className="text-xs text-slate-500" data-part="confirm-undo">
          되돌리기: {undo}
        </p>
      )}
    </Modal>
  );
}
