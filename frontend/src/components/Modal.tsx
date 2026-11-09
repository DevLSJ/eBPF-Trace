import { X } from 'lucide-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { errorText, isUnsupported } from '../lib/api';

// 모달 · 확인 대화상자 — 목업 shared/ui-kit.js 의 modal · confirmDialog 를 옮긴 것(W16).
// <dialog> + 포커스 트랩 · Esc · 연 곳으로 포커스 복귀 · 미저장 보호(guard 가 true 면 닫기 전에 묻는다)

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function Modal({
  title,
  kind,
  children,
  foot,
  guard,
  onClose,
  wide,
}: {
  title: string;
  kind?: string;
  children: ReactNode;
  foot?: ReactNode;
  guard?: () => boolean;
  onClose: () => void;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [warn, setWarn] = useState(false);
  const closeRef = useRef(onClose);
  useEffect(() => {
    closeRef.current = onClose;
  });

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
    if (guard?.() && !warn) {
      setWarn(true);
      return;
    }
    closeRef.current();
  };

  return (
    <dialog
      ref={ref}
      data-part={kind ?? 'modal'}
      aria-label={title}
      onCancel={(e) => {
        e.preventDefault();
        tryClose();
      }}
      onKeyDown={(e) => {
        if (e.key !== 'Tab') return;
        const d = ref.current!;
        const els = [...d.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((x) => x.offsetParent !== null);
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
      }}
      className={`m-auto rounded-[var(--r-xl)] border border-border bg-raised p-0 text-text shadow-[var(--sh-2)] backdrop:bg-black/50 ${wide ? 'w-[40rem]' : 'w-[28rem]'} max-w-[calc(100vw-2rem)]`}
    >
      <div className="grid gap-4 p-5">
        <div className="flex items-center justify-between gap-3">
          <h3 className="text-base font-semibold">{title}</h3>
          <button type="button" aria-label="닫기" onClick={tryClose} className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700">
            <X className="size-4" aria-hidden />
          </button>
        </div>
        {children}
        {warn && (
          <div role="alert" className="flex items-center gap-2 rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-900">
            <span className="flex-1">저장하지 않은 내용이 있습니다. 닫으면 사라집니다.</span>
            <button type="button" onClick={() => setWarn(false)} className="rounded px-2 py-1 hover:bg-amber-100">
              계속 쓰기
            </button>
            <button type="button" data-action="discard-close" onClick={() => closeRef.current()} className="rounded px-2 py-1 text-red-700 hover:bg-red-50">
              버리고 닫기
            </button>
          </div>
        )}
        {foot && <div className="flex justify-end gap-2">{foot}</div>}
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
export function ConfirmDialog({
  title,
  target,
  effects,
  loadEffects,
  undo,
  okLabel = '확인',
  tone = 'danger',
  reason = false,
  onConfirm,
  onCancel,
}: {
  title: string;
  target: string;
  effects?: EffectItem[];
  loadEffects?: () => Promise<EffectItem[]>;
  undo?: string;
  okLabel?: string;
  tone?: 'danger' | 'primary';
  reason?: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const [text, setText] = useState('');
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
        ? [{ kind: 'error', text: `영향을 계산하지 못했습니다 — ${loaded.error}` }]
        : (loaded.items ?? [])
    : (effects ?? []);
  const shown = items.length ? items : ['따로 바뀌는 것 없음'];
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
          <button
            type="button"
            data-confirm="ok"
            onClick={() => onConfirm(text.trim())}
            className={`sg-btn ${tone === 'primary' ? 'sg-btn-primary' : 'sg-btn-danger'}`}
          >
            {okLabel}
          </button>
        </>
      }
    >
      <dl className="grid grid-cols-[3rem_1fr] gap-x-2 text-sm">
        <dt className="text-slate-500">대상</dt>
        <dd className="font-mono break-all" data-part="confirm-target">
          {target}
        </dd>
      </dl>
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
