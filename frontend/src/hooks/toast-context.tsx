import { X } from 'lucide-react';
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import type { NavState } from '../lib/nav';

export type ToastTone = 'info' | 'ok' | 'warn' | 'danger';
export interface ToastOptions {
  // 같은 key 는 한 토스트로 묶고 ×N 을 올린다(같은 대상의 연속 격리 등)
  key?: string;
  tone?: ToastTone;
  // state: 이동할 화면의 초기 필터(주소에 남기지 않는다, 10/21)
  action?: { label: string; to?: string; state?: NavState; run?: () => void };
}
interface ToastItem extends ToastOptions {
  id: number;
  text: string;
  n: number;
}

export const TOAST_MS = 8000;
const MAX = 4;

const ToastContext = createContext<((text: string, o?: ToastOptions) => void) | null>(null);

const toneStyle: Record<ToastTone, string> = {
  info: 'border-slate-300 bg-white text-slate-800',
  ok: 'border-emerald-300 bg-emerald-50 text-emerald-900',
  warn: 'border-amber-300 bg-amber-50 text-amber-900',
  danger: 'border-red-300 bg-red-50 text-red-900',
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const seq = useRef(0);
  const timers = useRef(new Map<number, number>());
  const navigate = useNavigate();

  const itemsRef = useRef<ToastItem[]>([]);
  const commit = useCallback((next: ToastItem[]) => {
    itemsRef.current = next;
    setItems(next);
  }, []);

  const close = useCallback(
    (id: number) => {
      window.clearTimeout(timers.current.get(id));
      timers.current.delete(id);
      commit(itemsRef.current.filter((x) => x.id !== id));
    },
    [commit],
  );

  const arm = useCallback(
    (id: number) => {
      window.clearTimeout(timers.current.get(id));
      timers.current.set(id, window.setTimeout(() => close(id), TOAST_MS));
    },
    [close],
  );

  const toast = useCallback(
    (text: string, o: ToastOptions = {}) => {
      const xs = itemsRef.current;
      const same = o.key ? xs.find((x) => x.key === o.key) : undefined;
      if (same) {
        commit(xs.map((x) => (x === same ? { ...x, ...o, text, n: x.n + 1 } : x)));
        arm(same.id);
        return;
      }
      const id = ++seq.current;
      const next = [...xs, { ...o, id, text, n: 1 }];
      for (const old of next.slice(0, Math.max(0, next.length - MAX))) {
        window.clearTimeout(timers.current.get(old.id));
        timers.current.delete(old.id);
      }
      commit(next.slice(-MAX));
      arm(id);
    },
    [arm, commit],
  );

  useEffect(() => {
    const ts = timers.current;
    return () => ts.forEach((t) => window.clearTimeout(t));
  }, []);

  return (
    <ToastContext.Provider value={toast}>
      {children}
      {/* 10/20: 왼쪽 아래(사이드바 w-52 바로 오른쪽) — 오른쪽 아래 도우미 버튼 · 상세 시트와 겹치지 않게(목업 결정) */}
      <div className="pointer-events-none fixed bottom-5 left-[calc(var(--sg-sidebar-w,13rem)+1.25rem)] z-50 flex w-[min(24rem,calc(100vw-2.5rem))] flex-col gap-2" role="status" aria-live="polite" aria-label="알림">
        {items.map((t) => (
          <div
            key={t.id}
            data-toast={t.key ?? ''}
            className={`pointer-events-auto flex items-start gap-2 rounded-lg border px-3.5 py-2.5 text-sm shadow-md ${toneStyle[t.tone ?? 'info']}`}
          >
            <span className="min-w-0 flex-1">
              {t.text}
              {t.n > 1 && <b className="num ml-1.5 rounded bg-black/10 px-1.5 text-xs" data-toast-count>×{t.n}</b>}
            </span>
            {t.action && (
              <button
                type="button"
                className="shrink-0 rounded px-1.5 text-xs font-semibold underline-offset-2 hover:underline"
                onClick={() => {
                  if (t.action?.to) navigate(t.action.to, { state: t.action.state });
                  t.action?.run?.();
                  close(t.id);
                }}
              >
                {t.action.label}
              </button>
            )}
            <button type="button" onClick={() => close(t.id)} className="shrink-0 rounded p-0.5 opacity-60 hover:opacity-100" aria-label="알림 닫기">
              <X className="size-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useToast() {
  const t = useContext(ToastContext);
  if (!t) throw new Error('useToast must be used inside ToastProvider');
  return t;
}
