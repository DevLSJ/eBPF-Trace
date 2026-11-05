import { create } from 'zustand';

// 알림 센터(드로어)와 토스트의 단일 저장소.
// - notices: 상단 종 아이콘 드로어에 쌓이는 기록(새 탐지 이벤트 · 연결 상태 · 수집기 상태). 화면을 옮겨도 남는다.
// - toasts : 화면 오른쪽 아래에 잠깐 떠오르는 즉시 피드백. 자동으로 사라진다.
export type NoticeLevel = 'info' | 'ok' | 'warn' | 'error';
export type NoticeKind = 'event' | 'system';
export interface Notice { id: string; kind: NoticeKind; level: NoticeLevel; title: string; body?: string; at: number; href?: string; eventId?: number; read: boolean }
export interface ToastAction { label: string; href?: string; onClick?: () => void }
export interface Toast { id: string; level: NoticeLevel; text: string; action?: ToastAction; leaving?: boolean }

interface Store {
  notices: Notice[]; toasts: Toast[]; drawerOpen: boolean; bump: number;
  notify: (notice: Omit<Notice, 'id' | 'at' | 'read'> & { at?: number }) => void;
  toast: (toast: Omit<Toast, 'id'> & { duration?: number }) => string;
  dismissToast: (id: string) => void;
  openDrawer: (open: boolean) => void;
  markAllRead: () => void;
  clearNotices: () => void;
}

const MAX_NOTICES = 120, MAX_TOASTS = 4;
const uid = () => (typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`);
const timers = new Map<string, ReturnType<typeof setTimeout>>();

export const useNotifyStore = create<Store>((set, get) => ({
  notices: [], toasts: [], drawerOpen: false, bump: 0,
  notify: notice => set(state => ({
    notices: [{ ...notice, id: uid(), at: notice.at ?? Date.now(), read: state.drawerOpen }, ...state.notices].slice(0, MAX_NOTICES),
    bump: state.drawerOpen ? state.bump : state.bump + 1,
  })),
  toast: ({ duration = 4200, ...toast }) => {
    const id = uid();
    set(state => ({ toasts: [...state.toasts.filter(t => !t.leaving), { ...toast, id }].slice(-MAX_TOASTS) }));
    timers.set(id, setTimeout(() => get().dismissToast(id), duration));
    return id;
  },
  dismissToast: id => {
    clearTimeout(timers.get(id)); timers.delete(id);
    if (!get().toasts.some(t => t.id === id)) return;
    set(state => ({ toasts: state.toasts.map(t => t.id === id ? { ...t, leaving: true } : t) }));
    setTimeout(() => set(state => ({ toasts: state.toasts.filter(t => t.id !== id) })), 220);
  },
  openDrawer: open => set(state => ({ drawerOpen: open, notices: open ? state.notices.map(n => n.read ? n : { ...n, read: true }) : state.notices })),
  markAllRead: () => set(state => ({ notices: state.notices.map(n => n.read ? n : { ...n, read: true }) })),
  clearNotices: () => set({ notices: [] }),
}));

export const unreadCount = (notices: Notice[]) => notices.reduce((count, n) => count + (n.read ? 0 : 1), 0);
