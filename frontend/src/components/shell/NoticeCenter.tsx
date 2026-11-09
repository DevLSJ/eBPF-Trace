import { Bell, CirclePause, FilePen, Flag, Globe, KeyRound, ListTree, MailWarning, WifiOff, type LucideIcon } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/auth-context';
import { useCases } from '../../hooks/cases-context';
import { useStream } from '../../hooks/stream-context';
import { api } from '../../lib/api';
import { computeNotices, loadJSON, NOTICE_READ_KEY, saveJSON, type Notice } from '../../lib/shell';
import type { Proposal } from '../../lib/types';
import '../table-kit.css';

// C. 알림 센터(상단 종, 10/20 확정) — 목업 shared/shell-plus.js bellCenter.
// 판정 대기 · 적용하지 않은 제안 · 실시간 연결 끊김 · 도메인 판단 꺼짐 · dry-run · 알림 발송 실패 · 라이선스 30일 이하/만료 · 새 위반을 데이터로 계산한다.
// 읽음은 「알림 id → 그때의 서명」(localStorage). 누르면 그 화면(서버 상태는 /settings)

const ICON: Record<Notice['id'], LucideIcon> = {
  pending: Flag,
  proposals: FilePen,
  conn: WifiOff,
  dns: Globe,
  dryrun: CirclePause,
  webhook: MailWarning,
  license: KeyRound,
  violations: ListTree,
};
const TONE: Record<Notice['tone'], string> = {
  danger: 'bg-red-50 text-red-600',
  warn: 'bg-amber-50 text-amber-600',
  info: 'bg-indigo-50 text-indigo-600',
};

export function NoticeCenter() {
  const { cases } = useCases();
  const { info, stats, down, unseenAlerts, ackAlerts } = useStream();
  const { me, noAuth } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [proposals, setProposals] = useState<Proposal[] | null>(null);
  const [read, setRead] = useState<Record<string, string>>(() => loadJSON(NOTICE_READ_KEY, {}));
  const wrap = useRef<HTMLDivElement>(null);
  const btn = useRef<HTMLButtonElement>(null);

  // 제안 초안 — 처음 한 번, 건의 판정 · 상태가 바뀔 때(판정 → 제안 · 적용 → 종결), 종을 열 때 다시 읽는다. 옛 백엔드(라우트 없음)면 항목 없음.
  // 건 목록을 처음 받은 것만으로는 다시 읽지 않는다(첫 화면 직후 요청을 늘리지 않게)
  const caseSig = cases ? cases.map((c) => `${c.id}:${c.decision}:${c.state}:${c.proposalId ?? ''}`).join(',') : null;
  const [seenSig, setSeenSig] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  if (caseSig !== null && caseSig !== seenSig) {
    setSeenSig(caseSig);
    if (seenSig !== null) setNonce((n) => n + 1);
  }
  useEffect(() => {
    let live = true;
    api.proposals('draft').then(
      (ps) => live && setProposals(ps),
      () => live && setProposals(null),
    );
    return () => {
      live = false;
    };
  }, [nonce]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      setOpen(false);
      btn.current?.focus();
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const notices = computeNotices({
    cases,
    proposals,
    down,
    info,
    enforceKill: stats?.enforceKill ?? info?.enforceKill,
    license: me?.license ?? null,
    noAuth,
    unseen: unseenAlerts,
  });
  const isUnread = (x: Notice) => read[x.id] !== x.sig;
  const unread = notices.filter(isUnread).length;

  const markRead = (xs: Notice[]) => {
    const next = { ...read };
    for (const x of xs) next[x.id] = x.sig;
    saveJSON(NOTICE_READ_KEY, next);
    setRead(next);
  };

  return (
    <div ref={wrap} className="relative">
      <button
        ref={btn}
        type="button"
        data-part="bell"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-label={`알림 ${unread}건 안 읽음`}
        onClick={() => {
          if (!open) setNonce((n) => n + 1);
          setOpen(!open);
        }}
        className="relative rounded-md p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900"
      >
        <Bell className="size-5" aria-hidden />
        {unread > 0 && (
          <span data-part="bell-badge" className="num absolute -top-1 -right-1.5 min-w-5 rounded-full bg-red-600 px-1 text-center text-[11px] leading-5 font-semibold text-white">
            {unread}
          </span>
        )}
      </button>
      {open && (
        <div
          data-part="notices"
          role="dialog"
          aria-label="알림 센터"
          className="tk-pop-in absolute top-full right-0 z-50 mt-2 w-[22rem] max-w-[calc(100vw-2rem)] overflow-hidden rounded-xl border border-border bg-raised shadow-[var(--sh-2)]"
        >
          <div className="flex items-center justify-between border-b border-slate-100 px-4 py-2.5">
            <b className="text-sm">알림</b>
            <button type="button" onClick={() => markRead(notices)} className="rounded px-2 py-1 text-xs text-slate-600 hover:bg-slate-100">
              모두 읽음
            </button>
          </div>
          {notices.length === 0 ? (
            <p className="px-4 py-6 text-center text-sm text-slate-400">새 알림 없음</p>
          ) : (
            <ul className="max-h-[min(28rem,calc(100vh-6rem))] overflow-y-auto py-1">
              {notices.map((x) => {
                const Icon = ICON[x.id];
                const u = isUnread(x);
                return (
                  <li key={x.id}>
                    <button
                      type="button"
                      data-notice={x.id}
                      data-unread={String(u)}
                      onClick={() => {
                        markRead([x]);
                        setOpen(false);
                        if (x.id === 'violations') ackAlerts();
                        navigate(x.to);
                      }}
                      className="flex w-full items-start gap-3 px-4 py-2.5 text-left hover:bg-slate-50"
                    >
                      <span className={`mt-0.5 grid size-7 shrink-0 place-items-center rounded-md ${TONE[x.tone]}`} aria-hidden>
                        <Icon className="size-4" />
                      </span>
                      <span className="grid min-w-0 flex-1 gap-0.5">
                        <b className={`text-sm ${u ? 'text-slate-900' : 'font-medium text-slate-600'}`}>{x.title}</b>
                        {x.text && <span className="text-xs break-words text-slate-500">{x.text}</span>}
                      </span>
                      {u && <i className="mt-2 size-2 shrink-0 rounded-full bg-indigo-600" aria-label="안 읽음" />}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
