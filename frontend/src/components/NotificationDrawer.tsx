import { useEffect, useState } from 'react';
import { Bell, BellOff, CheckCheck, CheckCircle2, CircleAlert, Info, ShieldAlert, TriangleAlert, X } from 'lucide-react';
import { useNotifyStore, type Notice, type NoticeKind } from '../store/notifyStore';

const ICON = { ok: CheckCircle2, warn: TriangleAlert, error: CircleAlert, info: Info };
const FILTERS: { value: NoticeKind | 'all'; label: string }[] = [{ value: 'all', label: '전체' }, { value: 'event', label: '탐지' }, { value: 'system', label: '시스템' }];
export function relativeTime(at: number, now = Date.now()) {
  const seconds = Math.max(0, Math.round((now - at) / 1000));
  if (seconds < 10) return '방금';
  if (seconds < 60) return `${seconds}초 전`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}분 전`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}시간 전`;
  return new Date(at).toLocaleDateString('ko-KR', { month: 'short', day: 'numeric' });
}

// 상단 종 아이콘으로 여는 알림 센터 드로어. 화면을 옮겨도 남는 기록을 시간순으로 보여준다.
export function NotificationDrawer({ onClose, onOpenEvent }: { onClose: () => void; onOpenEvent: (id: number) => void }) {
  const notices = useNotifyStore(s => s.notices), markAllRead = useNotifyStore(s => s.markAllRead), clear = useNotifyStore(s => s.clearNotices);
  const [filter, setFilter] = useState<NoticeKind | 'all'>('all'), [now, setNow] = useState(Date.now());
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 15000); return () => clearInterval(timer); }, []);
  useEffect(() => { const key = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); }; window.addEventListener('keydown', key); return () => window.removeEventListener('keydown', key); }, [onClose]);
  const shown = notices.filter(n => filter === 'all' || n.kind === filter);
  const count = (kind: NoticeKind | 'all') => notices.filter(n => kind === 'all' || n.kind === kind).length;
  const open = (notice: Notice) => { if (notice.eventId) onOpenEvent(notice.eventId); else if (notice.href) location.hash = notice.href; onClose(); };
  return <>
    <div className="notify-backdrop" onClick={onClose} aria-hidden="true"/>
    <aside className="notify-drawer" aria-label="알림 센터">
      <header className="notify-head"><div><h2><Bell size={17}/>알림</h2><p>새 탐지 이벤트와 연결 상태 변화가 여기에 쌓여요.</p></div><button className="icon-button" type="button" aria-label="알림 센터 닫기" onClick={onClose}><X size={18}/></button></header>
      <div className="notify-filters" role="group" aria-label="알림 종류">{FILTERS.map(f => <button key={f.value} type="button" className={filter === f.value ? 'active' : ''} aria-pressed={filter === f.value} onClick={() => setFilter(f.value)}>{f.label}<b>{count(f.value)}</b></button>)}<button className="text-button notify-read-all" type="button" onClick={markAllRead} disabled={!notices.some(n => !n.read)}><CheckCheck size={14}/>모두 읽음</button></div>
      <div className="notify-list">
        {shown.length ? shown.map(n => { const Icon = n.kind === 'event' ? ShieldAlert : ICON[n.level]; const clickable = Boolean(n.eventId || n.href); return <article className={`notify-item level-${n.level}${n.read ? '' : ' unread'}`} key={n.id}>
          <span className="notify-icon"><Icon size={16} aria-hidden="true"/></span>
          <div className="notify-body"><strong>{n.title}</strong>{n.body && <p>{n.body}</p>}<small><time dateTime={new Date(n.at).toISOString()}>{relativeTime(n.at, now)}</time>{clickable && <button type="button" className="notify-open" onClick={() => open(n)}>{n.eventId ? '기록 열기' : '화면으로 이동'}</button>}</small></div>
        </article>; }) : <div className="notify-empty"><BellOff size={30}/><strong>아직 알림이 없어요</strong><p>{filter === 'event' ? '새 탐지 이벤트가 실시간으로 들어오면 여기에 표시돼요.' : filter === 'system' ? '연결·수집기 상태가 바뀌면 여기에 표시돼요.' : '새 탐지 이벤트와 연결·수집기 상태 변화가 여기에 표시돼요.'}</p></div>}
      </div>
      <footer className="notify-foot"><a href="#notifications" onClick={onClose}>운영자 알림 전달 기록 보기 →</a><button className="text-button" type="button" onClick={clear} disabled={!notices.length}>기록 비우기</button></footer>
    </aside>
  </>;
}
