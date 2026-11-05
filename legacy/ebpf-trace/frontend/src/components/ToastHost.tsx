import { CheckCircle2, CircleAlert, Info, TriangleAlert, X } from 'lucide-react';
import { useNotifyStore } from '../store/notifyStore';

const ICON = { ok: CheckCircle2, warn: TriangleAlert, error: CircleAlert, info: Info };

// 화면 오른쪽 아래 토스트. 자동으로 사라지고, 행동 버튼(링크)을 하나 붙일 수 있다.
export function ToastHost() {
  const toasts = useNotifyStore(s => s.toasts), dismiss = useNotifyStore(s => s.dismissToast);
  if (!toasts.length) return null;
  return <div className="toast-host" aria-live="polite">
    {toasts.map(t => { const Icon = ICON[t.level]; return <div className={`toast toast-${t.level}${t.leaving ? ' leaving' : ''}`} role="status" key={t.id}>
      <Icon size={17} aria-hidden="true"/><span className="toast-text">{t.text}</span>
      {t.action && (t.action.href ? <a className="toast-action" href={t.action.href} onClick={() => { t.action?.onClick?.(); dismiss(t.id); }}>{t.action.label}</a> : <button className="toast-action" type="button" onClick={() => { t.action?.onClick?.(); dismiss(t.id); }}>{t.action.label}</button>)}
      <button className="toast-x" type="button" aria-label="알림 지우기" onClick={() => dismiss(t.id)}><X size={14}/></button>
    </div>; })}
  </div>;
}
