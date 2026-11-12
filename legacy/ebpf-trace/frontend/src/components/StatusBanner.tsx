import type { ReactNode } from 'react';
import { CheckCircle2, CircleAlert, TriangleAlert } from 'lucide-react';
import type { StatusLevel } from '../labels';
import { STATUS_LEVEL } from '../labels';

const ICON = { ok: CheckCircle2, warn: TriangleAlert, error: CircleAlert };

// 3색 신호등 배너: 색 + 아이콘 + "정상/주의/문제" 텍스트 + 원인 한 줄 + 다음 행동 버튼.
export function StatusBanner({ level, title, cause, action, children }: { level: StatusLevel; title: string; cause?: string; action?: { label: string; href?: string; onClick?: () => void }; children?: ReactNode }) {
  const Icon = ICON[level];
  return <div className={`status-banner status-${level}`} role={level === 'error' ? 'alert' : 'status'} data-level={level}>
    <Icon size={18} aria-hidden="true"/>
    <div className="status-body"><strong><span className="status-name">{STATUS_LEVEL[level].name}</span>{title}</strong>{cause && <p>{cause}</p>}{children}</div>
    {action && (action.href ? <a className="status-action" href={action.href} onClick={action.onClick}>{action.label}</a> : <button className="status-action" type="button" onClick={action.onClick}>{action.label}</button>)}
  </div>;
}
