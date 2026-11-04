import { useStream } from '../hooks/stream-context';
import { fmtNum } from '../lib/format';

export function WsStatus() {
  const { connected, stats } = useStream();
  return (
    <div className="hidden items-center gap-4 text-sm md:flex" role="status">
      <span className="flex items-center gap-1.5">
        <span className={`size-2 rounded-full ${connected ? 'bg-emerald-500' : 'sg-blink bg-slate-400'}`} />
        <span className={connected ? 'text-slate-700' : 'text-slate-500'}>{connected ? '실시간 연결됨' : '재연결 중…'}</span>
      </span>
      <span className="text-slate-500">
        초당 <b className="num font-semibold text-slate-900">{fmtNum(stats?.eventsPerSec ?? 0)}</b> evt
      </span>
    </div>
  );
}
