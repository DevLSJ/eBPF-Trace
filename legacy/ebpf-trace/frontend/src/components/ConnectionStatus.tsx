import { RefreshCw, Wifi, WifiOff } from 'lucide-react';
import { useEventStore } from '../store/eventStore';

const VIEW = {
  connected: { text: '실시간 연결됨', icon: Wifi, title: '대시보드가 서버와 실시간으로 연결되어 있습니다' },
  reconnecting: { text: '다시 연결 중', icon: RefreshCw, title: '실시간 연결이 끊겨 자동으로 다시 연결하고 있습니다' },
  disconnected: { text: '연결 끊김', icon: WifiOff, title: '실시간 연결이 끊겼습니다. 네트워크를 확인하거나 새로고침하세요' },
};
export function ConnectionStatus() {
  const status = useEventStore(s => s.status);
  const { text, icon: Icon, title } = VIEW[status];
  return <span className={`connection ${status}`} role="status" title={title}><Icon size={12} aria-hidden="true"/>{text}</span>;
}
