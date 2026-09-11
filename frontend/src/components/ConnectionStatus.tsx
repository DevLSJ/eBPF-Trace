import { useEventStore } from '../store/eventStore';

export function ConnectionStatus() {
  const status = useEventStore(s => s.status);
  return <span className={`connection ${status}`} role="status"><i/>{
    { connected: '실시간 연결됨', reconnecting: '다시 연결 중', disconnected: '연결 끊김' }[status]
  }</span>;
}
