import { useEffect } from 'react';
import { useEventStore } from '../store/eventStore';

export function useWebSocket() {
  useEffect(() => {
    let disposed = false, attempts = 0, timer: ReturnType<typeof setTimeout>;
    let socket: WebSocket | undefined;
    const connect = () => {
      if (disposed) return;
      if (!navigator.onLine) { useEventStore.getState().setStatus('disconnected'); return; }
      if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) return;
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const current = new WebSocket(import.meta.env.VITE_WS_URL || `${protocol}//${location.host}/ws/dashboard`);
      socket = current;
      current.onopen = () => { if (!disposed) { attempts = 0; useEventStore.getState().setStatus('connected'); } };
      current.onmessage = event => { if (!disposed) { try { useEventStore.getState().receive(JSON.parse(event.data)); } catch { /* Invalid frame: retain previous data. */ } } };
      current.onerror = () => current.close();
      current.onclose = () => {
        if (disposed || socket !== current) return;
        if (!navigator.onLine) { useEventStore.getState().setStatus('disconnected'); return; }
        useEventStore.getState().setStatus(attempts < 5 ? 'reconnecting' : 'disconnected');
        if (attempts < 5) timer = setTimeout(connect, 1000 * 2 ** attempts++);
      };
    };
    const offline = () => { clearTimeout(timer); socket?.close(); socket = undefined; useEventStore.getState().setStatus('disconnected'); };
    const online = () => { clearTimeout(timer); attempts = 0; connect(); };
    window.addEventListener('offline', offline);
    window.addEventListener('online', online);
    connect();
    return () => { disposed = true; clearTimeout(timer); socket?.close(); window.removeEventListener('offline', offline); window.removeEventListener('online', online); };
  }, []);
}
