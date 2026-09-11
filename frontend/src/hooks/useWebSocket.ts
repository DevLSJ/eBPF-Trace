import { useEffect } from 'react';
import { useEventStore } from '../store/eventStore';

export function useWebSocket() {
  useEffect(() => {
    let disposed = false, attempts = 0, timer: ReturnType<typeof setTimeout>;
    let socket: WebSocket;
    const connect = () => {
      if (disposed) return;
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      socket = new WebSocket(import.meta.env.VITE_WS_URL || `${protocol}//${location.host}/ws/dashboard`);
      socket.onopen = () => { if (!disposed) { attempts = 0; useEventStore.getState().setStatus('connected'); } };
      socket.onmessage = event => { if (!disposed) { try { useEventStore.getState().receive(JSON.parse(event.data)); } catch { /* Invalid frame: retain previous data. */ } } };
      socket.onerror = () => socket.close();
      socket.onclose = () => {
        if (disposed) return;
        useEventStore.getState().setStatus(attempts < 5 ? 'reconnecting' : 'disconnected');
        if (attempts < 5) timer = setTimeout(connect, 1000 * 2 ** attempts++);
      };
    };
    connect();
    return () => { disposed = true; clearTimeout(timer); socket?.close(); };
  }, []);
}
