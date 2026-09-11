import { create } from 'zustand';
import type { ConnectionState, DetectionEvent, StreamMessage, SystemMetric, TrafficPoint } from '../types';

interface Store {
  events: DetectionEvent[]; metric: SystemMetric | null; status: ConnectionState;
  traffic: TrafficPoint[]; flows: Map<string, TrafficPoint>;
  setStatus: (status: ConnectionState) => void;
  setMetric: (metric: SystemMetric | null) => void;
  receive: (message: StreamMessage) => void;
}
export const useEventStore = create<Store>((set) => ({
  events: [], metric: null, status: 'disconnected', traffic: [], flows: new Map(),
  setStatus: status => set({ status }), setMetric: metric => set({ metric }),
  receive: message => set(state => {
    if (message.type === 'detection_event') return { events: [message, ...state.events.filter(e => e.event_id !== message.event_id)].slice(0, 500) };
    if (message.type === 'system_metrics') return { metric: message.metric };
    if (message.type !== 'traffic') return {};
    const timestamp = Math.floor(message.timestamp / 1000) * 1000;
    // Replayed historical traffic must not replace the latest live bucket.
    if (timestamp < Date.now() - 300000) return {};
    const flows = new Map([...state.flows].filter(([, point]) => point.timestamp >= timestamp - 1000));
    const key = Object.values(message.flow).join(':');
    flows.set(key, { timestamp, ...message.features, anomaly_score: message.anomaly_score });
    let pkt_rate = 0, byte_rate = 0;
    for (const point of flows.values()) { pkt_rate += point.pkt_rate; byte_rate += point.byte_rate; }
    const scores = [...flows.values()].map(p => p.anomaly_score).filter((n): n is number => n !== null);
    const point = { timestamp, pkt_rate, byte_rate, anomaly_score: scores.length ? Math.min(...scores) : null };
    return { flows, traffic: [...state.traffic.filter(p => p.timestamp > Date.now() - 300000 && p.timestamp !== timestamp), point].sort((a,b) => a.timestamp-b.timestamp).slice(-300) };
  }),
}));
