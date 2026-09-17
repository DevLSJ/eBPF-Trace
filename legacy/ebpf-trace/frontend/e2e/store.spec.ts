import { test, expect } from '@playwright/test';
import { useEventStore } from '../src/store/eventStore';

test('traffic buckets expire prior-second flows and ignore out-of-order replay', () => {
  useEventStore.setState({ traffic: [], flows: new Map() });
  const now = Math.floor(Date.now() / 1000) * 1000;
  const base = { type: 'traffic' as const, timestamp: now, anomaly_score: null,
    flow: { src_ip: '192.0.2.1', dst_ip: '192.0.2.2', src_port: 1, dst_port: 80, protocol: 6 as const },
    features: { pkt_rate: 10, byte_rate: 600, syn_ratio: 0, port_entropy: 0, flow_duration: 0, avg_pkt_size: 60, port_cnt: 1 } };
  const receive = useEventStore.getState().receive;
  receive({ ...base, source: 'simulation', features: { ...base.features, pkt_rate: 99999 } });
  expect(useEventStore.getState().traffic).toHaveLength(0);
  receive(base);
  receive({ ...base, timestamp: now + 1000, flow: { ...base.flow, src_port: 2 } });
  expect(useEventStore.getState().traffic.at(-1)?.pkt_rate).toBe(10);
  receive(base);
  expect(useEventStore.getState().traffic.at(-1)?.pkt_rate).toBe(10);
  expect(useEventStore.getState().flows.size).toBe(1);
});
