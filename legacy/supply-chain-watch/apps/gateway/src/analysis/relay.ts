// analyzer → 화면 이벤트 중계 (ADR-020 U5). analyzer가 Redis 채널에 올린 이벤트를 받아 /ws로 그대로 보낸다.
// 구독 전용 연결이 따로 필요하다(구독 중인 Redis 연결은 다른 명령을 못 쓴다).
import { Redis } from 'ioredis';
import { EVENTS_CHANNEL, type WsEnvelope } from '@scw/shared-types';
import { env } from '../env.js';
import { logger } from '../logger.js';
import { broadcast } from '../ws.js';

// analyzer가 보낼 수 있는 이벤트만 통과시킨다
const ALLOWED = new Set(['analysis.started', 'analysis.completed', 'analysis.failed', 'agent.tick']);

let sub: Redis | null = null;

// 채널 메시지 → 화면으로 보낼 이벤트. 형식이 틀리거나 허용되지 않은 종류면 null.
export function parseRelayEvent(raw: string): WsEnvelope | null {
  try {
    const msg = JSON.parse(raw) as Partial<WsEnvelope>;
    if (typeof msg?.type !== 'string' || !ALLOWED.has(msg.type)) return null;
    return msg as WsEnvelope;
  } catch {
    return null;
  }
}

export async function startEventRelay(): Promise<void> {
  sub = new Redis(env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: null });
  sub.on('message', (_channel: string, raw: string) => {
    const msg = parseRelayEvent(raw);
    if (msg) broadcast(msg.type, msg.payload);
    else logger.warn({ raw: raw.slice(0, 80) }, '[relay] dropped event');
  });
  await sub.connect();
  await sub.subscribe(EVENTS_CHANNEL);
  logger.info(`[relay] subscribed ${EVENTS_CHANNEL}`);
}

export function stopEventRelay(): void {
  sub?.disconnect();
  sub = null;
}
