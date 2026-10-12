// 화면 이벤트 발행 (ADR-020 U5). analyzer는 브라우저와 직접 연결하지 않고
// Redis 채널에 올리기만 한다. gateway가 구독해 /ws로 중계한다.
import { Redis } from 'ioredis';
import { EVENTS_CHANNEL, type WsEnvelope, type WsEventType } from '@scw/shared-types';
import { env } from './env.js';
import { logger } from './logger.js';

const pub = new Redis(env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 2 });

export function publish<T>(type: WsEventType, payload: T): void {
  const msg: WsEnvelope<T> = { type, ts: new Date().toISOString(), payload };
  void (async () => {
    if (pub.status === 'wait' || pub.status === 'end') await pub.connect();
    await pub.publish(EVENTS_CHANNEL, JSON.stringify(msg));
  })().catch((err: Error) => logger.warn({ err: err.message, type }, 'event publish failed'));
}

export function closeEvents(): void {
  pub.disconnect();
}
