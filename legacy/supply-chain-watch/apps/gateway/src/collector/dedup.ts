// 중복 검사 (docs/02 §5). Redis SET NX 7d — 빠른 1차. DB UNIQUE가 최종 방어선.
import { redis } from '../db/redis.js';

export async function seenBefore(repoId: number, sha: string): Promise<boolean> {
  try {
    if (redis.status === 'wait' || redis.status === 'end') await redis.connect();
    const ok = await redis.set(`seen:${repoId}:${sha}`, '1', 'EX', 604800, 'NX');
    return ok === null; // null = 이미 존재
  } catch {
    return false; // Redis 장애 시 DB UNIQUE에 위임
  }
}

export async function seenDelivery(deliveryId: string): Promise<boolean> {
  try {
    if (redis.status === 'wait' || redis.status === 'end') await redis.connect();
    const ok = await redis.set(`delivery:${deliveryId}`, '1', 'EX', 86400, 'NX');
    return ok === null;
  } catch {
    return false;
  }
}
