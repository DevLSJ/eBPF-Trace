// GitHub Webhook 수신 (docs/02 §4, skill). raw body HMAC 검증, delivery dedup, push 처리.
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import { env } from '../env.js';
import { logger } from '../logger.js';
import { getRepoByFullName } from '../repo/repos.js';
import { handleNewCommit } from './handle.js';
import { seenDelivery } from './dedup.js';

interface PushPayload {
  ref?: string;
  deleted?: boolean;
  commits?: Array<{ id: string; distinct: boolean; message: string }>;
  repository?: { full_name: string; owner: { name?: string; login?: string }; name: string };
}

function validSignature(raw: Buffer, signature: string | undefined): boolean {
  if (!env.GITHUB_WEBHOOK_SECRET || !signature) return false;
  const expected = 'sha256=' + createHmac('sha256', env.GITHUB_WEBHOOK_SECRET).update(raw).digest('hex');
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function githubWebhook(req: Request, res: Response): Promise<void> {
  const event = req.header('x-github-event');
  const delivery = req.header('x-github-delivery') ?? '';
  const raw: Buffer = (req as Request & { rawBody?: Buffer }).rawBody ?? Buffer.from('');

  if (!validSignature(raw, req.header('x-hub-signature-256'))) {
    logger.warn({ delivery }, 'webhook signature invalid');
    res.status(401).json({ ok: false, error: { code: 'BAD_SIGNATURE', message: 'signature mismatch' } });
    return;
  }
  if (event === 'ping') {
    res.json({ ok: true, data: { pong: true } });
    return;
  }
  if (event !== 'push') {
    res.json({ ok: true, data: { ignored: event } });
    return;
  }
  // 재전송 중복 차단
  if (delivery && (await seenDelivery(delivery))) {
    res.json({ ok: true, data: { duplicate: true } });
    return;
  }

  const payload = req.body as PushPayload;
  res.json({ ok: true, data: { accepted: true } }); // 즉시 200, 처리는 비동기

  if (payload.deleted) return;
  const full = payload.repository?.full_name;
  if (!full) return;
  const [owner, name] = full.split('/');
  if (!owner || !name) return;

  const repo = await getRepoByFullName(owner, name);
  if (!repo) {
    logger.warn({ full }, 'webhook for unregistered repo');
    return;
  }
  const branch = (payload.ref ?? '').replace(/^refs\/heads\//, '');
  for (const c of payload.commits ?? []) {
    if (!c.distinct) continue;
    await handleNewCommit(repo, c.id, branch, 'webhook');
  }
}
