// 단일 관리자 세션 (docs/09 ADR-010, docs/05 §1.5). 비밀번호 1개 + 서명 쿠키.
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { env } from './env.js';

const COOKIE = 'scw_session';
const SUBJECT = 'admin';

function sign(subject: string): string {
  const mac = createHmac('sha256', env.SESSION_SECRET).update(subject).digest('hex');
  return `${subject}.${mac}`;
}

function verify(token: string | undefined): boolean {
  if (!token) return false;
  const dot = token.lastIndexOf('.');
  if (dot < 0) return false;
  const subject = token.slice(0, dot);
  const expected = sign(subject);
  const a = Buffer.from(token);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function readCookie(req: Request, name: string): string | undefined {
  const raw = req.headers.cookie;
  if (!raw) return undefined;
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return undefined;
}

export function login(req: Request, res: Response): void {
  const password = (req.body?.password ?? '') as string;
  if (!env.ADMIN_PASSWORD) {
    res.status(500).json({ ok: false, error: { code: 'NO_ADMIN_PASSWORD', message: 'ADMIN_PASSWORD 미설정' } });
    return;
  }
  const a = Buffer.from(password);
  const b = Buffer.from(env.ADMIN_PASSWORD);
  const ok = a.length === b.length && timingSafeEqual(a, b);
  if (!ok) {
    res.status(401).json({ ok: false, error: { code: 'BAD_PASSWORD', message: '비밀번호가 올바르지 않습니다' } });
    return;
  }
  const secure = env.NODE_ENV === 'production';
  res.setHeader(
    'Set-Cookie',
    `${COOKIE}=${encodeURIComponent(sign(SUBJECT))}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 7}${secure ? '; Secure' : ''}`,
  );
  res.json({ ok: true, data: { authenticated: true } });
}

export function logout(_req: Request, res: Response): void {
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; Max-Age=0`);
  res.json({ ok: true, data: { authenticated: false } });
}

export function me(req: Request, res: Response): void {
  res.json({ ok: true, data: { authenticated: verify(readCookie(req, COOKIE)) } });
}

// 보호 라우트용 미들웨어 (webhook·gate·health·auth 제외하고 적용 예정)
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (verify(readCookie(req, COOKIE))) {
    next();
    return;
  }
  res.status(401).json({ ok: false, error: { code: 'UNAUTHENTICATED', message: '로그인이 필요합니다' } });
}
