import type { IncomingMessage } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocketServer, type WebSocket } from 'ws';
import type { WsEnvelope, WsEventType } from '@scw/shared-types';
import { logger } from './logger.js';

// web 대시보드용 WS. noServer 모드 — 업그레이드 라우팅은 index.ts가 경로별로 한다
// (한 HTTP 서버에 /ws·/agent-ws 두 WSS를 붙일 때 생기는 400 충돌 회피).
const wss = new WebSocketServer({ noServer: true });

wss.on('connection', (ws: WebSocket) => {
  logger.debug('ws client connected');
  ws.send(JSON.stringify(envelope('stats.tick', { connected: true })));
  ws.on('close', () => logger.debug('ws client disconnected'));
  ws.on('error', (e) => logger.warn({ err: e.message }, 'ws error'));
});

export function handleWebUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
}

function envelope<T>(type: WsEventType, payload: T): WsEnvelope<T> {
  return { type, ts: new Date().toISOString(), payload };
}

export function broadcast<T>(type: WsEventType, payload: T): void {
  const msg = JSON.stringify(envelope(type, payload));
  for (const client of wss.clients) {
    if (client.readyState === client.OPEN) client.send(msg);
  }
}
