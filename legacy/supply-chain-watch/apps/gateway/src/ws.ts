import type { Server } from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import type { WsEnvelope, WsEventType } from '@scw/shared-types';
import { logger } from './logger.js';

let wss: WebSocketServer | null = null;

export function attachWs(server: Server): void {
  wss = new WebSocketServer({ server, path: '/ws' });
  wss.on('connection', (ws: WebSocket) => {
    logger.debug('ws client connected');
    ws.send(JSON.stringify(envelope('stats.tick', { connected: true })));
    ws.on('close', () => logger.debug('ws client disconnected'));
    ws.on('error', (e) => logger.warn({ err: e.message }, 'ws error'));
  });
}

function envelope<T>(type: WsEventType, payload: T): WsEnvelope<T> {
  return { type, ts: new Date().toISOString(), payload };
}

export function broadcast<T>(type: WsEventType, payload: T): void {
  if (!wss) return;
  const msg = JSON.stringify(envelope(type, payload));
  for (const client of wss.clients) {
    if (client.readyState === client.OPEN) client.send(msg);
  }
}
