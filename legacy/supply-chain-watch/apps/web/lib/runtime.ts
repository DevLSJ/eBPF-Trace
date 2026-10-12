import { api } from './api';
import type { RuntimeIncident } from '@scw/shared-types';

export interface TopoNode {
  key: string;
  name: string;
  role: string;
  container: string;
  infected: boolean;
}
export interface Topology {
  nodes: TopoNode[];
  edges: [string, string][];
  c2Visible: boolean;
}
export interface RuntimeSummary {
  agentsOnline: number;
  tracked: number;
  openIncidents: number;
  blockedToday: number;
}

export const getSummary = () => api<RuntimeSummary>('/api/runtime/summary');
export const getTopology = () => api<Topology>('/api/runtime/topology');
export const getIncidents = () => api<RuntimeIncident[]>('/api/runtime/incidents');

export interface RuntimeConfig {
  autoBlock: boolean;
  whitelist: unknown;
}
export const getRuntimeConfig = () => api<RuntimeConfig>('/api/runtime/config');
export const setAutoBlock = (autoBlock: boolean) =>
  api<{ autoBlock: boolean }>('/api/runtime/config', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ autoBlock }),
  });
export const pushWhitelist = (whitelist: unknown) =>
  api<{ pushed: number }>('/api/runtime/whitelist', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ whitelist }),
  });

export const DEFAULT_WHITELIST = {
  service_comms: ['node', 'python', 'python3', 'uvicorn'],
  shell_names: ['sh', 'bash', 'dash', 'ash', 'busybox'],
  tool_names: ['curl', 'nc', 'ncat', 'socat'],
  benign_comms: ['node', 'python', 'python3', 'uvicorn', 'nginx', 'postgres', 'redis-server', 'redis-cli', 'pg_isready', 'wget', 'uv', 'npm', 'sh'],
  allowed_dest_cidrs: ['10.77.0.0/28', '127.0.0.0/8'],
  allowed_dest_ports: [53],
};

export const killIncident = (key: string) =>
  api(`/api/runtime/incidents/${encodeURIComponent(key)}/kill`, { method: 'POST' });
export const blockIncident = (key: string) =>
  api(`/api/runtime/incidents/${encodeURIComponent(key)}/block`, { method: 'POST' });

export interface IncidentPreview {
  container: string;
  service: string;
  agentOnline: boolean;
  kill: { loops: { ppid: number; tools: string[]; runs: number }[]; keeps: string };
  block: {
    destIp: string | null; ports: number[]; destLabel: string; internalService: string | null;
    affected: string[]; undo: string;
  };
}
export const getIncidentPreview = (key: string) =>
  api<IncidentPreview>(`/api/runtime/incidents/${encodeURIComponent(key)}/preview`);

export const simulate = (scenario: 'pay' | 'image' | 'normal' | 'reset') =>
  api<{ scenario: string }>('/api/runtime/simulate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scenario }),
  });

// 룰 ID → 쉬운 한글(docs/06 §0.9, 화면 용어 규칙)
export const RULE_LABEL: Record<string, string> = {
  PROC_CHAIN_SUSPECT: '수상한 프로그램 실행',
  TOOL_EXEC_IN_CONTAINER: '외부 도구 실행',
  NET_UNALLOWED_CONNECT: '허용되지 않은 서버 접속',
  TMP_EXEC: '임시 폴더에서 실행',
};

export function purlShort(purl?: string): string {
  if (!purl) return '';
  const m = /^pkg:\w+\/(.+?)@/.exec(purl);
  return m ? m[1] : purl;
}

export type { RuntimeIncident };
