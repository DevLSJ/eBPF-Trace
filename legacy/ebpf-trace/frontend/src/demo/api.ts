import { api } from '../api/client';

export interface Component { id: string; name: string; version: string; purpose: string; license: string; depends_on: string[]; example: boolean }
export interface Version { id: string; number: number; artifact: { version: string; builder: string; source_revision: string; components: Component[] }; digest: string; signature: string | null; created_at: string }
export interface Check { id: string; title: string; passed: boolean; source: string; evidence: string }
export interface Finding { id: string; title: string; component: string; impact: string; evidence: string; why: string; fix: string; check_id: string; source: string }
export interface Scan { id: string; version_id: string; status: 'queued' | 'running' | 'completed' | 'failed'; stage: string; checks: Check[]; findings: Finding[]; artifact_digest: string; policy_revision: string; error: string | null; created_at: string; finished_at: string | null }
export interface Activity { id: string; kind: string; title: string; detail: Record<string, unknown>; created_at: string }
export interface Deployment { id: string; version_id: string; scan_id: string; digest: string; asset: string; created_at: string }
export interface DemoSession { id: string; created_at: string; completed_at: string | null; expires_at: string; stage: number; revision: number; active_version: number; versions: Version[]; scans: Scan[]; activities: Activity[]; deployment: Deployment | null; duration_seconds: number | null; help_count: number; policy_revision: string }
export interface Envelope { session: DemoSession | null; csrf_token?: string; expired?: boolean; result?: { allowed?: boolean; reasons?: string[]; scan_id?: string } }
export interface Catalog { project: { name: string; description: string; environment: string }; components: Component[]; scope: string }
export type CommandKind = 'scan' | 'fix' | 'deploy' | 'replay' | 'finish' | 'help' | 'feedback';
let csrf = '';
function accept(value: Envelope) { if (value.csrf_token) csrf = value.csrf_token; return value; }
export const loadSession = (signal?: AbortSignal) => api.get<Envelope>('/api/demo/session', { signal, withCredentials: true }).then(r => accept(r.data));
export const loadCatalog = (signal?: AbortSignal) => api.get<Catalog>('/api/demo/catalog', { signal }).then(r => r.data);
export const startDemo = (requestId: string) => api.post<Envelope>('/api/demo/session', { request_id: requestId }, { withCredentials: true }).then(r => accept(r.data));
export const demoCommand = (kind: CommandKind, requestId: string, args: Record<string, unknown> = {}) => api.post<Envelope>(`/api/demo/commands/${kind}`, { ...args, request_id: requestId }, { withCredentials: true, headers: { 'X-Demo-CSRF': csrf } }).then(r => accept(r.data));
export const resetDemo = () => api.post<Envelope>('/api/demo/reset', {}, { withCredentials: true, headers: { 'X-Demo-CSRF': csrf } }).then(r => { csrf = ''; return r.data; });
export async function downloadReport() {
  const response = await api.get('/api/demo/report', { withCredentials: true, responseType: 'blob' });
  const url = URL.createObjectURL(response.data); const link = document.createElement('a');
  link.href = url; link.download = 'supply-chain-demo-result.json'; document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export const latestScan = (session: DemoSession | null, version?: Version) => [...(session?.scans || [])].reverse().find(s => s.version_id === version?.id);
