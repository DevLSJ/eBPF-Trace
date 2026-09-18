import { api } from './client';
import axios from 'axios';

let csrf = '';
api.interceptors.response.use(response => response, error => {
  if (axios.isAxiosError(error) && error.response?.status === 401 &&
      error.config?.url?.startsWith('/api/ops') && !error.config.url.endsWith('/login')) {
    csrf = '';
    window.dispatchEvent(new Event('ops-session-expired'));
  }
  return Promise.reject(error);
});
export interface Operator { id: string; username: string; name: string; role: string; active: boolean }
export interface Incident {
  id: string; title: string; attack_type: string; priority: string; status: string; source: string;
  asset_id: string | null; asset_name: string; dst_ip: string; dst_port: number; protocol: number;
  owner_id: string | null; owner_name: string | null; version: number; event_count: number;
  created_at: string; last_seen_at: string; ack_due_at: string; acknowledged_at: string | null;
  contained_at: string | null; recovering_at: string | null; resolved_at: string | null;
  summary: { sources: string[]; schema_version: number; peak_pps: number; latest_pps: number; asset_registered: boolean; evidence: string };
}
export interface Audit { id: string; actor_name: string; kind: string; created_at: string; detail: Record<string, unknown> }
export interface Delivery { id: string; incident_id: string; kind: string; channel: string; status: string; destination: string; attempts: number; created_at: string; next_attempt_at: string; last_error: string | null; provider_id: string | null; acknowledged_at: string | null; payload: { title: string } }
export interface Policy { action: string; source_ip: string; destination_ip: string; destination_port: number; protocol: number; ttl_seconds: number; rate_pps: number; source: string; point_id: string }
export interface ActionRun { id: string; incident_id: string; point_id: string; request_id: string; status: string; policy: Policy; policy_hash: string; created_at: string; applied_at: string | null; expires_at: string | null; released_at: string | null; last_error: string | null; agent_result: { mode?: string; detail?: string } }
export interface ActionPreview { id: string; incident_id: string; requester_id: string; status: string; policy: Policy; policy_hash: string; expires_at: string; reason: string; preview: { mode: string; asset: string; point: string; impact: string; protected_cidrs: string[]; affected_sessions: number | null } }
export interface IncidentDetail extends Incident { events: import('../types').DetectionEvent[]; events_truncated: boolean; timeline: Audit[]; notifications: Delivery[]; actions: ActionRun[] }
export interface Asset { id: string; name: string; address: string; service_port: number; protocol: number; environment: string; criticality: string; protected_cidrs: string[] }
export interface Point { id: string; asset_id: string; name: string; mode: string; enabled: boolean; last_seen_at: string | null; capabilities: string[]; health: { healthy?: boolean; success_rate?: number; latency_ms?: number; normal_sessions?: number } }
export interface Observation { id: string; point_id: string; healthy: boolean; observed_at: string; success_rate: number; ingress_pps: number; policy_hits: number; latency_ms: number; source: string }
export interface ResponseContext { points: Point[]; previews: ActionPreview[]; observations: Observation[]; max_ttl_seconds: number; recovery_observation_seconds: number }
export interface Timing { mean_seconds: number | null; p95_seconds?: number | null; samples: number }
export interface Outcomes { source: string; window_days: number; incidents: number; open: number; unacknowledged_urgent: number; overdue: number; false_positive_incidents: number; mtta: Timing; mttc: Timing; mttr: Timing; mttd: Timing; notification_failures: number; notifications_not_configured: number; external_notification_attempts: number; notification_failure_rate: number | null; active_actions: number; recovery_failures: number }
export interface Model { id: string; stage: string; enabled: boolean; artifact_hash: string; promotion_ready: boolean; manifest: { threshold: number; limitations?: string[] }; gates: { id: string; label: string; passed: boolean }[]; statistics: { samples: number; successful: number; observed_days: number; failure_rate: number | null; disagreement_rate: number | null; p95_latency_ms: number | null; score_mean_shift: number | null; drift_status: string } }
export interface ModelOverview { runtime: string; shadow_status: string; sample_modulus: number; collector_schema: number | null; items: Model[] }

export const opsGet = <T>(path: string, params?: Record<string, unknown>, signal?: AbortSignal) => api.get<T>(`/api/ops${path}`, { params, signal, withCredentials: true }).then(r => r.data);
export const opsPost = <T>(path: string, data: unknown = {}) => api.post<T>(`/api/ops${path}`, data, { withCredentials: true, headers: { 'X-CSRF-Token': csrf } }).then(r => r.data);
export async function operatorSession() { const r = await opsGet<{ operator: Operator; csrf_token: string }>('/me'); csrf = r.csrf_token; return r.operator; }
export async function operatorLogin(username: string, password: string) { const r = await opsPost<{ operator: Operator; csrf_token: string }>('/login', { username, password }); csrf = r.csrf_token; return r.operator; }
export async function operatorLogout() { await opsPost('/logout'); csrf = ''; }
