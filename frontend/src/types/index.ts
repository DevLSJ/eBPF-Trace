export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type ConnectionState = 'connected' | 'reconnecting' | 'disconnected';
export interface FlowInfo { src_ip: string; dst_ip: string; src_port: number; dst_port: number; protocol: 6 | 17 }
export interface Features { pkt_rate: number; byte_rate: number; syn_ratio: number; port_entropy: number; flow_duration: number; avg_pkt_size: number; port_cnt: number }
export interface DetectionEvent { type: 'detection_event'; event_id: number; detected_at: string; attack_type: string; severity: Severity; anomaly_score: number | null; flow: FlowInfo; features: Features }
export interface SystemMetric { collected_at: string; cpu_percent: number; memory_percent: number; event_total: number }
export interface TrafficPoint { timestamp: number; pkt_rate: number; byte_rate: number; anomaly_score: number | null }
export interface TrafficMessage { type: 'traffic'; timestamp: number; flow: FlowInfo; features: Features; anomaly_score: number | null }
export type StreamMessage = DetectionEvent | TrafficMessage | { type: 'system_metrics'; metric: SystemMetric };
export interface EventPage { items: DetectionEvent[]; total: number; page: number; page_size: number }
export interface Health { status: string; detection_mode: string; collector_connected: boolean; redis: string; database: string; model_status?: string; model_validation_threshold?: number | null }
export interface Thresholds {
  syn_ratio_threshold: number; syn_pps_threshold: number; port_entropy_threshold: number;
  port_cnt_threshold: number; spike_threshold_multiplier: number; baseline_pps: number;
  large_flow_threshold: number; anomaly_threshold: number;
}
export interface CaptureReport {
  source: string; source_bytes: number; sha256: string | null; complete: boolean;
  started_at: number; ended_at: number; counts: Record<string, number>;
  protocols: Record<string, number>; rule_detections: Record<string, number>;
  label_status: string; model_validated: boolean;
  traffic_minutes: { timestamp: number; packets: number; bytes: number }[];
}
