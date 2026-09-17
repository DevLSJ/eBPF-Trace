export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type ConnectionState = 'connected' | 'reconnecting' | 'disconnected';
export interface FlowInfo { src_ip: string; dst_ip: string; src_port: number; dst_port: number; protocol: 6 | 17 }
export interface Features {
  pkt_rate: number; byte_rate: number; syn_ratio: number; port_entropy: number; flow_duration: number; avg_pkt_size: number; port_cnt: number;
  source_pkt_rate?: number; source_syn_rate?: number; feature_schema_version?: 1 | 2;
  destination_pkt_rate?: number | null; destination_byte_rate?: number | null; destination_syn_rate?: number | null;
  destination_source_count?: number | null; service_pkt_rate?: number | null; service_byte_rate?: number | null;
  service_syn_rate?: number | null; service_source_count?: number | null; reverse_pkt_rate?: number | null;
  reverse_byte_rate?: number | null; bidirectional_pkt_rate?: number | null; bidirectional_byte_rate?: number | null;
  reverse_packet_fraction?: number | null; bidirectional_syn_ratio?: number | null;
  source_pkt_rate_10s?: number | null; destination_pkt_rate_10s?: number | null;
}
export interface DetectionEvent { source?: 'live' | 'simulation'; scenario_run_id?: string | null; expected_label?: string | null; is_confirmed?: boolean | null; note?: string | null; reviewed_at?: string | null; type: 'detection_event'; event_id: number; detected_at: string; attack_type: string; severity: Severity; anomaly_score: number | null; flow: FlowInfo; features: Features }
export interface SystemMetric { collected_at: string; cpu_percent: number; memory_percent: number; event_total: number }
export interface TrafficPoint { timestamp: number; pkt_rate: number; byte_rate: number; anomaly_score: number | null }
export interface TrafficMessage { source?: 'live' | 'simulation'; scenario_run_id?: string | null; type: 'traffic'; timestamp: number; flow: FlowInfo; features: Features; anomaly_score: number | null }
export type StreamMessage = DetectionEvent | TrafficMessage | { type: 'system_metrics'; metric: SystemMetric };
export interface EventPage { items: DetectionEvent[]; total: number; page: number; page_size: number }
export interface Health { status: string; detection_mode: string; collector_connected: boolean; redis: string; database: string; model_status?: string; model_validation_threshold?: number | null }
export interface Thresholds {
  syn_ratio_threshold: number; syn_pps_threshold: number; port_entropy_threshold: number;
  port_cnt_threshold: number; spike_threshold_multiplier: number; baseline_pps: number;
  large_flow_threshold: number; anomaly_threshold: number;
}
export interface CaptureReport {
  labels: LabelReport | null;
  source: string; source_bytes: number; sha256: string | null; complete: boolean;
  started_at: number; ended_at: number; counts: Record<string, number>;
  protocols: Record<string, number>; rule_detections: Record<string, number>;
  label_status: string; model_validated: boolean;
  traffic_minutes: { timestamp: number; packets: number; bytes: number }[];
}

export interface LabelReport {
  alignment?: { policy: string; duration_tolerance_us: number };
  counts: Record<string, number>; sources: string[]; coverage: number;
  distribution: Record<string, number>; source_distribution: Record<string, number>;
  timezone: string; timestamp_uncertainty_seconds: number; generated_at: string;
}
export interface ModelAnalysis {
  runtime: { mode: string; status: string; feature_count?: number; collector_feature_schema_version?: number | null };
  context_evaluation?: ContextBenchmark | null;
  preparation?: DatasetPreparation | null;
  evaluation: null | {
    dataset: string; status: string; deployment_approved: boolean; generated_at: string;
    model: string; threshold: number; features: string[];
    performance: { precision: number; recall: number; f1: number; fpr: number; tn: number; fp: number; fn: number; tp: number; passed: boolean; per_label?: Record<string, { rows: number; detected: number; detection_rate: number }> };
    split: { rows: number; benign: number; attacks: number; training_rows: number; held_out_rows: number; purged_rows: number; cut_timestamp: number; split_policy: string };
    six_feature_comparison?: { performance: { f1: number; precision: number; recall: number; fpr: number } } | null;
    targets: { f1_min: number; fpr_max: number }; limitations: string[];
  };
}

export interface BenchmarkMetrics {
  precision: number; recall: number; f1: number; fpr: number | null;
  tn: number; fp: number; fn: number; tp: number; passed: boolean;
  per_label?: Record<string, { rows: number; detected: number; detection_rate: number }>;
  per_day?: Record<string, BenchmarkMetrics>;
}
export interface BenchmarkCandidate {
  id: string; model: string; features: string[]; threshold: number;
  calibration: BenchmarkMetrics; performance: BenchmarkMetrics;
  calibration_curve: { threshold: number; precision: number; recall: number; f1: number; fpr: number }[];
}
export interface ContextBenchmark {
  dataset: string; generated_at: string; preferred_id: string; deployment_approved: boolean;
  selection_partition: string; features: string[]; candidates: BenchmarkCandidate[];
  protocol: { block_seconds: number; purge_seconds: number; split_policy: string };
  attack_coverage?: { matched_attack_types: string[]; tested_attack_types: string[]; missing_test_attack_types: string[] };
  split: {
    counts: Record<string, number>; distribution: Record<string, Record<string, number>>;
    sampled_training: Record<string, number>; sources: { file: string; day_index: number; sha256: string }[];
  };
  targets: { f1_min: number; fpr_max: number }; limitations: string[];
}
export interface DatasetPreparation {
  status: 'running' | 'complete' | 'failed'; features: string[]; days: string[];
  completed: { day: string; source: string; source_bytes: number; feature_rows: number; matched_rows: number; replay_seconds: number; sha256: string }[];
  failures: { day: string; error: string }[];
}
export interface EventSummary { total: number; severity: Record<string, number>; attack_type: Record<string, number>; source: Record<string, number>; is_confirmed: Record<string, number>; timeline: { timestamp: string; count: number }[]; timeline_start: string; timeline_end: string }
export interface Scenario { id: string; name: string; description: string; stages: string[]; duration_seconds: number }
export interface ScenarioSample { step: number; timestamp: string; stage: string; expected_label: string; detected_label: string; features: Features; anomaly_score: number | null; event_id: number | null }
export interface ScenarioRun { id: string; scenario_id: string; status: string; started_at: string; finished_at: string | null; thresholds: Thresholds; detection_mode: string; samples?: ScenarioSample[]; event_count?: number; matched_steps?: number; sample_count?: number }
