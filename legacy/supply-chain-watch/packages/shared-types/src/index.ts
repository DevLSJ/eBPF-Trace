// Supply Chain Watch — gateway ↔ web 공용 타입.
// 설계 근거: docs/05-api-spec.md §4. engine(Pydantic)은 camelCase alias로 맞춘다.

export type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW';

export type Tag =
  | 'C2_CONNECTION'
  | 'ENV_EXFILTRATION'
  | 'CREDENTIAL_ACCESS'
  | 'OBFUSCATION'
  | 'INSTALL_HOOK'
  | 'DOWNLOAD_EXECUTE'
  | 'PERSISTENCE'
  | 'BACKDOOR'
  | 'SUPPLY_CHAIN'
  | 'EVASION'
  | 'CI_SECRET_LEAK'
  | 'CI_PRIVILEGE_ESCALATION'
  | 'CI_UNTRUSTED_ACTION'
  | 'NONE';

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type LlmStatus =
  | 'OK'
  | 'SKIPPED_GATE'
  | 'SKIPPED_BUDGET'
  | 'REFUSED'
  | 'ERROR'
  | 'CACHED';

export type RepoMode = 'polling' | 'webhook';

export type RepoStatus =
  | 'REGISTERED'
  | 'ACTIVE'
  | 'RATE_LIMITED'
  | 'NOT_FOUND'
  | 'PAUSED'
  | 'ERROR';

export type CommitStatus =
  | 'QUEUED'
  | 'ANALYZING'
  | 'DONE'
  | 'FAILED'
  | 'MISSING'
  | 'SKIPPED';

export interface MatchedRule {
  ruleId: string;
  category: Tag;
  severity: Severity;
  file: string;
  snippet: string;
  lineHint: string;
  /** 같은 파일에서 이 룰이 맞은 줄 수 */
  count?: number;
  /** 룰의 쉬운 설명 (engine rules/*.yaml description_ko) */
  descriptionKo?: string;
}

export interface Evidence {
  file: string;
  lineHint: string;
  reasonKo: string;
}

export interface LlmAnalysis {
  riskScore: number;
  riskLevel: RiskLevel;
  detectedTags: Tag[];
  attackNarrativeKo: string;
  evidence: Evidence[];
  benignExplanationKo: string | null;
  confidence: number;
  recommendedActionKo: string;
}

export interface LlmUsage {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
}

export interface AnalysisResult {
  riskScore: number;
  riskLevel: RiskLevel;
  tags: Tag[];
  static: {
    score: number;
    level: RiskLevel;
    matchedRules: MatchedRule[];
    sensitiveFiles: string[];
    latencyMs: number;
  };
  llm: {
    status: LlmStatus;
    model?: string;
    promptVersion?: number;
    result?: LlmAnalysis;
    usage?: LlmUsage;
    latencyMs?: number;
    error?: string;
    /** 게이트 판단 (docs/03 §4): LLM 2차 분석으로 넘길지, 그 이유, 사용할 프롬프트 */
    gatePassed?: boolean;
    gateReasons?: string[];
    promptName?: string | null;
    /** 2단계 분석 기록 (1단계 저렴한 모델 → 2단계 정밀 모델) */
    stages?: { model: string; status: string; riskScore?: number | null; latencyMs?: number; error?: string | null }[];
  };
  preprocess: {
    truncated: boolean;
    excludedFiles: string[];
    analyzedBytes: number;
  };
}

export interface CommitSummary {
  id: number;
  repoId: number;
  repoFullName: string;
  sha: string;
  shortSha: string;
  authorLogin: string | null;
  authorName: string | null;
  message: string;
  committedAt: string;
  receivedAt: string;
  status: CommitStatus;
  source: string;
  htmlUrl: string;
  filesChanged: number;
  additions: number;
  deletions: number;
}

export interface AnalysisSummary {
  analysisId: number;
  riskScore: number;
  riskLevel: RiskLevel;
  tags: Tag[];
  llmStatus: LlmStatus;
  summaryKo: string | null;
}

// WebSocket 서버 → 클라이언트 이벤트 (docs/05 §3)
export type WsEventType =
  | 'commit.received'
  | 'analysis.started'
  | 'analysis.completed'
  | 'analysis.failed'
  | 'repo.status'
  | 'stats.tick'
  | 'alert.sent'
  | 'agent.tick'
  | 'fix.completed'
  | 'runtime.incident'
  | 'runtime.topology'
  | 'runtime.action';

export interface WsEnvelope<T = unknown> {
  type: WsEventType;
  ts: string;
  payload: T;
}

export interface ApiResponse<T> {
  ok: boolean;
  data?: T;
  error?: { code: string; message: string };
}

export interface HealthReport {
  ok: boolean;
  service: string;
  checks: Record<string, { ok: boolean; detail?: string; latencyMs?: number }>;
  ts: string;
}

// ===== 런타임 축 (eBPF, docs/13) =====
export type RuntimeRuleId =
  | 'PROC_CHAIN_SUSPECT'
  | 'NET_UNALLOWED_CONNECT'
  | 'TOOL_EXEC_IN_CONTAINER'
  | 'TMP_EXEC';

export interface SbomComponent {
  purl: string;
  name?: string;
  version?: string;
  ecosystem?: string;
}

export interface RuntimeEvent {
  id: number;
  incidentKey: string;
  container: string;
  image?: string;
  kind: 'EXECVE' | 'CONNECT';
  pid?: number;
  ppid?: number;
  comm?: string;
  filename?: string;
  destIp?: string;
  destPort?: number;
  ruleId: RuntimeRuleId;
  riskLevel: RiskLevel;
  purl?: string;
  commitSha?: string;
  createdAt: string;
}

export interface RuntimeIncident {
  incidentKey: string;
  container: string;
  image?: string;
  riskLevel: RiskLevel;
  score: number;
  rules: RuntimeRuleId[];
  purl?: string;
  commitSha?: string;
  blocked: boolean;
  firstAt: string;
  lastAt: string;
  eventCount: number;
}

export interface RuntimeAction {
  id: number;
  incidentKey: string;
  container: string;
  action: 'KILL_PROCESS' | 'BLOCK_DEST';
  target?: string;
  status: 'REQUESTED' | 'DONE' | 'FAILED';
  result?: string;
  createdAt: string;
}

// ---- 서비스 간 Redis 계약 (ADR-020 U5) ----
// gateway가 큐에 넣고(LPUSH) analyzer가 꺼낸다(BRPOP). analyzer의 화면 이벤트는
// EVENTS_CHANNEL로 발행(PUBLISH)하고 gateway가 구독해 /ws로 중계한다.
export const ANALYSIS_QUEUE_KEY = 'analysis:queue';
export const ANALYSIS_INFLIGHT_KEY = 'analysis:inflight';
export const EVENTS_CHANNEL = 'scw:events';

export interface AnalysisJob {
  commitId: number;
  repoFullName: string;
  sha: string;
  attempt: number;
}
