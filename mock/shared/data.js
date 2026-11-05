/* eBPF Trace 목업 — 시드 고정 더미 데이터 (window.MOCK)
   주소는 모두 문서용 TEST-NET(192.0.2.x · 198.51.100.x · 203.0.113.x)만 쓴다. 실제 고객·운영 데이터 없음. */
(function () {
  const pad = n => String(n).padStart(2, '0');
  const base = new Date('2026-09-23T09:00:00+09:00');
  const at = (minutesAgo, seconds = 0) => new Date(base.getTime() - minutesAgo * 60000 - seconds * 1000);
  const fmt = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const iso = d => d.toISOString();

  const operators = [
    { id: 'op-1', username: 'minseo', name: '김민서', role: 'admin', roleLabel: '관리자' },
    { id: 'op-2', username: 'jihoon', name: '박지훈', role: 'approver', roleLabel: '승인자' },
    { id: 'op-3', username: 'yuna', name: '이유나', role: 'responder', roleLabel: '대응자' },
    { id: 'op-4', username: 'viewer', name: '열람 계정', role: 'viewer', roleLabel: '열람자' },
  ];

  const assets = [
    { id: 'as-1', name: '결제 API', address: '198.51.100.20', service_port: 443, protocol: 6, environment: 'production', criticality: 'critical', protected_cidrs: ['198.51.100.0/28', '203.0.113.5/32'], auto_response: true },
    { id: 'as-2', name: '관리 콘솔', address: '198.51.100.30', service_port: 8443, protocol: 6, environment: 'production', criticality: 'standard', protected_cidrs: ['198.51.100.0/28'], auto_response: false },
    { id: 'as-3', name: '훈련용 결제 API', address: '198.51.100.20', service_port: 443, protocol: 6, environment: 'simulation', criticality: 'critical', protected_cidrs: ['127.0.0.0/8'], auto_response: true },
  ];
  const points = [
    { id: 'pt-1', asset_id: 'as-1', name: 'edge-01 (nftables)', mode: 'nftables', enabled: true, capabilities: ['block_source', 'rate_limit'], last_seen_at: iso(at(0, 4)), health: { healthy: true, success_rate: 0.998, latency_ms: 21.4, normal_sessions: 143, ingress_pps: 412 } },
    { id: 'pt-2', asset_id: 'as-2', name: 'edge-02 (nftables)', mode: 'nftables', enabled: true, capabilities: ['block_source'], last_seen_at: iso(at(0, 9)), health: { healthy: true, success_rate: 1, latency_ms: 18.2, normal_sessions: 12, ingress_pps: 38 } },
    { id: 'pt-3', asset_id: 'as-3', name: '격리 훈련 어댑터', mode: 'lab', enabled: true, capabilities: ['block_source', 'rate_limit'], last_seen_at: iso(at(0, 2)), health: { healthy: true, success_rate: 1, latency_ms: 12, normal_sessions: 8, ingress_pps: 35 } },
  ];

  const gate = (score, level, reasons, hard_stop = null, signals = {}) => ({ version: 1, score, threshold: 0.4, level, route: level === 'low' ? 'automatic' : 'approval', hard_stop, reasons, evaluated_at: iso(at(3)), signals: { normal_fraction: { value: signals.n ?? 0.02, risk: signals.n ?? 0.02, weight: 0.4 }, port_diversity: { value: signals.p ?? 1, risk: signals.pr ?? 0.5, weight: 0.2 }, observation: { value: { count: signals.c ?? 6, span_seconds: signals.s ?? 5 }, risk: signals.or ?? 0.2, weight: 0.2 }, proximity: { value: signals.x ?? 0, risk: signals.x ?? 0, weight: 0.2 } } });
  const GATE_A = gate(0.14, 'low', ['SYN 비율 98% — 완료된 연결이 거의 없어 정상 세션 영향이 낮습니다.', '단일 서비스 집중 유입 — 포트 분포만으로는 출발지 성격을 가리지 못합니다.', '이 출발지를 6회, 5초에 걸쳐 관측했습니다.'], null, { n: 0.02, p: 1, pr: 0.5, c: 6, s: 5, or: 0.2, x: 0 });
  const GATE_B = gate(0.52, 'high', ['관측의 80%가 완료 연결·응답 트래픽입니다 — 정상 사용자가 섞인 출발지(공유 NAT·프록시)일 가능성이 높습니다.', '목적지 포트 48개 — 탐색 지문이 뚜렷해 대상이 특정됩니다.', '이 출발지를 3회, 2초에 걸쳐 관측했습니다.', '중요 자산이며 정상 트래픽이 섞여 있어 사람의 판단이 필요합니다.'], 'critical_asset_mixed_traffic', { n: 0.8, p: 48, pr: 0.1, c: 3, s: 2, or: 0.5, x: 0 });
  const GATE_C = gate(0.31, 'low', ['SYN 비율 100% — 완료된 연결이 거의 없어 정상 세션 영향이 낮습니다.', '목적지 포트 52개 — 탐색 지문이 뚜렷해 대상이 특정됩니다.', '이 출발지를 4회, 3초에 걸쳐 관측했습니다.', '보호 대상 주소와 같은 /16 네트워크의 출발지입니다 — 내부 장비일 수 있습니다.'], null, { n: 0, p: 52, pr: 0.1, c: 4, s: 3, or: 0.5, x: 0.5 });

  const incidents = [
    { id: 'inc-a1b2c3d4', title: 'SYN FLOOD · 결제 API', attack_type: 'SYN_FLOOD', priority: 'P1', status: 'contained', source: 'live', asset_id: 'as-1', asset_name: '결제 API', dst_ip: '198.51.100.20', dst_port: 443, protocol: 6, owner_id: 'op-1', owner_name: '김민서', version: 6, event_count: 41, created_at: iso(at(26)), last_seen_at: iso(at(19)), acknowledged_at: iso(at(23)), contained_at: iso(at(18)), ack_due_at: iso(at(24)),
      summary: { sources: ['203.0.113.77'], schema_version: 2, peak_pps: 4812, latest_pps: 36, asset_registered: true, evidence: 'rules', automatic: { status: 'applied', source_ip: '203.0.113.77', at: iso(at(25, 20)), run_id: 'run-auto-1', gate: GATE_A } } },
    { id: 'inc-e5f6a7b8', title: 'PORT SCAN · 결제 API', attack_type: 'PORT_SCAN', priority: 'P2', status: 'investigating', source: 'live', asset_id: 'as-1', asset_name: '결제 API', dst_ip: '198.51.100.20', dst_port: 443, protocol: 6, owner_id: 'op-3', owner_name: '이유나', version: 3, event_count: 9, created_at: iso(at(12)), last_seen_at: iso(at(10)), acknowledged_at: iso(at(11)), ack_due_at: iso(at(2)),
      summary: { sources: ['203.0.113.12'], schema_version: 2, peak_pps: 148, latest_pps: 122, asset_registered: true, evidence: 'rules', automatic: { status: 'declined', source_ip: '203.0.113.12', at: iso(at(11, 50)), gate: GATE_B, blocked_by: [] } } },
    { id: 'inc-c9d0e1f2', title: 'PORT SCAN · 관리 콘솔', attack_type: 'PORT_SCAN', priority: 'P2', status: 'open', source: 'live', asset_id: 'as-2', asset_name: '관리 콘솔', dst_ip: '198.51.100.30', dst_port: 8443, protocol: 6, owner_id: null, owner_name: null, version: 1, event_count: 4, created_at: iso(at(6)), last_seen_at: iso(at(5)), acknowledged_at: null, ack_due_at: iso(at(-4)),
      summary: { sources: ['198.51.7.7'], schema_version: 2, peak_pps: 96, latest_pps: 90, asset_registered: true, evidence: 'rules' } },
    { id: 'inc-13579bdf', title: 'LARGE FLOW · 198.51.100.44:22', attack_type: 'LARGE_FLOW', priority: 'P3', status: 'open', source: 'live', asset_id: null, asset_name: '198.51.100.44:22', dst_ip: '198.51.100.44', dst_port: 22, protocol: 6, owner_id: null, owner_name: null, version: 1, event_count: 17, created_at: iso(at(41)), last_seen_at: iso(at(2)), acknowledged_at: null, ack_due_at: iso(at(-19)),
      summary: { sources: ['203.0.113.201'], schema_version: 2, peak_pps: 9800, latest_pps: 9400, asset_registered: false, evidence: 'rules' } },
    { id: 'inc-2468ace0', title: 'TRAFFIC SPIKE · 결제 API', attack_type: 'TRAFFIC_SPIKE', priority: 'P3', status: 'resolved', source: 'live', asset_id: 'as-1', asset_name: '결제 API', dst_ip: '198.51.100.20', dst_port: 443, protocol: 6, owner_id: 'op-1', owner_name: '김민서', version: 9, event_count: 22, created_at: iso(at(360)), last_seen_at: iso(at(330)), acknowledged_at: iso(at(356)), contained_at: iso(at(340)), recovering_at: iso(at(336)), resolved_at: iso(at(320)), ack_due_at: iso(at(300)),
      summary: { sources: ['203.0.113.40', '203.0.113.41'], schema_version: 2, peak_pps: 12040, latest_pps: 210, asset_registered: true, evidence: 'rules_and_validated_model' } },
    { id: 'inc-sim-0001', title: 'SYN FLOOD · 훈련용 결제 API', attack_type: 'SYN_FLOOD', priority: 'P1', status: 'action_pending', source: 'simulation', asset_id: 'as-3', asset_name: '훈련용 결제 API', dst_ip: '198.51.100.20', dst_port: 443, protocol: 6, owner_id: 'op-1', owner_name: '김민서', version: 4, event_count: 3, created_at: iso(at(4)), last_seen_at: iso(at(3)), acknowledged_at: iso(at(3, 30)), ack_due_at: iso(at(2)),
      summary: { sources: ['192.0.2.10'], schema_version: 1, peak_pps: 4240, latest_pps: 4240, asset_registered: true, evidence: 'rules', automatic: { status: 'applied', source_ip: '192.0.2.10', at: iso(at(3, 55)), run_id: 'run-sim-1', gate: GATE_A } } },
    { id: 'inc-sim-0002', title: 'PORT SCAN · 훈련용 결제 API', attack_type: 'PORT_SCAN', priority: 'P2', status: 'acknowledged', source: 'simulation', asset_id: 'as-3', asset_name: '훈련용 결제 API', dst_ip: '198.51.100.20', dst_port: 443, protocol: 6, owner_id: 'op-3', owner_name: '이유나', version: 2, event_count: 3, created_at: iso(at(2)), last_seen_at: iso(at(1)), acknowledged_at: iso(at(1, 20)), ack_due_at: iso(at(-8)),
      summary: { sources: ['192.0.2.77'], schema_version: 1, peak_pps: 140, latest_pps: 140, asset_registered: true, evidence: 'rules', automatic: { status: 'declined', source_ip: '192.0.2.77', at: iso(at(1, 58)), gate: GATE_B, blocked_by: [] } } },
  ];
  const gates = { 'inc-a1b2c3d4': { '203.0.113.77': GATE_A }, 'inc-e5f6a7b8': { '203.0.113.12': GATE_B }, 'inc-c9d0e1f2': { '198.51.7.7': GATE_C }, 'inc-sim-0001': { '192.0.2.10': GATE_A }, 'inc-sim-0002': { '192.0.2.77': GATE_B } };

  const events = {};
  incidents.forEach(inc => {
    const rows = []; const n = Math.min(inc.event_count, 8);
    for (let i = 0; i < n; i++) {
      const scan = inc.attack_type === 'PORT_SCAN', shared = inc.summary.automatic?.status === 'declined';
      rows.push({ event_id: 9100 + i * 7 + rows.length, detected_at: iso(new Date(new Date(inc.created_at).getTime() + i * 1000)), src_ip: inc.summary.sources[i % inc.summary.sources.length], dst: `${inc.dst_ip}:${inc.dst_port}`, pkt_rate: inc.attack_type === 'SYN_FLOOD' ? 4200 + i * 40 : scan ? 80 + i * 6 : inc.attack_type === 'LARGE_FLOW' ? 9500 : 12000, syn_ratio: shared ? 0.2 : scan ? 1 : inc.attack_type === 'SYN_FLOOD' ? 0.98 : 0.05, port_cnt: scan ? 48 : 1, severity: inc.priority === 'P1' ? 'critical' : inc.priority === 'P2' ? 'high' : 'medium' });
    }
    events[inc.id] = rows;
  });

  const policy = (src, dst, port, ttl, action = 'block_source') => ({ version: 1, action, source_ip: src, destination_ip: dst, destination_port: port, protocol: 6, ttl_seconds: ttl, rate_pps: 100, source: 'live' });
  const runs = [
    { id: 'run-auto-1', incident_id: 'inc-a1b2c3d4', point_id: 'pt-1', origin: 'automatic', status: 'released', policy: policy('203.0.113.77', '198.51.100.20', 443, 60), created_at: iso(at(25, 20)), applied_at: iso(at(25, 5)), expires_at: iso(at(24, 5)), released_at: iso(at(24, 4)), agent_result: { detail: 'nftables timed set expired in kernel', policy_handle: 'p_7c1e…' }, last_error: null },
    { id: 'run-op-2', incident_id: 'inc-a1b2c3d4', point_id: 'pt-1', origin: 'operator', status: 'applied', policy: policy('203.0.113.77', '198.51.100.20', 443, 300, 'rate_limit'), created_at: iso(at(20)), applied_at: iso(at(19, 40)), expires_at: iso(at(14, 40)), released_at: null, agent_result: { detail: 'applied', policy_handle: 'p_91aa…' }, last_error: null },
    { id: 'run-op-3', incident_id: 'inc-2468ace0', point_id: 'pt-1', origin: 'operator', status: 'released', policy: policy('203.0.113.40', '198.51.100.20', 443, 120), created_at: iso(at(345)), applied_at: iso(at(344, 30)), expires_at: iso(at(342, 30)), released_at: iso(at(342, 30)), agent_result: { detail: 'released by kernel TTL', policy_handle: 'p_0be2…' }, last_error: null },
    { id: 'run-sim-1', incident_id: 'inc-sim-0001', point_id: 'pt-3', origin: 'automatic', status: 'applied', policy: { ...policy('192.0.2.10', '198.51.100.20', 443, 60), source: 'simulation' }, created_at: iso(at(3, 55)), applied_at: iso(at(3, 50)), expires_at: iso(at(2, 50)), released_at: null, agent_result: { detail: 'Synthetic lab adapter; no network policy changed', policy_handle: 'simulation:run-sim-1' }, last_error: null },
  ];
  const previews = [
    { id: 'req-pend-1', incident_id: 'inc-e5f6a7b8', requester_id: 'op-3', requester_name: '이유나', origin: 'operator', status: 'preview', policy: policy('203.0.113.12', '198.51.100.20', 443, 120), policy_hash: 'b1e6f3a9c2d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8', expires_at: iso(at(-3)), reason: '공유 NAT 가능성을 확인했고 120초 제한으로 영향 범위를 좁힘', preview: { mode: 'nftables', asset: '결제 API', point: 'edge-01 (nftables)', impact: '출발지별 정상 세션 영향은 미확인입니다. 공유 NAT 여부를 검토하고 승인하세요.', protected_cidrs: ['198.51.100.0/28', '203.0.113.5/32'], affected_sessions: null, automatic_approval: false, gate: GATE_B } },
  ];

  const timelines = {
    'inc-a1b2c3d4': [
      { kind: 'incident.opened', label: '새 사건 생성', actor: 'System', at: iso(at(26)), detail: { priority: 'P1' } },
      { kind: 'response.auto_approved', label: '게이트 저위험 · 승인 없이 자동 적용', actor: 'System', at: iso(at(25, 20)), cls: 'auto', detail: { run_id: 'run-auto-1', ttl_seconds: 60, gate_score: 0.14 } },
      { kind: 'response.applied', label: '에이전트 적용 확인', actor: 'System', at: iso(at(25, 5)), detail: { policy_handle: 'p_7c1e…' } },
      { kind: 'incident.acknowledged', label: '담당자 인수', actor: '김민서', at: iso(at(23)), detail: { reason: '자동 적용 결과 검토 시작' } },
      { kind: 'response.released', label: '정책 해제 확인 (커널 TTL 만료)', actor: 'System', at: iso(at(24, 4)), detail: {} },
      { kind: 'response.previewed', label: '대응 영향 미리보기', actor: '김민서', at: iso(at(21)), detail: { reason: '재발 방지를 위해 5분 유입률 제한' } },
      { kind: 'response.approved', label: '별도 승인자 승인', actor: '박지훈', at: iso(at(20)), detail: { reason: '대상·기한 확인' } },
      { kind: 'incident.contained', label: '억제 효과 확인', actor: '김민서', at: iso(at(18)), detail: { reason: '유입 4,812 → 36 pps, 정상 성공률 99.8%' } },
    ],
    'inc-e5f6a7b8': [
      { kind: 'incident.opened', label: '새 사건 생성', actor: 'System', at: iso(at(12)), detail: { priority: 'P2' } },
      { kind: 'response.auto_declined', label: '게이트 고위험 · 자동 차단 거부', actor: 'System', at: iso(at(11, 50)), cls: 'declined', detail: { hard_stop: 'critical_asset_mixed_traffic', gate_score: 0.52 } },
      { kind: 'incident.acknowledged', label: '담당자 인수', actor: '이유나', at: iso(at(11)), detail: {} },
      { kind: 'incident.investigating', label: '조사 시작', actor: '이유나', at: iso(at(9)), detail: { reason: 'NAT 뒤 정상 사용자 포함 여부 확인' } },
      { kind: 'response.previewed', label: '대응 영향 미리보기', actor: '이유나', at: iso(at(2)), detail: { reason: '120초 제한으로 영향 범위를 좁힘' } },
    ],
    'inc-sim-0001': [
      { kind: 'incident.opened', label: '새 사건 생성', actor: 'System', at: iso(at(4)), detail: { priority: 'P1' } },
      { kind: 'response.auto_approved', label: '게이트 저위험 · 승인 없이 자동 적용', actor: 'System', at: iso(at(3, 55)), cls: 'auto', detail: { run_id: 'run-sim-1', ttl_seconds: 60 } },
      { kind: 'response.applied', label: '에이전트 적용 확인', actor: 'System', at: iso(at(3, 50)), detail: {} },
      { kind: 'incident.acknowledged', label: '담당자 인수', actor: '김민서', at: iso(at(3, 30)), detail: {} },
    ],
    'inc-sim-0002': [
      { kind: 'incident.opened', label: '새 사건 생성', actor: 'System', at: iso(at(2)), detail: { priority: 'P2' } },
      { kind: 'response.auto_declined', label: '게이트 고위험 · 자동 차단 거부', actor: 'System', at: iso(at(1, 58)), cls: 'declined', detail: { hard_stop: 'critical_asset_mixed_traffic' } },
      { kind: 'incident.acknowledged', label: '담당자 인수', actor: '이유나', at: iso(at(1, 20)), detail: {} },
    ],
  };
  incidents.forEach(i => { timelines[i.id] ||= [{ kind: 'incident.opened', label: '새 사건 생성', actor: 'System', at: i.created_at, detail: { priority: i.priority } }]; });

  const notifications = [
    { id: 'nt-1', incident_id: 'inc-a1b2c3d4', title: 'SYN FLOOD · 결제 API', kind: 'auto_response', channel: 'in_app', destination: 'workspace', status: 'provider_accepted', attempts: 1, created_at: iso(at(25, 20)), acknowledged_at: iso(at(23)) },
    { id: 'nt-2', incident_id: 'inc-a1b2c3d4', title: 'SYN FLOOD · 결제 API', kind: 'opened', channel: 'slack', destination: '#sec-ops', status: 'provider_accepted', attempts: 1, created_at: iso(at(26)), acknowledged_at: iso(at(23)) },
    { id: 'nt-3', incident_id: 'inc-a1b2c3d4', title: 'SYN FLOOD · 결제 API', kind: 'opened', channel: 'email', destination: 'oncall@example.test', status: 'provider_accepted', attempts: 1, created_at: iso(at(26)), acknowledged_at: iso(at(23)) },
    { id: 'nt-4', incident_id: 'inc-e5f6a7b8', title: 'PORT SCAN · 결제 API', kind: 'opened', channel: 'slack', destination: '#sec-ops', status: 'retrying', attempts: 2, created_at: iso(at(12)), acknowledged_at: null, last_error: 'Provider rate limit' },
    { id: 'nt-5', incident_id: 'inc-c9d0e1f2', title: 'PORT SCAN · 관리 콘솔', kind: 'escalated', channel: 'slack', destination: '#sec-ops-escalation', status: 'provider_accepted', attempts: 1, created_at: iso(at(3)), acknowledged_at: null },
    { id: 'nt-6', incident_id: 'inc-13579bdf', title: 'LARGE FLOW · 198.51.100.44:22', kind: 'opened', channel: 'in_app', destination: 'workspace', status: 'provider_accepted', attempts: 1, created_at: iso(at(41)), acknowledged_at: null },
  ];

  const models = [{ id: 'hgb-25-context-v2', stage: 'shadow', enabled: true, artifact_hash: '5f3a9c1e7b2d4680a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f506172', promotion_ready: false,
    manifest: { threshold: 0.42, independent_validation: { independent: false, f1: 0.9098, fpr: 0.0026, attack_types: ['BOT', 'FTP-PATATOR', 'SSH-PATATOR', 'WEB BRUTE FORCE'], missing_attack_types: ['DDOS', 'PORTSCAN'] } },
    statistics: { samples: 1284, successful: 1281, observed_days: 3.4, failure_rate: 0.0023, disagreement_rate: 0.018, p95_latency_ms: 4.1, score_mean_shift: 0.03, drift_status: 'stable' },
    gates: [{ id: 'schema', label: '피처 스키마 2와 모델 해시', passed: true }, { id: 'independent', label: '새 공격 실행·별도 환경 검증', passed: false }, { id: 'coverage', label: '선언한 공격 유형의 시험 근거', passed: false }, { id: 'quality', label: '독립 시험 F1 ≥ 0.80 · FPR ≤ 0.05', passed: true }, { id: 'shadow', label: '실시간 Shadow 7일·1,000개 관측', passed: false }, { id: 'features', label: '누락·오류 비율 ≤ 1%', passed: true }, { id: 'latency', label: 'p95 추론 지연 ≤ 100ms', passed: true }, { id: 'review', label: '운영 오탐 사건의 독립 검토', passed: false }] }];

  const scenarios = [
    { id: 'intrusion', name: '침입 탐지 리허설', description: '정상 접속 → 포트 탐색 → SYN 폭주 → 대량 전송 → 회복', stages: ['baseline', 'recon', 'flood', 'transfer', 'recovery'] },
    { id: 'syn_flood', name: 'SYN Flood', description: '출발지 SYN 증가와 연결 폭주 탐지 확인 · 게이트 저위험 → 자동 적용', stages: ['baseline', 'flood', 'recovery'] },
    { id: 'port_scan', name: 'Port Scan', description: '다수 목적지 포트 접근과 탐색 이벤트 확인', stages: ['baseline', 'recon', 'recovery'] },
    { id: 'large_flow', name: '대량 데이터 전송', description: '전송량 급증을 통한 LARGE FLOW 규칙 확인', stages: ['baseline', 'transfer', 'recovery'] },
    { id: 'shared_source', name: '공유 출발지 탐색', description: '정상 사용자와 섞인 NAT 뒤 탐색 · 게이트가 자동 차단을 거부하고 승인 경로로 넘기는지 확인', stages: ['baseline', 'mixed_recon', 'recovery'] },
  ];
  const scenarioRuns = [
    { id: 'sr-1', scenario_id: 'syn_flood', status: 'completed', started_at: iso(at(4, 10)), finished_at: iso(at(4)), matched_steps: 9, sample_count: 9, event_count: 3, detection_mode: 'rules_only' },
    { id: 'sr-2', scenario_id: 'shared_source', status: 'completed', started_at: iso(at(2, 10)), finished_at: iso(at(2)), matched_steps: 9, sample_count: 9, event_count: 3, detection_mode: 'rules_only' },
    { id: 'sr-3', scenario_id: 'intrusion', status: 'completed', started_at: iso(at(140)), finished_at: iso(at(139)), matched_steps: 14, sample_count: 15, event_count: 9, detection_mode: 'rules_only' },
  ];

  // 60분 pps 추이 (분 단위) — 26분 전 SYN Flood 정점, 자동 적용 후 급감
  const trend = []; for (let m = 59; m >= 0; m--) { let pps = 380 + Math.round(60 * Math.sin(m / 4)); if (m <= 27 && m >= 25) pps = 4200 + (27 - m) * 300; if (m === 24) pps = 900; if (m <= 12 && m >= 10) pps += 148; trend.push({ label: `${pad(at(m).getHours())}:${pad(at(m).getMinutes())}`, pps, minute: m }); }
  const byType = [{ type: 'SYN_FLOOD', count: 41 }, { type: 'PORT_SCAN', count: 13 }, { type: 'LARGE_FLOW', count: 17 }, { type: 'TRAFFIC_SPIKE', count: 22 }, { type: 'ANOMALY', count: 2 }];

  // ---- 저장된 탐지 이벤트 (대시보드 · 탐지 이벤트 화면) — 시드 고정 의사난수로 36건 ----
  const prng = (seed => () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; })(20260928);
  const TYPE_POOL = ['SYN_FLOOD', 'SYN_FLOOD', 'PORT_SCAN', 'PORT_SCAN', 'LARGE_FLOW', 'TRAFFIC_SPIKE', 'TRAFFIC_SPIKE', 'ANOMALY'];
  const SRC_POOL = ['203.0.113.77', '203.0.113.12', '203.0.113.201', '203.0.113.40', '203.0.113.41', '203.0.113.9', '203.0.113.150'];
  const DST_POOL = [['198.51.100.20', 443], ['198.51.100.30', 8443], ['198.51.100.44', 22], ['198.51.100.20', 80]];
  const detections = [];
  for (let i = 0; i < 36; i++) {
    const type = TYPE_POOL[Math.floor(prng() * TYPE_POOL.length)], simulation = i % 9 === 4;
    const [dst_ip, dst_port] = DST_POOL[Math.floor(prng() * DST_POOL.length)];
    const src_ip = simulation ? '192.0.2.10' : SRC_POOL[Math.floor(prng() * SRC_POOL.length)];
    const severity = type === 'SYN_FLOOD' ? 'critical' : type === 'PORT_SCAN' ? 'high' : type === 'LARGE_FLOW' ? 'medium' : type === 'ANOMALY' ? 'medium' : prng() > .5 ? 'high' : 'low';
    const pkt_rate = type === 'SYN_FLOOD' ? 4200 + Math.round(prng() * 900) : type === 'PORT_SCAN' ? 60 + Math.round(prng() * 40) : type === 'LARGE_FLOW' ? 9000 + Math.round(prng() * 1200) : type === 'TRAFFIC_SPIKE' ? 11000 + Math.round(prng() * 2000) : 300 + Math.round(prng() * 200);
    const byte_rate = type === 'LARGE_FLOW' ? 13500000 + Math.round(prng() * 900000) : pkt_rate * (60 + Math.round(prng() * 900));
    const port_cnt = type === 'PORT_SCAN' ? 40 + Math.round(prng() * 14) : 1;
    const review = prng(); const is_confirmed = review < .55 ? null : review < .85 ? true : false;
    detections.push({ event_id: 9200 + i * 3, detected_at: iso(at(i * 6 + Math.round(prng() * 5), Math.round(prng() * 59))), attack_type: type, severity, source: simulation ? 'simulation' : 'live', scenario_run_id: simulation ? 'sr-3' : null, is_confirmed, note: is_confirmed === false ? '승인된 부하 테스트로 확인' : is_confirmed ? '실제 공격 시도로 판단' : '',
      flow: { src_ip, dst_ip, src_port: 40000 + Math.round(prng() * 20000), dst_port, protocol: 6 }, anomaly_score: type === 'ANOMALY' ? -(0.18 + prng() * 0.2) : null,
      features: { pkt_rate, byte_rate, syn_ratio: type === 'SYN_FLOOD' ? 0.96 + prng() * 0.04 : type === 'PORT_SCAN' ? 1 : 0.02 + prng() * 0.08, port_entropy: type === 'PORT_SCAN' ? 4.8 + prng() : 0.1, port_cnt, flow_duration: Math.round(400 + prng() * 9000), avg_pkt_size: type === 'LARGE_FLOW' ? 1400 : 60 + Math.round(prng() * 120), feature_schema_version: 2 } });
  }
  detections.sort((a, b) => new Date(b.detected_at) - new Date(a.detected_at));

  // ---- 알림 센터 초기 기록 (상단 종 아이콘 드로어) ----
  const notices = [
    { id: 'no-1', kind: 'event', level: 'warn', read: false, title: '연결 폭주(SYN Flood) · 긴급', body: '203.0.113.77 → 198.51.100.20:443 · 실제 수집기 관측', at: iso(at(0, 40)), eventId: detections[0].event_id },
    { id: 'no-2', kind: 'event', level: 'info', read: false, title: '모의 포트 스캔(Port Scan) · 높음', body: '192.0.2.10 → 198.51.100.20:443 · 훈련용 SIMULATION 기록', at: iso(at(2)), eventId: detections.find(d => d.source === 'simulation')?.event_id },
    { id: 'no-3', kind: 'system', level: 'ok', read: true, title: '서버와 실시간으로 연결됐어요', body: '새 탐지 이벤트와 트래픽이 이 화면으로 바로 전달돼요.', at: iso(at(5)) },
    { id: 'no-4', kind: 'system', level: 'ok', read: true, title: '네트워크 수집기(Collector)가 다시 연결됐어요', body: '실시간 트래픽 그래프가 다시 채워져요.', at: iso(at(47)), href: '/system' },
    { id: 'no-5', kind: 'system', level: 'warn', read: true, title: '네트워크 수집기(Collector) 연결이 잠시 끊겼어요', body: '규칙 탐지는 저장된 기록으로 계속 볼 수 있어요. 수집기 서비스 상태를 확인하세요.', at: iso(at(48)), href: '/system' },
  ];

  // ---- 시스템 상태 ----
  const system = { cpu_percent: 4.6, memory_percent: 28.1, collected_at: iso(at(0, 8)), websocket: 'connected', uptime_hours: 71.4,
    collector: { connected: true, host: '192.168.64.2 (Ubuntu VM)', schema_version: 2, last_message_at: iso(at(0, 1)), messages_per_minute: 58, tunnel: 'SSH 터널 · 활성' },
    services: [{ id: 'collector', name: '네트워크 수집기(Collector)', status: 'ok', detail: 'XDP 관측 전용 · 피처 25개(v2) 수신 중' }, { id: 'redis', name: '실시간 저장소(Redis)', status: 'ok', detail: '60초 슬라이딩 윈도우 · 응답 0.4ms' }, { id: 'database', name: '기록 저장소(PostgreSQL 17)', status: 'ok', detail: '탐지 이벤트 1,527건 · 볼륨 영속' }, { id: 'engine', name: '분석 엔진', status: 'ok', detail: '규칙만 사용(Rules only) · 실험 모델은 Shadow 관측' }] };

  // ---- 데이터 분석 (CIC-IDS-2017) — 문서의 검증 수치 ----
  const analysis = {
    captures: [
      { day: '월', source: 'Monday-WorkingHours.pcap', date: '2017-07-03', gib: 10.82, packets: 11709971, feature_rows: 2898867, matched: 2345037, labels: { BENIGN: 2345037 } },
      { day: '화', source: 'Tuesday-WorkingHours.pcap', date: '2017-07-04', gib: 10.34, packets: 11551954, feature_rows: 2675578, matched: 2166408, labels: { BENIGN: 2151060, 'FTP-Patator': 7938, 'SSH-Patator': 5897, Infiltration: 1513 } },
      { day: '수', source: 'Wednesday-WorkingHours.pcap', date: '2017-07-05', gib: 12.42, packets: 13788878, feature_rows: 3694503, matched: 2847052, labels: { BENIGN: 2607000, 'DoS Hulk': 173000, 'DoS GoldenEye': 10293, 'DoS slowloris': 5796, 'DoS Slowhttptest': 5499, Heartbleed: 11 } },
      { day: '목', source: 'Thursday-WorkingHours.pcap', date: '2017-07-06', gib: 7.73, packets: 9322025, feature_rows: 2599785, matched: 2170602, labels: { BENIGN: 2166000, 'Web Attack – Brute Force': 1507, 'Web Attack – XSS': 652, 'Web Attack – Sql Injection': 21, Infiltration: 36 } },
      { day: '금', source: 'Friday-WorkingHours.pcap', date: '2017-07-07', gib: 11.12, packets: 12000000, feature_rows: 3357642, matched: 2721376, labels: { BENIGN: 2360000, DDoS: 128027, PortScan: 158930, Bot: 1966 } },
    ],
    candidates: [
      { id: 'if_6', name: '이상 탐지 AI(IF) · 기본 6개', calibration_f1: 0.3042, f1: 0, recall: 0, fpr: 0.0299, passed: false },
      { id: 'if_9', name: '이상 탐지 AI(IF) · 출발지 9개', calibration_f1: 0.6047, f1: 0, recall: 0, fpr: 0.0419, passed: false },
      { id: 'if_25', name: '이상 탐지 AI(IF) · 양방향 25개', calibration_f1: 0.6193, f1: 0, recall: 0, fpr: 0.0406, passed: false },
      { id: 'if_25_large', name: '이상 탐지 AI(IF) · 25개 / 표본 확대', calibration_f1: 0.6464, f1: 0, recall: 0, fpr: 0.0395, passed: false },
      { id: 'hgb_25', name: '학습형 AI(HGB) · 25개', calibration_f1: 0.9628, f1: 0.9098, recall: 0.9862, fpr: 0.0026, passed: true, preferred: true, per_label: { BENIGN: [354657, 923], Bot: [1966, 1011], 'FTP-Patator': [1520, 1519], 'SSH-Patator': [1118, 1117], 'Web Attack – Brute Force': [473, 460] } },
    ],
    coverage: { tested: ['Bot', 'FTP-Patator', 'SSH-Patator', 'Web Attack – Brute Force'], matched_total: 14, missing: ['DDoS', 'PortScan', 'DoS Hulk', 'DoS GoldenEye', 'DoS slowloris', 'DoS Slowhttptest', 'Heartbleed', 'Infiltration', 'Web Attack – XSS', 'Web Attack – Sql Injection'] },
    targets: { f1_min: 0.8, fpr_max: 0.05 }, test_rows: 360657, split: { training: 1200000, calibration: 402000, test: 360657, purged: 41000 },
  };

  // ---- 시나리오 실행 샘플 (실행 기록 상세 · 단계 스테퍼) ----
  const STAGE_LABEL = { baseline: 'BENIGN', recon: 'PORT_SCAN', flood: 'SYN_FLOOD', transfer: 'LARGE_FLOW', recovery: 'BENIGN', mixed_recon: 'PORT_SCAN' };
  const STAGE_PPS = { baseline: 35, recon: 80, flood: 4800, transfer: 9500, recovery: 35, mixed_recon: 120 };
  const STAGE_BPS = { baseline: 28000, recon: 12000, flood: 288000, transfer: 13500000, recovery: 28000, mixed_recon: 96000 };
  const runSamples = {};
  scenarioRuns.forEach((run, ri) => {
    const sc = scenarios.find(s => s.id === run.scenario_id); const rows = []; let step = 0, eid = 9400 + ri * 40;
    sc.stages.forEach(stage => { for (let k = 0; k < 3; k++) { const expected = STAGE_LABEL[stage]; const miss = run.id === 'sr-3' && stage === 'recon' && k === 0; const detected = miss ? 'BENIGN' : expected; rows.push({ step, stage, timestamp: iso(new Date(new Date(run.started_at).getTime() + step * 1000)), expected_label: expected, detected_label: detected, pps: STAGE_PPS[stage] + k * 3, mbps: STAGE_BPS[stage] * 8 / 1e6, event_id: detected === 'BENIGN' ? null : eid++ }); step++; } });
    runSamples[run.id] = rows;
  });
  scenarioRuns.push({ id: 'sr-4', scenario_id: 'intrusion', status: 'running', started_at: iso(at(0, 9)), finished_at: null, matched_steps: 7, sample_count: 7, event_count: 3, detection_mode: 'rules_only' });
  runSamples['sr-4'] = runSamples['sr-3'].slice(0, 7).map(r => ({ ...r, detected_label: r.expected_label, event_id: r.expected_label === 'BENIGN' ? null : 9560 + r.step }));

  // ---- 실시간 검사 (내 네트워크) — 서버 호스트의 인터페이스와 방어선 점검 결과 ----
  const interfaces = [
    { name: 'en0', kind: 'wifi', label: 'Wi-Fi', addresses: ['192.0.2.22'], is_up: true, speed_mbps: 0, active: true },
    { name: 'en5', kind: 'ethernet', label: 'USB 10/100/1000 LAN', addresses: ['192.0.2.213'], is_up: true, speed_mbps: 1000, active: true },
    { name: 'bridge100', kind: 'virtual', label: 'Thunderbolt Bridge', addresses: ['198.51.100.1'], is_up: true, speed_mbps: 0, active: true },
    { name: 'lo0', kind: 'loopback', label: '루프백', addresses: ['127.0.0.1'], is_up: true, speed_mbps: 0, active: false },
  ];
  const liveCapabilities = { packet: { available: false, reason: '/dev/bpf 접근 권한이 없습니다 — 관리자 권한(sudo)으로 실행하거나 Wireshark의 ChmodBPF를 설치하세요' }, counters: { available: true, reason: '' } };
  const liveCheck = { checked_at: iso(at(0, 3)), summary: { ok: 3, warn: 0, skipped: 1, fail: 0 }, items: [
    { id: 'capture', title: '수집 · 내 네트워크 인터페이스', status: 'ok', detail: '활성 인터페이스 3개 · 카운터 검사만 가능 (/dev/bpf 접근 권한이 없습니다 — 관리자 권한(sudo)으로 실행하거나 Wireshark의 ChmodBPF를 설치하세요)', interfaces: ['en0', 'en5', 'bridge100'], capabilities: liveCapabilities },
    { id: 'rules', title: '1차 방어선 · 규칙 엔진', status: 'ok', detail: '5/5 판정이 저장된 임계값과 일치해요', probes: [
      { name: '연결 폭주(SYN Flood)', expected: 'SYN_FLOOD', detected: 'SYN_FLOOD', passed: true }, { name: '포트 스캔(Port Scan)', expected: 'PORT_SCAN', detected: 'PORT_SCAN', passed: true },
      { name: '트래픽 급증(Traffic Spike)', expected: 'TRAFFIC_SPIKE', detected: 'TRAFFIC_SPIKE', passed: true }, { name: '대용량 전송(Large Flow)', expected: 'LARGE_FLOW', detected: 'LARGE_FLOW', passed: true }, { name: '정상 접속', expected: 'BENIGN', detected: 'BENIGN', passed: true }] },
    { id: 'model', title: '2차 방어선 · AI 이상 탐지', status: 'skipped', detail: '모델 산출물이 없거나 검증되지 않아 규칙만 사용해요', probes: [], mode: 'rules_only', contract: 'legacy-6', live_applied: false, live_reason: '' },
    { id: 'response', title: '대응 · 차단 안전 점검과 자동 경로', status: 'ok', detail: '차단 안전 점검이 저위험은 자동 경로, 고위험은 승인 경로로 나눴어요 · 자동 경로 켜짐', probes: [
      { name: '단일 출발지 연결 폭주', expected: 'automatic', route: 'automatic', score: 0.15, level: 'low', hard_stop: null, reason: 'SYN 비율 98% — 완료된 연결이 거의 없어 정상 세션 영향이 낮습니다.', passed: true },
      { name: '정상 사용자가 섞인 공유 출발지', expected: 'approval', route: 'approval', score: 0.44, level: 'high', hard_stop: 'critical_asset_mixed_traffic', reason: '관측의 80%가 완료 연결·응답 트래픽입니다 — 정상 사용자가 섞인 출발지(공유 NAT·프록시)일 가능성이 높습니다.', passed: true }],
      control: { auto_response: true, kill_switch: false }, assets: 3, assets_opted_in: 2, points_enabled: 3, auto_ttl_seconds: 60 },
  ] };

  window.MOCK = {
    fmt, iso, at, operators, assets, points, incidents, gates, events, runs, previews, timelines, notifications, models, scenarios, scenarioRuns, trend, byType, detections, notices, system, analysis, runSamples, interfaces, liveCapabilities, liveCheck,
    control: { kill_switch: false, auto_response: true, auto_usage: { used: 1, limit: 10 }, auto_ttl_seconds: 60, risk_threshold: 0.4 },
    health: { detection_mode: 'rules_only', collector_connected: true, redis: 'ok', database: 'ok', collector_feature_schema_version: 2 },
    thresholds: { syn_ratio_threshold: 0.8, syn_pps_threshold: 1000, port_entropy_threshold: 3.5, port_cnt_threshold: 20, spike_threshold_multiplier: 10, baseline_pps: 1000, large_flow_threshold: 12500000, anomaly_threshold: -0.1 },
    metrics: { incidents: 5, open: 3, unacknowledged_urgent: 1, overdue: 2, automatic_actions: 1, active_actions: 1, notification_failures: 0, recovery_failures: 0, mtta: { mean_seconds: 148, p95_seconds: 190, samples: 3 }, mttc: { mean_seconds: 480, p95_seconds: 1200, samples: 2 }, mttr: { mean_seconds: 2400, p95_seconds: 2400, samples: 1 } },
  };
})();
