// SupplyGuard 목업 — 「평가」 화면 예시 데이터 [11/04 U1 1단계]. 실측이 아니다 — 화면에 「예시 데이터」 배지가 붙는다(sample: true).
// 모양은 bench/reports 의 세 파일 그대로: static.json · runtime.json · model.json → { static, runtime, model }.
// 실측 JSON 이 생기면 이 파일의 세 값만 그 내용으로 바꾸고 sample 을 지운다(화면 코드는 eval.js, 그대로 둔다).
// 값은 일부러 둥근 수(100 · 300 · 50 · 10회 · 100ms 단위)와 0000000 커밋 · 2026-01-01 시각으로 둔다 — 실측처럼 보이지 않게.
(function () {
  'use strict';
  const ZERO_SHA = '0'.repeat(64);
  window.EVAL_SAMPLE = {
    sample: true,
    static: {
      schema: 1,
      generatedAt: '2026-01-01T00:00:00Z',
      scanner: { guarddog: '0.0.0', osv: '0.0.0', backendCommit: '0000000' },
      datasets: [
        { id: 'datadog-malicious', label: 'DataDog 실제 악성', kind: 'malicious', source: '예시 출처', sourceCommit: '0000000', files: 100, listSha256: ZERO_SHA },
        { id: 'pypi-top300', label: '인기 PyPI 300', kind: 'benign', source: '예시 출처', sourceCommit: '0000000', files: 300, listSha256: ZERO_SHA },
      ],
      sets: [
        { id: 'datadog-malicious', kind: 'malicious', total: 100, scanned: 100, skipped: {}, verdicts: { malicious: 80, vulnerable: 0, suspicious: 10, clean: 10, error: 0 } },
        { id: 'pypi-top300', kind: 'benign', total: 300, scanned: 300, skipped: {}, verdicts: { malicious: 3, vulnerable: 20, suspicious: 30, clean: 247, error: 0 } },
      ],
      // 양성 = 판정 「악성」. tp 80 · fn 20 · fp 3 · tn 297 에서 계산
      metrics: { detectionRate: 0.8, detectionRateWithSuspicious: 0.9, falsePositiveRate: 0.01, precision: 0.964, recall: 0.8, f1: 0.874 },
      confusion: { tp: 80, fn: 20, fp: 3, tn: 297 },
      rules: [
        { rule: 'threat-setup-exec', maliciousHits: 60, benignHits: 0 },
        { rule: 'threat-setup-download', maliciousHits: 50, benignHits: 0 },
        { rule: 'network-exfil', maliciousHits: 40, benignHits: 0 },
        { rule: 'threat-dynamic-import', maliciousHits: 10, benignHits: 40 },
        { rule: 'threat-process-hooks', maliciousHits: 10, benignHits: 30 },
        { rule: 'download-exec', maliciousHits: 30, benignHits: 0 },
        { rule: 'threat-env-read', maliciousHits: 10, benignHits: 20 },
        { rule: 'network-exfil-env', maliciousHits: 20, benignHits: 0 },
        { rule: 'dns-exfil', maliciousHits: 10, benignHits: 0 },
        { rule: 'reverse-shell', maliciousHits: 10, benignHits: 0 },
        { rule: 'self-propagation', maliciousHits: 5, benignHits: 0 },
        { rule: 'npm-preinstall-script', maliciousHits: 0, benignHits: 5 },
      ],
      durationsSec: { p50: 10, p95: 30 },
      limits: [
        '예시 — 실제 악성 세트는 PyPI 패키지만 담고 npm 은 담지 않는다',
        '예시 — 인기 패키지 300개를 모두 정상으로 가정한다(섞여 있는 악성이 있으면 오탐률이 높게 나온다)',
      ],
    },
    runtime: {
      schema: 1,
      generatedAt: '2026-01-01T00:00:00Z',
      host: { name: 'sg-vm', kernel: '5.15', discovery: 'fanotify', igVersion: 'v0.56.1', backendCommit: '0000000' },
      benign: {
        installs: 50, byEcosystem: { pip: 30, npm: 20 }, violations: 1, falsePositiveRate: 0.02,
        items: [
          { ecosystem: 'pip', name: 'example-pip-a', result: 'passed', rule: '', seconds: 10 },
          { ecosystem: 'npm', name: 'example-npm-b', result: 'passed', rule: '', seconds: 20 },
          { ecosystem: 'npm', name: 'example-npm-c', result: 'isolated', rule: 'sandbox-egress', seconds: 20 },
        ],
      },
      scenarios: [
        { id: 'shell-download', label: '셸로 내려받아 실행', kind: 'attack', runs: 10, detected: 10, killed: 10, rule: 'no-shell-download', latencyMs: { p50: 100, p95: 200, max: 300 } },
        { id: 'read-secrets', label: '자격 증명 파일 읽기', kind: 'attack', runs: 10, detected: 10, killed: 10, rule: 'sandbox-secrets', latencyMs: { p50: 100, p95: 200, max: 300 } },
        { id: 'egress', label: '외부 서버 연결', kind: 'attack', runs: 10, detected: 10, killed: 10, rule: 'sandbox-egress', latencyMs: { p50: 100, p95: 300, max: 400 } },
        { id: 'dns-exfil', label: 'DNS 유출 질의', kind: 'attack', runs: 10, detected: 9, killed: 9, rule: 'sandbox-dns', latencyMs: { p50: 200, p95: 400, max: 500 } },
        { id: 'chain', label: '연쇄(내려받기 → 연결 → 읽기)', kind: 'attack', runs: 10, detected: 10, killed: 0, rule: 'chain-download-secrets', latencyMs: null },
        { id: 'benign-install', label: '정상 설치(대조)', kind: 'control', runs: 10, detected: 0, killed: 0, rule: '', latencyMs: null },
      ],
      limits: [
        '예시 — 한 호스트(커널 5.15 · fanotify)에서만 잰 값이다',
        '예시 — 연쇄 규칙은 dryRun 이라 탐지만 하고 격리하지 않는다(지연 없음)',
      ],
    },
    model: {
      schema: 1,
      protocol: { seed: 0, split: '예시 — 세트별 층화 60 / 20 / 20', selection: '보정 세트 F1 이 가장 높은 후보' },
      features: ['riskScore', 'installThreats', 'threats', 'vulnCount', 'ruleHits'],
      candidates: [
        { id: 'rules', label: '규칙 판정', calibration: { f1: 0.86, fpr: 0.02 }, test: { f1: 0.865, precision: 0.941, recall: 0.8, fpr: 0.017 }, confusion: { tp: 16, fn: 4, fp: 1, tn: 59 } },
        { id: 'logreg', label: '로지스틱 회귀', calibration: { f1: 0.88, fpr: 0.02 }, test: { f1: 0.872, precision: 0.895, recall: 0.85, fpr: 0.033 }, confusion: { tp: 17, fn: 3, fp: 2, tn: 58 } },
        { id: 'hgb', label: 'HGB', calibration: { f1: 0.9, fpr: 0.01 }, test: { f1: 0.923, precision: 0.947, recall: 0.9, fpr: 0.017 }, confusion: { tp: 18, fn: 2, fp: 1, tn: 59 } },
      ],
      preferredId: 'hgb',
      deploymentApproved: false,
      limits: [
        '예시 — 시험 세트가 80개뿐이라 F1 차이 0.05 안쪽은 우연일 수 있다',
        '예시 — 모델은 운영에 적용하지 않았다(판정은 지금도 규칙으로 한다)',
      ],
    },
  };
})();
