-- 런타임 축(eBPF) 스키마 (docs/13 §4, ADR-018). gateway 메인 DB에 적용.
-- 인시던트는 별도 테이블 없이 runtime_events.incident_key(= container|최상위 pid)로 묶어 gateway가 집계한다.

CREATE TYPE runtime_agent_status  AS ENUM ('ONLINE','OFFLINE');
CREATE TYPE runtime_event_kind    AS ENUM ('EXECVE','CONNECT');
CREATE TYPE runtime_action_kind   AS ENUM ('KILL_PROCESS','BLOCK_DEST');
CREATE TYPE runtime_action_status AS ENUM ('REQUESTED','DONE','FAILED');

-- 접속한 관측 에이전트 등록·헬스
CREATE TABLE runtime_agents (
  id            BIGSERIAL PRIMARY KEY,
  agent_uid     TEXT UNIQUE NOT NULL,
  hostname      TEXT,
  status        runtime_agent_status NOT NULL DEFAULT 'ONLINE',
  tracked       INT NOT NULL DEFAULT 0,
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 의심 이벤트 원장 (에이전트 업링크 + gateway 점수화 결과)
CREATE TABLE runtime_events (
  id            BIGSERIAL PRIMARY KEY,
  agent_id      BIGINT REFERENCES runtime_agents(id) ON DELETE CASCADE,
  incident_key  TEXT NOT NULL,                     -- container|pid 프로세스 트리 묶음
  container     TEXT NOT NULL,
  image         TEXT,
  kind          runtime_event_kind NOT NULL,
  pid           INT,
  ppid          INT,
  comm          TEXT,
  filename      TEXT,
  dest_ip       INET,
  dest_port     INT,
  rule_id       TEXT NOT NULL,                     -- 에이전트가 보낸 룰 ID
  risk_level    risk_level NOT NULL,               -- gateway 환산(0001 enum 재사용)
  purl          TEXT,                              -- 오염 패키지(커밋 축 연결)
  commit_sha    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_runtime_events_incident ON runtime_events (incident_key, created_at);
CREATE INDEX idx_runtime_events_created  ON runtime_events (created_at DESC);

-- 차단 명령 감사 로그 (UI/관리자 앱 → gateway → 에이전트)
CREATE TABLE runtime_actions (
  id            BIGSERIAL PRIMARY KEY,
  incident_key  TEXT NOT NULL,
  event_id      BIGINT REFERENCES runtime_events(id) ON DELETE SET NULL,
  container     TEXT NOT NULL,
  action        runtime_action_kind NOT NULL,
  target        TEXT,                              -- pid 또는 dest_ip
  requested_by  TEXT NOT NULL DEFAULT 'admin',
  status        runtime_action_status NOT NULL DEFAULT 'REQUESTED',
  result        TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at   TIMESTAMPTZ
);
CREATE INDEX idx_runtime_actions_incident ON runtime_actions (incident_key, created_at);

-- 서비스별 SBOM (에이전트가 매니페스트 파싱해 agent.hello로 업로드)
CREATE TABLE sbom_components (
  id            BIGSERIAL PRIMARY KEY,
  agent_id      BIGINT REFERENCES runtime_agents(id) ON DELETE CASCADE,
  container     TEXT NOT NULL,
  purl          TEXT NOT NULL,
  name          TEXT,
  version       TEXT,
  ecosystem     TEXT,                              -- npm / pypi / ...
  source_file   TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (agent_id, container, purl)
);
