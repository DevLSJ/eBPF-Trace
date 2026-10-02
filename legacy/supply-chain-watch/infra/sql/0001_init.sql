-- Supply Chain Watch — 초기 스키마 (docs/04-data-model.md + docs/12-remediation-bot.md)
-- 멱등 적용: 마이그레이션 러너가 schema_migrations로 1회만 실행.

CREATE TYPE repo_mode AS ENUM ('polling','webhook');
CREATE TYPE repo_status AS ENUM ('REGISTERED','ACTIVE','RATE_LIMITED','NOT_FOUND','PAUSED','ERROR');
CREATE TYPE commit_status AS ENUM ('QUEUED','ANALYZING','DONE','FAILED','MISSING','SKIPPED');
CREATE TYPE risk_level AS ENUM ('HIGH','MEDIUM','LOW');
CREATE TYPE llm_status AS ENUM ('OK','SKIPPED_GATE','SKIPPED_BUDGET','REFUSED','ERROR','CACHED');

CREATE TABLE repositories (
  id              BIGSERIAL PRIMARY KEY,
  owner           TEXT NOT NULL,
  name            TEXT NOT NULL,
  full_name       TEXT GENERATED ALWAYS AS (owner || '/' || name) STORED,
  mode            repo_mode NOT NULL DEFAULT 'polling',
  status          repo_status NOT NULL DEFAULT 'REGISTERED',
  default_branch  TEXT,
  stars           INT,
  always_llm      BOOLEAN NOT NULL DEFAULT false,
  poll_interval_s INT NOT NULL DEFAULT 15,
  etag            TEXT,
  last_event_id   TEXT,
  last_commit_seen_at TIMESTAMPTZ,
  last_sync_at    TIMESTAMPTZ,
  next_poll_at    TIMESTAMPTZ,
  rate_limit_remaining INT,
  last_error      TEXT,
  webhook_id      BIGINT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (owner, name)
);

CREATE TABLE commits (
  id              BIGSERIAL PRIMARY KEY,
  repo_id         BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  sha             CHAR(40) NOT NULL,
  branch          TEXT,
  author_name     TEXT,
  author_login    TEXT,
  author_email    TEXT,
  message         TEXT,
  committed_at    TIMESTAMPTZ,
  html_url        TEXT,
  source          TEXT NOT NULL,
  status          commit_status NOT NULL DEFAULT 'QUEUED',
  files_changed   INT,
  additions       INT,
  deletions       INT,
  diff_size_bytes INT,
  diff_truncated  BOOLEAN NOT NULL DEFAULT false,
  diff_hash       CHAR(64),
  diff_text       TEXT,
  files_json      JSONB,
  received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (repo_id, sha)
);
CREATE INDEX idx_commits_received ON commits (received_at DESC);
CREATE INDEX idx_commits_status ON commits (status);

CREATE TABLE analyses (
  id              BIGSERIAL PRIMARY KEY,
  commit_id       BIGINT NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
  attempt         INT NOT NULL DEFAULT 1,
  risk_score      INT NOT NULL,
  risk_level      risk_level NOT NULL,
  tags            TEXT[] NOT NULL DEFAULT '{}',
  static_score    INT NOT NULL,
  static_level    risk_level NOT NULL,
  matched_rules   JSONB NOT NULL DEFAULT '[]',
  sensitive_files TEXT[] NOT NULL DEFAULT '{}',
  llm_status      llm_status NOT NULL,
  llm_model       TEXT,
  llm_result      JSONB,
  prompt_version  INT,
  llm_input_tokens  INT,
  llm_output_tokens INT,
  llm_cache_read_tokens INT,
  llm_latency_ms  INT,
  static_latency_ms INT,
  verdict_by_user TEXT,
  verdict_note    TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_analyses_commit ON analyses (commit_id, attempt DESC);
CREATE INDEX idx_analyses_level_created ON analyses (risk_level, created_at DESC);

CREATE TABLE alerts (
  id          BIGSERIAL PRIMARY KEY,
  analysis_id BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  channel     TEXT NOT NULL,
  status      TEXT NOT NULL,
  response    TEXT,
  sent_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE prompt_templates (
  id            BIGSERIAL PRIMARY KEY,
  name          TEXT NOT NULL DEFAULT 'default',
  version       INT NOT NULL,
  system_prompt TEXT NOT NULL,
  user_template TEXT NOT NULL,
  is_active     BOOLEAN NOT NULL DEFAULT false,
  note          TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (name, version)
);
CREATE UNIQUE INDEX one_active_prompt ON prompt_templates (name) WHERE is_active;

CREATE TABLE static_rule_overrides (
  rule_id    TEXT PRIMARY KEY,
  enabled    BOOLEAN NOT NULL DEFAULT true,
  weight     INT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE webhook_deliveries (
  delivery_id TEXT PRIMARY KEY,
  repo_full_name TEXT,
  event       TEXT,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- docs/12: LLM Provider / 수정 제안 봇
CREATE TABLE llm_providers (
  id          BIGSERIAL PRIMARY KEY,
  kind        TEXT NOT NULL,
  name        TEXT NOT NULL,
  base_url    TEXT,
  api_key_enc BYTEA NOT NULL,
  key_hint    TEXT,
  models      TEXT[] NOT NULL DEFAULT '{}',
  is_active   BOOLEAN NOT NULL DEFAULT false,
  last_test_at TIMESTAMPTZ,
  last_test_ok BOOLEAN,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX one_active_provider ON llm_providers ((true)) WHERE is_active;

CREATE TABLE fixes (
  id          BIGSERIAL PRIMARY KEY,
  commit_id   BIGINT NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
  files       TEXT[] NOT NULL,
  patches     JSONB NOT NULL,
  verify_ok   BOOLEAN,
  verify_log  TEXT,
  pr_mode     TEXT,
  pr_url      TEXT,
  pr_state    TEXT,
  pr_number   INT,
  bot_branch  TEXT,
  fork_full_name TEXT,
  llm_model   TEXT,
  prompt_version INT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE bot_actions (
  id BIGSERIAL PRIMARY KEY,
  fix_id BIGINT REFERENCES fixes(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  repo_full_name TEXT,
  sha CHAR(40),
  ok BOOLEAN NOT NULL,
  response JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE github_accounts (
  id BIGSERIAL PRIMARY KEY,
  role TEXT NOT NULL,
  login TEXT,
  token_enc BYTEA NOT NULL,
  token_hint TEXT,
  scopes TEXT[],
  is_active BOOLEAN NOT NULL DEFAULT false,
  last_test_at TIMESTAMPTZ,
  last_test_ok BOOLEAN,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 대시보드 집계 뷰: 커밋별 최신 분석
CREATE VIEW v_commit_latest AS
SELECT c.*, a.risk_score, a.risk_level, a.tags, a.llm_status, a.id AS analysis_id
FROM commits c
LEFT JOIN LATERAL (
  SELECT * FROM analyses WHERE commit_id = c.id ORDER BY attempt DESC LIMIT 1
) a ON true;
