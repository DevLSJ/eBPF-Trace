# 실시간 검사 — API · 데이터베이스 명세 · 로컬 실행 (Docker PostgreSQL)

> 웹앱(`/#live`)이 호출하는 실제 API와 그 데이터가 저장되는 테이블. 로컬에서는 Docker PostgreSQL·Redis 위에서 동일하게 동작한다.
> 전체 OpenAPI는 백엔드 실행 후 `http://127.0.0.1:8000/docs`.

## 1. 인증과 공통 규약

- 모든 `/api/live/*` 요청은 `Authorization: Bearer <ADMIN_TOKEN>` 헤더가 필요하다(서버 호스트의 네트워크 장치를 다루므로). 없거나 틀리면 `401`.
- 오류 본문은 공통 형식 `{"error": {"code": "...", "message": "...", "timestamp": "..."}}`. 코드: `UNAUTHORIZED`(401) · `BAD_REQUEST`(400) · `NOT_FOUND`(404) · `VALIDATION_ERROR`(422) · `UNAVAILABLE`(503) · `HTTP_ERROR`(409 등).
- 시각은 ISO 8601 UTC. 관측 창의 `t`는 epoch 밀리초.

## 2. 엔드포인트

| 메서드 · 경로 | 역할 | 응답 |
|---|---|---|
| `GET /api/live/interfaces` | 백엔드 호스트의 네트워크 인터페이스와 검사 가능 여부 | `{ items[], capabilities, host, platform }` |
| `POST /api/live/check` | 방어선 점검(저장 없음). 저장된 임계값 표본으로 규칙·모델·차단 안전 점검 판정 | `{ checked_at, items[4], summary }` |
| `POST /api/live/inspections` | 검사 시작 (`201`). 동시 1개, 진행 중이면 `409` | 검사 객체(창 없음) |
| `GET /api/live/inspections` | 최근 검사 20건 (DB, 시작 시각 내림차순) | `{ items[] }` |
| `GET /api/live/inspections/{id}` | 검사 상세 + 관측 창(최근 300초) | 검사 객체 + `windows[]` |
| `POST /api/live/inspections/{id}/stop` | 진행 중인 검사 중지 → `cancelled` | 검사 상세 |

### 2.1 `GET /api/live/interfaces`

```json
{
  "items": [
    { "name": "en0", "kind": "wifi", "label": "Wi-Fi", "addresses": ["192.168.100.22"], "is_up": true,
      "speed_mbps": 0, "packets_received": 45051, "bytes_received": 9253888, "active": true }
  ],
  "capabilities": {
    "packet":   { "available": false, "reason": "/dev/bpf 접근 권한이 없습니다 — 관리자 권한(sudo)으로 실행하거나 Wireshark의 ChmodBPF를 설치하세요" },
    "counters": { "available": true,  "reason": "" }
  },
  "host": "my-mac.local", "platform": "darwin"
}
```

`kind`: `wifi` · `ethernet` · `loopback` · `virtual` · `other`. `active`는 "켜져 있고 IPv4 주소가 있으며 루프백이 아님".

### 2.2 `POST /api/live/inspections`

요청(`InspectionRequest`, 추가 필드 금지):

```json
{ "interface": "en0", "mode": "auto", "duration_seconds": 30 }
```

| 필드 | 타입 · 제약 | 설명 |
|---|---|---|
| `interface` | 문자열 1~32자, `^[A-Za-z0-9._:-]+$` | `GET /interfaces`의 `name`. 없으면 `404`, 꺼져 있으면 `400` |
| `mode` | `auto` \| `packet` \| `counters` (기본 `auto`) | `auto`는 패킷 검사가 가능하면 패킷, 아니면 카운터. 불가한 `packet`은 `400` |
| `duration_seconds` | 정수 5~300 (기본 30) | 관측 초 수 = 저장되는 창 수 |

응답(검사 객체) — `GET /inspections/{id}`는 같은 형태에 `windows`가 붙는다:

```json
{
  "id": "0d2f…", "interface": "en0", "address": "192.168.100.22", "mode": "counters",
  "status": "running", "duration_seconds": 30, "elapsed_seconds": 7, "error": "",
  "started_at": "2026-09-28T05:10:00.120000+00:00", "finished_at": null,
  "detection_mode": "rules_only",
  "thresholds": { "syn_ratio_threshold": 0.8, "syn_pps_threshold": 1000, "port_cnt_threshold": 20, "baseline_pps": 1000, "spike_threshold_multiplier": 10, "large_flow_threshold": 12500000, "port_entropy_threshold": 3.5, "anomaly_threshold": -0.1 },
  "stages": {
    "capture":  { "status": "running", "mode": "counters", "packets": 2410, "bytes": 1893200, "peak_pps": 812, "flows": 1, "seconds": 7, "note": "…" },
    "rules":    { "status": "running", "checked": 7, "hits": {}, "thresholds": { "…": "…" }, "note": "…" },
    "model":    { "status": "skipped", "reason": "모델 산출물이 없거나 검증되지 않아 규칙만 적용해요", "scored": 0, "min_score": null, "anomalies": 0, "mode": "rules_only", "model_status": "unavailable_or_unvalidated", "threshold": -0.1, "feature_count": 6 },
    "response": { "status": "running", "events": 0, "incidents": 0, "automatic": { "applied": 0, "declined": 0, "other": 0 }, "live_enabled": false, "note": "…" }
  },
  "event_ids": [],
  "windows": [
    { "t": 1790564400120, "pkt_rate": 340, "byte_rate": 270400, "flows": 1, "rule_hits": {}, "scored": 0, "min_score": null, "events": [] }
  ]
}
```

`status`: `running` → `completed` | `cancelled`(중지) | `failed`(`error`에 사유) | `interrupted`(서버 재시작으로 중단, 기동 시 자동 표시).
단계 `status`: `running` · `ok` · `empty`(관측 없음) · `idle`(해당 없음) · `skipped`(2차 AI, `reason` 포함) · `fail`.
창의 `events[]` 원소: `{ event_id, attack_type, severity, incident_id, automatic }` — `automatic`은 `applied` · `declined` · null(평가 없음).

### 2.3 `POST /api/live/check`

```json
{
  "checked_at": "2026-09-28T05:12:00+00:00",
  "items": [
    { "id": "capture",  "title": "수집 · 내 네트워크 인터페이스", "status": "ok", "detail": "활성 인터페이스 3개 · 카운터 검사만 가능 (…)", "interfaces": ["en0", "en5"], "capabilities": { "…": "…" } },
    { "id": "rules",    "title": "1차 방어선 · 규칙 엔진", "status": "ok", "detail": "5/5 판정이 저장된 임계값과 일치해요",
      "probes": [ { "name": "연결 폭주(SYN Flood)", "expected": "SYN_FLOOD", "detected": "SYN_FLOOD", "passed": true } ], "thresholds": { "…": "…" } },
    { "id": "model",    "title": "2차 방어선 · AI 이상 탐지", "status": "skipped", "detail": "모델 산출물이 없거나 검증되지 않아 규칙만 사용해요", "probes": [], "mode": "rules_only", "contract": "legacy-6", "live_applied": false, "live_reason": "" },
    { "id": "response", "title": "대응 · 차단 안전 점검과 자동 경로", "status": "ok", "detail": "…",
      "probes": [ { "name": "단일 출발지 연결 폭주", "expected": "automatic", "route": "automatic", "score": 0.148, "level": "low", "hard_stop": null, "reason": "SYN 비율 98% — …", "passed": true } ],
      "control": { "auto_response": false, "kill_switch": false }, "assets": 0, "assets_opted_in": 0, "points_enabled": 0, "auto_ttl_seconds": 60 }
  ],
  "summary": { "ok": 3, "warn": 0, "skipped": 1, "fail": 0 }
}
```

## 3. 데이터베이스 명세

마이그레이션 `f3a1c8d2e6b4_live_inspections` (down: `b7d3e9f1a2c4`). 추가만 하며 기존 테이블은 건드리지 않는다.
JSON 열은 PostgreSQL에서 `JSONB`, SQLite에서 `JSON`.

### `live_inspections` — 검사 1건 = 1행

| 열 | 타입 | 설명 |
|---|---|---|
| `id` | `varchar(36)` PK | UUID |
| `interface` | `varchar(32)` | 인터페이스 이름 |
| `address` | `varchar(45)` | 인터페이스 IPv4 (카운터 검사 이벤트의 목적지) |
| `mode` | `varchar(16)` | `packet` \| `counters` |
| `status` | `varchar(16)`, index | `running` \| `completed` \| `cancelled` \| `failed` \| `interrupted` |
| `duration_seconds` / `elapsed_seconds` | `integer` | 요청 초 / 실제 관측 초 |
| `started_at` (index) / `finished_at` | `timestamptz` | |
| `error` | `varchar(240)` | `failed`일 때 사유 |
| `thresholds` | `jsonb` | 시작 당시 규칙 임계값 스냅샷 |
| `detection_mode` | `varchar(16)` | 시작 당시 엔진(`hybrid` \| `rules_only`) |
| `totals` | `jsonb` | 단계 집계: `packets, bytes, peak_pps, flows, seconds, checked, rule_hits{}, scored, min_score, model_hits, events, automatic{applied,declined,other}` |
| `event_ids` | `jsonb` | 이 검사가 만든 `detection_events.id` 목록 |
| `incident_ids` | `jsonb` | 묶인 `incidents.id` 목록 |

### `live_inspection_windows` — 관측 1초 = 1행

| 열 | 타입 | 설명 |
|---|---|---|
| `id` | `bigint` PK | |
| `run_id` | `varchar(36)` FK → `live_inspections.id`, index | |
| `second` | `integer` | 0부터. `(run_id, second)` 유일 |
| `observed_at` | `timestamptz`, index | 보존 정책 기준 |
| `pkt_rate` / `byte_rate` | `double precision` | 그 초의 합계(패킷 검사는 흐름 합) |
| `flows` | `integer` | 그 초에 관측한 흐름 수 |
| `rule_hits` | `jsonb` | `{ "TRAFFIC_SPIKE": 1 }` 등 |
| `scored` / `min_score` | `integer` / `double precision` | 모델 점수 수 · 최저 점수 |
| `events` | `jsonb` | 그 초에 만든 탐지 `[{event_id, attack_type, severity, incident_id, automatic}]` |

탐지 이벤트 자체는 기존 `detection_events`(source=`live`)와 `incidents`에 저장된다. 보존: `infra/ops_retention.py`가 `OPS_RETENTION_DAYS`(기본 30일)보다 오래된 창 행만 지운다(검사 행과 이벤트 연결은 유지).

## 4. 로컬 실행 — 웹앱 + 실제 API + Docker PostgreSQL

```bash
# 1) DB·Redis 컨테이너 (포트 25432 / 26379, 볼륨에 영속)
export DEV_POSTGRES_PASSWORD=ebpf-dev-local
docker compose -f docker-compose.dev.yml up -d

# 2) 스키마 적용
export DATABASE_URL="postgresql+asyncpg://ebpf_test:${DEV_POSTGRES_PASSWORD}@127.0.0.1:25432/ebpf_test"
.venv/bin/python -m alembic upgrade head

# 3) 백엔드 (관리자 토큰은 실시간 검사·임계값·시나리오 실행에 쓰인다)
ADMIN_TOKEN=local-admin-token REDIS_URL=redis://127.0.0.1:26379/0 OPS_ALLOW_INSECURE_LOCAL=true \\
  .venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# 4) 프론트엔드 (Vite가 /api·/health·/ws를 8000으로 프록시)
cd frontend && npm run dev            # http://127.0.0.1:5173/#live
```

확인:

```bash
# API로 10초 카운터 검사 시작 → 상세 조회
curl -s -H "Authorization: Bearer local-admin-token" http://127.0.0.1:8000/api/live/interfaces | head -c 400
curl -s -X POST -H "Authorization: Bearer local-admin-token" -H "Content-Type: application/json" \\
  -d '{"interface":"en0","mode":"counters","duration_seconds":10}' http://127.0.0.1:8000/api/live/inspections
# 저장 확인
docker exec ebpf-dev-postgres-1 psql -U ebpf_test -d ebpf_test \\
  -c "SELECT interface, mode, status, elapsed_seconds, (totals->>'packets')::float::int AS packets, jsonb_array_length(event_ids) AS events FROM live_inspections ORDER BY started_at DESC LIMIT 3;" \\
  -c "SELECT run_id, second, pkt_rate, byte_rate, rule_hits FROM live_inspection_windows ORDER BY observed_at DESC LIMIT 5;"
# 실제 PostgreSQL을 쓰는 통합 테스트까지 포함해 실행
TEST_DATABASE_URL="$DATABASE_URL" .venv/bin/python -m pytest -q
```

- `.env`의 `POSTGRES_HOST`가 비어 있으면 `DATABASE_URL`이 그대로 쓰인다. 운영 compose(`docker-compose.yml`)는 `POSTGRES_HOST=postgres`로 내부 네트워크만 사용한다.
- 패킷 검사까지 쓰려면 `pip install scapy` 후 백엔드를 sudo로 실행(또는 macOS ChmodBPF). 없으면 카운터 검사로 자동 전환된다.
