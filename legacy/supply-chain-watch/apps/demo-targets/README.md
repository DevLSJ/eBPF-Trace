# demo-targets — 런타임 축 모사 환경 (Phase R, docs/13 §8)

공격 시연 전용 서비스들. **방어 목적·무해 데모**이며 실제 결제·외부 전송은 없다.

| 서비스 | 컨테이너 / IP (carrot-net 10.77.0.0/24) | 역할 |
|---|---|---|
| `edge/` (nginx) | carrot-edge / 10.77.0.2, 호스트 `:8088` | 앱이 부르는 단일 입구. `/api/pay/*`, `/api/image/*` |
| `carrot-pay-service/` (Node/Express) | 10.77.0.11 | 안전결제 → 주문 저장 (`POST /pay`, `GET /orders/:id`) |
| `carrot-image-service/` (Python/FastAPI) | 10.77.0.12 | 사진 올리기 → 썸네일 저장 (`POST /upload`) |
| postgres / redis | 10.77.0.10 / 10.77.0.13 | 주문 DB / 캐시 (호스트 미노출) |
| `fake-c2/` | 10.77.0.66:9001 | 가짜 외부 서버. 요청 메타데이터만 로그, 본문은 버림. 호스트에서 접근 불가 |

```bash
docker compose -f infra/docker-compose.runtime.yml up -d --build   # 기동
curl localhost:8088/api/pay/health                                 # 헬스
docker logs -f carrot-fake-c2                                      # 가짜 외부 서버 수신 로그
docker compose -f infra/docker-compose.runtime.yml down            # 종료(데이터 초기화)
```

오염 데모 패키지와 트리거는 Phase R-2, 웹 모사 앱(`shop-web`)은 ADR-019에 따라 모바일 앱(`apps/mobile-shop`)으로 대체한다.
