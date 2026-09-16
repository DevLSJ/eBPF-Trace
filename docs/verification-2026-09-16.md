# 2026-09-16 개발 및 검증

## 범위

기존 Markdown 문서와 사용자가 제공한 `pcap/`의 Thursday/Friday 캡처를 바탕으로 개발을 이어갔다. 원본 PCAP과 생성 피처, 비밀 설정은 Git/Docker 이미지에서 제외한다. 기존 9월 11일·15일 문서는 당시 기록으로 보존한다.

## 실제 캡처 분석

| 항목 | Thursday | Friday |
|---|---:|---:|
| 파일 bytes | 8,302,500,180 | 8,839,309,056 |
| 형식 | PCAPNG | PCAPNG |
| 전체 패킷 | 9,322,025 | 9,997,874 |
| 분석 가능한 IPv4 TCP/UDP 패킷 | 9,238,976 | 9,914,144 |
| 피처 행 | 2,599,785 | 3,357,642 |
| Port Scan 규칙에 해당한 행 | 442,088 | 927,974 |
| SYN Flood 규칙에 해당한 행 | 51,977 | 14 |
| 시각 역전으로 clamp한 패킷 | 3,661 | 8,324 |
| 65,536 플로우 한도에 따른 제거 | 465,405 | 809,584 |

두 파일 모두 끝까지 읽었으며 원본 SHA-256, 시작/종료 시각, 제외 사유, 분 단위 패킷/바이트 합계를 `ml/reports/{thursday,friday}.json`에 기록했다. 출력은 로컬 `ml/data/{thursday,friday}-features.csv.gz`에 있다.

출발지별 10초 이력을 매번 순회하던 코드를 증분 포트 카운터/엔트로피 계산으로 바꿨다. 3,000개 무작위 snapshot 회귀 테스트로 이전 수식과 비교했다. Friday 전체 변환은 기존 1,259.15초, 최적화 후 229.21초였다. 후자는 Thursday와 동시에 실행했으므로 엄밀한 벤치마크 비율로 일반화하지 않는다. 패킷 수·피처 행·규칙 탐지 횟수는 전후 정확히 일치했다.

이 결과는 **규칙에 해당하는 피처 행 수**다. 고유 공격 수나 탐지 성능이 아니다. 공식 정답 CSV가 없어 실제 모델 학습, Precision/Recall/F1/FPR은 산출하지 않았다. 공개 공격 시간표로 정답을 추정하지 않았다. 100ms snapshot/1초 flush 모사는 실제 BPF ring/스레드 스케줄링의 완전한 재현을 보장하지 않는다.

## 구현

- PCAP/PCAPNG endian·인터페이스·시각 해상도·offset 처리, 잘린 캡처/블록 길이 오류 거부, VLAN/SYN/fragment 판정.
- `ml.labels`: GeneratedLabelledFlows CSV/폴더/ZIP과 양방향 5-tuple·관찰 구간 결합. 시간대/형식 명시 필수. 충돌은 AMBIGUOUS, 미매칭은 UNLABELED.
- 시간 순서 분리, 경계 양쪽 10초 및 경계를 넘는 장기 플로우 제거. 미지정/충돌 레이블을 공격 정답으로 간주하던 위험 제거.
- 검증 결과·분리 이력·피처 순서·sklearn 버전·모델/스케일러 SHA-256 확인 후 모델 역직렬화. 실패 시 rules_only.
- F-M03에 맞춰 고유 목적지 포트 수로 Port Scan 판정. `port_entropy_threshold`는 호환 API 필드로만 유지.
- 홈페이지 이벤트 상세, 유형 필터, 페이지 내보내기, 캡처 선택, 관리자 임계값 설정. 토큰은 저장하지 않고 공개 HTTP 화면에서는 입력을 막는다. HTTPS 또는 localhost SSH 터널에서 수정 가능.
- 오프라인/온라인 이벤트 처리, 재연결 후 REST 목록 복구, REST 기준 페이지 합계, 오래된 WS 재전송의 시계열 덮어쓰기 방지. SQLite 시각에 UTC 명시.
- CI에 실제 PostgreSQL/Redis와 브라우저 E2E 추가. Docker 빌드를 GitHub Ubuntu runner로 이동하고 EC2에 최소 공간 검사/`--no-build` 배포 적용.

## 검증

| 검사 | 결과 |
|---|---|
| Python 단위/API/fixture | 40 passed, 외부 서비스 2 skipped (Slack opt-in 회귀 추가 전) |
| EC2 전용 테스트 PostgreSQL/Redis 포함 전체 | **43 passed**, skip 없음 (Slack opt-in 회귀 포함) |
| Ruff | 통과 |
| TypeScript / Vite | 통과; 차트 청크 분리로 기존 500 kB 경고 해소 |
| 프론트 검증 | **8 passed**: 실제 FastAPI+Chrome UI 6개, 상태 스토어 회귀 2개 (1440×1000, 390×844) |
| PCAP 전체 분석 | 두 파일 EOF 완료·SHA-256 기록 |
| Git diff / 배포 shell 문법 | 통과 |
| VM 기동 후 상태 | GitHub runner online/idle, 운영 Collector 연결 true |

브라우저 검사는 실제 격리 SQLite API를 사용한다. 상세·필터·페이지·JSON 다운로드·두 캡처 선택, 관리자 인증 거부/성공/저장 후 재조회, 오류 재시도, 오프라인/온라인 재연결을 확인했다. UI 테스트 데이터는 `infra.e2e_app` 전용이며 운영 .env/Slack을 사용하지 않는다.

초기 브라우저 검사에서 빈 차트의 임계값 표시 누락과 오프라인 시 연결 상태가 유지되는 문제를 발견해 수정했다. Python 테스트의 Starlette/httpx 및 AnyIO deprecation warning 2개는 남아 있다.

재현:

```bash
.venv/bin/python -m pytest -q -rs
.venv/bin/python -m ruff check backend collector ml infra
.venv/bin/python infra/test_remote.py  # README의 SSH 테스트 터널 필요
cd frontend
npm run build
npx playwright install chromium
npm run test:e2e
```

## 배포 및 남은 조건

첫 구현 커밋 `684a752`를 main에 푸시했다. Actions의 Redis health 명령 인수 따옴표 처리 오류를 수정한 `71a367c`는 [검사·빌드·배포 모두 성공](https://github.com/DevLSJ/eBPF-Trace/actions/runs/35069687423)했다. 운영 브라우저에서 두 캡처 선택·이벤트 상세·데스크톱/모바일 화면을 확인했으며 JS 오류와 가로 넘침은 없었다. 운영 DB/Redis는 9월 11일 생성된 기존 컨테이너와 볼륨을 유지했다.

배포 후 `/home/ubuntu/ebpf-current` 링크 누락을 확인해 컨테이너 exec의 대화형 입력을 끄고 배포 subprocess stdin을 `/dev/null`로 분리했다. 후속 커밋 `2eae69b`는 링크 생성 뒤 실제 대상까지 검사한다. VM 수집기 소스는 웹/API 자동 배포 범위 밖이며 기존 피처 형식은 호환된다.

배포 전 `.env`에는 Webhook이 있었으나 실행 컨테이너에는 없음을 값 노출 없이 확인했다. 기존 미활성 상태를 보존하도록 `SLACK_ENABLED=false`를 기본값으로 추가했으며 회귀 테스트로 저장된 URL만으로 발송되지 않음을 확인했다. 실제 발송은 수행하지 않았다.

최종 `2eae69beb6f220828ccdf7166ea04e12c8f8d751`의 [Actions 실행 35070522692](https://github.com/DevLSJ/eBPF-Trace/actions/runs/35070522692)는 검사·이미지 빌드·배포 모두 성공했다. backend/frontend 실행 이미지 태그와 `/home/ubuntu/ebpf-current`가 같은 SHA를 가리키는 것을 SSH로 확인했다. 공개 주소 `http://52.62.165.10`에서 재검증한 결과 DB/Redis ok, Collector 연결 true, rules_only, 두 PCAP 보고서 정상, JS 오류 0개, 모바일 가로 넘침 없음이었다. 정답 CSV 부재에 따른 rules_only 상태는 의도된 결과다.

배포 후 여유 공간이 686 MiB로 줄어 이번 작업의 중간 SHA `71a367c` backend/frontend 이미지가 어떤 컨테이너에서도 사용되지 않음을 확인하고 해당 2개만 `docker image rm`으로 제거했다. 여유는 약 1.1 GiB로 복구했다. Docker Hub에서 같은 SHA를 다시 받을 수 있으며 기존 dev 이미지, 현재 실행 이미지, 컨테이너, DB/Redis 볼륨은 삭제하지 않았다. 다음 이미지 크기에 따라 사전 디스크 검사가 배포를 중단할 수 있으므로 장기적인 용량 계획은 여전히 필요하다.

실제 CIC 정답 CSV, 모델 성능, Slack 실제 전송, Terraform 기존 자원 편입/SG 확인, HTTPS, 최종 격리망·부하·장애복구 재검증은 남아 있다. 과거 커널 실측을 이번 재검증으로 표시하지 않는다. 릴리즈 `v1.0.0`은 발행하지 않았다.

근거: [CIC 데이터 구조](https://www.unb.ca/cic/datasets/ids-2017.html), [PCAPNG 형식](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-05.html), [GitHub의 Docker 이미지 빌드](https://docs.docker.com/build/ci/github-actions/multi-platform/), 각 로컬 구현·테스트 및 생성 보고서.
