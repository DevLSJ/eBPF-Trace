# 2026-09-17 · 레이블 연동과 백엔드·프론트엔드 검증

## 구현 범위

- `/api/analysis/pcap`: 캡처와 정답 결합 보고서를 연결하고 피처 행 수 정합성을 검증한다. 원본 패킷 수, 시간대별 트래픽, 매칭률, 정답 분포, 미매칭·충돌·오류 건수와 SHA-256을 제공한다.
- `/api/analysis/model`: 오프라인 평가 보고서와 현재 런타임 탐지 상태를 별도로 제공한다. 평가 보고서가 없으면 `evaluation: null`이다.
- `/api/events?ip=`: 출발지 또는 목적지 IP를 기존 심각도·기간·유형 필터와 함께 검색한다. 잘못된 IP는 422로 거부한다.
- 프론트엔드: 대시보드·분석·설정을 분리하고 데스크톱 사이드바와 모바일 메뉴를 연결했다. 캡처 선택, 분당 트래픽, 프로토콜 구성, 정답 분포, 실제 성능, 혼동 행렬, JSON 내보내기, 오류 후 재시도를 제공한다.
- 데이터 결합: 제공 CSV의 인코딩·시각 형식·빈 행·음수 지속시간을 처리했다. 원본은 Git/Docker에서 제외한다.

## 입력 데이터 확인

사용자가 `label/`에 준비한 자료는 압축 해제된 `TrafficLabelling ` 폴더의 CSV 8개다. 목요일·금요일 PCAP에 해당하는 CSV 5개만 사용했다. 월·화·수 CSV는 대응 PCAP이 없어 이번 분석에 포함하지 않았다.

[공식 CIC-IDS2017 설명](https://www.unb.ca/cic/datasets/ids-2017.html)은 CSV에 타임스탬프·양쪽 IP·포트·프로토콜·정답이 포함되고, 캡처가 2017년 7월 3~7일 주간에 수행되었다고 설명한다. 아래 입력 해석은 공식 설명과 **제공된 파일의 실제 내용 및 PCAP 시각 정합**을 근거로 한다.

| 항목 | 확인 결과 및 처리 |
|---|---|
| 인코딩 | CP1252. Web Attack 레이블의 en dash를 보존한다. |
| 날짜 | `6/7/2017`, `7/7/2017`은 7월 6일·7일이다. |
| 시각 | `8:59`, `12:59`, `1:00` 등 AM/PM 없는 12시간 시계다. 주간 캡처에서 1~7시는 13~19시로 해석하고, 08~18시 범위 밖은 거부한다. |
| UTC 정합 | Friday 첫 동일 tuple의 CSV `7/7/2017 8:59`와 PCAP `1499428790.315195`(11:59:50 UTC), Thursday의 CSV `6/7/2017 8:59`와 PCAP `1499342340.49014`(11:59:00 UTC)가 UTC−03:00에 맞는다. `America/Halifax`를 명시한다. |
| 시간 해상도 | 초가 없어 시작 시각을 `[t, t+60초]`의 불확실 구간으로 취급한다. 정확히 `:00`에 시작했다고 가정하지 않는다. |
| 빈 행 | Thursday Morning CSV의 288,602개 빈 행을 제외한다. |
| 음수 지속시간 | Thursday 15개, Friday 47개를 제외한다. |
| 부동소수점 | 나노초 왕복 변환으로 역전된 1μs 이하 윈도우를 정규화했다(Thursday 29개, Friday 17개). 더 큰 역전은 오류로 거부한다. 전처리에서도 같은 허용 범위의 시작 시각 3개를 기록했다. |

## 정답 결합 정책과 결과

양방향 5-tuple을 비교한다. 가능한 모든 시작 시각에 대해 피처의 **관찰 구간 전체가 레이블 지속 구간 안에 포함**되어야 매칭한다. 겹칠 가능성이 있는 다른 정답이 존재하면 `AMBIGUOUS`로 제외한다. `UNLABELED`를 공격으로 치환하지 않는다.

| 항목 | Thursday | Friday |
|---|---:|---:|
| 입력 CSV 행 | 747,570 | 703,245 |
| 전체 피처 행 | 2,599,785 | 3,357,642 |
| 매칭 | 281,933 | 261,319 |
| 매칭률 | 10.84% | 7.78% |
| 미매칭 | 2,306,793 | 2,849,769 |
| 정답 충돌 | 11,059 | 246,554 |
| 매칭 BENIGN | 274,944 | 258,963 |
| 매칭 공격 | Infiltration 6,578 · XSS 411 | DDoS 2,356 |

수치는 **피처 행 수**다. 고유 플로우 수, 고유 공격 수 또는 전체 CSV의 공격 분포가 아니다. 짧은 Bot·PortScan 등의 피처는 이 정책으로 매칭되지 않아 평가에 포함되지 않았다. 상세 원본 분포와 해시는 [목요일](../ml/reports/labels/thursday.json), [금요일](../ml/reports/labels/friday.json)에 있다.

## 실제 모델 평가

두 날의 매칭된 543,252행을 결합했다. 시간순 70% 지점 양쪽 10초 및 경계를 가로지르는 플로우를 제외하고, scaler와 Isolation Forest는 정상 학습 행에만 적합했다. `n_estimators=100`, `contamination=0.05`, `random_state=42`, 점수 임계값 `-0.1`을 사용했다. 평가 후 수치가 유리하도록 임계값을 바꾸지 않았다.

| 분리 | 피처 행 |
|---|---:|
| 정상 학습 | 373,239 |
| 시간순 평가 | 161,667 |
| 경계·장기 플로우 제외 | 1,357 |

| 지표 | 실측 | 목표 |
|---|---:|---:|
| Precision | 2.7530% | — |
| Recall | 2.8862% | — |
| F1 | 2.8181% | ≥80% |
| FPR | 1.5077% | ≤5% |
| TN / FP / FN / TP | 156,909 / 2,402 / 2,288 / 68 | — |

**목표 미달이며 운영 미승인이다.** 긴 플로우에 치우친 매칭 표본이라 전체 CIC-IDS2017 벤치마크 성능으로 해석할 수 없다. 같은 분 단위 프로필 실험에서는 수치 목표를 충족하더라도 `deployment_eligible=false`로 남긴다. 모델 파일은 로컬 `ml/models/cic2017-experiment/`에만 생성했고 운영 서버에 복사하지 않았다. 공개 보고서는 [combined.json](../ml/reports/evaluation/combined.json)이다.

## 검증

| 검사 | 결과 |
|---|---|
| Python 전체 + 실제 PostgreSQL/Redis | **49 passed** (`infra/test_remote.py`) |
| Ruff | `backend collector ml infra` 통과 |
| 프론트엔드 | TypeScript·Vite production build 통과 |
| Playwright | **12 passed** — 데스크톱·390px 모바일 |
| 브라우저 동작 | 필터·페이지 이동·상세·내보내기·토큰 인증·설정 저장·재연결·IP 검색·캡처 전환·분석 오류 복구 |
| 데이터 보호 | 분 단위 시간 불확실성·다른 정답 충돌·CP1252·빈 행·음수 지속시간·정오 해석·해시 불일치·평가와 운영 상태 분리 회귀 검사 |
| 화면 | 데스크톱·모바일 가로 넘침 없음, 분석 시나리오 JavaScript 오류 없음 |

Starlette/httpx 관련 의존성 deprecation 경고 2개는 남아 있다. 이번 작업에서는 Linux 커널·격리망 공격·장애복구·Slack 발송·Terraform·HTTPS를 새로 측정하거나 변경하지 않았다.

## 재현

[운영 가이드의 명령](operations.md#탐지학습)으로 PCAP 피처 변환 → 레이블 결합 → `ml.evaluate_dataset`을 실행한다. CI는 원본 수 GB를 다운로드하지 않으며, 커밋된 작은 보고서와 회귀 fixture로 API/UI를 검증한다.

운영 화면 캡처는 `docs/scripts/capture.mjs`로 수행한다. 실제 운영 API만 조회하고 이벤트나 트래픽을 주입하지 않는다. 캡처 시점·연결 상태·실측 값은 [capture-manifest.json](screenshots/capture-manifest.json)에 기록한다.

## 배포 및 운영 화면

기능 커밋 [`da3f62d`](https://github.com/DevLSJ/eBPF-Trace/commit/da3f62db97891632a66ba6c8f02e2599105cf200)를 `main`에 푸시했다. GitHub에서 실제 PostgreSQL/Redis·브라우저·eBPF 컴파일 검사와 amd64 이미지 빌드가 통과했다.

VM runner 재시작과 진행 중인 배포가 겹쳐 최초 Actions의 배포 단계는 중단 상태로 끝났다. 서버에서는 새 이미지와 release pointer까지 적용된 것을 확인했다. 배포 재시도를 위해 사용 중인 컨테이너가 없는 예전 `local/ebpf-ids-{backend,frontend}:dev` 이미지 2개만 제거해 가용 공간을 674 MiB에서 1,046 MiB로 확보했다. 현재·직전 배포 이미지와 모든 DB 볼륨은 보존했다.

공개 주소에서 `/health`의 DB/Redis 정상, Collector 연결 true, rules_only를 확인했다. 새 분석 API가 커밋된 평가 수치를 반환하고 IP 검색이 적용되는 것도 확인했다. 운영 화면 4개를 저장했으며 JavaScript 오류 0개, 데스크톱·모바일 가로 넘침 없음이다.

배포 작업 재실행은 **성공**했다. [GitHub Actions 35165796214](https://github.com/DevLSJ/eBPF-Trace/actions/runs/35165796214)의 테스트·이미지 빌드·배포가 모두 성공이며, `/home/ubuntu/ebpf-current`와 실행 중인 backend/frontend 이미지 태그가 모두 `da3f62db97891632a66ba6c8f02e2599105cf200`을 가리킨다.
