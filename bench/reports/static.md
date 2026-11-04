# 공급망 검사 실측 (2026-11-04T01:22:53Z)

GuardDog 3.2.0 · OSV-Scanner 2.7.0 · 백엔드 a5af1f9b020cd226f9e0ccfb3ed101bdcf049f40

| 세트 | 종류 | 전체 | 검사 | 건너뜀 | 악성 | 취약 | 주의 | 정상 | 오류 | 악성 비율 | 악성+주의 |
|---|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| datadog-pypi | malicious | 300 | 297 | 내용 없음(메타데이터만) 3 | 210 | 3 | 30 | 54 | 0 | 70.7% | 80.8% |
| datadog-npm | malicious | 300 | 297 | 업로드 50MB 초과 3 | 194 | 1 | 35 | 67 | 0 | 65.3% | 77.1% |
| benign-pypi | benign | 300 | 300 | 0 | 8 | 2 | 5 | 285 | 0 | 2.7% | 4.3% |
| benign-pypi-sdist (보조) | benign | 300 | 300 | 0 | 14 | 58 | 7 | 220 | 1 | 4.7% | 7.0% |

| 지표 | 전체 | npm | pypi |
|---|---:|---:|---:|
| 탐지율(악성 판정) | 68.0% | 65.3% | 70.7% |
| 탐지율(악성+주의) | 79.0% | 77.1% | 80.8% |
| 오탐률(악성 판정) | 2.7% | - | 2.7% |
| 오탐률(악성+주의) | 4.3% | - | 4.3% |
| 정밀도 | 98.1% | 100.0% | 96.3% |
| F1 | 80.3% | 79.0% | 81.6% |

혼동 행렬(양성 = 악성 판정): TP 404 · FN 190 · FP 8 · TN 292 · 검사 시간 p50 1.18s · p95 6.39s

| 규칙 | 설치 시점 | 악성 세트 | 정상 세트 |
|---|---|---:|---:|
| capability-process-spawn |  | 350 | 113 |
| capability-process-hooks |  | 275 | 0 |
| capability-network-outbound |  | 264 | 105 |
| capability-network-download |  | 199 | 41 |
| threat-process-hooks |  | 181 | 0 |
| threat-network-outbound-shady-links |  | 163 | 2 |
| capability-filesystem-read |  | 160 | 160 |
| threat-network-exfiltration | 예 | 123 | 3 |
| threat-process-download-exec | 예 | 120 | 5 |
| threat-npm-preinstall-script | 예 | 116 | 0 |
| threat-network-exfil-sysinfo | 예 | 112 | 1 |
| threat-runtime-system-info |  | 106 | 3 |
| threat-setup-suspicious-imports | 예 | 73 | 0 |
| threat-process-powershell-encoded |  | 70 | 0 |
| threat-filesystem-read |  | 63 | 12 |
| capability-filesystem-delete |  | 62 | 80 |
| threat-setup-network-in-install | 예 | 53 | 0 |
| capability-network-lolbas |  | 43 | 3 |
| threat-runtime-obfuscation-base64exec |  | 39 | 0 |
| capability-filesystem-write-executable |  | 38 | 54 |
| threat-runtime-environment-read |  | 36 | 13 |
| threat-runtime-self-propagation | 예 | 32 | 0 |
| threat-network-exfil-messenger | 예 | 31 | 0 |
| threat-process-spawn-silent |  | 29 | 3 |
| threat-runtime-obfuscation-js-mangling |  | 23 | 0 |
| threat-npm-dependency-confusion | 예 | 18 | 0 |
| capability-filesystem-browser |  | 15 | 0 |
| capability-process-schedule |  | 15 | 25 |
| threat-runtime-obfuscation |  | 11 | 1 |
| threat-filesystem-autostart |  | 11 | 3 |
| threat-runtime-obfuscation-chr |  | 7 | 0 |
| threat-filesystem-destruction |  | 6 | 0 |
| threat-setup-import-aliasing | 예 | 6 | 0 |
| threat-npm-http-dependency | 예 | 5 | 0 |
| threat-process-sysinfo |  | 4 | 0 |
| threat-runtime-obfuscation-steganography |  | 4 | 4 |
| threat-network-dns-exfil | 예 | 3 | 0 |
| threat-network-reverse-shell | 예 | 3 | 0 |
| threat-runtime-obfuscation-general |  | 3 | 0 |
| threat-runtime-obfuscation-import-exec |  | 3 | 0 |

한계:
- 정상 세트는 PyPI 만이다 — npm 은 탐지율만 있고 오탐률은 재지 않았다(정밀도 npm 100%는 정상 표본이 없어서다).
- 주 정상 세트는 wheel 이라 setup.py 가 없다. 같은 300개를 레지스트리 sdist 로 받은 보조 세트(지표 제외)는 악성 판정 4.7% · 악성+주의 7.0% 로 wheel(2.7% · 4.3%)보다 높다.
- DataDog 세트는 2026-10-12 에 생태계별 300개만 받은 일부(경로 정렬 상위)다. 같은 패키지의 다른 버전이 섞여 있다(packageGroup 으로 묶음, PyPI 273 · npm 283 묶음).
- 악성 zip 은 공통 경로 접두를 걷어 tar.gz 로 다시 묶은 파일 검사다 — 레지스트리 패키지 검사와 달리 자기 버전 OSV 조회가 없다.
- GuardDog 과 데이터셋이 모두 DataDog 것이라 규칙이 이 데이터에 맞춰져 있을 수 있다 — 낙관적인 탐지율일 수 있다.
- 오류(error)는 지표 분모에서 뺐다. 건너뜀: 메타데이터만 있는 zip 3 · 50MB 초과 3(PyPI 보조 세트의 50MB 초과 sdist 1건은 백엔드가 오류로 끝냄).
- 정밀도는 세트 크기 비율(악성 594 : 정상 300)에 좌우된다. 실제 레지스트리의 악성 비율에서는 훨씬 낮다.
- 검사 시간은 백엔드 기록(시작~끝)이며 SCAN_CONCURRENCY=1 · sg-vm(arm64 4코어 8GB) 기준이다.
