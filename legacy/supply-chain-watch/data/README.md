# data/ — 외부 평가 데이터 (git 추적 제외)

정적 분석 룰의 탐지율·오탐률을 재기 위한 외부 공개 데이터. 받기: `bash scripts/fetch-datasets.sh` (실제 커밋은 `python3 -I scripts/fetch_real_commits.py data/real-commits 20`).
이 README만 커밋되고, 나머지는 `.gitignore`로 제외된다. 출처·커밋은 `SOURCES.tsv`에 기록된다.

| 폴더 | 출처 | 내용 | 용도 | 위험도 |
|---|---|---|---|---|
| `zizmor/` | [zizmorcore/zizmor](https://github.com/zizmorcore/zizmor) (MIT) | GitHub Actions 보안 검사기의 테스트 워크플로우 YAML | `CI_*` 룰 | 낮음 (설정 파일) |
| `guarddog/` | [DataDog/guarddog](https://github.com/DataDog/guarddog) (Apache-2.0) | 악성 패키지 탐지 룰과 테스트 예시 | 일반 룰 참고 | 낮음 |
| `ossf/` | [ossf/malicious-packages](https://github.com/ossf/malicious-packages) | 악성 패키지 보고서(OSV JSON, 코드 없음) 일부 | 타이포스쿼팅 이름 목록, 통계 | 낮음 |
| `datadog/` | [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (Apache-2.0) | **실제 악성** npm·PyPI 패키지 일부 (암호 zip) | 실전 탐지율 | **높음** |
| `real-commits/` | GitHub API (유명 JS/TS·파이썬 레포 20개 최근 커밋) | 실제 커밋 JSON(files[].patch) | LLM 호출 비율(게이트 통과율) | 낮음 |

## 안전 규칙 (datadog/)
- zip은 **암호가 걸린 상태 그대로** 둔다. 풀어야 할 때는 평가 스크립트가 임시 폴더에서 텍스트로만 읽는다.
- `npm install`, `pip install`, `python setup.py`, `node` 실행 금지. 어떤 파일도 실행하지 않는다.
- 이 폴더의 내용은 커밋·push·공유하지 않는다. 보고서에는 수치만 인용한다.
- 개수 늘리기: `DATADOG_LIMIT=100 bash scripts/fetch-datasets.sh datadog`
