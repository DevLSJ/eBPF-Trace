# demo-packages — 자체 제작 무해 데모 패키지 (Phase R, docs/13 §8, ADR-019)

공급망 공격 탐지 시스템의 **런타임 축을 시연하기 위한 무해 패키지**들이다. 오염된 의존성이
배포 후 하는 전형적 행동(외부 서버 비콘)을 **무해하게** 흉내 낸다.

| 패키지 | 생태계 | 사용처 | 오염 동작 |
|---|---|---|---|
| `pay-analytics-demo` | npm | carrot-pay-service | `track()` 호출 시 `sh -c → curl`로 fake-c2 비콘 |
| `img-optimize-demo` | pip | carrot-image-service | `optimize()` 호출 시 `sh -c → curl`로 fake-c2 비콘 |

- 접속 대상은 compose 내부 `fake-c2`(`http://fake-c2:9001/beacon`)뿐이며 환경변수로 바꿀 수 있다.
- 보내는 내용은 고정 문자열(`?e=pay` 등)이고 실제 비밀값·환경변수는 전송하지 않는다.
- **실제 npm/PyPI 레지스트리에 배포 금지.** 지금은 서비스 이미지에 `file:` 의존성(vendor/)으로 설치한다.
- Phase R-13에서 DevLSJ GitHub 레포로 push하고 git 의존성으로 전환해, 커밋 검사(축 1)와 런타임 차단(축 2)을 한 흐름으로 잇는다.
