# reqeusts — 타이포스쿼팅 데모 패키지 (무해)

`requests` 의 오타를 노린 악성 패키지를 흉내 낸 **시뮬레이션**이다. 실제 악성 행위는 없다.
`setup.py` 가 설치 단계에서 세 가지 행동을 흉내만 낸다:

1. `sh -c "wget ... | sh"` — 외부 스크립트 실행 패턴 (목적지는 TEST-NET, 아무것도 받지 못함)
2. `/etc/shadow`·`/root/.ssh/id_rsa` 열기 시도 — 내용은 읽지도 보내지도 않음
3. `203.0.113.7:4444` 연결 시도 — RFC 5737 예약 대역이라 타임아웃

## 실행 (반드시 감시 컨테이너 안에서)

```bash
make sandbox-up                          # 가젯 소스 백엔드를 :8000 에 띄운다
tools/sg-install pip ./deploy/demo/reqeusts
```

정책(`sandbox-secrets`·`no-shell-download`·`sandbox-egress`)에 걸려 컨테이너가 SIGKILL 로 격리되고,
`sg-install` 이 위반 목록을 출력하며 종료 코드 2 로 끝난다. 목적지·파일은 전부 무해하므로
개발자 PC 나 네트워크에 영향이 없다.
