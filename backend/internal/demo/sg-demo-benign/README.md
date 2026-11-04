# sg-demo-benign

SupplyGuard 시연의 **정상 설치 대조군**이다. 순수 파이썬 모듈 하나(`sg_demo_benign.py`)뿐이고, 설치 중에
다른 프로그램 실행 · 직접 네트워크 접속 · 민감 파일 열기를 하지 않는다. 기본 정책에서 위반 없이 「통과」로 끝나야 한다.

```bash
tools/sg-install pip ./deploy/demo/sg-demo-benign
```

대시보드 시연(`POST /api/demo/run {"scenario":"benign"}`)은 같은 패키지를 `sg-install-demo-*` 컨테이너에서 설치한다.
