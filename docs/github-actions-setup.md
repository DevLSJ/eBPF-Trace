# GitHub Actions 설정 가이드

eBPF-trace 레포지토리에서 CI/CD 파이프라인을 실행하기 위해 필요한
Secrets 등록과 Self-Hosted Runner 연결 방법을 단계별로 설명합니다.

---

## 전체 구조 요약

```
[Mac 로컬] git push
     │
     ▼
[GitHub] ci-cd.yml 트리거
     │
     ▼
[Linux VM 192.168.64.255] ← self-hosted runner
     │  CI (린트/빌드/테스트)
     │  Docker 이미지 빌드 & Docker Hub 푸시
     │
     ▼ SSH 접속
[AWS EC2 52.62.165.10]
     docker compose pull & up
```

---

## Step 1. GitHub Secrets 등록

GitHub 레포 → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

| Secret 이름 | 값 | 설명 |
|---|---|---|
| `DOCKERHUB_USERNAME` | Docker Hub 아이디 | 예: `myusername` |
| `DOCKERHUB_TOKEN` | Docker Hub Access Token | 아래 발급 방법 참고 |
| `EC2_HOST` | `52.62.165.10` | EC2 퍼블릭 IP |
| `EC2_USER` | `ubuntu` | EC2 SSH 사용자 이름 |
| `EC2_SSH_KEY` | `.pem` 파일 전체 내용 | 아래 복사 방법 참고 |

### Docker Hub Access Token 발급

1. [hub.docker.com](https://hub.docker.com) 로그인
2. 우측 상단 프로필 → **Account Settings** → **Security**
3. **New Access Token** → 이름 입력 → **Read, Write, Delete** 권한 선택
4. 생성된 토큰 값을 `DOCKERHUB_TOKEN`에 붙여넣기

### EC2_SSH_KEY 복사 방법

Mac 터미널에서 다음 명령어로 `.pem` 파일 내용을 클립보드에 복사합니다.

```bash
# 프로젝트 루트에서 실행
cat "don forget.pem" | pbcopy
```

복사된 내용을 `EC2_SSH_KEY` Secret 값에 그대로 붙여넣습니다.
`-----BEGIN RSA PRIVATE KEY-----` 첫 줄부터 `-----END RSA PRIVATE KEY-----` 마지막 줄까지 전체 포함해야 합니다.

---

## Step 2. Self-Hosted Runner 등록 (Linux VM)

### 2-1. GitHub에서 Runner Token 발급

1. GitHub 레포 → **Settings** → **Actions** → **Runners**
2. **New self-hosted runner** 클릭
3. OS: **Linux**, Architecture: **x64** 선택
4. **"Configure"** 섹션의 `--token` 값 복사 (약 30분 유효)

### 2-2. Linux VM에 SSH 접속

```bash
ssh ubuntu@192.168.64.255
```

### 2-3. 설치 스크립트 실행

레포를 클론하거나 스크립트를 직접 VM에 복사한 후 실행합니다.

```bash
# 방법 A: 레포 클론 후 실행
git clone https://github.com/YourOrg/eBPF-trace.git
cd eBPF-trace
chmod +x infra/setup-runner.sh
./infra/setup-runner.sh https://github.com/YourOrg/eBPF-trace <RUNNER_TOKEN>

# 방법 B: scp로 스크립트만 복사
scp infra/setup-runner.sh ubuntu@192.168.64.255:~/
ssh ubuntu@192.168.64.255 "chmod +x setup-runner.sh && ./setup-runner.sh https://github.com/YourOrg/eBPF-trace <RUNNER_TOKEN>"
```

> `YourOrg/eBPF-trace` 부분을 실제 GitHub 레포 경로로 교체하세요.

### 2-4. 등록 확인

GitHub 레포 → **Settings** → **Actions** → **Runners** 에서
`ebpf-linux-vm` 이 **Idle (초록)** 상태로 표시되면 완료입니다.

---

## Step 3. EC2 서버 초기 설정

EC2에는 Docker와 Git만 있으면 됩니다. 처음 배포 전 1회만 실행합니다.

```bash
# EC2에 SSH 접속
ssh -i "don forget.pem" ubuntu@52.62.165.10

# Docker 설치
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker ubuntu
newgrp docker

# 프로젝트 클론 (최초 1회)
git clone https://github.com/YourOrg/eBPF-trace.git ~/ebpf-project
cd ~/ebpf-project

# .env 파일 생성 (GitHub Actions가 git pull만 하므로 .env는 EC2에 직접 관리)
cp .env.example .env
nano .env   # 실제 값으로 수정
```

---

## Step 4. 파이프라인 동작 확인

### 트리거 조건

| 이벤트 | CI | Docker Build | EC2 배포 |
|---|---|---|---|
| `main` 브랜치 push | ✅ | ✅ | ✅ |
| `develop` 브랜치 push | ✅ | ✅ | ❌ |
| PR (→ main) | ✅ | ❌ | ❌ |

### 첫 번째 push 테스트

```bash
# Mac 로컬에서
cd /Users/ineb_lsj/Documents/eBPF-project
git add .github/workflows/ci-cd.yml
git commit -m "ci: GitHub Actions CI/CD 파이프라인 추가"
git push origin main
```

push 후 GitHub 레포 → **Actions** 탭에서 실행 상태를 확인합니다.

---

## 문제 해결

### Runner가 Offline 상태인 경우

```bash
ssh ubuntu@192.168.64.255

# 서비스 상태 확인
sudo systemctl status actions.runner.*.service

# 로그 확인
sudo journalctl -u actions.runner.*.service -n 50

# 서비스 재시작
cd ~/actions-runner
sudo ./svc.sh restart
```

### EC2 배포 실패 시 — SSH 연결 오류

1. EC2 Security Group에서 인바운드 SSH(22번) 포트가 허용되어 있는지 확인
2. `EC2_SSH_KEY` Secret에 `.pem` 파일 내용이 정확히 복사됐는지 확인 (개행 포함)

### Docker 이미지 푸시 실패

```bash
# Linux VM에서 Docker 로그인 상태 확인
docker login
```

`DOCKERHUB_USERNAME` 과 `DOCKERHUB_TOKEN` 이 일치하는지 재확인합니다.
