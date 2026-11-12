"""fake-c2 — 공격 시연용 '가짜 외부 서버' (docs/13 §8, ADR-008).

compose 내부 네트워크에서만 접근 가능하다. 받은 요청은 메타데이터(시각·출발지·경로·크기)만
로그로 출력하고, 본문은 저장·출력·전달하지 않는다. 런타임 탐지가 '허용되지 않은 접속'을
관측할 대상을 제공하는 것이 유일한 목적이다.
"""

import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 9001
MAX_DRAIN = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "fake-c2"

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(min(length, MAX_DRAIN))  # 버린다 — 내용은 보지 않는다
        if self.path != "/health":
            print(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "svc": "fake-c2",
                "src": self.client_address[0],
                "method": self.command,
                "path": self.path.split("?", 1)[0][:128],
                "bytes": length,
            }), flush=True)
        self.send_response(204 if self.path != "/health" else 200)
        self.end_headers()

    do_GET = do_POST = do_PUT = _handle

    def log_message(self, *args) -> None:  # 기본 접근 로그 끔 (위 JSON 한 줄만)
        pass


if __name__ == "__main__":
    print(json.dumps({"svc": "fake-c2", "msg": f"listening on :{PORT} (log-only)"}), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
