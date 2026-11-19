"""수집기의 통신 함수 http() 가 읽는 중 끊김도 다시 시도하는가(네트워크 없이) — python3 -B -m unittest discover -s bench/v2 -p 'test_*.py'

2026-11-18 v3 정상 수집에서 순위 목록을 받다가 http.client.IncompleteRead 로 수집이 통째로 멈췄다.
IncompleteRead 는 OSError 가 아니라 http.client.HTTPException 이어서 다시 시도 목록에 없었다.
"""
import gzip
import http.client
import os
import sys
import unittest
import urllib.error
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import collect  # noqa: E402


class FakeResponse:
    def __init__(self, body, headers=None, fail_read=None):
        self._body = body
        self.headers = headers or {}
        self._fail_read = fail_read

    def read(self, n=None):
        if self._fail_read is not None:
            raise self._fail_read
        return self._body if n is None else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def run_http(responses, **kw):
    """urlopen 이 차례로 responses 를 돌려주게(예외면 던지게) 하고 http() 를 부른다. (결과, 부른 횟수)"""
    calls = []

    def fake_urlopen(req, timeout=None, context=None):
        calls.append(req.full_url)
        item = responses[len(calls) - 1]
        if isinstance(item, BaseException):
            raise item
        return item

    with mock.patch.object(collect.urllib.request, "urlopen", fake_urlopen), mock.patch.object(collect.time, "sleep", lambda s: None):
        out = collect.http("https://example.invalid/x", **kw)
    return out, len(calls)


class HttpRetry(unittest.TestCase):
    def test_incomplete_read_is_retried(self):
        broken = FakeResponse(b"", fail_read=http.client.IncompleteRead(b"half", 100))
        (body, _), calls = run_http([broken, FakeResponse(b"whole")])
        self.assertEqual(body, b"whole")
        self.assertEqual(calls, 2)

    def test_remote_disconnect_while_opening_is_retried(self):
        (body, _), calls = run_http([http.client.RemoteDisconnected("closed"), FakeResponse(b"ok")])
        self.assertEqual(body, b"ok")
        self.assertEqual(calls, 2)

    def test_bad_status_line_is_retried(self):
        (body, _), calls = run_http([http.client.BadStatusLine("x"), FakeResponse(b"ok")])
        self.assertEqual(body, b"ok")
        self.assertEqual(calls, 2)

    def test_truncated_gzip_body_is_retried(self):
        whole = gzip.compress(b'{"rows": [1, 2, 3]}')
        cut = FakeResponse(whole[:-6], headers={"Content-Encoding": "gzip"})
        good = FakeResponse(whole, headers={"Content-Encoding": "gzip"})
        (body, _), calls = run_http([cut, good], compressed=True)
        self.assertEqual(body, b'{"rows": [1, 2, 3]}')
        self.assertEqual(calls, 2)

    def test_gives_up_with_stop_after_tries(self):
        broken = [FakeResponse(b"", fail_read=http.client.IncompleteRead(b"", 10)) for _ in range(3)]
        with self.assertRaises(collect.Stop) as ctx:
            run_http(broken, tries=3)
        self.assertIn("IncompleteRead", str(ctx.exception))

    def test_existing_behaviour_unchanged(self):
        # 404 · 410 은 다시 하지 않고 (None, None)
        e404 = urllib.error.HTTPError("https://example.invalid/x", 404, "nf", {}, None)
        (body, headers), calls = run_http([e404])
        self.assertIsNone(body)
        self.assertIsNone(headers)
        self.assertEqual(calls, 1)
        # 본문이 max_bytes 를 넘으면 (None, None)
        (body, _), calls = run_http([FakeResponse(b"x" * 11)], max_bytes=10)
        self.assertIsNone(body)
        self.assertEqual(calls, 1)
        # 그 밖의 HTTP 오류와 연결 오류는 전처럼 다시 한다
        e503 = urllib.error.HTTPError("https://example.invalid/x", 503, "busy", {}, None)
        (body, _), calls = run_http([e503, urllib.error.URLError("dns"), FakeResponse(b"ok")])
        self.assertEqual(body, b"ok")
        self.assertEqual(calls, 3)


if __name__ == "__main__":
    unittest.main()
