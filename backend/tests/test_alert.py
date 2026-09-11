import logging

import httpx
import pytest

from backend.services.alert import send_alert


@pytest.mark.parametrize(
    "status,body,expected",
    [(200, "ok", True), (200, "invalid", False), (403, "invalid_token", False)],
)
async def test_slack_status_and_safe_logging(monkeypatch, caplog, status, body, expected):
    original_client = httpx.AsyncClient
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(status, text=body)

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    event = {
        "severity": "critical",
        "attack_type": "SYN_FLOOD",
        "flow": {"src_ip": "10.200.0.1", "dst_ip": "10.200.0.2"},
        "detected_at": "2026-09-11T00:00:00Z",
        "event_id": 1,
    }
    with caplog.at_level(logging.INFO):
        assert await send_alert("https://hooks.slack.com/services/test-secret", event) is expected
    assert len(requests) == 1
    assert "test-secret" not in caplog.text
    assert "invalid_token" not in caplog.text


async def test_slack_only_sends_critical():
    assert await send_alert("", {"severity": "critical"}) is False
    assert await send_alert("https://hooks.slack.com/services/test", {"severity": "high"}) is False
