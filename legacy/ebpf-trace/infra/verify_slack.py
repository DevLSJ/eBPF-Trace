"""Run inside the deployed backend: send ONE explicitly labelled integration test."""

import asyncio
import json
import time
from datetime import datetime, timezone

from backend.core.config import Settings
from backend.services.alert import send_alert


async def main():
    event = {
        "event_id": "INTEGRATION-TEST",
        "severity": "critical",
        "attack_type": "[연동 검증 / 실제 공격 아님] Slack Webhook Test",
        "flow": {"src_ip": "10.200.0.1", "dst_ip": "10.200.0.2"},
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }
    start = time.perf_counter()
    accepted = await send_alert(Settings().slack_webhook_url.get_secret_value(), event)
    elapsed = round((time.perf_counter() - start) * 1000, 2)
    print(
        json.dumps(
            {"slack_http_200_ok": accepted, "elapsed_ms": elapsed, "channel_ui_verified": False}
        )
    )
    return accepted and elapsed < 60_000


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
