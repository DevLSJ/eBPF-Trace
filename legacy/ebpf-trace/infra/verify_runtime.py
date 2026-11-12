"""API/WS persistence and concurrent latency smoke test against the deployment."""

import argparse
import asyncio
import json
import statistics
import time
import uuid

import httpx
from websockets.asyncio.client import connect


async def verify(base_url, token):
    base_url = base_url.rstrip("/")
    ws_base = base_url.replace("http://", "ws://").replace("https://", "wss://")
    started = time.perf_counter()
    message = {
        "type": "flow_features",
        "message_id": str(uuid.uuid4()),
        "timestamp": int(time.time() * 1000),
        "flow": {
            "src_ip": "10.200.0.1",
            "dst_ip": "10.200.0.2",
            "src_port": 30000,
            "dst_port": 80,
            "protocol": 6,
        },
        "features": {
            "pkt_rate": 1200,
            "byte_rate": 64800,
            "syn_ratio": 1,
            "port_entropy": 0,
            "flow_duration": 1000,
            "avg_pkt_size": 54,
        },
    }
    async with connect(ws_base + "/ws/dashboard") as dashboard:
        async with connect(
            ws_base + "/ws/collector", additional_headers={"Authorization": f"Bearer {token}"}
        ) as collector:
            started = time.perf_counter()
            await collector.send(json.dumps(message))
            ack = json.loads(await asyncio.wait_for(collector.recv(), 5))
            assert ack["message_id"] == message["message_id"]
            while True:
                event = json.loads(await asyncio.wait_for(dashboard.recv(), 5))
                if (
                    event.get("type") == "detection_event"
                    and event["flow"]["src_ip"] == "10.200.0.1"
                ):
                    break
            latency_ms = (time.perf_counter() - started) * 1000
    async with httpx.AsyncClient(base_url=base_url, timeout=10) as client:
        response = await client.get(f"/api/events/{event['event_id']}")
        response.raise_for_status()
        assert response.json()["severity"] == "critical"
        semaphore = asyncio.Semaphore(10)

        async def request():
            async with semaphore:
                start = time.perf_counter()
                result = await client.get("/api/events?page_size=100")
                result.raise_for_status()
                return (time.perf_counter() - start) * 1000

        timings = await asyncio.gather(*(request() for _ in range(100)))
    report = {
        "event_id": event["event_id"],
        "broadcast_ms": round(latency_ms, 2),
        "requests": 100,
        "concurrency": 10,
        "p95_ms": round(statistics.quantiles(timings, n=100)[94], 2),
        "mean_ms": round(statistics.mean(timings), 2),
    }
    report["passed"] = report["broadcast_ms"] <= 1000 and report["p95_ms"] <= 200
    return report


if __name__ == "__main__":
    import os

    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1")
    args = parser.parse_args()
    result = asyncio.run(verify(args.base_url, os.environ["COLLECTOR_TOKEN"]))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
