import asyncio
import json
import uuid

import fakeredis.aioredis
from websockets.asyncio.server import serve

from collector.cache import SlidingWindowCache
from collector.ws_client import Outbox, WebSocketClient


def message(timestamp=100000):
    return {
        "message_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "flow": {
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 100,
            "dst_port": 80,
            "protocol": 6,
        },
        "features": {"pkt_rate": 10},
    }


async def test_cache_retains_sixty_seconds():
    redis = fakeredis.aioredis.FakeRedis()
    cache = SlidingWindowCache("", client=redis, retry_delay=0)
    old, recent = message(100000), message(160001)
    assert await cache.add(old)
    assert await cache.add(recent)
    assert len(await cache.recent(recent)) == 1
    assert await redis.ttl(cache.key(recent)) == 60
    await cache.close()


def test_outbox_survives_process_restart(tmp_path):
    path, item = tmp_path / "outbox.db", message()
    first = Outbox(path)
    first.put(item)
    first.close()
    second = Outbox(path)
    assert second.peek()[0] == item["message_id"]
    second.acknowledge(item["message_id"])
    assert second.peek() is None
    second.close()


async def test_websocket_replays_after_lost_ack(tmp_path):
    attempts, received = [], asyncio.Event()
    item = message()

    async def handler(ws):
        packet = json.loads(await ws.recv())
        attempts.append(packet)
        if len(attempts) == 1:
            await ws.close(code=1011)
            return
        await ws.send(json.dumps({"type": "ack", "message_id": packet["message_id"]}))
        received.set()
        await ws.wait_closed()

    outbox = Outbox(tmp_path / "queue.db")
    outbox.put(item)
    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        client = WebSocketClient(f"ws://127.0.0.1:{port}", "token", outbox, retry_delay=0.01)
        task = asyncio.create_task(client.run())
        await asyncio.wait_for(received.wait(), 5)
        for _ in range(20):
            if outbox.peek() is None:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert outbox.peek() is None
    assert len(attempts) == 2 and attempts[0]["message_id"] == attempts[1]["message_id"]
    outbox.close()
