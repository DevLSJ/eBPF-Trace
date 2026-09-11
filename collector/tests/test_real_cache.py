import os
import time
import uuid

import pytest

from collector.cache import SlidingWindowCache


async def test_real_redis_window():
    url = os.getenv("TEST_REDIS_URL")
    if not url:
        pytest.skip("Set TEST_REDIS_URL to a dedicated Redis test service")
    cache = SlidingWindowCache(url, retry_delay=0)
    item = {
        "message_id": str(uuid.uuid4()),
        "timestamp": int(time.time() * 1000),
        "flow": {
            "src_ip": f"test-{uuid.uuid4()}",
            "dst_ip": "test",
            "src_port": 1,
            "dst_port": 80,
            "protocol": 6,
        },
        "features": {"pkt_rate": 1},
    }
    try:
        assert await cache.add(item)
        assert len(await cache.recent(item)) == 1
        assert 58 <= await cache.client.ttl(cache.key(item)) <= 60
        item["timestamp"] += 61000
        item["message_id"] = str(uuid.uuid4())
        assert await cache.add(item)
        assert len(await cache.recent(item)) == 1
    finally:
        await cache.client.delete(cache.key(item))
        await cache.close()
