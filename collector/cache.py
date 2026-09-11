import asyncio
import json
import logging

from redis.asyncio import Redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


class SlidingWindowCache:
    def __init__(self, url, client=None, retry_delay=1):
        self.client = client or Redis.from_url(url, socket_connect_timeout=1, socket_timeout=1)
        self.retry_delay = retry_delay

    @staticmethod
    def key(message):
        flow = message["flow"]
        return "flow:" + ":".join(
            str(flow[key]) for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")
        )

    async def add(self, message):
        key, timestamp = self.key(message), message["timestamp"]
        for attempt in range(3):
            try:
                async with self.client.pipeline(transaction=True) as pipe:
                    pipe.zadd(key, {json.dumps(message, sort_keys=True): timestamp})
                    pipe.zremrangebyscore(key, "-inf", timestamp - 60_000)
                    pipe.expire(key, 60)
                    await pipe.execute()
                return True
            except (RedisError, OSError):
                logger.warning("Redis cache unavailable (attempt %d/3)", attempt + 1)
                if attempt < 2:
                    await asyncio.sleep(self.retry_delay)
        logger.error("Redis cache skipped; streaming detection remains active")
        return False

    async def recent(self, message):
        return await self.client.zrangebyscore(
            self.key(message), message["timestamp"] - 60_000, message["timestamp"]
        )

    async def close(self):
        await self.client.aclose()
