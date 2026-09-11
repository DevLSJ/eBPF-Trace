import asyncio
import logging
import os
import signal
import time
import uuid

from collector.cache import SlidingWindowCache
from collector.features import FeatureCalculator
from collector.reader import RingBufferReader
from collector.ws_client import Outbox, WebSocketClient


async def run():
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    token = os.environ["COLLECTOR_TOKEN"]
    outbox = Outbox(os.getenv("OUTBOX_PATH", "collector-outbox.db"))
    cache = SlidingWindowCache(os.getenv("REDIS_URL", "redis://127.0.0.1:16379/0"))
    calculator = FeatureCalculator()
    cache_queue = asyncio.Queue(maxsize=1000)
    latest = {}
    reader = RingBufferReader(
        os.environ.get("IFACE", "enp0s1"), lambda item: latest.update({item.key: item})
    )
    ws = WebSocketClient(os.environ["COLLECTOR_WS_URL"], token, outbox)

    async def caching():
        while True:
            await cache.add(await cache_queue.get())

    async def polling():
        last_flush = 0
        while True:
            await asyncio.to_thread(reader.poll)
            if time.monotonic() - last_flush >= 1:
                await asyncio.to_thread(reader.flush)
                last_flush = time.monotonic()
            batch = list(latest.values())
            latest.clear()
            for snapshot in batch:
                features = calculator.compute(snapshot, time.monotonic())
                if features is None:
                    continue
                message = {
                    "type": "flow_features",
                    "message_id": str(uuid.uuid4()),
                    "timestamp": int(time.time() * 1000),
                    "flow": dict(
                        zip(("src_ip", "dst_ip", "src_port", "dst_port", "protocol"), snapshot.key)
                    ),
                    "features": features,
                }
                outbox.put(message)
                try:
                    cache_queue.put_nowait(message)
                except asyncio.QueueFull:
                    pass  # Cache is optional; durable WebSocket delivery is independent.

    tasks = [asyncio.create_task(coro()) for coro in (polling, caching, ws.run)]
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: [task.cancel() for task in tasks])
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        reader.close()
        await cache.close()
        outbox.close()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except asyncio.CancelledError:
        pass
