import asyncio
import json
import logging
import sqlite3
import time

from websockets.asyncio.client import connect

logger = logging.getLogger(__name__)


class Outbox:
    """Durable delivery: delete only after the backend acknowledges the message ID."""

    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY, "
            "message_id TEXT UNIQUE NOT NULL, payload TEXT NOT NULL)"
        )

    def put(self, message):
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO outbox(message_id,payload) VALUES (?,?)",
                (message["message_id"], json.dumps(message)),
            )

    def peek(self):
        return self.db.execute(
            "SELECT message_id,payload FROM outbox ORDER BY id LIMIT 1"
        ).fetchone()

    def batch(self, limit=256):
        return self.db.execute(
            "SELECT message_id,payload FROM outbox ORDER BY id LIMIT ?", (limit,)
        ).fetchall()

    def acknowledge(self, message_id):
        with self.db:
            self.db.execute("DELETE FROM outbox WHERE message_id=?", (message_id,))

    def close(self):
        self.db.close()


class WebSocketClient:
    def __init__(self, url, token, outbox, retry_delay=1):
        self.url, self.token, self.outbox, self.retry_delay = url, token, outbox, retry_delay

    async def run(self):
        failures = 0
        while True:
            try:
                async with connect(
                    self.url,
                    additional_headers={"Authorization": f"Bearer {self.token}"},
                    open_timeout=10,
                    ping_interval=20,
                    ping_timeout=20,
                    max_size=65536,
                ) as ws:
                    logger.info("Collector connected to backend")
                    pending = {}

                    async def send():
                        while True:
                            for message_id, payload in self.outbox.batch():
                                if message_id not in pending:
                                    pending[message_id] = time.monotonic()
                                    await ws.send(payload)
                            if pending and time.monotonic() - min(pending.values()) > 30:
                                raise TimeoutError("Backend acknowledgement deadline exceeded")
                            await asyncio.sleep(0.01)

                    async def receive():
                        nonlocal failures
                        while True:
                            ack = json.loads(await ws.recv())
                            message_id = ack.get("message_id")
                            if ack.get("type") != "ack" or message_id not in pending:
                                raise ValueError("Backend did not acknowledge a pending message")
                            self.outbox.acknowledge(message_id)
                            pending.pop(message_id)
                            failures = 0

                    tasks = [asyncio.create_task(send()), asyncio.create_task(receive())]
                    try:
                        await asyncio.gather(*tasks)
                    finally:
                        for task in tasks:
                            task.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
            except Exception as error:
                # asyncio.CancelledError intentionally propagates (BaseException).
                failures += 1
                logger.warning(
                    "Collector connection failed (%s), attempt %d/5", type(error).__name__, failures
                )
                if failures >= 5:
                    raise RuntimeError(
                        "Reconnect budget exhausted; systemd will restart collector"
                    ) from error
                await asyncio.sleep(self.retry_delay * 2 ** (failures - 1))
