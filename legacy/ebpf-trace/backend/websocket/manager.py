import asyncio


class ConnectionManager:
    def __init__(self):
        self.connections = set()

    async def connect(self, ws):
        await ws.accept()
        self.connections.add(ws)

    def disconnect(self, ws):
        self.connections.discard(ws)

    async def broadcast(self, message):
        async def send(ws):
            try:
                await asyncio.wait_for(ws.send_json(message), timeout=1)
            except Exception:
                self.disconnect(ws)
                try:
                    await ws.close(code=1013)
                except Exception:
                    pass

        await asyncio.gather(*(send(ws) for ws in tuple(self.connections)))

    async def close(self):
        for ws in tuple(self.connections):
            try:
                await ws.close(code=1001)
            except Exception:
                pass
        self.connections.clear()
