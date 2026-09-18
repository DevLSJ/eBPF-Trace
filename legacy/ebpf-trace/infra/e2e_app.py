"""Isolated browser-test backend. Never reads production .env or sends alerts."""

import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from backend.core.config import Settings
from backend.core.operator_auth import provision_operator
from backend.core.schemas import FlowMessage
from backend.db.crud import create_event
from backend.main import create_app

temporary = tempfile.TemporaryDirectory(prefix="ebpf-browser-")
app = create_app(Settings(
    _env_file=None,
    database_url=f"sqlite+aiosqlite:///{Path(temporary.name) / 'browser_test.db'}",
    postgres_host="", auto_create_schema=True, metrics_enabled=False,
    collector_token="browser-collector", admin_token="browser-admin",
    slack_webhook_url="", model_path="missing", scaler_path="missing",
    ops_allow_insecure_local=True, recovery_observation_seconds=10,
    public_base_url="http://127.0.0.1:15173", allowed_origins="http://127.0.0.1:15173",
))
original_lifespan = app.router.lifespan_context


@asynccontextmanager
async def lifespan(application):
    async with original_lifespan(application):
        async with application.state.db.sessions() as session:
            for username, name, role in [("operator", "김민서", "admin"), ("approver", "박지훈", "approver")]:
                await provision_operator(session, username, name, role, "browser-test-password")
            await session.commit()
            for index in range(25):
                scan = index >= 21
                message = FlowMessage(
                    type="flow_features", message_id=uuid.uuid4(), timestamp=int(time.time() * 1000),
                    flow={"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2",
                          "src_port": 5000 + index, "dst_port": 80, "protocol": 6},
                    features={"pkt_rate": 20 if scan else 1500, "byte_rate": 90000,
                              "syn_ratio": 1, "port_entropy": 0.1, "port_cnt": 20 if scan else 1,
                              "flow_duration": 1000, "avg_pkt_size": 60},
                )
                result = application.state.detector.analyze(message.features.model_dump())
                await create_event(session, message, result)
        yield


app.router.lifespan_context = lifespan
