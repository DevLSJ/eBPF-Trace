import os
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.core.config import Settings
from backend.main import create_app


@pytest.fixture
def client(tmp_path):
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        auto_create_schema=True,
        metrics_enabled=False,
        collector_token="test-collector-token",
        admin_token="test-admin-token",
        model_path="missing-model",
        scaler_path="missing-scaler",
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def message():
    return {
        "type": "flow_features",
        "message_id": str(uuid.uuid4()),
        "timestamp": 1789110000000,
        "flow": {
            "src_ip": "192.168.64.1",
            "dst_ip": "192.168.64.2",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": 6,
        },
        "features": {
            "pkt_rate": 1250,
            "byte_rate": 75000,
            "syn_ratio": 1,
            "port_entropy": 0,
            "flow_duration": 1000,
            "avg_pkt_size": 60,
        },
    }


@pytest.fixture
def postgres_client():
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set TEST_DATABASE_URL to a dedicated PostgreSQL database ending in _test")
    from sqlalchemy.engine import make_url

    if not make_url(url).database.endswith("_test"):
        raise ValueError("Integration tests require a dedicated *_test database")
    settings = Settings(
        _env_file=None,
        database_url=url,
        auto_create_schema=True,
        metrics_enabled=False,
        collector_token="test-collector-token",
        admin_token="test-admin-token",
        model_path="missing",
        scaler_path="missing",
    )
    with TestClient(create_app(settings)) as client:
        yield client
