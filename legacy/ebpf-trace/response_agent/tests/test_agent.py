import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from response_agent.agent import Ledger, NftablesAdapter, ResponseAgent, canonical, validate_command


def command(config, token="agent-secret", **overrides):
    policy = {
        "version": 1,
        "action": "block_source",
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "destination_port": 443,
        "protocol": 6,
        "ttl_seconds": 30,
        "rate_pps": 100,
        "point_id": config["point_id"],
        "source": "live",
        **overrides,
    }
    payload = {
        "run_id": str(uuid4()),
        "point_id": config["point_id"],
        "operation": "apply",
        "policy": policy,
        "policy_hash": hashlib.sha256(canonical(policy).encode()).hexdigest(),
        "command_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat(),
    }
    return {
        "payload": payload,
        "signature": hmac.new(
            token.encode(), canonical(payload).encode(), hashlib.sha256
        ).hexdigest(),
    }


@pytest.fixture
def config():
    return {
        "point_id": str(uuid4()),
        "backend": "https://backend.example",
        "mode": "nftables",
        "allowed_services": ["198.51.100.20:443/6"],
        "protected_cidrs": ["192.0.2.1/32"],
        "max_ttl_seconds": 300,
    }


@pytest.mark.parametrize(
    "policy",
    [
        {"source_ip": "192.0.2.1"},
        {"source_ip": "127.0.0.1"},
        {"source_ip": "192.0.2.10; flush ruleset"},
        {"destination_port": 22},
        {"ttl_seconds": 1000},
        {"rate_pps": "100; reboot"},
        {"source": "simulation"},
        {"protocol": 1},
        {"action": "arbitrary_shell"},
    ],
)
def test_local_scope_ttl_and_injection_rejected(config, policy):
    with pytest.raises(ValueError):
        validate_command(command(config, **policy), "agent-secret", config)


def test_signature_deadline_and_agent_identity(config):
    envelope = command(config)
    assert validate_command(envelope, "agent-secret", config)["operation"] == "apply"
    with pytest.raises(ValueError):
        validate_command(envelope, "wrong-secret", config)
    with pytest.raises(ValueError):
        validate_command(envelope, "agent-secret", config, now=time.time() + 60)
    with pytest.raises(ValueError):
        validate_command(envelope, "agent-secret", {**config, "point_id": str(uuid4())})


class FakeAdapter:
    def __init__(self):
        self.applies, self.releases = [], []

    def apply(self, run_id, policy):
        self.applies.append(run_id)
        return run_id

    def release(self, run_id):
        self.releases.append(run_id)
        return run_id

    def cleanup(self, run_id):
        pass


def test_durable_replay_local_expiry_and_restart_while_backend_offline(config, tmp_path):
    adapter = FakeAdapter()
    path = tmp_path / "ledger.db"
    ledger = Ledger(path)
    offline = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: (_ for _ in ()).throw(httpx.ConnectError("offline"))
        )
    )
    agent = ResponseAgent(config, "agent-secret", ledger, adapter, offline)
    envelope = command(config)
    run_id = envelope["payload"]["run_id"]
    agent.accept(envelope)
    original_expiry = ledger.get(run_id)["expires"]
    agent.accept(envelope)
    assert len(adapter.applies) == 1 and ledger.get(run_id)["expires"] == original_expiry
    ledger.db.execute("UPDATE commands SET expires=? WHERE id=?", (time.time() - 1, run_id))
    ledger.db.commit()
    with pytest.raises(Exception):
        agent.cycle()
    assert ledger.get(run_id)["status"] == "released"
    assert ledger.get(run_id)["pending"] == 1
    restarted = ResponseAgent(config, "agent-secret", Ledger(path), adapter, offline)
    restarted.accept(envelope)
    assert len(adapter.applies) == 1
    assert run_id in adapter.releases


def test_kernel_policy_has_timed_set_and_never_flushes_shared_rules(config):
    invocations = []

    def runner(args, **kwargs):
        invocations.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    adapter = NftablesAdapter(config["point_id"], runner=runner)
    envelope = command(config, action="rate_limit", rate_pps=50)
    adapter.apply(envelope["payload"]["run_id"], envelope["payload"]["policy"])
    args, options = invocations[-1]
    assert args == ["nft", "-f", "-"] and "shell" not in options
    assert "flags timeout" in options["input"] and "timeout 30s" in options["input"]
    assert "limit rate over 50/second" in options["input"]
    assert "flush ruleset" not in options["input"] and "198.51.100.20" in options["input"]


def test_release_permission_failure_is_never_reported_success(config):
    def runner(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="Operation not permitted")

    adapter = NftablesAdapter(config["point_id"], runner=runner)
    with pytest.raises(RuntimeError):
        adapter.release(str(uuid4()))
