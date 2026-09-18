"""Polling response agent. Production execution requires an explicit local configuration.

The nftables adapter only edits its own table and never flushes existing firewall rules.
The timed set expires in the kernel even when this agent or the backend is unavailable.
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import signal
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import httpx

logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def validate_command(envelope, token, config, now=None):
    payload = envelope["payload"]
    expected = hmac.new(token.encode(), canonical(payload).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, envelope.get("signature", "")):
        raise ValueError("Invalid command signature")
    UUID(payload["run_id"])
    if payload["point_id"] != config["point_id"] or payload["operation"] not in {"apply", "revoke"}:
        raise ValueError("Command scope mismatch")
    policy = payload["policy"]
    if hashlib.sha256(canonical(policy).encode()).hexdigest() != payload["policy_hash"]:
        raise ValueError("Policy hash mismatch")
    if payload["operation"] == "revoke":
        return payload
    deadline = datetime.fromisoformat(payload["command_expires_at"])
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    if deadline.timestamp() <= (time.time() if now is None else now):
        raise ValueError("Command expired")
    source = ipaddress.IPv4Address(policy["source_ip"])
    ipaddress.IPv4Address(policy["destination_ip"])
    service = f"{policy['destination_ip']}:{policy['destination_port']}/{policy['protocol']}"
    if service not in config["allowed_services"]:
        raise ValueError("Service not authorized by local agent configuration")
    if (
        source.is_loopback
        or source.is_multicast
        or source.is_unspecified
        or any(source in ipaddress.ip_network(c) for c in config.get("protected_cidrs", []))
    ):
        raise ValueError("Protected source address")
    if policy["source_ip"] == policy["destination_ip"]:
        raise ValueError("Cannot target the protected service address")
    if policy["action"] not in {"block_source", "rate_limit"} or policy["protocol"] not in {6, 17}:
        raise ValueError("Unsupported action")
    for name, low, high in [
        ("destination_port", 1, 65535),
        ("ttl_seconds", 30, config.get("max_ttl_seconds", 300)),
        ("rate_pps", 10, 100000),
    ]:
        if type(policy[name]) is not int or not low <= policy[name] <= high:
            raise ValueError("Invalid bounded policy value")
    if policy["source"] != "live" or config.get("mode") != "nftables":
        raise ValueError("Network adapter accepts explicitly authorized live policies only")
    return payload


class NftablesAdapter:
    def __init__(self, point_id, runner=subprocess.run):
        self.table = "ebpf_response_" + UUID(point_id).hex[:12]
        self.runner = runner

    def execute(self, script):
        result = self.runner(
            ["nft", "-f", "-"], input=script, text=True, capture_output=True, timeout=5, check=False
        )
        if result.returncode:
            raise RuntimeError("nftables transaction failed")

    def exists(self):
        result = self.runner(
            ["nft", "list", "table", "inet", self.table],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode and "No such file or directory" not in result.stderr:
            raise RuntimeError("Cannot inspect response table")
        return result.returncode == 0

    def initialize(self):
        if not self.exists():
            self.execute(
                f"add table inet {self.table}\n"
                f"add chain inet {self.table} ingress {{ type filter hook input priority -10; policy accept; }}\n"
                f"add chain inet {self.table} forwarded {{ type filter hook forward priority -10; policy accept; }}\n"
            )

    def apply(self, run_id, policy):
        name = "p_" + UUID(run_id).hex
        protocol = "tcp" if policy["protocol"] == 6 else "udp"
        rate = (
            f"limit rate over {policy['rate_pps']}/second "
            if policy["action"] == "rate_limit"
            else ""
        )
        script = f"add set inet {self.table} {name} {{ type ipv4_addr; flags timeout; timeout {policy['ttl_seconds']}s; }}\n"
        script += f"add element inet {self.table} {name} {{ {policy['source_ip']} timeout {policy['ttl_seconds']}s }}\n"
        for chain in ("ingress", "forwarded"):
            script += (
                f"add rule inet {self.table} {chain} ip saddr @{name} ip daddr {policy['destination_ip']} "
                f'{protocol} dport {policy["destination_port"]} {rate}counter drop comment "{name}"\n'
            )
        self.execute(script)
        return name

    def release(self, run_id):
        name = "p_" + UUID(run_id).hex
        # Removing the timed elements immediately disables both rules, without touching other policies.
        result = self.runner(
            ["nft", "list", "set", "inet", self.table, name],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            self.execute(f"flush set inet {self.table} {name}\n")
        elif self.exists():
            # A missing set means no matching policy remains. Distinguish it from privilege failures.
            if "No such file or directory" not in result.stderr:
                raise RuntimeError("Cannot verify policy release")
        return name

    def cleanup(self, run_id):
        name = "p_" + UUID(run_id).hex
        if not self.exists():
            return
        result = self.runner(
            ["nft", "-j", "-a", "list", "table", "inet", self.table],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        if result.returncode:
            return
        commands = []
        found_set = False
        for item in json.loads(result.stdout).get("nftables", []):
            rule = item.get("rule", {})
            if rule.get("comment") == name and rule.get("chain") in {"ingress", "forwarded"}:
                commands.append(
                    f"delete rule inet {self.table} {rule['chain']} handle {int(rule['handle'])}"
                )
            found_set |= item.get("set", {}).get("name") == name
        if found_set:
            commands.append(f"delete set inet {self.table} {name}")
        if commands:
            self.execute("\n".join(commands) + "\n")


class Ledger:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS commands (
            id TEXT PRIMARY KEY, policy_hash TEXT NOT NULL, policy TEXT NOT NULL,
            status TEXT NOT NULL, expires REAL NOT NULL, sequence INTEGER NOT NULL,
            pending INTEGER NOT NULL, handle TEXT NOT NULL, detail TEXT NOT NULL)""")
        self.db.commit()

    def get(self, run_id):
        self.db.row_factory = sqlite3.Row
        row = self.db.execute("SELECT * FROM commands WHERE id=?", (run_id,)).fetchone()
        return dict(row) if row else None

    def reserve(self, command):
        self.db.execute(
            "INSERT OR IGNORE INTO commands VALUES (?,?,?,?,?,?,?,?,?)",
            (
                command["run_id"],
                command["policy_hash"],
                canonical(command["policy"]),
                "preparing",
                time.time() + command["policy"]["ttl_seconds"],
                0,
                0,
                "",
                "",
            ),
        )
        self.db.commit()

    def record(self, run_id, status, handle="", detail=""):
        self.db.execute(
            "UPDATE commands SET status=?, sequence=sequence+1, pending=1, handle=?, detail=? WHERE id=?",
            (status, handle, detail, run_id),
        )
        self.db.commit()

    def rows(self):
        self.db.row_factory = sqlite3.Row
        return [dict(r) for r in self.db.execute("SELECT * FROM commands")]


class ResponseAgent:
    def __init__(self, config, token, ledger, adapter, client=None):
        self.config, self.token, self.ledger, self.adapter = config, token, ledger, adapter
        self.client = client or httpx.Client(
            base_url=config["backend"],
            timeout=5,
            headers={"Authorization": "Bearer " + token},
            follow_redirects=False,
        )
        self.prefix = f"/api/ops/agents/{config['point_id']}"

    def local_expiry(self, recovering=False):
        for row in self.ledger.rows():
            if row["status"] in {"released", "failed"}:
                continue
            if recovering or row["expires"] <= time.time():
                try:
                    handle = self.adapter.release(row["id"])
                    self.ledger.record(
                        row["id"], "released", handle, "Local expiry or restart recovery"
                    )
                    self.adapter.cleanup(row["id"])
                except Exception:
                    self.ledger.record(
                        row["id"], "release_failed", detail="Local release could not be verified"
                    )

    def accept(self, envelope):
        command = validate_command(envelope, self.token, self.config)
        prior = self.ledger.get(command["run_id"])
        if prior and prior["policy_hash"] != command["policy_hash"]:
            raise ValueError("Run ID was reused with a different policy")
        if command["operation"] == "revoke":
            if not prior:
                self.ledger.reserve(command)
            handle = self.adapter.release(command["run_id"])
            if not prior or prior["status"] != "released":
                self.ledger.record(command["run_id"], "released", handle, "Requested release")
            self.adapter.cleanup(command["run_id"])
            return
        if prior:
            return  # Durable duplicate protection; never extend a TTL through replay.
        self.ledger.reserve(command)  # Intent survives a crash before the kernel operation.
        try:
            handle = self.adapter.apply(command["run_id"], command["policy"])
            self.ledger.record(
                command["run_id"], "applied", handle, "Kernel timed-set policy applied"
            )
        except Exception:
            try:
                self.adapter.release(command["run_id"])
                self.ledger.record(
                    command["run_id"], "failed", detail="Apply failed; no active policy"
                )
            except Exception:
                self.ledger.record(
                    command["run_id"], "release_failed", detail="Apply result and release unknown"
                )

    def receipts(self):
        for row in self.ledger.rows():
            if not row["pending"]:
                continue
            response = self.client.post(
                f"{self.prefix}/actions/{row['id']}/report",
                json={
                    "sequence": row["sequence"],
                    "status": row["status"],
                    "policy_hash": row["policy_hash"],
                    "policy_handle": row["handle"],
                    "detail": row["detail"],
                },
            )
            response.raise_for_status()
            self.ledger.db.execute(
                "UPDATE commands SET pending=0 WHERE id=? AND sequence=?",
                (row["id"], row["sequence"]),
            )
            self.ledger.db.commit()

    def heartbeat(self):
        # Local metrics are produced by an explicitly configured service probe. Never fabricate health.
        path = Path(self.config["observation_file"])
        data = json.loads(path.read_text())
        if time.time() - path.stat().st_mtime > 15:
            raise ValueError("Service observation file is stale")
        body = {
            k: data[k]
            for k in (
                "healthy",
                "success_rate",
                "latency_ms",
                "ingress_pps",
                "policy_hits",
                "normal_sessions",
            )
        }
        self.client.post(
            f"{self.prefix}/heartbeat",
            json={**body, "mode": "nftables", "capabilities": ["block_source", "rate_limit"]},
        ).raise_for_status()

    def cycle(self):
        self.local_expiry()  # Runs before every network call; kernel TTL is independent as well.
        try:
            self.receipts()
            self.heartbeat()
            response = self.client.get(f"{self.prefix}/commands")
            response.raise_for_status()
            for envelope in response.json()["items"]:
                self.accept(envelope)
            self.receipts()
        except Exception:
            self.local_expiry(
                recovering=True
            )  # Fail open if service health/control cannot be verified.
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "--execute", action="store_true", help="Explicitly enable the local nftables adapter"
    )
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    if not args.execute or config.get("mode") != "nftables" or not config.get("allowed_services"):
        parser.error("--execute, mode=nftables and a nonempty allowed_services list are required")
    if not config["backend"].startswith("https://"):
        parser.error("The response agent requires an HTTPS backend")
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]+", config.get("token_env", "EBPF_RESPONSE_TOKEN")):
        parser.error("Invalid token environment variable name")
    token = os.environ[config.get("token_env", "EBPF_RESPONSE_TOKEN")]
    adapter = NftablesAdapter(config["point_id"])
    adapter.initialize()
    ledger = Ledger(config["ledger"])
    agent = ResponseAgent(config, token, ledger, adapter)
    agent.local_expiry(recovering=True)  # Reboot/restart never silently reinstalls an old block.
    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopped:
        try:
            agent.cycle()
        except Exception as error:
            logger.warning(
                "Response cycle unavailable (%s); local expiry remains enforced",
                type(error).__name__,
            )
        time.sleep(2)
    agent.local_expiry(recovering=True)


if __name__ == "__main__":
    main()
