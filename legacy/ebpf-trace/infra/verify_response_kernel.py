"""Verify the actual nftables adapter in a disposable, network-isolated Linux namespace.

No production interfaces or firewall tables are modified. Uses TEST-NET addresses only.
Requires Linux iproute2/nftables and permission to use sudo unshare --net.
"""

import argparse
import ast
import subprocess
from pathlib import Path

SMOKE = r"""
assert sys.platform == "linux" and os.geteuid() == 0
assert os.readlink("/proc/self/ns/net") != sys.argv[1], "Refuse to test the parent network namespace"
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
for address in ("192.0.2.10", "192.0.2.11", "198.51.100.20"):
    subprocess.run(["ip", "address", "add", address + "/32", "dev", "lo"], check=True)
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"healthy")
servers = []
for _ in range(2):
    server = socketserver.ThreadingTCPServer(("198.51.100.20", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    servers.append(server)
port, other_port = [s.server_address[1] for s in servers]
def reachable(source, destination_port=port):
    try:
        with socket.create_connection(("198.51.100.20", destination_port), timeout=.4,
                                      source_address=(source, 0)) as connection:
            return connection.recv(7) == b"healthy"
    except (TimeoutError, OSError):
        return False
adapter = NftablesAdapter(str(uuid4()))
adapter.initialize()
adapter.execute("add table inet unrelated_test_guard\n")
policy = {"source_ip": "192.0.2.10", "destination_ip": "198.51.100.20", "destination_port": port,
          "protocol": 6, "action": "block_source", "ttl_seconds": 3, "rate_pps": 50}
assert reachable("192.0.2.10"), "Baseline unavailable"
run = str(uuid4())
adapter.apply(run, policy)
assert not reachable("192.0.2.10"), "Selected source was not blocked"
assert reachable("192.0.2.11"), "Normal source was affected"
assert reachable("192.0.2.10", other_port), "Unrelated service was affected"
time.sleep(3.2)  # No backend or agent worker is running: only the kernel expires this policy.
assert reachable("192.0.2.10"), "Kernel TTL did not independently restore service"
adapter.release(run)
adapter.cleanup(run)
run = str(uuid4())
adapter.apply(run, {**policy, "ttl_seconds": 30})
assert not reachable("192.0.2.10")
adapter.release(run)
assert reachable("192.0.2.10"), "Explicit release did not restore service"
adapter.cleanup(run)
run = str(uuid4())
adapter.apply(run, {**policy, "action": "rate_limit"})
assert reachable("192.0.2.11")
adapter.release(run)
adapter.cleanup(run)
subprocess.run(["nft", "list", "table", "inet", "unrelated_test_guard"], check=True, capture_output=True)
print(json.dumps({"isolated_namespace": True, "source_block": "passed", "normal_source": "passed",
    "other_service": "passed", "kernel_ttl_without_backend": "passed", "explicit_release": "passed",
    "rate_limit_install_release": "passed", "unrelated_table_preserved": "passed"}))
"""


def payload():
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse((root / "response_agent/agent.py").read_text())
    adapter = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "NftablesAdapter"
    )
    imports = "import json, os, socket, socketserver, subprocess, sys, threading, time\nfrom uuid import UUID, uuid4\n"
    child = imports + ast.unparse(adapter) + "\n" + SMOKE
    # The parent checks namespace identity through an argv value, not a spoofable observation.
    return (
        "import os, subprocess\nsubprocess.run("
        + repr(["sudo", "-n", "unshare", "--net", "--", "python3", "-c", child])
        + (" + [os.readlink('/proc/self/ns/net')], check=True)\n")
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-host")
    parser.add_argument("--ssh-key")
    args = parser.parse_args()
    command = ["python3", "-"]
    if args.ssh_host:
        command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
        if args.ssh_key:
            command += ["-i", args.ssh_key]
        command += [args.ssh_host, "python3 -"]
    subprocess.run(command, input=payload(), text=True, check=True, timeout=30)
