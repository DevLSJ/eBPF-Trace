"""Local traffic inspection: this host's own Wi-Fi or Ethernet interface through the same
rule → model → incident → automatic-response path the VM collector feeds.

Two capture backends. Packet capture (scapy; needs raw-socket privilege) computes the full feature
contract with the collector's FeatureCalculator. Counter capture (psutil; no privilege) only knows
received packets and bytes per second, so SYN and port features keep neutral values and only the
volume rules (TRAFFIC_SPIKE · LARGE_FLOW) or the model can fire. Runs and their per-second windows are
stored in `live_inspections` / `live_inspection_windows`; the detection events they produce are
ordinary `live` records with the interface address as destination.

The defense check never touches the database rows that matter: it probes the rule engine and the
model with vectors derived from the current thresholds, and the collateral-damage gate with two
canonical sources, then reports what the live path would do with them.
"""

import asyncio
import importlib.util
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import psutil
from fastapi import HTTPException
from sqlalchemy import func, select, update

from backend.core.schemas import FlowMessage
from backend.db.crud import utc_iso
from backend.db.models import (
    Asset,
    EnforcementPoint,
    Incident,
    IncidentEvent,
    LiveInspection,
    LiveInspectionWindow,
    OpsControl,
    utcnow,
)
from backend.services.detection import process_flow, traffic_message
from backend.services.risk_gate import assess
from collector.feature_schema import CONTEXT_FEATURES, LEGACY_FEATURES
from collector.features import FeatureCalculator, Snapshot

logger = logging.getLogger(__name__)

STEP_SECONDS = 1
MAX_RUNS = 20
MAX_FLOWS_PER_SECOND = 200
WINDOW_HISTORY = 300
KIND_LABEL = {"wifi": "Wi-Fi", "ethernet": "유선 LAN", "loopback": "루프백", "virtual": "가상", "other": "기타"}
KIND_ORDER = {"wifi": 0, "ethernet": 1, "other": 2, "virtual": 3, "loopback": 4}
VIRTUAL_PREFIXES = (
    "docker", "veth", "br-", "virbr", "utun", "awdl", "llw", "bridge", "vmenet", "vmnet", "tun",
    "tap", "gif", "stf", "anpi", "ipsec", "p2p", "wg", "ap",
)
_ports_cache = {"at": 0.0, "value": {}}


# ---------------------------------------------------------------- interfaces

def _hardware_ports():
    """macOS maps device → hardware port name; cached, empty on other platforms."""
    if sys.platform != "darwin":
        return {}
    if time.time() - _ports_cache["at"] < 60:
        return _ports_cache["value"]
    ports, name = {}, None
    try:
        output = subprocess.run(
            ["networksetup", "-listallhardwareports"], capture_output=True, text=True, timeout=3
        ).stdout
        for line in output.splitlines():
            if line.startswith("Hardware Port:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Device:") and name:
                ports[line.split(":", 1)[1].strip()] = name
                name = None
    except Exception:
        ports = {}
    _ports_cache.update(at=time.time(), value=ports)
    return ports


def interface_kind(name, ports=None):
    port = (ports or {}).get(name, "").lower()
    if name.startswith("lo"):
        return "loopback"
    if "wi-fi" in port or "airport" in port or name.startswith(("wl", "wlan", "wlp")):
        return "wifi"
    if os.path.isdir(f"/sys/class/net/{name}/wireless"):
        return "wifi"
    if "bridge" in port or name.startswith(VIRTUAL_PREFIXES):
        return "virtual"
    if "ethernet" in port or "lan" in port or name.startswith(("en", "eth", "em", "eno", "ens", "enp")):
        return "ethernet"
    return "other"


def list_interfaces():
    ports = _hardware_ports()
    addresses, stats, counters = (
        psutil.net_if_addrs(), psutil.net_if_stats(), psutil.net_io_counters(pernic=True)
    )
    items = []
    for name in sorted(addresses):
        v4 = [a.address for a in addresses[name] if a.family == socket.AF_INET]
        stat, io = stats.get(name), counters.get(name)
        kind = interface_kind(name, ports)
        up = bool(stat and stat.isup)
        items.append({
            "name": name, "kind": kind, "label": ports.get(name) or KIND_LABEL[kind],
            "addresses": v4, "is_up": up, "speed_mbps": stat.speed if stat else 0,
            "packets_received": io.packets_recv if io else 0,
            "bytes_received": io.bytes_recv if io else 0,
            "active": up and bool(v4) and kind != "loopback",
        })
    items.sort(key=lambda item: (not item["active"], KIND_ORDER.get(item["kind"], 9), item["name"]))
    return items


def _raw_capture_permitted():
    if os.name != "posix":
        return False, "이 운영체제에서는 패킷 검사를 지원하지 않습니다"
    if getattr(os, "geteuid", lambda: 1)() == 0:
        return True, ""
    if sys.platform == "darwin":
        for index in range(4):
            try:
                os.close(os.open(f"/dev/bpf{index}", os.O_RDWR))
                return True, ""
            except PermissionError:
                return False, "/dev/bpf 접근 권한이 없습니다 — 관리자 권한(sudo)으로 실행하거나 Wireshark의 ChmodBPF를 설치하세요"
            except OSError:
                continue
        return False, "/dev/bpf 장치를 열 수 없습니다"
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW).close()
        return True, ""
    except (AttributeError, OSError):
        return False, "원시 소켓 권한이 없습니다 — root 또는 CAP_NET_RAW 권한이 필요합니다"


def capabilities():
    installed = importlib.util.find_spec("scapy") is not None
    permitted, reason = _raw_capture_permitted()
    if not installed:
        reason = "scapy 패키지가 없습니다 — `pip install scapy` 후 다시 시도하세요"
    return {
        "packet": {"available": installed and permitted, "reason": "" if installed and permitted else reason},
        "counters": {"available": True, "reason": ""},
    }


# ---------------------------------------------------------------- samplers

class CounterSampler:
    """Interface-wide received packets and bytes per second. No privilege needed."""

    mode = "counters"

    def __init__(self, interface, address):
        self.interface, self.address, self.started = interface, address, time.time()
        self.previous = self._read()

    def _read(self):
        io = psutil.net_io_counters(pernic=True).get(self.interface)
        if io is None:
            raise LookupError(f"{self.interface} 인터페이스의 카운터를 읽을 수 없습니다")
        return io.packets_recv, io.bytes_recv

    def start(self):
        return None

    def stop(self):
        return None

    def sample(self, now):
        packets, byte_count = self._read()
        delta_packets = max(0, packets - self.previous[0])
        delta_bytes = max(0, byte_count - self.previous[1])
        self.previous = (packets, byte_count)
        features = dict(
            pkt_rate=float(delta_packets), byte_rate=float(delta_bytes), syn_ratio=0.0,
            port_entropy=0.0, flow_duration=(now - self.started) * 1000,
            avg_pkt_size=delta_bytes / delta_packets if delta_packets else 0.0, port_cnt=1,
            source_pkt_rate=float(delta_packets), source_syn_rate=0.0,
        )
        return [FlowMessage(
            type="flow_features", message_id=uuid4(), timestamp=int(now * 1000),
            flow=dict(src_ip="0.0.0.0", dst_ip=self.address, src_port=0, dst_port=0, protocol=6),
            features=features,
        )]


class PacketAccumulator:
    """Cumulative per-flow counters, the shape the XDP map exports. Fed from the sniffer thread."""

    def __init__(self, max_flows=65536):
        self.lock, self.flows, self.touched, self.max_flows = threading.Lock(), {}, set(), max_flows
        self.packets = self.bytes = 0

    def add(self, src, dst, sport, dport, protocol, length, syn, now_ns=None):
        now_ns = now_ns or time.time_ns()
        key = (src, dst, sport, dport, protocol)
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                flow = self.flows[key] = [0, 0, 0, now_ns, now_ns]
            flow[0] += 1
            flow[1] += length
            flow[2] += int(syn)
            flow[4] = now_ns
            self.touched.add(key)
            self.packets += 1
            self.bytes += length

    def drain(self):
        with self.lock:
            touched, self.touched = self.touched, set()
            # First-seen order: a reply flow is computed after the request it answers, so the
            # calculator can attach reverse-direction context deterministically.
            snapshots = [Snapshot(*key, *self.flows[key]) for key in self.flows if key in touched]
            if len(self.flows) > self.max_flows:
                for stale in sorted(self.flows, key=lambda k: self.flows[k][4])[: len(self.flows) - self.max_flows]:
                    del self.flows[stale]
        return snapshots


def packet_tuple(packet):
    """scapy packet → (src, dst, sport, dport, protocol, length, syn); None unless IPv4 TCP/UDP."""
    ip = packet.getlayer("IP")
    if ip is None:
        return None
    tcp = packet.getlayer("TCP")
    if tcp is not None:
        flags = int(tcp.flags)
        return (ip.src, ip.dst, int(tcp.sport or 0), int(tcp.dport or 0), 6, len(packet),
                bool(flags & 0x02) and not flags & 0x10)
    udp = packet.getlayer("UDP")
    if udp is not None:
        return ip.src, ip.dst, int(udp.sport or 0), int(udp.dport or 0), 17, len(packet), False
    return None


def messages_from(snapshots, calculator, now):
    """Flow snapshots → schema-2 feature messages, busiest flows first, bounded per second."""
    messages = []
    for snapshot in snapshots:
        features = calculator.compute(snapshot, now)
        if features is None:
            continue
        messages.append(FlowMessage(
            type="flow_features", message_id=uuid4(), timestamp=int(now * 1000),
            flow=dict(src_ip=snapshot.src_ip, dst_ip=snapshot.dst_ip, src_port=snapshot.src_port,
                      dst_port=snapshot.dst_port, protocol=snapshot.protocol),
            features=features,
        ))
    # Later snapshots of one second carry the fullest source context, so rank by it.
    messages.sort(key=lambda m: (-m.features.source_pkt_rate, -m.features.pkt_rate))
    return messages[:MAX_FLOWS_PER_SECOND]


class PacketSampler:
    """Every IPv4 TCP/UDP packet on the interface, both directions, into the collector's calculator."""

    mode = "packet"

    def __init__(self, interface, address):
        self.interface, self.address = interface, address
        self.accumulator, self.calculator, self.sniffer = PacketAccumulator(), FeatureCalculator(), None

    def start(self):
        from scapy.all import AsyncSniffer  # Optional dependency; imported only when permitted.

        self.sniffer = AsyncSniffer(iface=self.interface, store=False, filter="ip and (tcp or udp)",
                                    prn=self._on_packet)
        self.sniffer.start()

    def _on_packet(self, packet):
        record = packet_tuple(packet)
        if record:
            self.accumulator.add(*record)

    def stop(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                logger.debug("Sniffer already stopped")

    def sample(self, now):
        return messages_from(self.accumulator.drain(), self.calculator, now)


# ---------------------------------------------------------------- inspection runs

def _new_window(now):
    return {"t": int(now * 1000), "pkt_rate": 0.0, "byte_rate": 0.0, "flows": 0, "rule_hits": {},
            "scored": 0, "min_score": None, "events": []}


def _new_totals():
    return {"packets": 0.0, "bytes": 0.0, "peak_pps": 0.0, "flows": 0, "seconds": 0, "checked": 0,
            "rule_hits": {}, "scored": 0, "min_score": None, "model_hits": 0, "events": 0,
            "automatic": {"applied": 0, "declined": 0, "other": 0}}


def sampler_interface(state):
    return state.get("interface", "")


def window_dict(row):
    return {"t": int(_aware(row.observed_at).timestamp() * 1000), "pkt_rate": row.pkt_rate,
            "byte_rate": row.byte_rate, "flows": row.flows, "rule_hits": row.rule_hits or {},
            "scored": row.scored, "min_score": row.min_score, "events": row.events or []}


def _aware(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class LiveInspector:
    """Runs live in a task; every observed second is written to the database as it happens, so the
    web app reads history from the same tables after a reload or a server restart."""

    def __init__(self, app):
        self.app, self.tasks, self.lock = app, {}, asyncio.Lock()

    async def recover(self):
        async with self.app.state.db.sessions() as session:
            await session.execute(update(LiveInspection).where(LiveInspection.status == "running")
                                  .values(status="interrupted", finished_at=utcnow()))
            await session.commit()

    def stages(self, row):
        totals, detector, settings = row.totals or _new_totals(), self.app.state.detector, self.app.state.settings
        running = row.status == "running"
        capture = {
            "status": "running" if running else ("ok" if totals["packets"] else "empty" if row.status == "completed" else row.status),
            "mode": row.mode, "packets": int(totals["packets"]), "bytes": int(totals["bytes"]),
            "peak_pps": int(totals["peak_pps"]), "flows": totals["flows"], "seconds": totals["seconds"],
            "note": "패킷 하나하나를 읽어 25개 관측 항목을 계산해요" if row.mode == "packet"
            else "인터페이스 카운터만 읽어요 — 초당 패킷·전송량은 정확하고, SYN·포트 항목은 0으로 둡니다",
        }
        rules = {
            "status": "running" if running else ("ok" if totals["checked"] else "idle"),
            "checked": totals["checked"], "hits": totals["rule_hits"], "thresholds": row.thresholds,
            "note": "연결 폭주(SYN Flood)·포트 스캔 규칙은 패킷 검사에서만 판정돼요" if row.mode == "counters"
            else "저장된 임계값으로 4개 규칙을 매초 판정해요",
        }
        if row.detection_mode != "hybrid":
            model_status, reason = "skipped", (
                "모델 산출물이 없거나 검증되지 않아 규칙만 적용해요" if detector.model is None
                else "실시간 저장소(Redis)가 연결되지 않아 실시간 경로에서는 규칙만 적용해요")
        elif detector.feature_names == CONTEXT_FEATURES and row.mode == "counters":
            model_status, reason = "skipped", "이 모델은 25개 관측 항목이 필요해 패킷 검사에서만 점수를 내요"
        else:
            model_status, reason = ("running" if running else "ok" if totals["scored"] else "idle"), ""
        model = {
            "status": model_status, "reason": reason, "scored": totals["scored"],
            "min_score": totals["min_score"], "anomalies": totals["model_hits"],
            "mode": row.detection_mode, "model_status": detector.model_status,
            "threshold": (row.thresholds or {}).get("anomaly_threshold"),
            "feature_count": len(detector.feature_names),
        }
        response = {
            "status": "running" if running else ("ok" if totals["events"] else "idle"),
            "events": totals["events"], "incidents": len(row.incident_ids or []),
            "automatic": totals["automatic"], "live_enabled": settings.response_live_enabled,
            "note": "탐지 이벤트는 사건으로 묶이고, 자동 경로가 켜져 있으면 차단 안전 점검을 거쳐요",
        }
        return {"capture": capture, "rules": rules, "model": model, "response": response}

    def run_dict(self, row, windows=None):
        item = {key: getattr(row, key) for key in ("id", "interface", "address", "mode", "status", "duration_seconds",
                                                    "elapsed_seconds", "error", "detection_mode", "thresholds")}
        item.update(started_at=utc_iso(row.started_at),
                    finished_at=utc_iso(row.finished_at) if row.finished_at else None,
                    stages=self.stages(row), event_ids=(row.event_ids or [])[-50:])
        if windows is not None:
            item["windows"] = [window_dict(w) for w in windows]
        return item

    async def list(self, limit=MAX_RUNS):
        async with self.app.state.db.sessions() as session:
            rows = await session.scalars(select(LiveInspection).order_by(LiveInspection.started_at.desc()).limit(limit))
            return [self.run_dict(row) for row in rows]

    async def detail(self, run_id):
        async with self.app.state.db.sessions() as session:
            row = await session.get(LiveInspection, run_id)
            if row is None:
                raise HTTPException(404, "검사 기록을 찾을 수 없습니다")
            windows = list(await session.scalars(
                select(LiveInspectionWindow).where(LiveInspectionWindow.run_id == run_id)
                .order_by(LiveInspectionWindow.second.desc()).limit(WINDOW_HISTORY)))
            return self.run_dict(row, list(reversed(windows)))

    async def start(self, body):
        async with self.lock:
            if self.tasks:
                raise HTTPException(409, "이미 검사가 진행 중입니다. 끝나기를 기다리거나 중지하세요")
            interfaces = {item["name"]: item for item in await asyncio.to_thread(list_interfaces)}
            iface = interfaces.get(body.interface)
            if iface is None:
                raise HTTPException(404, "인터페이스를 찾을 수 없습니다")
            if not iface["is_up"]:
                raise HTTPException(400, "인터페이스가 비활성 상태입니다")
            caps = capabilities()
            mode = body.mode
            if mode == "auto":
                mode = "packet" if caps["packet"]["available"] else "counters"
            elif mode == "packet" and not caps["packet"]["available"]:
                raise HTTPException(400, f"패킷 검사를 사용할 수 없습니다: {caps['packet']['reason']}")
            address = (iface["addresses"] or ["127.0.0.1"])[0]
            sampler = (PacketSampler if mode == "packet" else CounterSampler)(body.interface, address)
            try:
                await asyncio.to_thread(sampler.start)
            except Exception as error:
                raise HTTPException(503, f"캡처를 시작하지 못했습니다: {error}") from None
            detector = self.app.state.detector
            row = LiveInspection(
                id=str(uuid4()), interface=body.interface, address=address, mode=mode, status="running",
                duration_seconds=body.duration_seconds, elapsed_seconds=0, started_at=utcnow(), error="",
                thresholds=detector.rules.thresholds.model_dump(),
                detection_mode=detector.mode if self.app.state.redis_available else "rules_only",
                totals=_new_totals(), event_ids=[], incident_ids=[],
            )
            async with self.app.state.db.sessions() as session:
                session.add(row)
                await session.commit()
                await session.refresh(row)
                result = self.run_dict(row)
            task = asyncio.create_task(self.execute(row.id, row.duration_seconds, sampler))
            self.tasks[row.id] = task
            task.add_done_callback(lambda _: self.tasks.pop(row.id, None))
            return result

    async def _inspect(self, message, state, window, run_id, mode):
        totals = state["totals"]
        async with self.app.state.db.sessions() as session:
            result, event = await process_flow(self.app, session, message)
            automatic = incident_id = None
            if event:
                incident_id = await session.scalar(select(IncidentEvent.incident_id).where(
                    IncidentEvent.event_id == event["event_id"]))
                incident = await session.get(Incident, incident_id) if incident_id else None
                automatic = ((incident.summary or {}).get("automatic") or {}).get("status") if incident else None
            await session.commit()
        window["pkt_rate"] += message.features.pkt_rate
        window["byte_rate"] += message.features.byte_rate
        totals["checked"] += 1
        if result["severity"]:
            if result["attack_type"] == "ANOMALY":
                totals["model_hits"] += 1
            else:
                for holder in (window["rule_hits"], totals["rule_hits"]):
                    holder[result["attack_type"]] = holder.get(result["attack_type"], 0) + 1
        if result["anomaly_score"] is not None:
            window["scored"] += 1
            totals["scored"] += 1
            for holder in (window, totals):
                holder["min_score"] = result["anomaly_score"] if holder["min_score"] is None else min(holder["min_score"], result["anomaly_score"])
        if event:
            totals["events"] += 1
            state["event_ids"].append(event["event_id"])
            if incident_id and incident_id not in state["incident_ids"]:
                state["incident_ids"].append(incident_id)
            if automatic:
                totals["automatic"][automatic if automatic in ("applied", "declined") else "other"] += 1
            window["events"].append({"event_id": event["event_id"], "attack_type": event["attack_type"],
                                     "severity": event["severity"], "incident_id": incident_id,
                                     "automatic": automatic})
            await self.app.state.manager.broadcast(event)
        await self.app.state.manager.broadcast({
            **traffic_message(message, result),
            "capture": {"inspection_id": run_id, "interface": sampler_interface(state), "mode": mode},
        })

    async def execute(self, run_id, duration, sampler):
        status, error = "completed", ""
        state = {"totals": _new_totals(), "event_ids": [], "incident_ids": [], "interface": sampler.interface}
        totals = state["totals"]
        try:
            for second in range(duration):
                await asyncio.sleep(STEP_SECONDS)
                now = time.time()
                messages = await asyncio.to_thread(sampler.sample, now)
                window = _new_window(now)
                window["flows"] = len(messages)
                for message in messages:
                    await self._inspect(message, state, window, run_id, sampler.mode)
                totals["packets"] += window["pkt_rate"]
                totals["bytes"] += window["byte_rate"]
                totals["peak_pps"] = max(totals["peak_pps"], window["pkt_rate"])
                totals["flows"] = max(totals["flows"], window["flows"])
                totals["seconds"] += 1
                async with self.app.state.db.sessions() as session:
                    session.add(LiveInspectionWindow(
                        run_id=run_id, second=second, observed_at=datetime.fromtimestamp(now, timezone.utc),
                        pkt_rate=window["pkt_rate"], byte_rate=window["byte_rate"], flows=window["flows"],
                        rule_hits=window["rule_hits"], scored=window["scored"], min_score=window["min_score"],
                        events=window["events"]))
                    await session.execute(update(LiveInspection).where(LiveInspection.id == run_id).values(
                        elapsed_seconds=totals["seconds"], totals=dict(totals), event_ids=list(state["event_ids"]),
                        incident_ids=list(state["incident_ids"])))
                    await session.commit()
        except asyncio.CancelledError:
            status = "cancelled"
        except Exception as failure:
            logger.exception("Live inspection failed: %s", run_id)
            status, error = "failed", str(failure)[:240]
        finally:
            await asyncio.to_thread(sampler.stop)
            async with self.app.state.db.sessions() as session:
                await session.execute(update(LiveInspection).where(LiveInspection.id == run_id).values(
                    status=status, finished_at=utcnow(), error=error, elapsed_seconds=totals["seconds"],
                    totals=dict(totals), event_ids=list(state["event_ids"]), incident_ids=list(state["incident_ids"])))
                await session.commit()

    async def stop(self, run_id):
        task = self.tasks.get(run_id)
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return await self.detail(run_id)

    async def close(self):
        for task in list(self.tasks.values()):
            task.cancel()
        await asyncio.gather(*list(self.tasks.values()), return_exceptions=True)


# ---------------------------------------------------------------- defense check

def _full_features(base):
    """Legacy vector → schema-2 vector so any deployed feature contract can score it."""
    packets, byte_count, syns = base["pkt_rate"], base["byte_rate"], base["source_syn_rate"]
    return {
        **base, "feature_schema_version": 2,
        "destination_pkt_rate": packets, "destination_byte_rate": byte_count, "destination_syn_rate": syns,
        "destination_source_count": 1, "service_pkt_rate": packets, "service_byte_rate": byte_count,
        "service_syn_rate": syns, "service_source_count": 1, "reverse_pkt_rate": 0.0,
        "reverse_byte_rate": 0.0, "bidirectional_pkt_rate": packets, "bidirectional_byte_rate": byte_count,
        "reverse_packet_fraction": 0.0, "bidirectional_syn_ratio": base["syn_ratio"],
        "source_pkt_rate_10s": packets, "destination_pkt_rate_10s": packets,
    }


def rule_probes(thresholds):
    """Vectors just past each stored threshold, and one benign vector below all of them."""
    t = thresholds
    benign = dict(pkt_rate=35, byte_rate=28000, syn_ratio=0.03, port_entropy=0.2, flow_duration=1000,
                  avg_pkt_size=800, port_cnt=2, source_pkt_rate=35, source_syn_rate=1)
    syn_rate = t.syn_pps_threshold * 1.2
    ratio = min(1.0, max(t.syn_ratio_threshold, 0.9))
    spike = t.baseline_pps * t.spike_threshold_multiplier * 1.2
    return [
        ("연결 폭주(SYN Flood)", "SYN_FLOOD", {**benign, "pkt_rate": syn_rate / ratio, "syn_ratio": ratio,
                                          "port_cnt": 1, "source_pkt_rate": syn_rate / ratio,
                                          "source_syn_rate": syn_rate, "avg_pkt_size": 60}),
        ("포트 스캔(Port Scan)", "PORT_SCAN", {**benign, "pkt_rate": 80, "syn_ratio": 1, "port_entropy": 5.6,
                                          "port_cnt": t.port_cnt_threshold + 5, "source_pkt_rate": 80,
                                          "source_syn_rate": 80, "avg_pkt_size": 60}),
        ("트래픽 급증(Traffic Spike)", "TRAFFIC_SPIKE", {**benign, "pkt_rate": spike, "syn_ratio": 0.05,
                                                  "source_pkt_rate": spike, "source_syn_rate": spike * 0.05,
                                                  "byte_rate": min(spike * 75, t.large_flow_threshold * 0.5)}),
        ("대용량 전송(Large Flow)", "LARGE_FLOW", {**benign, "pkt_rate": min(9500, t.baseline_pps * t.spike_threshold_multiplier * 0.5),
                                              "byte_rate": t.large_flow_threshold * 1.1, "avg_pkt_size": 1422}),
        ("정상 접속", None, benign),
    ]


async def defense_check(app):
    detector, settings = app.state.detector, app.state.settings
    thresholds = detector.rules.thresholds
    caps = capabilities()
    interfaces = await asyncio.to_thread(list_interfaces)
    active = [item for item in interfaces if item["active"]]
    capture = {
        "id": "capture", "title": "수집 · 내 네트워크 인터페이스",
        "status": "ok" if active else "warn",
        "detail": (f"활성 인터페이스 {len(active)}개 · " + ("패킷 검사 가능" if caps["packet"]["available"]
                   else f"카운터 검사만 가능 ({caps['packet']['reason']})")) if active
        else "IPv4 주소가 있는 활성 인터페이스가 없습니다",
        "capabilities": caps, "interfaces": [item["name"] for item in active],
    }

    probes = []
    for name, expected, features in rule_probes(thresholds):
        detected = detector.rules.detect(features)
        probes.append({"name": name, "expected": expected or "BENIGN", "detected": detected or "BENIGN",
                       "passed": detected == expected})
    rules = {
        "id": "rules", "title": "1차 방어선 · 규칙 엔진",
        "status": "ok" if all(p["passed"] for p in probes) else "fail",
        "detail": f"{sum(p['passed'] for p in probes)}/{len(probes)} 판정이 저장된 임계값과 일치해요",
        "probes": probes, "thresholds": thresholds.model_dump(),
    }

    model_probes, model_status, model_detail = [], "skipped", ""
    if detector.model is None:
        model_detail = {
            "not_configured": "모델 경로가 설정되지 않아 규칙만 사용해요",
        }.get(detector.model_status, "모델 산출물이 없거나 검증되지 않아 규칙만 사용해요")
    else:
        try:
            for name, _, features in (rule_probes(thresholds)[0], rule_probes(thresholds)[4]):
                result = await asyncio.to_thread(detector.analyze, _full_features(features), True)
                model_probes.append({"name": name, "score": result["anomaly_score"],
                                     "flagged": result["anomaly_score"] is not None
                                     and result["anomaly_score"] < thresholds.anomaly_threshold})
            scored = all(p["score"] is not None for p in model_probes)
            model_status = "ok" if scored else "fail"
            model_detail = (f"{len(detector.feature_names)}개 관측 항목 모델이 점수를 냈어요"
                            if scored else "모델이 점수를 내지 못했어요")
        except Exception as error:
            model_status, model_detail = "fail", f"추론 오류: {error}"
    shadow = app.state.shadow_model
    model = {
        "id": "model", "title": "2차 방어선 · AI 이상 탐지",
        "status": model_status, "detail": model_detail, "probes": model_probes,
        "mode": detector.mode, "model_status": detector.model_status,
        "feature_count": len(detector.feature_names),
        "contract": "context-25" if detector.feature_names == CONTEXT_FEATURES
        else "legacy-6" if detector.feature_names == LEGACY_FEATURES else "source-9",
        "threshold": thresholds.anomaly_threshold,
        "live_applied": detector.model is not None and app.state.redis_available,
        "live_reason": "" if detector.model is None or app.state.redis_available
        else "실시간 저장소(Redis)가 연결되지 않아 실시간 경로에서는 규칙만 적용돼요",
        "context_model_status": shadow.status,
    }

    now = datetime.now(timezone.utc)
    standard = SimpleNamespace(address="198.51.100.20", protected_cidrs=["198.51.100.0/28"], criticality="standard")
    critical = SimpleNamespace(address="198.51.100.20", protected_cidrs=["198.51.100.0/28"], criticality="critical")
    flood = [SimpleNamespace(syn_ratio=0.98, raw_features={"reverse_packet_fraction": 0.01, "port_cnt": 1},
                             detected_at=now - timedelta(seconds=6 - i)) for i in range(6)]
    mixed = [SimpleNamespace(syn_ratio=0.2, raw_features={"reverse_packet_fraction": 0.8, "port_cnt": 48},
                             detected_at=now - timedelta(seconds=3 - i)) for i in range(3)]
    gate_probes = []
    for name, source, asset, events, expected in (
        ("단일 출발지 연결 폭주", "203.0.113.77", standard, flood, "automatic"),
        ("정상 사용자가 섞인 공유 출발지", "203.0.113.12", critical, mixed, "approval"),
    ):
        gate = assess(source_ip=source, asset=asset, events=events, threshold=settings.response_risk_threshold, now=now)
        gate_probes.append({"name": name, "expected": expected, "route": gate["route"], "score": gate["score"],
                            "level": gate["level"], "hard_stop": gate["hard_stop"],
                            "reason": gate["reasons"][0] if gate["reasons"] else "",
                            "passed": gate["route"] == expected})
    async with app.state.db.sessions() as session:
        control = await session.get(OpsControl, 1)
        assets = await session.scalar(select(func.count()).select_from(Asset)) or 0
        opted_in = await session.scalar(select(func.count()).select_from(Asset).where(Asset.auto_response.is_(True))) or 0
        points = await session.scalar(select(func.count()).select_from(EnforcementPoint).where(EnforcementPoint.enabled.is_(True))) or 0
    auto_on = bool(control and control.auto_response and not control.kill_switch)
    response = {
        "id": "response", "title": "대응 · 차단 안전 점검과 자동 경로",
        "status": "ok" if all(p["passed"] for p in gate_probes) else "fail",
        "detail": ("차단 안전 점검이 저위험은 자동 경로, 고위험은 승인 경로로 나눴어요 · "
                   + ("자동 경로 켜짐" if auto_on else "자동 경로 꺼짐(승인 경로만)")),
        "probes": gate_probes, "threshold": settings.response_risk_threshold,
        "control": {"auto_response": bool(control and control.auto_response),
                    "kill_switch": bool(control and control.kill_switch)},
        "assets": assets, "assets_opted_in": opted_in, "points_enabled": points,
        "live_enabled": settings.response_live_enabled,
        "auto_ttl_seconds": settings.response_auto_ttl_seconds,
    }
    items = [capture, rules, model, response]
    return {
        "checked_at": now.isoformat(),
        "items": items,
        "summary": {status: sum(item["status"] == status for item in items) for status in ("ok", "warn", "skipped", "fail")},
    }
