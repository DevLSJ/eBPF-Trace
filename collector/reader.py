import ctypes
import ctypes.util
import os
import socket
from pathlib import Path

from collector.features import Snapshot


class FlowKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]


class FlowStats(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_uint64)
        for name in (
            "pkt_cnt",
            "byte_cnt",
            "syn_cnt",
            "first_seen_ns",
            "last_seen_ns",
            "last_export_ns",
        )
    ]
    _fields_ += [
        ("dst_ports", ctypes.c_uint16 * 16),
        ("port_cnt", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 7),
    ]


class FlowEvent(ctypes.Structure):
    _fields_ = [("key", FlowKey), ("stats", FlowStats), ("export_ts_ns", ctypes.c_uint64)]


class RingBufferReader:
    def __init__(self, iface, callback):
        from bcc import BPF  # Available only in the Ubuntu system Python.

        self.callback = callback
        self.bpf = BPF(
            src_file=str(Path(__file__).parents[1] / "ebpf-agent/xdp_agent.c"),
            cflags=["-DBCC_BUILD"],
        )
        program = self.bpf.load_func("xdp_packet_handler", BPF.XDP)
        library = ctypes.CDLL(ctypes.util.find_library("bpf"), use_errno=True)
        library.bpf_link_create.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_void_p,
        ]
        library.bpf_link_create.restype = ctypes.c_int
        # XDP BPF link (BPF_XDP=37) owns the attachment. Closing the process fd, even
        # after SIGKILL, detaches it and releases maps. No persistent bpffs pins.
        self.link_fd = library.bpf_link_create(program.fd, socket.if_nametoindex(iface), 37, None)
        if self.link_fd < 0:
            error = ctypes.get_errno()
            self.bpf.cleanup()
            raise OSError(error, "Native XDP link attachment failed: " + os.strerror(error))
        self.bpf["events"].open_ring_buffer(self._event)

    @staticmethod
    def snapshot(key, stats):
        def ip(value):
            return socket.inet_ntoa(bytes(ctypes.c_uint32(value)))

        return Snapshot(
            ip(key.src_ip),
            ip(key.dst_ip),
            key.src_port,
            key.dst_port,
            key.protocol,
            stats.pkt_cnt,
            stats.byte_cnt,
            stats.syn_cnt,
            stats.first_seen_ns,
            stats.last_seen_ns,
        )

    def _event(self, context, data, size):
        if size != ctypes.sizeof(FlowEvent):
            return 0
        # Ubuntu 22.04 BCC 0.18 cannot infer nested ring-buffer structures.
        event = ctypes.cast(data, ctypes.POINTER(FlowEvent)).contents
        self.callback(self.snapshot(event.key, event.stats))
        return 0

    def poll(self):
        self.bpf.ring_buffer_poll(100)

    def flush(self):
        # Export the final partial interval of idle / single-packet flows.
        for key, stats in self.bpf["flow_stats_map"].items():
            self.callback(self.snapshot(key, stats))

    def close(self):
        os.close(self.link_fd)
        self.bpf.cleanup()
