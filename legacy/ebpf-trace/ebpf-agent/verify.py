"""Root-only kernel verifier and packet tests; no packets are sent onto a network."""
import ctypes
import ctypes.util
import json
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bcc import BPF  # noqa: E402


def packet(port=80, protocol=6, flags=2, fragment=0):
    ethernet = bytes.fromhex("0200000000020200000000010800")
    transport = (struct.pack("!HHIIBBHHH", 12345, port, 0, 0, 0x50, flags, 1024, 0, 0)
                 if protocol == 6 else struct.pack("!HHHH", 12345, port, 8, 0))
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(transport), 0, fragment, 64,
                        protocol, 0, socket.inet_aton("10.200.0.1"), socket.inet_aton("10.200.0.2"))
    return ethernet + ipv4 + transport


def main():
    bpf = BPF(src_file=str(Path(__file__).with_name("xdp_agent.c")), cflags=["-DBCC_BUILD"])
    function = bpf.load_func("xdp_packet_handler", BPF.XDP)
    library = ctypes.CDLL(ctypes.util.find_library("bpf"), use_errno=True)
    test_run = library.bpf_prog_test_run
    test_run.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
                         ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
                         ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    test_run.restype = ctypes.c_int
    def check(data, repeat=1):
        incoming, outgoing = ctypes.create_string_buffer(data), ctypes.create_string_buffer(4096)
        size, retval, duration = ctypes.c_uint32(4096), ctypes.c_uint32(), ctypes.c_uint32()
        result = test_run(function.fd, repeat, incoming, len(data), outgoing,
                          ctypes.byref(size), ctypes.byref(retval), ctypes.byref(duration))
        if result:
            raise OSError(ctypes.get_errno(), "BPF_PROG_TEST_RUN failed")
        assert retval.value == 2, "Every packet must return XDP_PASS"
    try:
        check(packet(), 100)
        check(packet(flags=0x12), 10)
        check(packet(port=53, protocol=17), 5)
        # IPv4 fragments and unsupported EtherTypes must not create flows.
        check(packet(port=9000, fragment=0x2000))
        check(bytes.fromhex("02000000000202000000000186dd") + bytes(40))
        stats = {key.dst_port: value for key, value in bpf["flow_stats_map"].items()}
        assert stats[80].pkt_cnt == 110 and stats[80].syn_cnt == 100
        assert stats[80].byte_cnt == len(packet()) * 110
        assert stats[53].pkt_cnt == 5 and stats[53].syn_cnt == 0
        assert 9000 not in stats and len(stats) == 2
        for port in range(1000, 1020):
            check(packet(port=port))
        assert len(list(bpf["flow_stats_map"].items())) == 22
        received = []
        bpf["events"].open_ring_buffer(lambda ctx, data, size: received.append(size))
        bpf.ring_buffer_poll(10)
        assert len(received) >= 22
        print(json.dumps({"kernel_packet_tests": "passed", "flows": 22,
                          "ring_events": len(received), "tcp_packets": 110,
                          "syn_packets": 100, "udp_packets": 5}))
    finally:
        bpf.cleanup()


if __name__ == "__main__":
    main()
