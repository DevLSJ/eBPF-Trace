import ctypes
import socket

from collector.reader import FlowEvent, RingBufferReader


def test_nested_ring_event_binary_abi():
    assert ctypes.sizeof(FlowEvent) == 112
    event = FlowEvent()
    event.key.src_ip = int.from_bytes(socket.inet_aton("10.200.0.1"), "little")
    event.key.dst_ip = int.from_bytes(socket.inet_aton("10.200.0.2"), "little")
    event.key.src_port, event.key.dst_port, event.key.protocol = 40000, 80, 6
    event.stats.pkt_cnt, event.stats.byte_cnt, event.stats.syn_cnt = 100, 5400, 100
    received = []
    reader = RingBufferReader.__new__(RingBufferReader)
    reader.callback = received.append
    reader._event(None, ctypes.byref(event), ctypes.sizeof(event))
    assert received[0].src_ip == "10.200.0.1"
    assert received[0].src_port == 40000
    assert received[0].pkt_cnt == 100
    assert reader._event(None, ctypes.byref(event), 5) == 0
    assert len(received) == 1
