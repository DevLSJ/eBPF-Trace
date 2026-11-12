import io
import struct

import pytest

from collector.features import FeatureCalculator, Snapshot
from ml.pcap import Packet, decode, packets
from ml.replay import Replay, analyze


def ethernet(flags=2, fragment=0, vlan=False):
    eth = b"\0" * 12 + (b"\x81\x00\0\1\x08\x00" if vlan else b"\x08\x00")
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, fragment, 64, 6, 0,
                     b"\xc0\xa8\0\1", b"\xc0\xa8\0\2")
    tcp = struct.pack("!HHIIBBHHH", 5000, 80, 0, 0, 0x50, flags, 100, 0, 0)
    return eth + ip + tcp


def classic(data, endian="<"):
    return (struct.pack(endian + "IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            + struct.pack(endian + "IIII", 1, 500000, len(data), len(data)) + data)


def block(kind, body, endian):
    body += b"\0" * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def ng(data, endian="<"):
    section = block(0x0a0d0d0a, struct.pack(endian + "IHHq", 0x1a2b3c4d, 1, 0, -1), endian)
    # Nanosecond resolution and a two-second timestamp offset.
    opts = struct.pack(endian + "HH", 9, 1) + b"\x09\0\0\0"
    opts += struct.pack(endian + "HHq", 14, 8, 2)
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535) + opts, endian)
    packet = block(6, struct.pack(endian + "IIIII", 0, 0, 1500000000, len(data), len(data))
                   + data, endian)
    return section + interface + packet


@pytest.mark.parametrize("endian", ["<", ">"])
def test_formats_endian_sections_and_resolution(endian):
    data = ethernet()
    assert list(packets(io.BytesIO(classic(data, endian)))) == [Packet(1.5, data, 54, 1)]
    assert list(packets(io.BytesIO(ng(data, endian)))) == [Packet(3.5, data, 54, 1)]
    assert len(list(packets(io.BytesIO(ng(data, endian) + ng(data, endian))))) == 2


def test_truncated_and_corrupt_capture_rejected():
    with pytest.raises(ValueError, match="Truncated"):
        list(packets(io.BytesIO(classic(ethernet())[:-1])))
    bad = bytearray(ng(ethernet()))
    bad[-1] = 0xff
    with pytest.raises(ValueError, match="disagree"):
        list(packets(io.BytesIO(bad)))


def test_xdp_parity_vlan_syn_and_fragments():
    for flags, expected in [(2, 1), (0x12, 0), (0x10, 0)]:
        data = ethernet(flags, vlan=True)
        (key, syn), reason = decode(Packet(1, data, len(data), 1))
        assert reason is None and syn == expected and key[-1] == 6
    data = ethernet(fragment=0x2000)
    assert decode(Packet(1, data, len(data), 1))[1] == "fragment"
    assert decode(Packet(1, data, len(data) + 1, 1))[1] == "truncated_packet"


def test_replay_uses_collector_snapshots_and_flushes_short_flow():
    replay = Replay()
    key = ("192.168.0.1", "192.168.0.2", 5000, 80, 6)
    first = list(replay.add(key, 1, 54, 1.0))[0]
    assert first["pkt_rate"] == 1 and first["syn_ratio"] == 1
    assert list(replay.add(key, 0, 54, 1.05)) == []
    flushed = list(replay.flush(2.0))[0]
    expected = FeatureCalculator()
    expected.compute(Snapshot(*key, 1, 54, 1, 10**9, 10**9), 1.0)
    features = expected.compute(Snapshot(*key, 2, 108, 1, 10**9, 1050000000), 2.0)
    for field, value in features.items():
        assert flushed[field] == value


def test_report_does_not_invent_labels(tmp_path):
    source = tmp_path / "test.pcap"
    source.write_bytes(ng(ethernet()))
    report = analyze(source, tmp_path / "features.csv.gz", tmp_path / "report.json")
    assert report["complete"] and len(report["sha256"]) == 64
    assert report["counts"]["eligible_packets"] == 1
    assert report["label_status"] == "unavailable" and not report["model_validated"]
