"""Bounded streaming reader for classic PCAP and PCAPNG Ethernet captures.

No packet payload is persisted. Invalid lengths fail closed; unsupported link
types and packets without timestamps are counted by the caller, never guessed.
"""

import struct
from dataclasses import dataclass
from socket import inet_ntoa

MAX_BLOCK = 16 * 1024 * 1024


@dataclass(frozen=True)
class Packet:
    timestamp: float | None
    data: bytes
    wire_length: int
    linktype: int


def exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("Truncated capture")
    return data


def options(data, endian):
    while data:
        if len(data) < 4:
            raise ValueError("Truncated PCAPNG option")
        code, size = struct.unpack_from(endian + "HH", data)
        if code == 0:
            return
        padded = (size + 3) & ~3
        if len(data) < 4 + padded:
            raise ValueError("Invalid PCAPNG option length")
        yield code, data[4:4 + size]
        data = data[4 + padded:]


def packets(stream):
    magic = exact(stream, 4)
    classic = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9),
    }
    if magic in classic:
        endian, resolution = classic[magic]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", exact(stream, 20))
        if (major, minor) != (2, 4):
            raise ValueError("Unsupported PCAP version")
        while header := stream.read(16):
            if len(header) != 16:
                raise ValueError("Truncated PCAP packet header")
            seconds, fraction, captured, wire = struct.unpack(endian + "IIII", header)
            if captured > min(snaplen, MAX_BLOCK) or captured > wire or fraction >= resolution:
                raise ValueError("Invalid PCAP packet length or timestamp")
            yield Packet(seconds + fraction / resolution, exact(stream, captured), wire,
                         linktype & 0xffff)
        return
    if magic != b"\x0a\x0d\x0d\x0a":
        raise ValueError("Not a PCAP or PCAPNG capture")
    endian, interfaces = "<", []
    header = magic + exact(stream, 4)
    while header:
        if len(header) != 8:
            raise ValueError("Truncated PCAPNG block header")
        section = header[:4] == b"\x0a\x0d\x0d\x0a"
        prefix = exact(stream, 4) if section else b""
        if section:
            if prefix not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                raise ValueError("Invalid PCAPNG byte order")
            endian = "<" if prefix[0] == 0x4d else ">"
        kind, size = struct.unpack(endian + "II", header)
        if size < (28 if section else 12) or size > MAX_BLOCK or size % 4:
            raise ValueError("Invalid PCAPNG block length")
        body = prefix + exact(stream, size - 8 - len(prefix))
        if struct.unpack(endian + "I", body[-4:])[0] != size:
            raise ValueError("PCAPNG block lengths disagree")
        body = body[:-4]
        if section:
            if struct.unpack_from(endian + "HH", body, 4) != (1, 0):
                raise ValueError("Unsupported PCAPNG version")
            interfaces = []
        elif kind == 1:
            if len(body) < 8:
                raise ValueError("Truncated interface description")
            linktype, _, snaplen = struct.unpack_from(endian + "HHI", body)
            resolution, offset = 1e6, 0
            for code, value in options(body[8:], endian):
                if code == 9 and len(value) == 1:
                    resolution = (2 if value[0] & 128 else 10) ** (value[0] & 127)
                if code == 14 and len(value) == 8:
                    offset = struct.unpack(endian + "q", value)[0]
            interfaces.append((linktype, snaplen, resolution, offset))
        elif kind in (2, 6):
            if len(body) < 20:
                raise ValueError("Truncated PCAPNG packet")
            interface, hi, lo, captured, wire = struct.unpack_from(endian + "IIIII", body)
            if kind == 2:
                interface = struct.unpack_from(endian + "H", body)[0]
            if interface >= len(interfaces):
                raise ValueError("Unknown PCAPNG interface")
            linktype, snaplen, resolution, offset = interfaces[interface]
            if (captured > wire or (snaplen and captured > snaplen)
                    or 20 + ((captured + 3) & ~3) > len(body)):
                raise ValueError("Invalid PCAPNG packet length")
            yield Packet(((hi << 32) | lo) / resolution + offset,
                         body[20:20 + captured], wire, linktype)
        elif kind == 3:
            if not interfaces or len(body) < 4:
                raise ValueError("Invalid simple packet block")
            yield Packet(None, b"", struct.unpack_from(endian + "I", body)[0], interfaces[0][0])
        header = stream.read(8)


def decode(packet):
    """Mirror xdp_agent.c IPv4/TCP/UDP and SYN-without-ACK eligibility."""
    data = packet.data
    if packet.linktype != 1:
        return None, "unsupported_linktype"
    if packet.timestamp is None:
        return None, "missing_timestamp"
    if len(data) != packet.wire_length:
        return None, "truncated_packet"
    if len(data) < 14:
        return None, "short_header"
    proto, offset = struct.unpack_from("!H", data, 12)[0], 14
    for _ in range(2):
        if proto in (0x8100, 0x88a8):
            if len(data) < offset + 4:
                return None, "short_header"
            proto = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4
    if proto != 0x800:
        return None, "non_ipv4"
    if len(data) < offset + 20 or data[offset] >> 4 != 4 or data[offset] & 15 < 5:
        return None, "short_header"
    if struct.unpack_from("!H", data, offset + 6)[0] & 0x3fff:
        return None, "fragment"
    protocol = data[offset + 9]
    transport = offset + (data[offset] & 15) * 4
    minimum = 20 if protocol == 6 else 8
    if protocol not in (6, 17):
        return None, "non_tcp_udp"
    if len(data) < transport + minimum:
        return None, "short_header"
    syn = 0
    if protocol == 6:
        size = (data[transport + 12] >> 4) * 4
        if size < 20 or len(data) < transport + size:
            return None, "short_header"
        syn = int(data[transport + 13] & 0x12 == 0x02)
    key = (inet_ntoa(data[offset + 12:offset + 16]), inet_ntoa(data[offset + 16:offset + 20]),
           *struct.unpack_from("!HH", data, transport), protocol)
    return (key, syn), None
