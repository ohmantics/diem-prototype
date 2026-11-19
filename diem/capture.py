"""The queries a resolver sent to authoritative servers, from a packet capture.   # draft: #undetectable

A capture of the resolver's outgoing packets (tcpdump -w, Ethernet, UDP over
IPv4) shows what each server was sent. Only the queries matter here: a
server that is asked again over TCP was already asked over UDP.
"""

import socket
import struct

import dns.flags
import dns.message

from diem.hierarchy import server_role
from diem.sources import Query

# microsecond timestamps, in the byte order of the machine that wrote it
PCAP_MAGIC = 0xA1B2C3D4
ETHERNET_HEADER = 14
UDP_HEADER = 8
DNS_PORT = 53


def queries(data):
    """The (time, server address, DNS message) of each query to port 53 in the bytes of a capture."""
    magic, _, _, _, _, _, link_type = struct.unpack_from("<IHHiIII", data)
    if magic != PCAP_MAGIC or link_type != 1:
        raise ValueError(
            "the capture is not a little-endian pcap file of Ethernet frames"
        )
    found, position = [], 24
    while position + 16 <= len(data):
        seconds, microseconds, length, _ = struct.unpack_from("<IIII", data, position)
        frame = data[position + 16 : position + 16 + length]
        position += 16 + length
        if len(frame) < length:
            break  # the last packet is still being written
        query = _udp_query(frame)
        if query:
            found.append((seconds + microseconds / 1e6, *query))
    return found


def _udp_query(frame):
    """(destination address, DNS message) if this frame is a DNS query over UDP and IPv4, else None."""
    ip = frame[ETHERNET_HEADER:]
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != socket.IPPROTO_UDP:
        return None
    header = (ip[0] & 15) * 4
    destination_port, length = struct.unpack_from("!2xHH2x", ip, header)
    if destination_port != DNS_PORT:
        return None
    message = dns.message.from_wire(ip[header + UDP_HEADER : header + length])
    if message.flags & dns.flags.QR:
        return None
    return socket.inet_ntoa(ip[16:20]), message


def server_queries(data, since, world):
    """The Queries after time `since`, with each server named as local mode names it.

    A capture shows an address, which is a Compose service. A walkthrough
    speaks of the zone a server holds that encloses the name asked for, so that
    the two modes read alike.
    """
    return [
        Query(
            _zone_server(_service_name(address), message.question[0].name, world),
            message.question[0].name,
            message.question[0].rdtype,
        )
        for when, address, message in queries(data)
        if when >= since
    ]


def _service_name(address):
    """The Compose service at an address, such as emblem-server (containers are named <project>-<service>-<n>)."""
    host = socket.gethostbyaddr(address)[0].split(".")[0]
    return host.removeprefix("diem-").removesuffix("-1")


def _zone_server(service, qname, world):
    held = [
        spec
        for spec in world.hierarchy.specs
        if server_role(spec) == service and qname.is_subdomain(spec.name)
    ]
    return max(held, key=lambda spec: len(spec.name)).server if held else service
