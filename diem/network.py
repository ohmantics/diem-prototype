"""Where records come from, when a real resolver is asked.   # draft: #discovery, #validation

The in-memory DNS of diem/sources.py walks delegations itself. This source
sends ordinary DNS queries, with the DO bit set, to a recursive resolver (UDP,
and TCP when a reply is truncated) and gathers what the validator needs from
the replies: the answer or the signed proof that there is none, and then the
DNSKEY RRset of the zone that signed it and the DS RRset that delegates to it,
zone by zone up to the root. It returns the same Answer, so the same dnssec.verify checks it.

The resolver's AD bit is never consulted. The resolver is a way to obtain
records, not a party the validator trusts.

Which servers saw a query is not something the validator can observe. It is
read from a capture of the resolver's outgoing packets, made beside the
resolver (diem/capture.py), and that capture is also what shows the resolver's
own behaviour, such as whether it minimises the names it sends.
"""

import argparse
import socket
import time

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype as rdatatype

from diem import capture, rrtypes
from diem.bundle import Bundle
from diem.sources import UDP_PAYLOAD, Answer, InMemoryDNS

# Seconds for the capture to catch up with the resolver's last packet.
SETTLE = 0.3


class Unavailable(Exception):
    """The resolver gave no usable reply; the message says why."""


class DNSSource:
    def __init__(self, resolver, capture_file, world, timeout=5.0):
        """resolver is an address or a host name, where every query is sent; capture_file is the capture
        of the resolver's outgoing queries; world names the zones, so that a log can speak of them.
        """
        self.address = socket.gethostbyname(resolver)
        self.capture_file, self.timeout, self.world = capture_file, timeout, world
        self.started = time.time()
        self._used_tcp = False

    @property
    def log(self):
        """The queries the resolver sent to servers since this source was made, as Queries."""
        time.sleep(SETTLE)
        with open(self.capture_file, "rb") as file:
            return capture.server_queries(file.read(), self.started, self.world)

    def fetch(self, name, type_name):
        qname, qtype = dns.name.from_text(name), rrtypes.number(type_name)
        self._used_tcp = False
        try:
            reply = self._ask(qname, qtype)
            status, bundle = self._collect(reply, qname, qtype)
        except Unavailable as problem:
            return Answer(qname, qtype, "unavailable", None, "", str(problem))
        return Answer(qname, qtype, status, bundle, self._transport())

    def _transport(self):
        how = (
            "over UDP, with TCP for a reply that did not fit"
            if self._used_tcp
            else "over UDP"
        )
        return f"retrieved through the resolver at {self.address}, {how}"

    def _ask(self, name, rdtype):
        query = dns.message.make_query(
            name, rdtype, want_dnssec=True, use_edns=0, payload=UDP_PAYLOAD
        )
        try:
            reply, tcp = dns.query.udp_with_fallback(
                query, self.address, timeout=self.timeout
            )
        except (dns.exception.Timeout, OSError) as error:
            raise Unavailable(
                f"the resolver at {self.address} did not answer ({error})"
            ) from error
        self._used_tcp = self._used_tcp or tcp
        if reply.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            raise Unavailable(
                f"the resolver answered {dns.rcode.to_text(reply.rcode())} "
                f"for {rrtypes.text(rdtype)} at {name.to_text()}"
            )
        return reply

    def _collect(self, reply, qname, qtype):
        """The answer first, then each zone's DNSKEY and DS from the signing zone up to the root."""
        bundle, signer = Bundle(), None
        rrset, signatures = _pair(reply.answer, qname, qtype)
        if rrset is not None:
            bundle.add(rrset, signatures)
            status = "answer"
            signer = signatures[0].signer if signatures else None
        else:
            status = "nxdomain" if reply.rcode() == dns.rcode.NXDOMAIN else "nodata"
            for proof in (r for r in reply.authority if r.rdtype == rdatatype.NSEC3):
                pair = _pair(reply.authority, proof.name, rdatatype.NSEC3)
                bundle.add(*pair)
                signer = pair[1][0].signer if pair[1] else signer
        self._add_chain(bundle, signer)
        return status, bundle

    def _add_chain(self, bundle, zone):
        while zone is not None:
            keys, signatures = _pair(
                self._ask(zone, rdatatype.DNSKEY).answer, zone, rdatatype.DNSKEY
            )
            if keys is None:
                return  # the validator reports the missing DNSKEY
            bundle.add(keys, signatures)
            if zone == dns.name.root:
                return
            ds, signatures = _pair(
                self._ask(zone, rdatatype.DS).answer, zone, rdatatype.DS
            )
            if ds is None:
                return  # an unsecured delegation: the validator reports the missing DS
            bundle.add(ds, signatures)
            zone = signatures[0].signer if signatures else None


def _pair(section, name, rdtype):
    """The RRset of this name and type in a section of a reply, and its RRSIGs; None for what is not there."""
    rrset = next((r for r in section if r.name == name and r.rdtype == rdtype), None)
    signatures = next(
        (
            r
            for r in section
            if r.name == name and r.rdtype == rdatatype.RRSIG and r.covers == rdtype
        ),
        None,
    )
    return rrset, signatures


def parse_options(description):
    """The command line of an example: where its records come from."""
    parser = argparse.ArgumentParser(description=description.splitlines()[0])
    parser.add_argument(
        "--resolver",
        metavar="ADDRESS",
        help="ask this recursive resolver for records, instead of the in-memory DNS",
    )
    parser.add_argument(
        "--capture",
        metavar="FILE",
        help="a capture (tcpdump -w) of the resolver's outgoing queries; needed with --resolver",
    )
    options = parser.parse_args()
    if options.resolver and not options.capture:
        parser.error("--resolver needs --capture")
    return options


def dns_source(options, world):
    """A function that makes a fresh DNS source: the resolver if one was named, else the in-memory DNS of world."""
    if options.resolver:
        return lambda: DNSSource(options.resolver, options.capture, world)
    return lambda: InMemoryDNS(world)
