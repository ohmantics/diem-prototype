"""Where records come from: the DNS, or a bundle.   # draft: #offline, #undetectable

Both sources answer fetch(name, type) with an Answer: the records (or the
signed proof that there are none) together with the bundle of keys and
signatures needed to check them. The validator checks them the same way
whichever source they came from. Only the transport differs.

The in-memory DNS walks delegations from the root as a resolver does, asking
each zone's server for the name and for its keys, and remembers which server
was asked what. That log is how a walkthrough shows who could see a query
(draft #undetectable). There is no cache and no wire: each query reaches
the server directly.
"""

from dataclasses import dataclass
from typing import NamedTuple

import dns.message
import dns.name
import dns.rdatatype as rdatatype

from diem import rrtypes
from diem.bundle import Bundle

# The EDNS payload size of DNS Flag Day 2020, which avoids fragmentation.
UDP_PAYLOAD = 1232


class Query(NamedTuple):
    server: str
    name: dns.name.Name
    rdtype: int


@dataclass
class Answer:
    name: dns.name.Name
    rdtype: int
    status: str  # "answer", "nxdomain", "nodata" or "unavailable"
    bundle: Bundle | None
    transport: str
    reason: str = ""

    @property
    def unavailable(self):
        return self.status == "unavailable"

    def describe(self):
        rrset = self.bundle.get(self.name, self.rdtype)[0]
        if rrset is None:
            kind = rrtypes.text(self.rdtype)
            return (
                f"no {kind} record, but a signed proof of its absence, {self.transport}"
            )
        count = len(rrset)
        kind = f"{rrtypes.text(self.rdtype)} record{'s' if count != 1 else ''}"
        return f"{count} {kind}, {self.transport}"


class InMemoryDNS:
    def __init__(self, world, down=()):
        """down names servers that do not answer."""
        self.world, self.down, self.log = world, set(down), []

    def fetch(self, name, type_name):
        qname, qtype = dns.name.from_text(name), rrtypes.number(type_name)
        zone, ds, learned = self.world.zones[dns.name.root], None, []
        while True:
            if zone.spec.server in self.down:
                return Answer(
                    qname,
                    qtype,
                    "unavailable",
                    None,
                    "",
                    f"{zone.spec.server} did not answer",
                )
            learned.append((self._ask(zone, zone.name, rdatatype.DNSKEY).rrsets[0], ds))
            reply = self._lookup(zone, qname, qtype)
            if reply.kind != "referral":
                break
            ds, zone = reply.rrsets[1], self.world.zones[reply.child]
        bundle = _collect(reply, learned)
        return Answer(
            qname, qtype, reply.kind, bundle, _how_found(qname, qtype, bundle)
        )

    def _lookup(self, zone, qname, qtype):
        """Ask a zone's server about qname, revealing no more of it than needed (RFC 9156).

        Starting one label below the zone, ask about ever longer parts of qname
        until a referral shows that a child zone must be asked instead; only then,
        or when a name does not exist, ask the full question. RFC 9156 recommends
        QTYPE A for these queries; this code asks for NS, which reveals the same
        name to the server, and what this example shows is which names are seen.
        """
        for labels in range(len(zone.name) + 1, len(qname)):
            reply = self._ask(zone, qname.split(labels)[1], rdatatype.NS)
            if reply.kind == "referral":
                return reply
            if reply.kind == "nxdomain":
                break
        return self._ask(zone, qname, qtype)

    def _ask(self, zone, name, rdtype):
        self.log.append(Query(zone.spec.server, name, rdtype))
        return zone.respond(name, rdtype)


def _how_found(qname, qtype, bundle):
    """How the records were found, and whether the response is too big for one UDP packet."""
    found = "found by following delegations from the root"
    rrset, signatures = bundle.get(qname, qtype)
    if rrset is None:
        return found
    query = dns.message.make_query(
        qname, qtype, want_dnssec=True, use_edns=0, payload=65535
    )
    response = dns.message.make_response(query)
    response.answer += [rrset, signatures] if signatures is not None else [rrset]
    size = len(response.to_wire())
    if size > UDP_PAYLOAD:
        found += f"; at {size} octets it is too big for one UDP answer, so the server truncates it and the resolver retries over TCP"
    return found


def _collect(reply, learned):
    """The answer first, then each zone's DNSKEY and DS, from the answer's zone up."""
    bundle = Bundle()
    for pair in reply.rrsets:
        bundle.add(*pair)
    for keys, ds in reversed(learned):
        bundle.add(*keys)
        if ds is not None:
            bundle.add(*ds)
    return bundle


class BundleSource:
    """An offline source: everything comes from a bundle; nobody is asked anything."""

    log = ()

    def __init__(self, data):
        self.problem = ""
        try:
            self.bundle = Bundle.from_bytes(data)
        except ValueError as error:
            self.bundle, self.problem = None, str(error)

    def fetch(self, name, type_name):
        qname, qtype = dns.name.from_text(name), rrtypes.number(type_name)
        if self.bundle is None:
            return Answer(qname, qtype, "unavailable", None, "", self.problem)
        if self.bundle.get(qname, qtype)[0] is None:
            return Answer(
                qname,
                qtype,
                "unavailable",
                None,
                "",
                f"the bundle has no {type_name} records for {name}",
            )
        return Answer(
            qname, qtype, "answer", self.bundle, "taken from the bundle, with no query"
        )
