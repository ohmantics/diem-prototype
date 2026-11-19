"""The test DNS world: its zones, and what a server answers.   # draft: #roles, #discovery

A Hierarchy says which zones exist and where each is delegated from its
parent; zones.py signs them into Zones, which hold the data and answer as an
authoritative server does: with the records, a referral to a child zone, or a
signed proof that a name or type does not exist.
"""

from dataclasses import dataclass, field
from typing import NamedTuple

import dns.name
import dns.rdatatype as rdatatype

from diem import denial, rrtypes


@dataclass(frozen=True)
class ZoneSpec:
    name: dns.name.Name
    server: str  # how the walkthrough refers to the server that holds it
    role: str  # one line saying what the zone is for
    records: tuple = ()  # (owner, rdtype, rdata bytes) published in the zone
    signature_days: int = 30
    online: bool = False  # a dynamic zone: its server signs each answer as it gives it


def server_role(spec):
    """The server role that holds a zone, as the draft's Roles figure names them."""
    if spec.name == dns.name.root:
        return "root"
    if len(spec.name) == 2:
        return "tld"
    if spec.name[0] == b"_diem":
        return "emblem-server"
    if any(rdtype == rrtypes.ENDORSE for _, rdtype, _ in spec.records):
        return "authorities"
    return "issuer-dns"


class Hierarchy:
    def __init__(self, specs):
        self.specs = list(specs)

    @property
    def root(self):
        return next(spec for spec in self.specs if spec.name == dns.name.root)

    def parent(self, name):
        """The zone that delegates `name`, which is the nearest enclosing zone."""
        above = [
            spec
            for spec in self.specs
            if name != spec.name and name.is_subdomain(spec.name)
        ]
        return max(above, key=lambda spec: len(spec.name), default=None)

    def children(self, name):
        return [
            spec
            for spec in self.specs
            if (parent := self.parent(spec.name)) and parent.name == name
        ]

    def outline(self):
        return [(spec.name.to_text(), spec.role) for spec in self.specs]


class Reply(NamedTuple):
    kind: str  # "answer", "referral", "nodata" or "nxdomain"
    # (RRset, RRSIGs or None) pairs: the answer, the delegation, or the proof
    rrsets: tuple
    child: dns.name.Name | None = None


@dataclass
class Zone:
    """A signed zone as its authoritative server holds it."""

    spec: ZoneSpec
    rrsets: dict = field(default_factory=dict)  # (name, rdtype) -> RRset
    signatures: dict = field(default_factory=dict)  # (name, rdtype) -> RRset of RRSIGs
    # every name that exists, empty non-terminals included
    names: frozenset = frozenset()
    cuts: frozenset = frozenset()  # the names of delegated child zones
    # name hash -> owner name of its NSEC3 record
    nsec3_owners: dict = field(default_factory=dict)

    @property
    def name(self):
        return self.spec.name

    def _pair(self, name, rdtype):
        return self.rrsets[(name, rdtype)], self.signatures.get((name, rdtype))

    def respond(self, qname, qtype):
        cut = next((cut for cut in self.cuts if qname.is_subdomain(cut)), None)
        if cut is not None and not (qname == cut and qtype == rdatatype.DS):
            return Reply(
                "referral",
                (self._pair(cut, rdatatype.NS), self._pair(cut, rdatatype.DS)),
                cut,
            )
        if (qname, qtype) in self.rrsets:
            return Reply("answer", (self._pair(qname, qtype),))
        if qname in self.names:
            return Reply("nodata", (self._nsec3_for(qname),))
        return Reply("nxdomain", self._nxdomain_proof(qname))

    def _nsec3_for(self, name):
        return self._pair(self.nsec3_owners[denial.name_hash(name)], rdatatype.NSEC3)

    def _covering(self, name):
        return self._pair(
            self.nsec3_owners[
                denial.covering(sorted(self.nsec3_owners), denial.name_hash(name))
            ],
            rdatatype.NSEC3,
        )

    def _nxdomain_proof(self, qname):
        """RFC 5155 7.2.2: match the closest encloser, cover the next closer and wildcard."""
        ancestor = qname
        while True:
            next_closer, ancestor = ancestor, ancestor.parent()
            if ancestor in self.names or ancestor == self.name:
                break
        wildcard = dns.name.Name((b"*",)) + ancestor
        proof = [
            self._nsec3_for(ancestor),
            self._covering(next_closer),
            self._covering(wildcard),
        ]
        return tuple({pair[0].name: pair for pair in proof}.values())


@dataclass
class World:
    hierarchy: Hierarchy
    zones: dict  # name -> Zone
    anchor: list  # the DS records of the root's key, which every validator holds
