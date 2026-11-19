"""Building and signing the test zones.   # draft: #roles, #facets, #confidentiality

Each zone gets one ECDSA P-256 key (flags 257, used for every RRset) and has
NSEC3 denial of existence, so its labels cannot be listed by walking the zone.
(The NSEC3 hashes can still be collected and dictionary-attacked when labels
are guessable.)
The keys are derived from the zone names so that the same inputs give the same
bytes, which makes the world reproducible and its keys worthless. A zone
delegates to each child with NS and DS records; the DS is how a validator moves
from a parent's keys to the child's. A dynamic zone signs as it answers.
"""

import hashlib
from dataclasses import dataclass

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass as rdataclass
import dns.rdatatype as rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec

from diem import denial
from diem.hierarchy import World, Zone

TTL = 3600
ONLINE_TTL = 300  # seconds: a dynamic facet is cached, and its signature lasts, for minutes
ALGORITHM = dns.dnssec.Algorithm.ECDSAP256SHA256


def signing_key(name):
    """The (private key, DNSKEY) of a zone."""
    scalar = (
        int.from_bytes(hashlib.sha256(name.to_text().encode()).digest(), "big") % 2**250
        + 1
    )
    private = ec.derive_private_key(scalar, ec.SECP256R1())
    return private, dns.dnssec.make_dnskey(private.public_key(), ALGORITHM, flags=257)


def signature(rrset, key, apex, inception, expiration):
    """The RRSIG RRset for an RRset, signed by a zone's key."""
    rrsig = dns.dnssec.sign(
        rrset, key[0], apex, key[1], inception=inception, expiration=expiration
    )
    return dns.rrset.from_rdata(rrset.name, rrset.ttl, rrsig)


@dataclass
class OnlineZone(Zone):
    """A zone whose server signs each answer as it gives it.

    Dynamic facets change constantly, so they are signed when asked for, with
    signatures that last minutes. The key that does this is online, and so
    more exposed than an offline one; that is why the draft puts dynamic
    facets in a zone of their own, apart from the static data. The clock is
    the time the server signs at.
    """

    key: tuple = ()
    clock: object = None

    def _pair(self, name, rdtype):
        rrset = self.rrsets[(name, rdtype)]
        if name in self.cuts and rdtype == rdatatype.NS:
            return rrset, None  # a cut's NS records are the child zone's to sign
        now = self.clock()
        return rrset, signature(
            rrset, self.key, self.name, now - 60, now + ONLINE_TTL
        )


def build(hierarchy, now):
    """Sign every zone in the hierarchy; signatures begin an hour before `now`."""
    keys = {spec.name: signing_key(spec.name) for spec in hierarchy.specs}
    zones = {
        spec.name: _sign(spec, _contents(spec, hierarchy, keys), keys[spec.name], now)
        for spec in hierarchy.specs
    }
    root = hierarchy.root.name
    return World(hierarchy, zones, [dns.dnssec.make_ds(root, keys[root][1], "SHA256")])


def _ttl(spec):
    return ONLINE_TTL if spec.online else TTL


def _server_name(zone):
    return dns.name.Name((b"ns",)) + zone


class _Nodes(dict):
    """The names of a zone, each {rdtype: RRset}; records added at one name and type make one RRset."""

    def __init__(self, ttl):
        super().__init__()
        self.ttl = ttl

    def add(self, name, rdtype, *rdatas):
        held = self.setdefault(name, {}).get(rdtype, ())
        self[name][rdtype] = dns.rrset.from_rdata_list(name, self.ttl, [*held, *rdatas])


def _text(rdtype, body):
    return dns.rdata.from_text(rdataclass.IN, rdtype, body)


def _contents(spec, hierarchy, keys):
    """The zone's RRsets before signing: name -> {rdtype: RRset}."""
    nodes, apex = _Nodes(_ttl(spec)), spec.name
    hostmaster = dns.name.Name((b"hostmaster",)) + apex
    soa = f"{_server_name(apex)} {hostmaster} 1 7200 900 1209600 300"
    nodes.add(apex, rdatatype.SOA, _text(rdatatype.SOA, soa))
    nodes.add(apex, rdatatype.NS, _text(rdatatype.NS, str(_server_name(apex))))
    nodes.add(apex, rdatatype.DNSKEY, keys[apex][1])
    nodes.add(apex, rdatatype.NSEC3PARAM, _text(rdatatype.NSEC3PARAM, "1 0 0 -"))
    for child in hierarchy.children(apex):
        server = str(_server_name(child.name))
        nodes.add(child.name, rdatatype.NS, _text(rdatatype.NS, server))
        ds = dns.dnssec.make_ds(child.name, keys[child.name][1], "SHA256")
        nodes.add(child.name, rdatatype.DS, ds)
    for owner, rdtype, body in spec.records:
        rdata = dns.rdata.from_wire(rdataclass.IN, rdtype, body, 0, len(body))
        nodes.add(owner, rdtype, rdata)
    return nodes


def _empty_non_terminals(names, apex):
    """Names with no records of their own that exist because a name below them does."""
    names = set(names)
    found = set()
    for name in names - {apex}:
        ancestor = name.parent()
        while ancestor != apex and ancestor not in names:
            found.add(ancestor)
            ancestor = ancestor.parent()
    return found


def _sign(spec, nodes, key, now):
    apex = spec.name
    cuts = frozenset(
        name for name, types in nodes.items() if name != apex and rdatatype.NS in types
    )
    for name in _empty_non_terminals(nodes, apex):
        nodes[name] = {}
    chain, owners = denial.chain(nodes, apex, _ttl(spec))
    rrsets = {
        (name, rdtype): rrset
        for name, types in nodes.items()
        for rdtype, rrset in types.items()
    }
    rrsets.update({(owner, rdatatype.NSEC3): rrset for owner, rrset in chain.items()})
    if spec.online:
        return OnlineZone(
            spec, rrsets, {}, frozenset(nodes), cuts, owners, key=key, clock=lambda: now
        )
    zone = Zone(spec, rrsets, {}, frozenset(nodes), cuts, owners)
    inception, expiration = now - 3600, now + spec.signature_days * 86400
    for (name, rdtype), rrset in rrsets.items():
        if name in cuts and rdtype == rdatatype.NS:
            continue  # a cut's NS records are the child zone's to sign
        zone.signatures[(name, rdtype)] = signature(
            rrset, key, apex, inception, expiration
        )
    return zone
