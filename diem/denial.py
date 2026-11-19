"""NSEC3 hashing and proofs of absence.   # draft: #confidentiality, #lifecycle

NSEC3 (RFC 5155) lets a zone prove that a name is absent without listing the
names it holds, so an unguessable label stays unguessable. The zones here use
the parameters RFC 9276 recommends: SHA-1, no salt, no extra iterations.
An absent emblem, proved this way, is how an online validator learns that an
emblem was removed (draft #lifecycle).
"""

import base64
import bisect

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset


def name_hash(name):
    return base64.b32hexdecode(dns.dnssec.nsec3_hash(name, None, 0, 1))


def covering(hashes, wanted):
    """The owner hash of the NSEC3 record whose span holds wanted: the one before it."""
    return hashes[bisect.bisect_left(hashes, wanted) - 1]


def _types(nsec3):
    for window, bitmap in nsec3.windows:
        for position, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    yield window * 256 + position * 8 + bit


def _covered(records, wanted):
    """Is wanted in the gap after some NSEC3 record? An opt-out record's gap may hide
    unsigned delegations (RFC 5155 section 6), so it proves nothing here."""
    if wanted in records:
        return False
    hashes = sorted(records)
    owner = covering(hashes, wanted)
    if records[owner].flags & 1:
        return False
    return owner >= records[owner].next or wanted < records[owner].next


def prove(nsec3_rrsets, zone, qname, qtype):
    """What these NSEC3 RRsets, all from the zone, prove about qname: "nodata",
    "nxdomain", or None.

    "nodata" means the name exists but has no records of the type; "nxdomain"
    means it does not exist. The proof of the second is the one in RFC 5155
    section 8.4: the closest name that does exist is matched, and the next
    name down towards qname, and the wildcard at the closest name, are both
    shown to be in gaps.
    """
    if not qname.is_subdomain(zone):
        return None
    records = {}
    for rrset in nsec3_rrsets:
        if (rrset[0].algorithm, rrset[0].iterations, rrset[0].salt) != (1, 0, b""):
            return None  # not the parameters name_hash uses
        if rrset.name.parent() == zone:
            records[base64.b32hexdecode(rrset.name.labels[0].decode().upper())] = rrset[
                0
            ]
    if name_hash(qname) in records:
        return "nodata" if qtype not in _types(records[name_hash(qname)]) else None
    ancestor = qname
    while ancestor != zone:
        next_closer, ancestor = ancestor, ancestor.parent()
        if name_hash(ancestor) in records:
            wildcard = dns.name.Name((b"*",)) + ancestor
            gaps = _covered(records, name_hash(next_closer)) and _covered(
                records, name_hash(wildcard)
            )
            return "nxdomain" if gaps else None
    return None


def chain(nodes, apex, ttl):
    """The NSEC3 RRsets of a zone's names, and the map from a name's hash to its NSEC3 owner."""
    digests = {name: name_hash(name) for name in nodes}
    order = sorted(digests.values())
    owners = {digest: dns.name.from_text(_label(digest), apex) for digest in order}
    found = {}
    for name, digest in digests.items():
        following = order[(order.index(digest) + 1) % len(order)]
        types = set(nodes[name]) | ({dns.rdatatype.RRSIG} if nodes[name] else set())
        bitmap = " ".join(dns.rdatatype.to_text(rdtype) for rdtype in sorted(types))
        found[owners[digest]] = dns.rrset.from_text(
            owners[digest],
            ttl,
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3,
            f"1 0 0 - {_label(following)} {bitmap}",
        )
    return found, owners


def _label(digest):
    return base64.b32hexencode(digest).decode().lower()
