"""RRsets with their signatures, and the format they travel in.   # draft: #offline

A bundle holds what a validator needs to check an answer without asking
anyone: the answer, and for each zone from the answer's up to the root the
DNSKEY RRset and the DS RRset that delegates to it, each with its RRSIGs.
Following the pattern of RFC 9102 it is serialized as a sequence of
uncompressed resource records, the answer first. Online, the same object
holds what a resolver collected while answering; offline, it is parsed from
bytes carried with the asset. Either way it is verified in the same way
(diem/dnssec.py).
"""

import struct

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset


class Bundle:
    def __init__(self):
        self._sets = {}

    def add(self, rrset, signatures=None):
        self._sets[(rrset.name, rrset.rdtype)] = (rrset, signatures)

    def __len__(self):
        return len(self._sets)

    def get(self, name, rdtype):
        """The RRset and its RRSIGs, or (None, None)."""
        return self._sets.get((name, rdtype), (None, None))

    def rrsets_of_type(self, rdtype):
        return [pair for (_, found), pair in self._sets.items() if found == rdtype]

    def to_bytes(self):
        out = bytearray()
        for rrset, signatures in self._sets.values():
            for part in (rrset, signatures):
                for rdata in part or ():
                    body = rdata.to_wire()
                    out += part.name.canonicalize().to_wire()
                    out += (
                        struct.pack(
                            "!HHIH", part.rdtype, part.rdclass, part.ttl, len(body)
                        )
                        + body
                    )
        return bytes(out)

    @classmethod
    def from_bytes(cls, data):
        """Parse a serialized bundle; raises ValueError if it is malformed."""
        found, position = {}, 0
        try:
            while position < len(data):
                name, used = dns.name.from_wire(data, position)
                rdtype, rdclass, ttl, length = struct.unpack(
                    "!HHIH", data[position + used : position + used + 10]
                )
                start = position + used + 10
                rdata = dns.rdata.from_wire(rdclass, rdtype, data, start, length)
                covers = rdata.type_covered if rdtype == dns.rdatatype.RRSIG else 0
                rrset = found.setdefault(
                    (name, rdtype, covers),
                    dns.rrset.RRset(name, rdclass, rdtype, covers),
                )
                rrset.add(rdata, ttl)
                position = start + length
        except (dns.exception.DNSException, struct.error) as error:
            raise ValueError(f"the bundle is malformed: {error}") from error
        return cls._assemble(found)

    @classmethod
    def _assemble(cls, found):
        bundle = cls()
        for (name, rdtype, covers), rrset in found.items():
            if rdtype != dns.rdatatype.RRSIG:
                bundle.add(rrset, found.get((name, dns.rdatatype.RRSIG, rdtype)))
        return bundle
