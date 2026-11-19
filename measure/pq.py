"""How big would the bundles be if zones signed with ML-DSA-65?

    python -m measure.pq > measure/results/pq.md

Every DNSKEY of a post-quantum zone becomes a 1,952-octet ML-DSA-65 key, every
signature by such a zone becomes 3,309 octets, and the DS record of a
post-quantum child is made over its new key. The keys and signatures are real
(cryptography's ML-DSA-65), under the private-use DNSSEC algorithm number 253,
because no number is assigned; the signature is over the RDATA of the RRset
and not the signed data of RFC 4034, since only the sizes are measured. A
stapled endorsement inside an emblem is rebuilt the same way.
"""

import dns.dnssec
import dns.name
import dns.rdataclass as rdataclass
import dns.rdatatype as rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS
from dns.rdtypes.ANY.RRSIG import RRSIG

from diem import emblem, rrtypes
from diem.bundle import Bundle
from measure import bundles, common

ALGORITHM = 253  # private use


class Keys:
    """The ML-DSA-65 keys of one zone: a key-signing key, and a zone-signing key if split."""

    def __init__(self, split):
        self.ksk = MLDSA65PrivateKey.generate()
        self.zsk = MLDSA65PrivateKey.generate() if split else self.ksk
        self.dnskeys = [self._dnskey(257, self.ksk)]
        if split:
            self.dnskeys.append(self._dnskey(256, self.zsk))

    def _dnskey(self, flags, key):
        raw = key.public_key().public_bytes_raw()
        return DNSKEY(rdataclass.IN, rdatatype.DNSKEY, flags, 3, ALGORITHM, raw)

    def sign(self, rrset, old):
        """A real signature in the shape of the old one.

        The KSK signs a DNSKEY set, the ZSK any other.
        """
        key = self.ksk if rrset.rdtype == rdatatype.DNSKEY else self.zsk
        signature = key.sign(b"".join(rdata.to_wire() for rdata in rrset))
        tag = dns.dnssec.key_id(self.dnskeys[0])
        sig = old[0]
        made = RRSIG(
            rdataclass.IN, rdatatype.RRSIG, sig.type_covered, ALGORITHM, sig.labels,
            sig.original_ttl, sig.expiration, sig.inception, tag, sig.signer, signature,
        )
        return dns.rrset.from_rdata(old.name, old.ttl, made)


class Zones:
    """The post-quantum zones, and what they turn the sets of a bundle into."""

    def __init__(self, post_quantum, split):
        self.zones, self.split, self.keys = set(post_quantum), split, {}

    def key(self, zone):
        return self.keys.setdefault(zone, Keys(self.split))

    def pairs(self, pairs):
        return [self.one(rrset, signatures) for rrset, signatures in pairs]

    def one(self, rrset, signatures):
        if rrset.rdtype == rdatatype.DNSKEY and rrset.name in self.zones:
            keys = self.key(rrset.name).dnskeys
            rrset = dns.rrset.from_rdata_list(rrset.name, rrset.ttl, keys)
        elif rrset.rdtype == rdatatype.DS and rrset.name in self.zones:
            made = dns.dnssec.make_ds(rrset.name, self.key(rrset.name).dnskeys[0], "SHA256")
            ds = DS(rdataclass.IN, rdatatype.DS, made.key_tag, ALGORITHM, 2, made.digest)
            rrset = dns.rrset.from_rdata(rrset.name, rrset.ttl, ds)
        elif rrset.rdtype == rrtypes.EMBLEM:
            rrset = self.restaple(rrset)
        signer = signatures[0].signer
        if signer in self.zones:
            signatures = self.key(signer).sign(rrset, signatures)
        return rrset, signatures

    def restaple(self, rrset):
        """An emblem whose stapled endorsement is rebuilt over the new keys."""
        rebuilt = []
        for rdata in rrset:
            record = emblem.from_cbor(rdata.data)
            for entry in record.get("endorsements", []):
                entry["staple"] = self.restapled(entry["staple"])
            rebuilt.append(rrtypes.rdata(rrtypes.EMBLEM, emblem.to_cbor(record)))
        return dns.rrset.from_rdata_list(rrset.name, rrset.ttl, rebuilt)

    def restapled(self, staple):
        old = Bundle.from_bytes(staple)
        new = Bundle()
        for kind in (rrtypes.ENDORSE, rdatatype.DNSKEY, rdatatype.DS):
            for rrset, signatures in old.rrsets_of_type(kind):
                new.add(*self.one(rrset, signatures))
        return new.to_bytes()


def size(item, anchor, post_quantum, split):
    """The octets of the item's bundle, anchored at `anchor`, with `post_quantum` switched."""
    trimmed = bundles.trimmed(item, anchor)
    pairs = [item.rrset()]
    for kind in (rdatatype.DNSKEY, rdatatype.DS):
        pairs += trimmed.rrsets_of_type(kind)
    converted = Bundle()
    for rrset, signatures in Zones(post_quantum, split).pairs(pairs):
        converted.add(rrset, signatures)
    return len(converted.to_bytes())


def main():
    cases = (
        ("all zones, anchored at the root, separate KSK and ZSK", 0, "all", True),
        ("all zones, anchored at the issuer zone, separate KSK and ZSK", 2, "all", True),
        (
            "only the issuer's zones, anchored at the root, separate KSK and ZSK",
            0,
            "issuer",
            True,
        ),
        ("all zones, anchored at the issuer zone, one key per zone", 2, "all", False),
    )
    listed = common.items()
    rows = [row(case, listed) for case in cases]
    print(f"# Post-quantum bundle sizes (octets)\n\nGenerated with {common.versions()}.\n")
    header = ("zones signed with ML-DSA-65", "smallest", "largest", "the largest is", "fit NFC")
    print(common.table(header, rows, text=(0, 3)))
    print(f"\nOf {len(listed)} bundles. One ML-DSA-65 signature is 3,309 octets and one key 1,952.")


def row(case, listed):
    label, place, which, split = case
    sizes = []
    for item in listed:
        anchors = bundles.anchor_zones(item)
        chain = item.answer().bundle.rrsets_of_type(rdatatype.DNSKEY)
        on_chain = {keys.name for keys, _ in chain}
        post_quantum = on_chain if which == "all" else {anchors[2], anchors[3]}
        sizes.append(size(item, anchors[place], post_quantum, split))
    biggest = listed[sizes.index(max(sizes))].label
    return (label, min(sizes), max(sizes), biggest, sum(s <= common.NFC_TAG for s in sizes))


if __name__ == "__main__":
    main()
