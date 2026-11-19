"""How big is an offline bundle, and what can carry it?

    python -m measure.bundles > measure/results/bundles.md

A bundle is the answer and the keys and signatures that lead to a trust anchor
(diem/bundle.py). A validator that holds the anchor of a zone closer to the
issuer than the root needs none of the chain above it, so the same record has
four sizes: with the anchor at the root, at the top-level domain, at the
issuer's own zone (the zone that holds the `_diem` delegation), and at the
zone that holds the emblem. Capacities are those of a version-40 QR code in
byte mode at each error-correction level, and of a 888-octet NFC tag.
"""

import base64
import hashlib

import dns.name
import dns.rdata
import dns.rdatatype as rdatatype
import dns.rrset

from diem.bundle import Bundle
from measure import common

PLACES = ("root", "top-level domain", "issuer zone", "emblem zone")


def signer(item):
    return item.answer().bundle.get(*_owner_and_type(item))[1][0].signer


def _owner_and_type(item):
    answer = item.answer()
    return answer.name, answer.rdtype


def anchor_zones(item):
    """The zone to anchor at for each place, for a record in the zone `holder`."""
    holder = signer(item)
    issuer = holder
    while issuer.labels and issuer.labels[0] in (b"_live", b"_diem"):
        issuer = issuer.parent()
    top = dns.name.Name(holder.labels[-2:])
    return (dns.name.root, top, issuer, holder)


def trimmed(item, anchor, split=False):
    """The bundle for a validator that holds the key of `anchor`.

    It has nothing above the anchor, and no DS for it. split gives the zones a
    separate zone-signing key, so that each DNSKEY set has one more key.
    """
    full = item.answer().bundle
    bundle = Bundle()
    bundle.add(*item.rrset())
    for keys, signatures in full.rrsets_of_type(rdatatype.DNSKEY):
        if keys.name.is_subdomain(anchor):
            bundle.add(_with_zsk(keys) if split else keys, signatures)
    for ds, signatures in full.rrsets_of_type(rdatatype.DS):
        if ds.name != anchor and ds.name.is_subdomain(anchor):
            bundle.add(ds, signatures)
    return bundle


def _with_zsk(keys):
    key = base64.b64encode(hashlib.sha256(keys.name.to_wire()).digest() * 2).decode()
    zsk = dns.rdata.from_text("IN", "DNSKEY", f"256 3 13 {key}")
    return dns.rrset.from_rdata_list(keys.name, keys.ttl, [*keys, zsk])


def sizes(item, split=False):
    return [len(trimmed(item, anchor, split).to_bytes()) for anchor in anchor_zones(item)]


def report(split):
    found = [(item.label, sizes(item, split)) for item in common.items()]
    print(common.table(("bundle", *PLACES), [(label, *row) for label, row in found]))
    print(f"\nBundles that fit, of {len(found)}:\n")
    carriers = [(f"NFC tag ({common.NFC_TAG})", common.NFC_TAG)]
    carriers += [(f"QR v40, level {k} ({v})", v) for k, v in common.QR_V40.items()]
    fits = [
        (name, *[sum(row[i] <= limit for _, row in found) for i in range(len(PLACES))])
        for name, limit in carriers
    ]
    print(common.table(("carrier (octets)", *PLACES), fits))


def main():
    print(f"# Offline bundle sizes (octets)\n\nGenerated with {common.versions()}.\n")
    print("## One key per zone, as the zones of this code are signed\n")
    report(split=False)
    print("\n## A separate zone-signing key in every zone, as many deployed zones are\n")
    report(split=True)
    print(
        "\nThe hospital emblem carries its endorsement and the chain that validates it inside "
        "the record; that stapled chain is anchored at the root whatever the bundle's own anchor."
    )


if __name__ == "__main__":
    main()
