"""Shorthand for describing the zones of a worked example."""

import dns.name

from diem import confidential, emblem, rrtypes
from diem.hierarchy import ZoneSpec


def zone(name, server, role, records=(), **options):
    return ZoneSpec(dns.name.from_text(name), server, role, records, **options)


def put(name, rdtype, data):
    """One record to publish: the owner name, the type and the RDATA."""
    return (dns.name.from_text(name), rdtype, data)


def emblems(*records):
    """EMBLEM records for emblems, each published at the name its `asset` gives."""
    return tuple(put(r["asset"], rrtypes.EMBLEM, emblem.to_cbor(r)) for r in records)


def key_owner(who):
    """Where a recipient publishes its public key: in its own zone."""
    return f"key._diem.{who.name}"


def keys(who, valid):
    return (
        put(
            key_owner(who),
            rrtypes.EMBLEM,
            emblem.to_cbor(confidential.key_record(who, *valid)),
        ),
    )


def top():
    """The root and the top-level domain, whose signatures last the weeks they do in practice."""
    return [
        zone(
            ".",
            "the root server",
            "the example's root; every validator here holds its trust anchor",
            signature_days=21,
        ),
        zone("example.", "the example. server", "top-level domain", signature_days=14),
    ]


def ordinary(name, role, records=(), **options):
    """A zone named like its server: ordinary DNS that knows nothing of DIEM, or an authority's."""
    return zone(f"{name}.", f"the {name}. server", role, records, **options)
