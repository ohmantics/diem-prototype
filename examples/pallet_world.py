"""The DNS and the published records of the pallet example.   # draft: #ex-logistics

Who publishes what: the manufacturer (the product family, its variants and
each item), the pallet producer (the ISPM 15 mark), the freight forwarder (the
consignment, and its live position in an online-signed zone of its own), the
national plant protection organization (NPPO, which endorses the producer),
and the origin and destination customs (each publishing a public key that
values are encrypted to). The walkthrough is examples/pallet.py.
"""

import os
from functools import cache

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype as rdatatype

from diem import confidential, emblem, endorsement, names, references, rrtypes, zones
from diem.hierarchy import Hierarchy
from diem.sources import InMemoryDNS
from diem.values import quantity, validity
from examples.build import emblems, key_owner, keys, ordinary, put, top, zone
from examples.records import logistics as records

VALID = (1793491200, 1801440000)  # 2026-11-01 to 2027-02-01


def variants():
    """The draft's X1 Pro, and the X1 and X1 Max, which differ in GTIN, model and battery."""

    def like_the_pro(short, gtin, model, watt_hours):
        return {
            **records.VARIANT,
            "asset": f"{short}.x1.models.{records.MAKER}",
            "gtin": gtin,
            "model": model,
            "battery-energy": quantity(watt_hours, "WHR"),
        }

    return [
        like_the_pro("std", "00614141999972", "X1", "18.5"),
        records.VARIANT,
        like_the_pro("max", "00614141999996", "X1 Max", "24.1"),
    ]


def endorse_pallet_producer():
    producer = dns.name.from_text("pallets.example.")
    return {
        "profile": "endorsement",
        "issuer": "pallets.example",
        "endorsed-profile": "ispm15",
        "scope": [],
        "valid": validity(*VALID),
        "dnskey-digest": endorsement.dnskey_digest(
            producer, zones.signing_key(producer)[1]
        ),
    }


def position():
    # in the North Pacific, on the way to Los Angeles
    where = "35 7 30.000 N 150 15 0.000 W 0m 1m 100m 10m"
    return dns.rdata.from_text(dns.rdataclass.IN, rdatatype.LOC, where).to_wire()


NOW = 1794916800  # 2026-11-17 12:00 UTC
LATER = NOW + 5 * 365 * 86400  # 2031-11-16, when a recycler scans a device
NPPO = "nppo.vn.example"
ORIGIN, DESTINATION = (
    confidential.recipient(f"customs.{c}.example") for c in ("vn", "us")
)
LIVE_SERVER = "the forwarder's live server"
CONSIGNMENT_NAME = records.CONSIGNMENT["asset"]
LIVE_NAME = names.facet_name(CONSIGNMENT_NAME, "_live")
ITEM_NAME = records.ITEM["asset"]
PALLET_NAME = records.PALLET["asset"]
FAMILY_NAME = records.FAMILY["asset"]


def hierarchy(consignment=None):
    """The DNS of the example; until a consignment is given, it is not yet published."""
    return Hierarchy(
        [*top(), *authority_zones(), *issuer_zones(consignment), *customs_zones()]
    )


def authority_zones():
    endorse = names.endorsement_name(NPPO, "pallets.example")
    record = emblem.to_cbor(endorse_pallet_producer())
    return [
        ordinary("gov.example", "the zone of government names"),
        ordinary(
            NPPO,
            "the plant protection organization, an authorizing entity",
            (put(endorse, rrtypes.ENDORSE, record),),
        ),
    ]


def issuer_zones(consignment):
    """The manufacturer, the pallet producer and the forwarder, each with an emblem zone."""
    return [
        ordinary("maker.example", "the manufacturer's ordinary DNS"),
        zone(
            "_diem.maker.example.",
            "the maker's emblem server",
            "family, variants and items",
            emblems(records.FAMILY, *variants(), records.ITEM),
        ),
        ordinary("pallets.example", "the pallet producer's ordinary DNS"),
        zone(
            "_diem.pallets.example.",
            "the pallet producer's emblem server",
            "the ISPM 15 mark of each pallet",
            emblems(records.PALLET),
        ),
        ordinary("forwarder.example", "the freight forwarder's ordinary DNS"),
        zone(
            "_diem.forwarder.example.",
            "the forwarder's emblem server",
            "consignments, at unguessable names",
            emblems(consignment) if consignment else (),
        ),
        zone(
            "_live._diem.forwarder.example.",
            LIVE_SERVER,
            "dynamic facets, signed when asked for",
            (put(LIVE_NAME, rdatatype.LOC, position()),),
            online=True,
        ),
    ]


def customs_zones():
    return [
        ordinary(
            "customs.vn.example",
            "origin customs, which publishes its public key",
            keys(ORIGIN, VALID),
        ),
        ordinary(
            "customs.us.example",
            "destination customs, likewise",
            keys(DESTINATION, VALID),
        ),
    ]


def pinned(source, name):
    """The digest of the RRset the forwarder sees at an emblem it refers to."""
    answer = source.fetch(name, "EMBLEM")
    return references.rrset_digest(answer.bundle.get(answer.name, rrtypes.EMBLEM)[0])


@cache
def consignment():
    """The forwarder's emblem: references pinned by digest, values encrypted to both customs."""
    world = zones.build(hierarchy(), NOW)
    source = InMemoryDNS(world)
    to = [
        confidential.public_key(who.name, key_owner(who), source, world.anchor, NOW)
        for who in (ORIGIN, DESTINATION)
    ]
    valuation = {**records.VALUATION, "salt": os.urandom(16)}
    asset = CONSIGNMENT_NAME
    return {
        **records.CONSIGNMENT,
        "valuation": confidential.encrypt(valuation, "valuation", asset, to),
        "valuation-digest": confidential.salted_digest(valuation, "valuation"),
        "parties": confidential.encrypt(records.PARTIES, "parties", asset, to),
        "contents": [
            {**entry, "digest": pinned(source, entry["emblem"])}
            for entry in records.CONSIGNMENT["contents"]
        ],
    }
