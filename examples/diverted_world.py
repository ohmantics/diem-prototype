"""The DNS and the published records of the diverted-flight example.   # draft: #open-issues

A humanitarian flight for state XA carries four packages: medical supplies, a
CITES permit item, a hard drive whose data has an emblem of its own, and a
diplomatic pouch from state XC to its mission in XA. The relief organization
(relief.example) issues all but the pouch, which XC's foreign ministry issues.
What the issuers meant to keep from most handlers they encrypted to the customs
of state XA, the flight's destination (state XA's names are under gov.example,
as in the other examples). The walkthrough is examples/diverted_flight.py.
"""

from functools import cache

import dns.rdata
import dns.rdataclass
import dns.rdatatype as rdatatype

from diem import confidential, zones
from diem.values import money, quantity, treatment, validity
from diem.hierarchy import Hierarchy
from diem.sources import InMemoryDNS
from examples.records import pouch as records
from examples.build import emblems, key_owner, keys, put, top, zone

NOW = 1793880000  # 2026-11-05 12:00 UTC
DAY = 86400
VALID = (NOW - DAY, NOW + 30 * DAY)
XA_CUSTOMS = confidential.recipient("customs.gov.example")
MEDICAL = "med-0417._diem.relief.example"
CITES = "cites-0233._diem.relief.example"
DRIVE = "drive-0051._diem.relief.example"
DATASET = "ds-0051._diem.relief.example"
POUCH = "p4tz-7mqe-2wk8._pouch._diem.mfa.xc.example"
POSITION = "med-0417._live._diem.relief.example"
PERMIT, SERIAL = "XA-CITES-2026-0233", "HD-0051-7731"
SEAL = "XC-2026-114357"

VALUATION = {
    "method": "fallback",
    "related-party": False,
    "incoterm": "DAP",
    "invoice": "REL-2026-0417",
    "lines": [{"class-ref": MEDICAL, "line-qty": 40, "unit-price": money("50", "USD")}],
    "total": money("2000", "USD"),
    "freight": money("150", "USD"),
    "insurance": money("40", "USD"),
    "additions": [],
}
DETAILS = {
    "title": "Field survey records",
    "records": 48210,
    "steward": "relief.example",
}
COURIER = {"name": "B. Courier-Example", "letter": "XC-MFA-DC-2026-00417"}


@cache
def all_records():
    """Every record the issuers publish, with what is for XA's customs encrypted to its published key."""
    world = zones.build(hierarchy(loaded=False), NOW)
    key = confidential.public_key(
        XA_CUSTOMS.name, key_owner(XA_CUSTOMS), InMemoryDNS(world), world.anchor, NOW
    )

    def for_xa(plaintext, name, asset):
        return confidential.encrypt(plaintext, name, asset, [key])

    return {
        "medical": medical(for_xa(VALUATION, "valuation", MEDICAL)),
        "cites": cites_permit(),
        "pouch": pouch(for_xa(COURIER, "courier", POUCH)),
        "drive": drive(),
        "dataset": dataset(for_xa(DETAILS, "details", DATASET)),
    }


def medical(valuation):
    return {
        "profile": "dg-package",
        "asset": MEDICAL,
        "un-number": "3373",
        "dg-class": "6.2",
        "gross-mass": quantity("212", "KGM"),
        "valuation": valuation,
    }


def cites_permit():
    return {
        "profile": "cites-permit",
        "asset": CITES,
        "permit-number": PERMIT,
        "appendix": "II",
        "species-code": "SPEC-0042",
        "valid": validity(*VALID),
    }


def pouch(courier):
    """A pouch from state XC to its mission in XA; the courier is for the receiving state."""
    return {
        **records.EMBLEM,
        "asset": POUCH,
        "sending-state": "XC",
        "consignee": "embassy.xc.example",
        "seal": SEAL,
        "courier": courier,
    }


def drive():
    """The drive is two things: an object, and (it holds a lithium battery) dangerous goods."""
    return [
        {
            "profile": "storage-device",
            "asset": DRIVE,
            "serial": SERIAL,
            "dataset": "ds-0051",
        },
        {
            "profile": "dg-package",
            "asset": DRIVE,
            "un-number": "3481",
            "dg-class": "9",
            "gross-mass": quantity("0.4", "KGM"),
        },
    ]


def dataset(details):
    return {
        "profile": "dataset",
        "asset": DATASET,
        "treatment": [treatment("prohibit", "read")],
        "details": details,
    }


def position():
    where = "30 0 0.000 N 140 0 0.000 W 0m 1m 100m 10m"
    return dns.rdata.from_text(dns.rdataclass.IN, rdatatype.LOC, where).to_wire()


def hierarchy(loaded=True, withdrawn=False):
    """The DNS of the example.

    Not loaded: only the key of XA's customs is in it. Withdrawn: the CITES
    permit has been taken out.
    """
    made = all_records() if loaded else None
    return Hierarchy([*top(), *relief_zones(made, withdrawn), *state_zones(made)])


def relief_zones(made, withdrawn):
    packages = ()
    if made:
        permit = () if withdrawn else (made["cites"],)
        packages = emblems(made["medical"], *permit, *made["drive"], made["dataset"])
    return [
        zone(
            "relief.example.",
            "the relief.example. server",
            "the relief organization's ordinary DNS",
        ),
        zone(
            "_diem.relief.example.",
            "the relief emblem server",
            "its packages and their datasets",
            packages,
        ),
        zone(
            "_live._diem.relief.example.",
            "the relief live server",
            "dynamic facets, signed when asked for",
            (put(POSITION, rdatatype.LOC, position()),),
            online=True,
        ),
    ]


def state_zones(made):
    return [
        zone(
            "mfa.xc.example.",
            "the mfa.xc.example. server",
            "state XC's foreign ministry, ordinary DNS",
        ),
        zone(
            "_diem.mfa.xc.example.",
            "the XC emblem server",
            "diplomatic pouches",
            emblems(made["pouch"]) if made else (),
        ),
        zone(
            "customs.gov.example.",
            "the customs.gov.example. server",
            "XA's customs, which publishes its public key",
            keys(XA_CUSTOMS, VALID),
        ),
    ]
