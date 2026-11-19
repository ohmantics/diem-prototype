"""The DNS and the published records of the hospital example.   # draft: #ex-ihl

The hospital, in territory that states XA and XB both claim, publishes its
emblem (with the endorsement of XA's ministry of health stapled in) and a
visual mark. Each state's ministry publishes an endorsement under a digest of
the hospital's name. The walkthrough is examples/hospital.py.

Signatures here last days, not the hours of the draft's IHL example, so that
the variants can show a staple expiring.
"""

import hashlib
from functools import cache
from pathlib import Path

import dns.name

from diem import emblem, endorsement, names, rrtypes, zones
from diem.hierarchy import Hierarchy
from diem.sources import InMemoryDNS
from diem.values import Text, Uri, citation, treatment, validity
from examples.build import ordinary, put, top, zone

ASSET = "records.hospital.example"
EMBLEM_NAME = "records._diem.hospital.example"
MARK_NAME = "_mark.records._diem.hospital.example"
ISSUER = "hospital.example"
HOME_MINISTRY = "health.gov.example"
OTHER_MINISTRY = "health.xb.example"
VALID = (1793491200, 1801440000)  # 2026-11-01 to 2027-02-01
NOW = 1794916800  # 2026-11-17 12:00 UTC
DAY = 86400

MARK_IMAGE = (Path(__file__).parent / "marks" / "placeholder.svg").read_bytes()
OTHER_IMAGE = (
    b'<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" '
    b'viewBox="0 0 100 100"><title>Green disc</title>'
    b'<circle cx="50" cy="50" r="40" fill="#008800" stroke="#ffffff"/></svg>'
)
SCOPE = ["protective-red-cross", treatment("prohibit", "attack")]


def endorse_record(scope=SCOPE):
    """The ENDORSE record a ministry publishes for the hospital."""
    hospital_key = zones.signing_key(dns.name.from_text(ISSUER))[1]
    return {
        "profile": "endorsement",
        "issuer": ISSUER,
        "endorsed-profile": "ihl-protective",
        "scope": scope,
        "valid": validity(*VALID),
        "dnskey-digest": endorsement.dnskey_digest(
            dns.name.from_text(ISSUER), hospital_key
        ),
        "mark-digest": hashlib.sha256(MARK_IMAGE).digest(),
    }


def mark_record(image=MARK_IMAGE):
    return {
        "profile": "mark",
        "asset": ASSET,
        "media-type": "image/svg+xml",
        "image": image,
    }


def emblem_record(staple):
    return {
        "profile": "ihl-protective",
        "purpose": ["protective-red-cross"],
        "asset": ASSET,
        "treatment": [treatment("prohibit", "attack")],
        "basis": [
            citation(
                "uri",
                Uri(
                    "https://ihl-databases.icrc.org/en/ihl-treaties/gci-1949/article-19"
                ),
                Text("en", "GC I, Art. 19"),
            )
        ],
        "valid": validity(*VALID),
        "issuer-name": Text("en", "Example General Hospital"),
        "mark": MARK_NAME,
        "endorsements": [{"by": HOME_MINISTRY, "staple": staple}],
    }


def hierarchy(
    emblem_bytes=None, mark_image=MARK_IMAGE, other_scope=SCOPE, home_scope=SCOPE
):
    """The DNS of the example.

    Without emblem_bytes the hospital has published no emblem, without a
    mark_image no mark, and a ministry whose scope is None has not endorsed the
    hospital.
    """
    return Hierarchy(
        [
            *top(),
            ordinary("gov.example", "state XA's government names"),
            ordinary(
                HOME_MINISTRY,
                "ministry of health of XA, which claims the hospital's territory",
                endorse(HOME_MINISTRY, home_scope),
                signature_days=7,
            ),
            ordinary(
                OTHER_MINISTRY,
                "ministry of health of XB, which claims it too",
                endorse(OTHER_MINISTRY, other_scope),
            ),
            ordinary(ISSUER, "the hospital's ordinary DNS (knows nothing of DIEM)"),
            zone(
                "_diem.hospital.example.",
                "the emblem server",
                "delegated to an emblem server (NS + DS at the cut)",
                published(emblem_bytes, mark_image),
            ),
        ]
    )


def endorse(ministry, scope):
    """The ENDORSE record a ministry publishes for the hospital, if it has endorsed it."""
    if scope is None:
        return ()
    owner = names.endorsement_name(ministry, ISSUER)
    return (put(owner, rrtypes.ENDORSE, emblem.to_cbor(endorse_record(scope))),)


def published(emblem_bytes, mark_image):
    """What the hospital publishes: its emblem and, with it, the mark."""
    if emblem_bytes is None:
        return ()
    found = (put(EMBLEM_NAME, rrtypes.EMBLEM, emblem_bytes),)
    if mark_image is None:
        return found
    return found + (
        put(MARK_NAME, rrtypes.EMBLEM, emblem.to_cbor(mark_record(mark_image))),
    )


@cache
def staple():
    """The home ministry's endorsement and the chain that validates it, as retrieved."""
    world = zones.build(hierarchy(), NOW)
    found = InMemoryDNS(world).fetch(
        names.endorsement_name(HOME_MINISTRY, ISSUER), "ENDORSE"
    )
    return found.bundle.to_bytes()


def published_emblem():
    return emblem.to_cbor(emblem_record(staple()))
