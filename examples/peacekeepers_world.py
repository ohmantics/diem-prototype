"""The DNS and the published records of the peacekeeping example.   # draft: #ex-peacekeepers

The mission is the issuer. The organization that deploys it (peace.example)
endorses the mission's zone. The mission's static data (a badge for each
person, and the mission's own emblem) is signed offline in its emblem zone;
a convoy's position, which changes constantly and is sensitive, is in a
dynamic zone beside it, encrypted to the mission's operations center and to
the host state's liaison. The walkthrough is examples/peacekeepers.py.
"""

from functools import cache

import dns.name

from diem import (
    confidential,
    emblem,
    endorsement,
    names,
    rrtypes,
    zones,
)
from diem.hierarchy import Hierarchy
from diem.sources import InMemoryDNS
from diem.values import Dec, Timestamp, validity
from examples.build import emblems, key_owner, keys, ordinary, put, top, zone
from examples.records import peacekeepers as records

NOW = 1794916800  # 2026-11-17 12:00 UTC
DAY = 86400
VALID = (1793491200, 1801267200)  # 2026-11-01 to 2027-01-30
DEPLOYER = "peace.example"
BADGE = records.PERSONNEL["asset"]
MISSION_NAME = (
    "_diem.mission.example"  # the mission's emblem, at the apex of its emblem zone
)
OLD_BADGE = "m2xa-5t9d-q8vw._p._diem.mission.example"  # issued for the previous rotation, removed since
CONVOY = "convoy-7._live._diem.mission.example"
OPERATIONS, LIAISON = (
    confidential.recipient(name)
    for name in ("ops.mission.example", "liaison.host.example")
)


def endorse(profile, scope):
    mission = dns.name.from_text("mission.example.")
    return {
        "profile": "endorsement",
        "issuer": "mission.example",
        "endorsed-profile": profile,
        "scope": scope,
        "valid": validity(*VALID),
        "dnskey-digest": endorsement.dnskey_digest(
            mission, zones.signing_key(mission)[1]
        ),
    }


def endorsements():
    """What the deploying organization publishes about the mission: two records at one name."""
    name = names.endorsement_name(DEPLOYER, "mission.example")
    scopes = (
        ("peacekeeping-personnel", records.PERSONNEL["treatment"]),
        ("peacekeeping-mission", records.MISSION["if-invalid"]),
    )
    return tuple(
        put(name, rrtypes.ENDORSE, emblem.to_cbor(endorse(*each))) for each in scopes
    )


@cache
def convoy():
    """The convoy's position, encrypted to both recipients using the keys their zones publish."""
    world = zones.build(hierarchy(published=False), NOW)
    source = InMemoryDNS(world)
    to = [
        confidential.public_key(who.name, key_owner(who), source, world.anchor, NOW)
        for who in (OPERATIONS, LIAISON)
    ]
    where = {
        "latitude": Dec.parse("12.5"),
        "longitude": Dec.parse("-118.75"),
        "as-of": Timestamp(NOW),
    }
    return {
        "profile": "peacekeeping-convoy",
        "asset": CONVOY,
        "mission": "mission.example",
        "valid": validity(NOW - DAY, NOW + DAY),
        "position": confidential.encrypt(where, "position", CONVOY, to),
    }


def hierarchy(published=True):
    """The DNS of the example; without `published` the convoy's position is not yet in it."""
    live = emblems(convoy()) if published else ()
    mission = emblems(records.PERSONNEL) + (
        put(MISSION_NAME, rrtypes.EMBLEM, emblem.to_cbor(records.MISSION)),
    )
    return Hierarchy(
        [
            *top(),
            ordinary(
                DEPLOYER,
                "the deploying organization, an authorizing entity",
                endorsements(),
            ),
            ordinary(
                "mission.example",
                "the mission's ordinary DNS; its operations center publishes its key",
                keys(OPERATIONS, VALID),
            ),
            zone(
                "_diem.mission.example.",
                "the mission's emblem server",
                "badges, and the mission's own emblem",
                mission,
            ),
            zone(
                "_live._diem.mission.example.",
                "the mission's live server",
                "convoy positions, signed when asked for",
                live,
                online=True,
            ),
            ordinary(
                "host.example",
                "the host state, whose liaison publishes its key",
                keys(LIAISON, VALID),
            ),
        ]
    )
