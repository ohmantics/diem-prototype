"""The DNS and the published records of the pouch example.   # draft: #ex-pouch

The foreign ministry of state XA publishes an emblem for each pouch in a zone
it delegates to an emblem server, and the receiving state's customs publishes
its public key in its own zone. The walkthrough is examples/pouch.py.
"""

from functools import cache

from diem import confidential, zones
from diem.values import quantity
from diem.hierarchy import Hierarchy
from diem.sources import InMemoryDNS
from examples.build import emblems, key_owner, keys, ordinary, top, zone
from examples.records import pouch as records

EMBLEM_NAME = "k7q2-9xwm-4hd3._pouch._diem.mfa.gov.example"
RECEIVER = confidential.recipient("customs.xb.example")  # the receiving state's customs
KEY_NAME = key_owner(RECEIVER)
NOW = 1793880000  # 2026-11-05 12:00 UTC, within the emblem's validity period
DAY = 86400

SEEN_ON_THE_POUCH = {
    "asset": EMBLEM_NAME,
    "seal": "XA-2026-114357",
    "pieces": 3,
    "gross-mass": quantity("18.4", "KGM"),
}


def hierarchy(published=True):
    """The DNS of the example; without `published` the ministry has not yet published the emblem."""
    valid = (NOW - 30 * DAY, NOW + 330 * DAY)
    pouch = emblems(record()) if published else ()
    return Hierarchy(
        [
            *top(),
            ordinary("gov.example", "the zone of government names"),
            ordinary(
                "mfa.gov.example", "the ministry's ordinary DNS (knows nothing of DIEM)"
            ),
            zone(
                "_diem.mfa.gov.example.",
                "the emblem server",
                "delegated to an emblem server (NS + DS at the cut)",
                pouch,
            ),
            ordinary(
                "customs.xb.example",
                "the receiving state's customs, which publishes its public key",
                keys(RECEIVER, valid),
            ),
        ]
    )


@cache
def record():
    """The pouch emblem, with the courier encrypted to the key the receiving state publishes."""
    world = zones.build(hierarchy(published=False), NOW)
    key = confidential.public_key(
        RECEIVER.name, KEY_NAME, InMemoryDNS(world), world.anchor, NOW
    )
    courier = confidential.encrypt(records.COURIER, "courier", EMBLEM_NAME, [key])
    return {**records.EMBLEM, "courier": courier}
