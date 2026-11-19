"""A diplomatic pouch, checked online, from a bundle, and by a state that cannot read the courier.   # draft: #ex-pouch

    python -m examples.pouch

The sending state's foreign ministry publishes an emblem for each pouch under
an unguessable name in a zone it delegates to an emblem server. The courier's
details are encrypted to the receiving state, whose key the ministry reads from
the receiving state's own zone. A customs officer of the receiving state reads
the name from the pouch's mark, finds the emblem, compares its seal number,
piece count and mass with the pouch in front of them, and reads the courier.
"""

from diem import network, profile, report, times, validator, zones
from diem.sources import BundleSource
from examples.pouch_world import (
    DAY,
    EMBLEM_NAME,
    NOW,
    RECEIVER,
    SEEN_ON_THE_POUCH,
    hierarchy,
    record,
)


def task(world, seen=SEEN_ON_THE_POUCH, keys=(RECEIVER,)):
    return validator.Task(
        emblem_name=EMBLEM_NAME,
        how_named="read from the mark on the pouch",
        profile=profile.load("diplomatic-pouch"),
        evidence=seen,
        trust_anchor=world.anchor,
        keys=keys,
        needs=("courier",),
    )


def check(title, task, source, now, first=None):
    """Validate and print; a later run (first is the earlier outcome) prints only what differs."""
    report.heading(f"{title}   ({times.moment(now)})")
    result = validator.validate(task, source, now)
    report.outcome(result, first)
    report.who_saw(source.log, task.emblem_name)
    return result


def introduction(world):
    print(
        "The foreign ministry of state XA marks a diplomatic pouch.   (draft #ex-pouch)"
    )
    report.hierarchy(world.hierarchy)
    report.heading(
        "The ministry publishes in a zone that can prove a name is absent without listing "
        "the names it holds. "
        "It reads the receiving state's public key from that state's own zone, and "
        "encrypts the courier's details to it."
    )
    report.published(EMBLEM_NAME, "EMBLEM", record())


def offline_runs(world, dns_source, first):
    """The officer at the border, with a bundle and no network."""
    bundle = dns_source().fetch(EMBLEM_NAME, "EMBLEM").bundle.to_bytes()
    report.heading(
        f"The ministry also sends a bundle with the pouch ({len(bundle)} octets: the "
        "emblem, and the keys and signatures that lead to the root)"
    )
    check(
        "The officer has no network at the border",
        task(world),
        BundleSource(bundle),
        NOW,
        first,
    )
    report.heading(
        "The officer keeps the bundle: the validated records are evidence of what was "
        "published, and valid, when the pouch was checked (draft #lifecycle)."
    )
    return bundle


def variants(world, dns_source, bundle, first):
    wrong_seal = {**SEEN_ON_THE_POUCH, "seal": "XA-2026-114358"}
    check(
        "Variant: the seal on the pouch is not the seal in the emblem",
        task(world, wrong_seal),
        dns_source(),
        NOW,
        first,
    )
    check(
        "Variant: an officer of a third state, state XC, checks the pouch",
        task(world, keys=()),
        dns_source(),
        NOW,
        first,
    )
    check(
        "Variant: the same bundle, used fifteen days later",
        task(world),
        BundleSource(bundle),
        NOW + 15 * DAY,
        first,
    )


def main():
    world = zones.build(hierarchy(), NOW)
    dns_source = network.dns_source(network.parse_options(__doc__), world)
    introduction(world)
    first = check(
        "A customs officer of state XB checks the pouch in front of them, using the DNS",
        task(world),
        dns_source(),
        NOW,
    )
    report.opened(first)
    bundle = offline_runs(world, dns_source, first)
    variants(world, dns_source, bundle, first)


if __name__ == "__main__":
    main()
