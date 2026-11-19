"""A hospital's records service, and the ministries that endorse it.   # draft: #ex-ihl

    python -m examples.hospital

Example General Hospital marks its patient records service. The hospital is in
territory that states XA and XB both claim, and each state's ministry of health
endorses it for the protective use of the emblem. The hospital staples XA's
endorsement into its emblem, so that a validator that recognizes XA's ministry
need not ask it anything. The emblem does not mention XB's endorsement, and a
validator that recognizes only XB's ministry queries it. Neither validator has
to decide between the two claims.
"""

import hashlib

from diem import names, network, profile, report, times, validator, zones
from diem.bundle import Bundle
from diem.sources import InMemoryDNS
from examples.hospital_world import (
    ASSET,
    DAY,
    EMBLEM_NAME,
    HOME_MINISTRY,
    ISSUER,
    MARK_NAME,
    NOW,
    OTHER_IMAGE,
    OTHER_MINISTRY,
    MARK_IMAGE,
    emblem_record,
    endorse_record,
    hierarchy,
    mark_record,
    published_emblem,
    staple,
)


def task(world, authority, canonical=True):
    checker = profile.load("ihl-protective")
    return validator.Task(
        emblem_name=EMBLEM_NAME,
        how_named="derived from the service name by the profile",
        profile=checker,
        evidence={"asset": ASSET},
        trust_anchor=world.anchor,
        authorities=(authority,),
        canonical_marks=(
            {"protective-red-cross": hashlib.sha256(MARK_IMAGE).digest()}
            if canonical
            else {}
        ),
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
        "Example General Hospital, in territory that states XA and XB both claim, "
        "marks its patient records service.   (draft #ex-ihl)"
    )
    report.hierarchy(world.hierarchy)
    report.heading(
        "Each ministry publishes its endorsement under a digest of the hospital's name"
    )
    for ministry in (HOME_MINISTRY, OTHER_MINISTRY):
        owner = names.endorsement_name(ministry, ISSUER)
        report.published(owner, "ENDORSE", endorse_record())
    report.heading("The hospital publishes")
    report.published(EMBLEM_NAME, "EMBLEM", emblem_record(staple()))
    print(
        f"    / staple: the ENDORSE RRset and its chain, "
        f"{len(Bundle.from_bytes(staple()))} RRsets /"
    )
    report.published(MARK_NAME, "EMBLEM", mark_record())


def variants(first):
    """The variants that change what is published, and so need zones of their own."""
    later = NOW + 10 * DAY
    for title, when, kind in (
        (
            "Variant: the mark facet now holds a different image",
            NOW,
            {"mark_image": OTHER_IMAGE},
        ),
        (
            "Variant: ten days later the staple has expired, and the ministry, which "
            "signs afresh, still endorses the hospital",
            later,
            {},
        ),
        (
            "Variant: ten days later the staple has expired, and the ministry has "
            "since withdrawn its endorsement",
            later,
            {"home_scope": None},
        ),
        ("Variant: the hospital has removed its emblem", NOW, {"emblem": False}),
    ):
        emblem_bytes = published_emblem() if kind.pop("emblem", True) else None
        world = zones.build(hierarchy(emblem_bytes, **kind), when)
        check(title, task(world, HOME_MINISTRY), InMemoryDNS(world), when, first)
    print(
        "  With no emblem published there is nothing to validate. That says nothing\n"
        "  about the hospital's protection, which exists in law whether or not an\n"
        "  emblem is displayed (draft #treatment)."
    )


def main():
    options = network.parse_options(__doc__)
    world = zones.build(hierarchy(published_emblem()), NOW)
    dns_source = network.dns_source(options, world)
    introduction(world)
    first = check(
        "A cyber unit that recognizes XA's ministry checks the service before any "
        "operation",
        task(world, HOME_MINISTRY),
        dns_source(),
        NOW,
    )
    check(
        "A unit that recognizes only XB's ministry queries that ministry instead",
        task(world, OTHER_MINISTRY),
        dns_source(),
        NOW,
        first,
    )
    if options.resolver:
        report.heading(
            "The variants that change what is published (a different mark, a removed "
            "emblem, an expired staple) run in local mode only: these servers hold one "
            "set of zones."
        )
        return
    variants(first)


if __name__ == "__main__":
    main()
