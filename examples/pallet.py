"""A pallet of smartphones and its consignment, checked by customs and a recycler.   # draft: #ex-logistics

    python -m examples.pallet

A manufacturer ships 1,400 phones of one model family, in three variants, on a
wooden pallet, by sea from Ho Chi Minh City to Los Angeles. A freight forwarder consolidates the pallet into a consignment.
Customs at the destination needs the consignment's commercial data, which only
customs may read; a recycler, years later, needs only one device's battery.
The records and the DNS they are in are in examples/pallet_world.py.
"""

from diem import network, profile, report, times, validator, zones
from diem.sources import InMemoryDNS
from examples import pallet_world as world_of

FOLLOW = ("contents", "class-ref")


def customs_task(world, keys=(world_of.DESTINATION,), needs=("valuation", "parties")):
    return validator.Task(
        emblem_name=world_of.CONSIGNMENT_NAME,
        how_named="read from the code on the container",
        profile=profile.load("consignment"),
        evidence={"asset": world_of.CONSIGNMENT_NAME},
        trust_anchor=world.anchor,
        authorities=(world_of.NPPO,),
        follow=FOLLOW,
        keys=keys,
        needs=needs,
    )


def device_task(world, name, serial):
    return validator.Task(
        emblem_name=name,
        how_named="read from the label on the device",
        profile=profile.load("product-item"),
        evidence={"asset": name, "serial": serial},
        trust_anchor=world.anchor,
        follow=("class-ref",),
    )


def check(title, task, source, first=None, now=world_of.NOW):
    report.heading(f"{title}   ({times.moment(now)})")
    result = validator.validate(task, source, now)
    report.outcome(result, first)
    report.who_saw(source.log, task.emblem_name)
    return result


def customs_arithmetic(valuation, contents):
    """What software can check because amounts are typed decimals with currency codes."""
    lines = valuation["lines"]
    price = {line["class-ref"]: line["unit-price"][0].to_decimal() for line in lines}
    total = sum(line["line-qty"] * price[line["class-ref"]] for line in lines)
    counts = {entry["emblem"]: entry["count"] for entry in contents if "count" in entry}
    declared = valuation["total"][0].to_decimal()
    extra = sum(valuation[k][0].to_decimal() for k in ("freight", "insurance"))
    return [
        (
            f"the lines add up to {total:,} USD, which is the declared total"
            if total == declared
            else f"the lines add up to {total:,} USD, but the declared total is {declared:,}"
        ),
        (
            "the quantities match the counts in the consignment's contents"
            if {line["class-ref"]: line["line-qty"] for line in lines} == counts
            else "the quantities differ from the counts in the consignment's contents"
        ),
        f"US customs values the goods at the price paid, {declared:,f} USD; the freight "
        f"and insurance shown separately ({extra:,f} USD) are not part of that value",
    ]


def introduction(world, consignment):
    print(
        "A pallet of smartphones goes by sea from Vietnam to the United States."
        "   (draft #ex-logistics)"
    )
    report.hierarchy(world.hierarchy)
    report.heading(
        "The manufacturer publishes a family, three variants and each item, as in the draft"
    )
    for name, what in (
        (world_of.FAMILY_NAME, "family: X1"),
        ("std." + world_of.FAMILY_NAME, "variant: X1, with class-ref x1.models"),
        ("pro." + world_of.FAMILY_NAME, "variant: X1 Pro, with class-ref x1.models"),
        ("max." + world_of.FAMILY_NAME, "variant: X1 Max, with class-ref x1.models"),
        (world_of.ITEM_NAME, "one device, with class-ref pro.x1.models"),
    ):
        report.listed(name, "EMBLEM", what)
    report.heading(
        "The NPPO endorses the pallet producer, whose pallet then carries the ISPM 15 data. "
        "The forwarder wraps everything in a consignment; its position (made up, in the "
        "North Pacific on the way to Los Angeles) is signed when asked for."
    )
    nppo = "ispm15, endorsed by " + world_of.NPPO
    report.listed(world_of.PALLET_NAME, "EMBLEM", nppo)
    report.listed(world_of.LIVE_NAME, "LOC", "online-signed, valid for five minutes")
    report.published(world_of.CONSIGNMENT_NAME, "EMBLEM", consignment)


def customs_runs(world, dns_source, consignment):
    first = check(
        "Customs at the destination scans the consignment",
        customs_task(world),
        dns_source(),
    )
    report.heading("Customs checks the valuation it decrypted, with exact decimals")
    sentences = customs_arithmetic(first.opened["valuation"], consignment["contents"])
    for sentence in sentences:
        print(f"  {sentence[0].upper()}{sentence[1:]}.")
    live_down = InMemoryDNS(world, down=[world_of.LIVE_SERVER])
    check(
        "Variant: the live position cannot be retrieved",
        customs_task(world),
        live_down,
        first,
    )
    check(
        "Variant: a warehouse that is not customs checks the same consignment",
        customs_task(world, keys=(), needs=()),
        dns_source(),
        first,
    )


def device_runs(world, dns_source, consignment, options):
    check(
        "An officer scans a device whose serial the manufacturer never issued",
        device_task(world, "sn-0badf00d._diem.maker.example", "0BADF00D"),
        dns_source(),
    )
    print(
        "\n  A serial that does not resolve in the brand's own zone is a red flag "
        "(draft #ex-logistics)."
    )
    later = zones.build(world_of.hierarchy(consignment), world_of.LATER)
    report.heading(
        "Five years on, the manufacturer's zones are signed afresh, as zones always are, "
        "and the old emblems are still there."
    )
    check(
        "A recycler scans one device and follows its class references",
        device_task(later, world_of.ITEM_NAME, "35791A7C"),
        network.dns_source(options, later)(),
        now=world_of.LATER,
    )


def main():
    options = network.parse_options(__doc__)
    consignment = world_of.consignment()
    world = zones.build(world_of.hierarchy(consignment), world_of.NOW)
    dns_source = network.dns_source(options, world)
    introduction(world, consignment)
    customs_runs(world, dns_source, consignment)
    device_runs(world, dns_source, consignment, options)


if __name__ == "__main__":
    main()
