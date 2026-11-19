"""A humanitarian flight diverted from state XA to state XB.   # draft: #open-issues

    python -m examples.diverted_flight

A flight bound for state XA carries medical supplies with dangerous-goods
data, a CITES permit item, a diplomatic pouch from state XC to its mission in
XA, and a hard drive whose emblem refers to the emblem of the dataset on it.
The issuers sent each package's emblems in a bundle, and encrypted what only
XA's customs should read to XA's customs. The flight diverts to state XB, whose
customs validates every package offline, and then online.
"""

import dns.rdatatype as rdatatype

from diem import network, profile, report, rrtypes, times, validator, zones
from diem.bundle import Bundle
from diem.sources import BundleSource
from examples import diverted_world as world_of
from examples.diverted_world import (
    CITES,
    DATASET,
    DRIVE,
    MEDICAL,
    NOW,
    PERMIT,
    POUCH,
    SEAL,
    SERIAL,
)

SEEN_POUCH = {"seal": SEAL}


def task(world, name, profile_name, evidence=None, **more):
    return validator.Task(
        emblem_name=name,
        how_named="read from the label on the package",
        profile=profile.load(profile_name),
        evidence={"asset": name, **(evidence or {})},
        trust_anchor=world.anchor,
        **more,
    )


def bundle(source, *names):
    """What the issuer sends with a package: the emblems, and the keys that lead to the root."""
    carried = Bundle()
    for name in names:
        found = source.fetch(name, "EMBLEM").bundle
        for kind in (rrtypes.EMBLEM, rdatatype.DNSKEY, rdatatype.DS):
            for pair in found.rrsets_of_type(kind):
                carried.add(*pair)
    return carried.to_bytes()


def check(title, task, source, first=None, keep=None):
    """Validate and print: in full, or (keep is a tuple of step numbers) just the steps worth saying."""
    report.heading(f"{title}   ({times.moment(NOW)})")
    result = validator.validate(task, source, NOW)
    if keep is None:
        report.outcome(result, first)
    else:
        report.brief(result, keep)
    return result


def introduction(world):
    print("A humanitarian flight is diverted to state XB.   (draft #open-issues)")
    report.heading(
        "This illustrates the draft's open issue of recipients not known at issuance. "
        "The flight was planned for state XA, so what the issuers encrypted was encrypted "
        "to the customs of XA; nobody planned for XB, and XB's customs holds no such key."
    )
    report.hierarchy(world.hierarchy)
    report.heading("The packages, each with an emblem")
    for name, what in (
        (MEDICAL, "dg-package; valuation encrypted to XA's customs"),
        (CITES, "cites-permit"),
        (POUCH, "diplomatic-pouch; courier encrypted to XA's customs"),
        (DRIVE, "storage-device and dg-package: a record for each profile"),
        (DATASET, 'dataset, "prohibit read"; details encrypted to XA\'s customs'),
    ):
        report.listed(name, "EMBLEM", what)


def offline_runs(world, dns_source):
    """The validations in XB from the bundles that came with the packages."""
    carried = {n: bundle(dns_source(), n) for n in (MEDICAL, CITES, POUCH, DATASET)}
    carried[DRIVE] = bundle(dns_source(), DRIVE, DATASET)
    report.heading(
        "In state XB, offline, from the bundles that came with the packages. "
        "After the first, only the steps with something to say are shown."
    )
    first = check(
        "Medical supplies: the dangerous-goods data is what every handler needs",
        task(world, MEDICAL, "dg-package"),
        BundleSource(carried[MEDICAL]),
    )
    check(
        "Variant: XB's customs wants the declared value, encrypted to XA's customs",
        task(world, MEDICAL, "dg-package", needs=("valuation",)),
        BundleSource(carried[MEDICAL]),
        first,
    )
    package_runs(world, carried)
    return first


PACKAGES = (
    (
        "The CITES permit, against the number printed on it",
        CITES,
        "cites-permit",
        {"permit-number": PERMIT},
        {},
        (),
    ),
    (
        "The diplomatic pouch: its treatments, and the seal against the pouch",
        POUCH,
        "diplomatic-pouch",
        SEEN_POUCH,
        {},
        (),
    ),
    (
        "The hard drive as an object, and the dataset it refers to",
        DRIVE,
        "storage-device",
        {"serial": SERIAL},
        {"follow": ("dataset",)},
        (8,),
    ),
    (
        "The same drive as dangerous goods: its record for that profile",
        DRIVE,
        "dg-package",
        {},
        {},
        (),
    ),
    (
        "Variant: XB's customs wants the dataset's details",
        DATASET,
        "dataset",
        {},
        {"needs": ("details",)},
        (),
    ),
)


def package_runs(world, carried):
    """The other packages: each shows only the steps with something to say."""
    for title, name, profile_name, evidence, more, keep in PACKAGES:
        wanted = task(world, name, profile_name, evidence, **more)
        check(title, wanted, BundleSource(carried[name]), keep=keep)


def online_runs(world, dns_source, first, options):
    """The same checks in XB with a network: live facets, and the status of an emblem."""
    report.heading("In state XB, online")
    check(
        "The medical supplies again, now with the live position (a made-up one, in "
        "open ocean)",
        task(world, MEDICAL, "dg-package"),
        dns_source(),
        first,
    )
    withdrawn = zones.build(world_of.hierarchy(withdrawn=True), NOW)
    check(
        "Variant: the issuer has since withdrawn the CITES permit",
        task(withdrawn, CITES, "cites-permit", {"permit-number": PERMIT}),
        network.dns_source(options, withdrawn)(),
        keep=(),
    )
    report.heading(
        "The bundle that came with the permit would still validate until its signatures "
        "expire (draft #open-issues, revocation for offline validators)."
    )


def main():
    options = network.parse_options(__doc__)
    world = zones.build(world_of.hierarchy(), NOW)
    dns_source = network.dns_source(options, world)
    introduction(world)
    first = offline_runs(world, dns_source)
    online_runs(world, dns_source, first, options)


if __name__ == "__main__":
    main()
