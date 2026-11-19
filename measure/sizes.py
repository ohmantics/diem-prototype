"""How big is each record, and does a response fit one UDP packet?

    python -m measure.sizes > measure/results/sizes.md

RDATA is the deterministic CBOR of the emblem. The answer is the whole UDP
response (header, question, the RRset, its RRSIG, an EDNS OPT record) as dnspython
serializes it.
"""

import dns.name

from examples import pallet_world
from measure import common, consignment

ITEMS_PER_PALLET = 1400


def main():
    rows, size = [], {}
    for item in common.items():
        rdata, answer = item.rdata_octets(), common.answer_octets(item)
        size[item.label] = rdata
        owner = len(dns.name.from_text(item.name).to_wire())
        fits = "yes" if answer <= common.UDP_PAYLOAD else "NO"
        rows.append((item.label, item.rrtype, rdata, rdata + owner + 10, answer, fits))
    print(f"# Sizes of the example records (octets)\n\nGenerated with {common.versions()}.\n")
    header = (
        "record",
        "type",
        "RDATA",
        "RR on the wire",
        "answer (serialized)",
        f"fits {common.UDP_PAYLOAD}",
    )
    print(common.table(header, rows, text=(0, 1)))
    pallet_labels = (
        "product family",
        "variant std",
        "variant pro",
        "variant max",
        "consignment",
        "ispm15 pallet",
    )
    pallet = [size[label] for label in pallet_labels]
    items = ITEMS_PER_PALLET * size["item"]
    print(
        f"\n- {ITEMS_PER_PALLET:,} item emblems: {items:,} octets of RDATA "
        f"({items / 1000:.1f} KB)."
    )
    print(f"- Family, three variants, consignment and pallet: {sum(pallet):,} octets of RDATA.")
    total = items + sum(pallet)
    print(f"- Everything above, once: {total:,} octets of RDATA ({total / 1000:.1f} KB).")
    print(f"- The consignment's encrypted fields: {encrypted_octets()}")
    consignment.report()


def encrypted_octets():
    record = pallet_world.consignment()
    from diem import cbor

    sizes = [(key, len(cbor.encode(record[key].wire()))) for key in ("valuation", "parties")]
    return ", ".join(f"{key} {size}" for key, size in sizes)


if __name__ == "__main__":
    main()
