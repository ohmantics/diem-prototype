"""How big is the consignment emblem, under four ways of encoding it?

The consignment is the largest example record, and the draft says it exceeds
the 1,232-octet limit commonly used for DNS over UDP. Its valuation and parties
are encrypted to the origin and destination customs; each COSE_Encrypt
recipient adds an HPKE encapsulated key and a wrapped content key. Variant (a)
is the example as in the example; the others change only what is measured here,
not the example.
"""

import os

from diem import cbor, confidential, cose_hpke, emblem
from diem.values import Encrypted
from examples import pallet_world, records
from measure import common, recipients

ASSET = pallet_world.CONSIGNMENT_NAME
MOST = 8  # the most recipients tried, to find how many fit one answer
SHOWN = 4  # the numbers of recipients that get a column of their own

VARIANTS = (
    (
        "a",
        "as in the example: valuation and parties each a COSE_Encrypt to every recipient; "
        "reference digests, valuation digest, salt",
    ),
    ("b", "as a, without the four reference digests (optional in the draft)"),
    (
        "c",
        "valuation and parties in one COSE_Encrypt to every recipient (one content key, "
        "one recipient list); no reference digests; valuation digest and salt kept",
    ),
    ("d", "as c, without the valuation digest and the salt"),
)


def rdata(variant, count):
    """The consignment emblem's RDATA for a variant, with `count` recipients."""
    record = dict(pallet_world.consignment())
    to = recipients.who(count)
    valuation = records.logistics.VALUATION
    if variant != "d":
        valuation = {**valuation, "salt": os.urandom(16)}
    if variant in "bcd":
        record["contents"] = [
            {k: v for k, v in e.items() if k != "digest"} for e in record["contents"]
        ]
    if variant in "ab":
        record["valuation"] = confidential.encrypt(valuation, "valuation", ASSET, to)
        record["parties"] = confidential.encrypt(
            records.logistics.PARTIES, "parties", ASSET, to
        )
    else:
        record["valuation"] = both(valuation, to)
        record.pop("parties")
    if variant == "d":
        record.pop("valuation-digest")
    return emblem.to_cbor(record)


def both(valuation, to):
    """One COSE_Encrypt holding the two plaintexts, as one map."""
    plaintext = {
        "valuation": cbor.decode(emblem.to_cbor(valuation, ("valuation",))),
        "parties": cbor.decode(
            emblem.to_cbor(records.logistics.PARTIES, ("parties",))
        ),
    }
    aad = confidential.binding(ASSET, "valuation")
    data = cbor.encode(plaintext)
    if len(to) == 1:
        return Encrypted(16, cose_hpke.encrypt0(data, to[0].kid, to[0].public, aad))
    return Encrypted(96, cose_hpke.encrypt(data, [(r.kid, r.public) for r in to], aad))


def rows():
    overhead = recipients.overhead("consignment")
    found = []
    for variant, what in VARIANTS:
        sizes = [len(rdata(variant, n)) for n in range(1, MOST + 1)]
        fits = max(
            (n for n, size in enumerate(sizes, 1) if size + overhead <= common.UDP_PAYLOAD),
            default=0,
        )
        found.append((variant, sizes, fits, sizes[3] - sizes[2], what))
    return found, overhead


def report():
    found, overhead = rows()
    print("\n## The consignment emblem under four encodings\n")
    for variant, _, _, _, what in found:
        print(f"- **{variant}**: {what}.")
    print(
        f"\nRDATA in octets by number of recipients; a UDP answer adds {overhead} octets "
        f"to the RDATA (header, question, owner names, RRSIG, EDNS), and must stay within "
        f"{common.UDP_PAYLOAD}.\n"
    )
    header = (
        "variant",
        *[str(n) for n in range(1, SHOWN + 1)],
        "answer at 1",
        f"most recipients that fit (of {MOST})",
        "each added recipient",
    )
    table = [
        (v, *sizes[:SHOWN], sizes[0] + overhead, fits or "none", f"+{step}")
        for v, sizes, fits, step, _ in found
    ]
    print(common.table(header, table))
    print(
        "\nOne recipient is a COSE_Encrypt0; two or more are a COSE_Encrypt. "
        "The last column is the cost of the third recipient."
    )
