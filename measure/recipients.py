"""What does each additional recipient of an encrypted value cost?

    python -m measure.recipients > measure/results/recipients.md

An encrypted value to one recipient is a COSE_Encrypt0; to several it is a
COSE_Encrypt with one recipient structure each, which holds the encapsulated
key and the wrapped content key. This seals the draft's valuation and parties
to n recipients, and says how large the consignment emblem and its UDP answer
become, against the 1,232-octet payload of DNS Flag Day 2020.
"""

import os

from diem import cbor, confidential, emblem
from diem.values import Dec, Timestamp
from examples import pallet_world, peacekeepers_world, pouch, records
from measure import common

MOST = 6
PLAINTEXTS = {
    "valuation": {**records.logistics.VALUATION, "salt": os.urandom(16)},
    "parties": records.logistics.PARTIES,
}


def who(count):
    return [confidential.recipient(f"customs{n}.example") for n in range(count)]


def octets(key, count):
    name = pallet_world.CONSIGNMENT_NAME
    sealed = confidential.encrypt(PLAINTEXTS[key], key, name, who(count))
    return len(cbor.encode(sealed.wire()))


def consignment_rdata(counts, pinned=True):
    """The consignment emblem with each encrypted field sealed to its number of recipients.

    Each field goes to one recipient unless `counts` says otherwise. Unpinned
    leaves out the digests of the references and of the valuation, and its salt.
    """
    record = dict(pallet_world.consignment())
    plaintexts = dict(PLAINTEXTS)
    if not pinned:
        record.pop("valuation-digest")
        record["contents"] = [
            {k: v for k, v in entry.items() if k != "digest"} for entry in record["contents"]
        ]
        plaintexts["valuation"] = {k: v for k, v in plaintexts["valuation"].items() if k != "salt"}
    for key, count in {**dict.fromkeys(plaintexts, 1), **counts}.items():
        record[key] = confidential.encrypt(
            plaintexts[key], key, pallet_world.CONSIGNMENT_NAME, who(count)
        )
    return emblem.to_cbor(record)


def overhead(label):
    """What a UDP answer adds to the RDATA: header, question, owner names, the RRSIG, EDNS."""
    item = next(item for item in common.items() if item.label == label)
    return common.answer_octets(item) - item.rdata_octets()


def answer(rdata, label="consignment"):
    return len(rdata) + overhead(label)


def per_field():
    """For each encrypted field, the emblem's answer as that field goes to more recipients."""
    where = {
        "latitude": Dec.parse("12.5"),
        "longitude": Dec.parse("-118.75"),
        "as-of": Timestamp(1),
    }
    cases = (
        ("pouch", pouch.record(), "courier", records.pouch.COURIER, pouch.EMBLEM_NAME),
        (
            "convoy position",
            peacekeepers_world.convoy(),
            "position",
            where,
            peacekeepers_world.CONVOY,
        ),
    )
    rows = []
    for label, record, key, plain, name in cases:
        sizes = [
            answer(
                emblem.to_cbor({**record, key: confidential.encrypt(plain, key, name, who(n))}),
                label,
            )
            for n in range(1, MOST + 1)
        ]
        fit = max((n for n, size in enumerate(sizes, 1) if size <= common.UDP_PAYLOAD), default=0)
        rows.append((f"{label}, {key}", *sizes, fit or "none"))
    return rows


def plural(count, noun):
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def main():
    print(f"# Cost of recipients\n\nGenerated with {common.versions()}.\n")
    rows = []
    for count in range(1, MOST + 1):
        single = {key: octets(key, count) for key in PLAINTEXTS}
        both = consignment_rdata({key: count for key in PLAINTEXTS})
        one = consignment_rdata({"valuation": count})
        rows.append(
            (count, single["valuation"], single["parties"], len(both), answer(both), answer(one))
        )
    header = (
        "recipients",
        "valuation (octets)",
        "parties (octets)",
        "consignment RDATA, both fields",
        "answer, both fields",
        "answer, valuation only",
    )
    print(common.table(header, rows, text=()))
    print("\nOne recipient is a COSE_Encrypt0; two or more are a COSE_Encrypt.")
    steps = [rows[i + 1][1] - rows[i][1] for i in range(1, MOST - 1)]
    each = f"{min(steps)}" if min(steps) == max(steps) else f"{min(steps)} to {max(steps)}"
    print(
        f"Each recipient after the second adds {each} octets to a field "
        f"(the first step, from Encrypt0 to Encrypt, adds {rows[1][1] - rows[0][1]})."
    )

    def fit(column):
        return max((row[0] for row in rows if row[column] <= common.UDP_PAYLOAD), default=0)

    if not fit(4) and not fit(5):
        print(
            f"Even with one recipient, the consignment answer exceeds {common.UDP_PAYLOAD} "
            "octets, whether both fields or only the valuation are sealed."
        )
    else:
        print(
            f"Most recipients for which the consignment answer stays within "
            f"{common.UDP_PAYLOAD} octets: {fit(4) or 'none'} with both fields sealed "
            f"to each; {fit(5) or 'none'} with only the valuation sealed to each."
        )
    key = confidential.key_record(confidential.recipient("customs.us.example"), 0, 1)
    bare = answer(consignment_rdata({}, pinned=False))
    print(
        f"Without the pinning digests and the salt, the consignment answer (not the RDATA) "
        f"to one recipient per field is {bare} octets."
    )
    header = ("field", *[plural(n, "recipient") for n in range(1, MOST + 1)], "most that fit")
    print("\nUDP answer for the whole emblem, as one field goes to more recipients:\n")
    print(common.table(header, per_field()))
    print(
        f"\nA recipient's published key (a recipient-key emblem): "
        f"{len(emblem.to_cbor(key))} octets of RDATA."
    )


if __name__ == "__main__":
    main()
