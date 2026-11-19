"""What the measurements share: the records of the examples, and how they are sized.

Everything measured here is built by the code under diem/ and examples/ and
retrieved from the in-memory DNS, so the numbers are those of this encoding
and of these examples. Nothing in diem/ depends on this directory.
"""

import platform
from dataclasses import dataclass
from importlib import metadata

import dns.message

from diem import names, rrtypes, sources, zones
from diem.sources import InMemoryDNS
from examples import hospital, pallet_world, peacekeepers_world, pouch

UDP_PAYLOAD = sources.UDP_PAYLOAD
QR_V40 = {"L": 2953, "M": 2331, "Q": 1663, "H": 1273}  # octets in byte mode, version 40
NFC_TAG = 888  # user memory of an NTAG216, the largest common tag


@dataclass
class Item:
    label: str
    name: str
    rrtype: str
    world: object
    now: int

    def answer(self):
        return InMemoryDNS(self.world).fetch(self.name, self.rrtype)

    def rrset(self):
        answer = self.answer()
        return answer.bundle.get(answer.name, answer.rdtype)

    def rdata_octets(self):
        return sum(len(rdata.to_wire()) for rdata in self.rrset()[0])


def items():
    """The records of the four examples that a person might carry or a validator fetch."""
    world = {
        "pouch": zones.build(pouch.hierarchy(), pouch.NOW),
        "hospital": zones.build(
            hospital.hierarchy(hospital.published_emblem()), hospital.NOW
        ),
        "pallet": zones.build(
            pallet_world.hierarchy(pallet_world.consignment()), pallet_world.NOW
        ),
        "peace": zones.build(peacekeepers_world.hierarchy(), peacekeepers_world.NOW),
    }
    h, p, k = hospital, pallet_world, peacekeepers_world
    ends = names.endorsement_name
    return [
        Item("hospital emblem", h.EMBLEM_NAME, "EMBLEM", world["hospital"], h.NOW),
        Item(
            "hospital endorsement",
            ends(h.HOME_MINISTRY, h.ISSUER),
            "ENDORSE",
            world["hospital"],
            h.NOW,
        ),
        Item("product family", p.FAMILY_NAME, "EMBLEM", world["pallet"], p.NOW),
        Item("variant std", "std." + p.FAMILY_NAME, "EMBLEM", world["pallet"], p.NOW),
        Item("variant pro", "pro." + p.FAMILY_NAME, "EMBLEM", world["pallet"], p.NOW),
        Item("variant max", "max." + p.FAMILY_NAME, "EMBLEM", world["pallet"], p.NOW),
        Item("item", p.ITEM_NAME, "EMBLEM", world["pallet"], p.NOW),
        Item("ispm15 pallet", p.PALLET_NAME, "EMBLEM", world["pallet"], p.NOW),
        Item(
            "ispm15 endorsement",
            ends(p.NPPO, "pallets.example"),
            "ENDORSE",
            world["pallet"],
            p.NOW,
        ),
        Item("consignment", p.CONSIGNMENT_NAME, "EMBLEM", world["pallet"], p.NOW),
        Item("pouch", pouch.EMBLEM_NAME, "EMBLEM", world["pouch"], pouch.NOW),
        Item("badge", k.BADGE, "EMBLEM", world["peace"], k.NOW),
        Item("mission emblem", k.MISSION_NAME, "EMBLEM", world["peace"], k.NOW),
        Item(
            "mission endorsement",
            ends(k.DEPLOYER, "mission.example"),
            "ENDORSE",
            world["peace"],
            k.NOW,
        ),
        Item("convoy position", k.CONVOY, "EMBLEM", world["peace"], k.NOW),
    ]


def answer_octets(item):
    """The size of the UDP response a resolver would return for the record.

    That is the header, the question, the RRset, its RRSIG and an EDNS OPT
    record, serialized with name compression.
    """
    rrset, signatures = item.rrset()
    query = dns.message.make_query(
        item.name, rrtypes.number(item.rrtype), want_dnssec=True, use_edns=0, payload=65535
    )
    response = dns.message.make_response(query)
    response.answer += [rrset, signatures]
    return len(response.to_wire())


def versions():
    packages = ("cbor2", "cryptography", "dnspython", "pyhpke")
    found = ", ".join(f"{name} {metadata.version(name)}" for name in packages)
    return f"Python {platform.python_version()}, {found}"


def table(header, rows, text=(0,)):
    """A markdown table; the columns listed in `text` are left-aligned, the rest right-aligned."""
    aligns = ["---" if i in text else "---:" for i in range(len(header))]
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(aligns) + "|"]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines)
