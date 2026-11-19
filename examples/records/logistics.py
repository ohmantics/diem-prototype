"""A pallet of smartphones and its consignment.   # draft: #ex-logistics"""

from diem.confidential import encrypt, recipient
from diem.values import Timestamp, Uri, money, quantity
from examples.records.base import Example

MAKER = "_diem.maker.example"
CONSIGNMENT_ASSET = "c-7f3k9q2m._diem.forwarder.example"
# Valuation and parties are encrypted to the customs of origin and of destination.
CUSTOMS = [recipient("customs.vn.example"), recipient("customs.us.example")]

FAMILY = {
    "profile": "product-class",
    "asset": f"x1.models.{MAKER}",
    "model": "X1",
    "dangerous-goods": {
        "un-number": "3481",
        "class": "9",
    },  # Li-ion batteries in equipment
    "battery-chemistry": "li-ion",
    "recycling": Uri("https://maker.example/recycle/x1"),
    "origin": "VN",
    "mid-us": "VNEXAMAK123HAN",  # US manufacturer ID
    "radio-auth": {"fcc-id": "2AEXAX1"},
}

VARIANT = {
    "profile": "product-class",
    "asset": f"pro.x1.models.{MAKER}",
    "class-ref": "x1.models",  # relative to the maker's emblem zone
    "gtin": "00614141999989",
    "model": "X1 Pro",
    "battery-energy": quantity("19.3", "WHR"),
}

ITEM = {
    "profile": "product-item",
    "asset": f"sn-35791a7c.{MAKER}",
    "class-ref": "pro.x1.models",
    "serial": "35791A7C",
    "made": Timestamp(1790812800),
}

PALLET = {
    "profile": "ispm15",
    "asset": "p-20261031-0042._diem.pallets.example",
    "country": "VN",
    "producer": "000123",
    "measure": "HT",
}

VALUATION = {
    "method": "transaction-value",
    "related-party": False,
    "incoterm": "FCA",
    "invoice": "INV-2026-10-4471",
    "lines": [
        {
            "class-ref": f"std.x1.models.{MAKER}",
            "line-qty": 600,
            "unit-price": money("380", "USD"),
        },
        {
            "class-ref": f"pro.x1.models.{MAKER}",
            "line-qty": 500,
            "unit-price": money("420", "USD"),
        },
        {
            "class-ref": f"max.x1.models.{MAKER}",
            "line-qty": 300,
            "unit-price": money("465", "USD"),
        },
    ],
    "total": money("577500", "USD"),
    "freight": money("3200", "USD"),
    "insurance": money("1155", "USD"),
    "additions": [],
}

PARTIES = {
    "seller": {"name": "Example Maker Co., Ltd.", "reference": "VN-TAX-0100123456"},
    "buyer": {"name": "Example Retail Inc.", "reference": "US-EIN-12-3456789"},
    "importer-of-record": {
        "name": "Example Retail Inc.",
        "reference": "US-IOR-12-3456789-00",
    },
    "bond": "CB-EX-0099120 (continuous)",
    "ship-to": {"name": "Example Retail DC Ontario", "reference": "US-CA-DC-0042"},
    "consolidator": {"name": "Example Forwarding Ltd.", "reference": "FMC-OTI-0099999"},
    "stuffing-location": "VNSGN, Cat Lai CFS bay 7",
}

CONSIGNMENT = {
    "profile": "consignment",
    "asset": CONSIGNMENT_ASSET,
    "hs-code": "851713",
    "hts-us": "8517130000",
    "origin": "VN",
    "container": "EXMU1234569",
    "seal": "EX4471029",
    "packages": quantity(1, "PX"),
    "gross-mass": quantity("725", "KGM"),
    "transport": {
        "bill-of-lading": "EXSC260098812",
        "carrier": "EXSC",
        "vessel": "EXAMPLE STAR",
        "voyage": "042E",
        "port-of-lading": "VNSGN",
        "port-of-unlading": "USLAX",
    },
    "valuation": encrypt(VALUATION, "valuation", CONSIGNMENT_ASSET, CUSTOMS),
    "parties": encrypt(PARTIES, "parties", CONSIGNMENT_ASSET, CUSTOMS),
    "contents": [
        {"emblem": "p-20261031-0042._diem.pallets.example"},
        {"emblem": f"std.x1.models.{MAKER}", "count": 600},
        {"emblem": f"pro.x1.models.{MAKER}", "count": 500},
        {"emblem": f"max.x1.models.{MAKER}", "count": 300},
    ],
}

EXAMPLES = [
    Example("#ex-logistics", "EMBLEM", FAMILY["asset"], FAMILY),
    Example("#ex-logistics", "EMBLEM", VARIANT["asset"], VARIANT),
    Example("#ex-logistics", "EMBLEM", ITEM["asset"], ITEM),
    Example("#ex-logistics", "EMBLEM", PALLET["asset"], PALLET),
    Example("#ex-logistics", "EMBLEM", CONSIGNMENT["asset"], CONSIGNMENT),
    Example(
        "#ex-logistics",
        "EMBLEM",
        CONSIGNMENT["asset"],
        VALUATION,
        profile="consignment",
        plaintext="valuation",
    ),
]
