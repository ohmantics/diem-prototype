"""A diplomatic pouch.   # draft: #ex-pouch"""

from diem.confidential import encrypt, recipient
from diem.values import Text, Uri, citation, quantity, treatment, validity
from examples.records.base import Example

# The courier's details are encrypted to the receiving state's customs.
RECEIVER = recipient("customs.xb.example")
ASSET = "k7q2-9xwm-4hd3._pouch._diem.mfa.gov.example"
COURIER = {"name": "A. Courier-Example", "letter": "XA-MFA-DC-2026-00417"}

EMBLEM = {
    "profile": "diplomatic-pouch",
    "asset": ASSET,
    "sending-state": "XA",
    "consignee": "embassy.xa.example",
    "seal": "XA-2026-114357",
    "pieces": 3,
    "gross-mass": quantity("18.4", "KGM"),
    "courier": encrypt(COURIER, "courier", ASSET, [RECEIVER]),
    "treatment": [treatment("prohibit", "open"), treatment("prohibit", "detain")],
    "basis": [
        citation(
            "uri",
            Uri(
                "https://legal.un.org/ilc/texts/instruments/english/conventions/9_1_1961.pdf"
            ),
            Text("en", "VCDR, Art. 27(3)"),
        )
    ],
    "valid": validity(1793750400, 1794355200),
}

EXAMPLES = [
    Example(
        "#ex-pouch", "EMBLEM", ASSET, EMBLEM
    ),
]
