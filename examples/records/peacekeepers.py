"""A peacekeeping mission and one of its people.   # draft: #ex-peacekeepers"""

from diem.values import Uri, treatment, validity
from examples.records.base import Example

PERSONNEL = {
    "profile": "peacekeeping-personnel",
    "asset": "r4nq-8w2k-c7tz._p._diem.mission.example",
    "mission": "mission.example",
    "status": "peacekeeper",
    "valid": validity(1793491200, 1801267200),
    "treatment": [treatment("prohibit", "attack"), treatment("prohibit", "detain")],
}

MISSION = {
    "profile": "peacekeeping-mission",
    "asset": "mission.example",
    "contact": Uri("https://mission.example/report"),
    "if-invalid": [treatment("request", "report"), treatment("request", "verify-identity")],
}

EXAMPLES = [
    Example(
        "#ex-peacekeepers",
        "EMBLEM",
        "r4nq-8w2k-c7tz._p._diem.mission.example",
        PERSONNEL,
    ),
    Example("#ex-peacekeepers", "EMBLEM", "_diem.mission.example", MISSION),
]
