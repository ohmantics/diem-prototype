"""The hospital's records service.   # draft: #ex-ihl

The records are built by examples/hospital.py, which also publishes them in a
signed DNS hierarchy; the stapled endorsement in the emblem is the real chain.
"""

from examples import hospital
from examples.records.base import Example

ENDORSE = hospital.endorse_record()
EMBLEM = hospital.emblem_record(hospital.staple())
MARK = hospital.mark_record()

EXAMPLES = [
    Example("#ex-ihl", "EMBLEM", hospital.EMBLEM_NAME, EMBLEM),
    Example(
        "#ex-ihl",
        "ENDORSE",
        hospital.names.endorsement_name(hospital.HOME_MINISTRY, hospital.ISSUER),
        ENDORSE,
    ),
    Example("#ex-ihl", "EMBLEM", hospital.MARK_NAME, MARK),
]
