"""Visual marks: whether one may be shown.   # draft: #marks

People recognize emblems by sight, so an emblem may refer to an image of the
sign people know, published as a facet of its own. The image is displayed only
if its digest is covered by a validated endorsement (the authorizing entity
attests that this issuer may show it), or if it is a canonical rendering that
the validator already holds for an enumerated value in the emblem. Otherwise
it is not displayed. A mark never overrides the emblem's data, and "mark not
authorized" is not "emblem invalid": a protected site must not appear
unprotected because of a mark (draft #open-issues).

The mark is an optional facet, so whatever goes wrong with it, the result of
validating the emblem is unchanged. The digest is taken over the image octets
as published, with no canonicalization.
"""

import hashlib
from dataclasses import dataclass

from diem import dnssec, emblem, names, profile, svg_tiny_ps


@dataclass
class Assessment:
    shown: bool
    text: str  # for step 8
    note: str = ""  # for the result, when there is something to tell the person


def assess(record, source, task, endorsement, now):
    """May the emblem's mark be shown? endorsement: the one accepted at step 7, if any."""
    answer = source.fetch(record["mark"], "EMBLEM")
    if answer.unavailable:
        return Assessment(
            False,
            f"the visual mark could not be retrieved ({answer.reason}); it is optional, "
            "so nothing changes",
            "No mark shown.",
        )
    chain = dnssec.verify(answer, task.trust_anchor, now)
    if chain.absent or not chain.secure:
        return Assessment(
            False,
            "the visual mark is not shown: " + (chain.reason or "none is published"),
            "No mark shown.",
        )
    mark, problem = _read(chain.rrset, record)
    if problem:
        return Assessment(
            False, f"the visual mark is not shown: {problem}", "No mark shown."
        )
    return _authorize(mark["image"], record, task, endorsement)


def _read(rrset, record):
    """The mark facet, or a sentence saying why it cannot be used."""
    checker = profile.load("mark")
    try:
        found = emblem.select(
            [emblem.from_cbor(rdata.data) for rdata in rrset], checker
        )
    except ValueError as error:
        return None, str(error)
    if found is None:
        return None, "the facet holds no record of the mark profile"
    problems = checker.check_types(found)
    if problems:
        return None, "; ".join(problems)
    if names.normalize(found["asset"]) != names.normalize(record["asset"]):
        return None, f"it depicts {found['asset']}, not {record['asset']}"
    if found["media-type"] != "image/svg+xml":
        return (
            None,
            f"its media type is {found['media-type']}, and only SVG Tiny PS is accepted",
        )
    flaws = svg_tiny_ps.problems(found["image"])
    return (None, f"it is not SVG Tiny PS: {flaws[0]}") if flaws else (found, "")


def _authorize(image, record, task, endorsement):
    digest = hashlib.sha256(image).digest()
    grounds = []
    if endorsement is not None and endorsement.get("mark-digest") == digest:
        grounds.append("its digest matches the endorsement")
    for value in _values(record):
        if task.canonical_marks.get(value) == digest:
            grounds.append(
                f"it is the canonical rendering this validator holds for {value}"
            )
    if grounds:
        return Assessment(
            True, "visual mark retrieved; " + " and ".join(grounds), "Mark displayed."
        )
    return Assessment(
        False,
        "visual mark retrieved, but it is NOT authorized: its digest is not the one in "
        "the endorsement, and it is not a rendering this validator holds for the "
        "emblem's values",
        "Mark not authorized, so not displayed; the emblem itself is unaffected.",
    )


def _values(record):
    """The enumerated values in an emblem; a validator may hold renderings for them."""
    found = []
    for value in record.values():
        found += value if isinstance(value, list) else [value]
    return [value for value in found if isinstance(value, str)]
