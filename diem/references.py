"""References between emblems.   # draft: #hierarchy

An emblem names the emblems it relates to: a variant its product family, a
consignment what is in it. Each referenced emblem is validated through its
own zone's DNSSEC chain, as an emblem found any other way would be. A
reference may carry a digest of the RRset it saw, which pins it: correcting
the referenced data then means publishing a new version. A profile says
whether references carry digests and whether they must.
"""

import hashlib
from dataclasses import dataclass, replace

from diem import names


@dataclass
class Followed:
    result: str  # "ok", "invalid" or "indeterminate"
    text: str
    # one line for each emblem followed, indented under the one that led to it
    details: tuple = ()


def rrset_digest(rrset):
    """A digest of an RRset that does not depend on its TTL or the order it was served in."""
    parts = sorted(rdata.to_wire() for rdata in rrset)
    return hashlib.sha256(
        b"".join(len(part).to_bytes(2, "big") + part for part in parts)
    ).digest()


def _listed(record, keys):
    """(map key, reference, digest or None) for each reference under the keys a task follows."""
    for key in keys:
        value = record.get(key)
        if isinstance(value, str):
            yield key, value, None
        for entry in value if isinstance(value, list) else ():
            yield key, entry["emblem"], entry.get("digest")


def follow(record, task, source, now, check):
    """Follow the references under the map keys task.follow; check validates one emblem."""
    details = []
    for key, reference, digest in _listed(record, task.follow):
        name = names.absolute(reference, task.emblem_name)
        if name in task.trail or name == task.emblem_name:
            return Followed(
                "invalid", f"{name} refers back to an emblem being validated"
            )
        sub = replace(
            task,
            emblem_name=name,
            how_named=f"the {key} reference of {task.emblem_name}",
            profile=None,
            evidence={"asset": name},
            needs=(),
            trail=task.trail + (task.emblem_name,),
        )
        found = check(sub, source, now)
        if found.result != "valid":
            why = f"{name}, which {key} refers to, is {found.result} at step {found.ended_at}"
            return Followed(
                found.result, f"{why}: {found.steps[-1].text}", tuple(details)
            )
        problem = _digest_problem(digest, found, name, task.profile)
        if problem:
            return Followed("invalid", problem, tuple(details))
        details += _line(name, found, digest) + _nested(found)
    if not details:
        return Followed("ok", "")
    counted = sum(1 for line in details if not line.startswith(" "))
    if counted == 1:
        text = "followed 1 reference, validated through its own zone"
    else:
        text = f"followed {counted} references, each validated through its own zone"
    return Followed("ok", text, tuple(details))


def _digest_problem(digest, found, name, policy):
    if digest is None:
        required = policy.digests == "required"
        return (
            f"the reference to {name} carries no digest, which {policy.name} requires"
            if required
            else None
        )
    if digest != rrset_digest(found.rrset):
        return f"{name} is not what was referred to: the RRset now published differs from the digest"
    return None


def _line(name, found, digest):
    by = f", endorsed by {found.authority}" if found.authority else ""
    pinned = "; its digest matches" if digest else ""
    return [f"{name}: valid ({found.profile}{by}){pinned}"]


def _nested(found):
    """The references that the followed emblem itself followed, one level further in."""
    later = next((step for step in found.steps if step.number == 8), None)
    return ["  " + line for line in later.details] if later else []
