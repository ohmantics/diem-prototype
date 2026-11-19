"""Dynamic facets: retrieved when they are wanted, and never decisive.   # draft: #facets

Something that changes constantly (the position of a container) is published
under a name of its own in an online-signed zone, with a short lifetime, so
that the offline keys that sign the emblem never have to be online. A
profile says which dynamic facets it has. An optional one adds information
and never changes the outcome: a protected asset must not appear unprotected
because a position query timed out.
"""

from diem import dnssec, names, times


def live(task, source, now):
    """One sentence about the emblem's live facet; empty if the profile has none."""
    spec = task.profile.facets.get("live")
    if spec is None:
        return ""
    what = spec["what"]
    answer = source.fetch(
        names.facet_name(task.emblem_name, spec["label"]), spec["rrtype"]
    )
    if answer.unavailable:
        return f"the live {what} could not be retrieved ({answer.reason}); it is optional, so nothing changes"
    chain = dnssec.verify(answer, task.trust_anchor, now)
    if chain.absent or not chain.secure:
        return f"no live {what} is used: {chain.reason or 'none is published'}"
    fix = " ".join(str(chain.rrset[0]).split()[:8])
    return (
        f"live {what} {fix}, signed when asked for by {chain.path[-1].to_text(True)}, "
        f"good until {times.moment(chain.expires)}"
    )
