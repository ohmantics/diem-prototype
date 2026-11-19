"""Issuer authorization: endorsements.   # draft: #endorsement

DNSSEC proves who published an emblem, not who authorized it. An
endorsement fills the gap: an ENDORSE record in the authorizing entity's own
signed zone, naming the endorsed issuer and what the issuer may claim. A
validator gets it in one of two ways, queried from the authority's zone or
stapled by the issuer into its emblem together with the chain that validates
it. Either way it is one object, validated by DNSSEC like any other record,
and then judged by the profile's rules: it must be about this issuer and
profile, current, wide enough to cover what the emblem claims, and (if the
profile says so) bound to the issuer's current key.

The validator accepts any one endorsement from an authority it recognizes
(draft #endorsement): authorities need not recognize one another.
"""

from dataclasses import dataclass

import dns.dnssec
import dns.name

from diem import dnssec, emblem, names, profile, times
from diem.sources import BundleSource


@dataclass
class Verdict:
    result: str  # "accepted", "invalid" or "indeterminate"
    text: str
    authority: str = ""
    endorsement: dict | None = None
    expired: bool = False  # not valid because its signatures have run out


def check(task, record, chain, source, now):
    """Look for an endorsement of the emblem's issuer from a recognized authority.

    chain is the validated chain of the emblem itself, whose keys an
    endorsement may be bound to.
    """
    issuer = task.profile.issuer_of(task.emblem_name)
    if not task.authorities:
        return Verdict(
            "invalid", "the validator recognizes no authority for this profile"
        )
    failures = {"invalid": [], "indeterminate": []}
    for authority in task.authorities:
        verdict = _from(authority, issuer, task, record, chain, source, now)
        if verdict.result == "accepted":
            return verdict
        failures[verdict.result].append(verdict.text)
    # An authority we could not reach might have endorsed it, so that is not a refusal.
    result = "indeterminate" if failures["indeterminate"] else "invalid"
    return Verdict(result, "; ".join(failures[result]))


def _from(authority, issuer, task, record, chain, source, now):
    """One authority's endorsement: the stapled one if the emblem carries it, else queried.

    What a validator does with a staple whose signatures have run out is an open
    question in the draft. This code chooses as follows. Online, it asks the
    authority instead, as a validator without a staple would (the profile accepts
    queried endorsements too); offline there is nobody to ask, and the result is
    indeterminate.
    """
    args = (authority, issuer, task, record, chain, now)
    staple = next(
        (e["staple"] for e in record.get("endorsements", []) if e["by"] == authority),
        None,
    )
    if staple is None:
        return _examine("queried", source, *args)
    stapled = _examine("stapled", BundleSource(staple), *args)
    if not stapled.expired:
        return stapled
    queried = _examine("queried", source, *args)
    queried.text = (
        f"the stapled endorsement from {authority} had expired, so the authority "
        f"was asked instead: {queried.text}"
    )
    return queried


def _examine(kind, where, authority, issuer, task, record, chain, now):
    """Fetch an endorsement from where, validate it, and judge whether it applies."""
    answer = where.fetch(names.endorsement_name(authority, issuer), "ENDORSE")
    who = f"the {kind} endorsement from {authority}"
    if answer.unavailable:
        return Verdict("indeterminate", f"{who} could not be obtained: {answer.reason}")
    proof = dnssec.verify(answer, task.trust_anchor, now)
    if proof.absent:
        return Verdict(
            "invalid", f"{authority} proves that it has not endorsed {issuer}"
        )
    if not proof.secure:
        return Verdict(
            "invalid", f"{who} is not valid: {proof.reason}", expired=proof.expired
        )
    found = _read(proof.rrset, record["profile"])
    if isinstance(found, str):
        return Verdict("invalid", f"{who} is unusable: {found}")
    problem = _judge(found, issuer, record, chain, task.profile, now)
    if problem:
        return Verdict("invalid", f"{who} does not apply: {problem}")
    return _accepted(kind, authority, issuer, task, record, found)


def _accepted(kind, authority, issuer, task, record, found):
    how = (
        "its chain validates without querying the authority"
        if kind == "stapled"
        else "validated with DNSSEC after querying the authority"
    )
    claims = _claims(record, task.profile)
    covered = " and ".join(_phrase(value) for value in claims)
    covered = covered or f"the use of profile {record['profile']}"
    binds = f" and binds {issuer}'s current key" if _binds(task.profile) else ""
    return Verdict(
        "accepted",
        f"{kind} endorsement from {authority}, which this validator recognizes; {how}; "
        f"it covers {covered}{binds}",
        authority,
        found,
    )


def dnskey_digest(zone, key):
    """The digest an endorsement uses to bind a zone's key: the one in a DS record."""
    return dns.dnssec.make_ds(zone, key, "SHA256").digest


def _read(rrset, wanted):
    """The endorsement in an ENDORSE RRset for the profile wanted (an authority may
    endorse an issuer for several), or a sentence saying why there is none."""
    try:
        records = [emblem.from_cbor(rdata.data) for rdata in rrset]
    except ValueError as error:
        return str(error)
    found = next(
        (r for r in records if r.get("endorsed-profile") == wanted),
        emblem.select(records, profile.load("endorsement")),
    )
    if found is None:
        return "it holds no record of the endorsement profile"
    problems = profile.load("endorsement").check_types(found)
    return "; ".join(problems) if problems else found


def _claims(record, policy):
    """What the emblem claims that an endorsement has to cover."""
    claims = []
    for key in policy.endorsement.get("scope-keys", []):
        value = record.get(key, [])
        claims += value if isinstance(value, list) else [value]
    return claims


def _binds(policy):
    return policy.endorsement.get("binds-key", False)


def _phrase(claim):
    if isinstance(claim, dict):
        return " ".join(f'"{modality} {action}"' for modality, action in claim.items())
    return claim


def _judge(endorsement, issuer, record, chain, policy, now):
    """Why an endorsement does not apply to this emblem, or None if it does."""
    if names.normalize(endorsement["issuer"]) != names.normalize(issuer):
        return f"it is about {endorsement['issuer']}, not {issuer}"
    if endorsement["endorsed-profile"] != record["profile"]:
        return (
            f"it is for profile {endorsement['endorsed-profile']}, "
            f"not {record['profile']}"
        )
    start, end = (moment.seconds for moment in endorsement["valid"])
    if not start <= now <= end:
        period = f"{times.day(start)} to {times.day(end)}"
        return f"its validity period, {period}, does not include the time of validation"
    uncovered = [
        _phrase(claim)
        for claim in _claims(record, policy)
        if claim not in endorsement["scope"]
    ]
    if uncovered:
        return f"its scope does not cover {' or '.join(uncovered)}"
    if _binds(policy):
        keys = chain.keys.get(dns.name.from_text(issuer))
        if keys is None:
            return (
                f"the emblem's chain has no keys of {issuer}; the binding is unchecked"
            )
        if not any(
            dnskey_digest(keys.name, key) == endorsement["dnskey-digest"]
            for key in keys
        ):
            return f"it names a key of {issuer} other than the one in use"
    return None
