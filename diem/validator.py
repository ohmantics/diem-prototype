"""The validation outline.   # draft: #validation

Every profile is validated by these ten steps. What differs between
profiles is data the validator loads (map keys and types, how an emblem
names its asset, which authorities are recognized), never code. Steps
carry the draft's numbers so that this file and a walkthrough's output
can be read side by side.

How far a validation goes is the task's: which references it follows, which
encrypted values it needs to read. What it cannot follow or read, and needs,
leaves the result indeterminate: the emblem may be fine, but we cannot say.
"""

from dataclasses import dataclass, field, replace

from diem import (
    confidential,
    dnssec,
    emblem,
    endorsement,
    facets,
    marks,
    references,
    times,
    treatment,
)
from diem.outcome import Outcome
from diem.profile import Profile, load


@dataclass
class Task:
    emblem_name: str
    # How we came by the name: printed on the asset, derived from its name ...
    how_named: str
    # None means whichever profile the emblem declares (for a reference)
    profile: Profile | None
    # What we can see of the asset itself: its name, a seal number ...
    evidence: dict
    # The DS records of the root's key
    trust_anchor: list
    # The authorizing entities this validator recognizes
    authorities: tuple = ()
    # Enumerated value -> digest of its canonical image
    canonical_marks: dict = field(default_factory=dict)
    # The map keys whose references this task follows
    follow: tuple = ()
    # The recipient keys this validator holds
    keys: tuple = ()
    # The encrypted values the task cannot do without
    needs: tuple = ()
    # The emblems being validated above this one
    trail: tuple = ()


def validate(task, source, now):
    """Validate the emblem at task.emblem_name for the asset in front of us.

    source is the DNS (through a resolver, or in memory) or an offline
    bundle. Either way we get RRsets with their RRSIGs and chains and check
    the signatures ourselves, all at one time, `now`: signatures can expire
    between queries, and a resolver's AD bit cannot be re-examined later.
    """
    out = _validate(task, source, now)
    if out.result == "invalid" and task.profile and task.profile.if_invalid_at:
        treatment.say_what_to_do(out, task, source, now, validate)
    return out


def _validate(task, source, now):
    """Take the steps in order; each ends the validation (returns True) or lets it go on."""
    run = _Run(task, source, now)
    steps = (
        run.name,
        run.retrieve,
        run.dnssec,
        run.types,
        run.asset,
        run.validity,
        run.authorization,
        run.references,
        run.decryption,
        run.result,
    )
    for step in steps:
        if step():
            break
    return run.out


class _Run:
    """One validation under way: its task and sources, what the steps have learned, its outcome."""

    def __init__(self, task, source, now):
        self.task, self.source, self.now = task, source, now
        self.out = Outcome(task)
        self.answer = self.chain = self.record = None
        self.accepted = self.mark = None

    def name(self):
        self.out.passed(1, f"{self.task.emblem_name}, {self.task.how_named}")

    def retrieve(self):
        # A record we cannot obtain is not evidence of anything, so this is
        # indeterminate, never invalid (draft #validation).
        self.answer = self.source.fetch(self.task.emblem_name, "EMBLEM")
        if self.answer.unavailable:
            why = f"could not retrieve the emblem: {self.answer.reason}"
            return self.out.indeterminate(2, why)
        self.out.passed(2, self.answer.describe())

    def dnssec(self):
        # Bogus data is treated as absent, always. Unsigned data is too, unless
        # the profile permits unvalidated emblems. A signed proof that the name
        # is empty is how an online validator learns of removal (draft #lifecycle).
        chain = self.chain = dnssec.verify(
            self.answer, self.task.trust_anchor, self.now
        )
        permitted = self.task.profile and self.task.profile.allows_unsigned
        if chain.absent:
            text = "no emblem: the zone proves that nothing is published at this name"
            return self.out.invalid(3, text)
        if chain.status == "bogus" or (chain.status == "unsigned" and not permitted):
            return self.out.invalid(3, f"no validated emblem: {chain.reason}")
        self.out.rrset = chain.rrset
        if chain.secure:
            self.out.passed(3, chain.describe())
        else:
            self.out.passed(
                3, f"not validated, which the profile allows: {chain.reason}"
            )

    def types(self):
        # Use the record for our profile, skip the others (draft #multi-profile),
        # and check every value against its type.
        task = self.task
        try:
            records = [emblem.from_cbor(rdata.data) for rdata in self.chain.rrset]
        except ValueError as error:
            return self.out.invalid(4, f"the emblem cannot be read: {error}")
        record = emblem.select(records, task.profile) if task.profile else records[0]
        if record is None:
            text = (
                f"none of the {len(records)} records is for profile {task.profile.name}"
            )
            return self.out.invalid(4, text)
        self.record = record
        self.task = task = replace(
            task, profile=task.profile or load(record["profile"])
        )
        self.out.profile, self.out.record = task.profile.name, record
        problems = task.profile.check_types(record)
        if problems:
            return self.out.invalid(4, "; ".join(problems))
        self.out.passed(4, task.profile.describe_types(record))

    def asset(self):
        # The emblem must name this asset, and its cross-check identifiers
        # (a seal number, a serial) must match what we see.
        mismatch = self.task.profile.compare_asset(self.record, self.task.evidence)
        if mismatch:
            return self.out.invalid(5, mismatch)
        self.out.passed(5, self.task.profile.describe_asset(self.record))

    def validity(self):
        # The emblem's own validity period (draft #lifecycle).
        problem, description = times.validity_problem(self.record, self.now)
        if problem:
            return self.out.invalid(6, problem)
        self.out.passed(6, description)

    def authorization(self):
        # Where the profile requires issuer authorization, an endorsement from an
        # authority we recognize, queried or stapled, whose scope covers the emblem.
        task = self.task
        self.accepted = endorsement.Verdict(
            "accepted", f"profile {task.profile.name} asks for no endorsement"
        )
        if task.profile.requires_endorsement:
            args = (task, self.record, self.chain, self.source, self.now)
            self.accepted = endorsement.check(*args)
            if self.accepted.result != "accepted":
                return self.out.ended(self.accepted.result, 7, self.accepted.text)
        self.out.authority = self.accepted.authority
        self.out.passed(7, self.accepted.text)

    def references(self):
        # References, as far as the task goes; and the optional facets, the visual
        # mark and a live one, which never change the result.
        task, record = self.task, self.record
        refs = references.follow(record, task, self.source, self.now, validate)
        if refs.result != "ok":
            return self.out.ended(refs.result, 8, refs.text, refs.details)
        if "mark" in record:
            args = (record, self.source, task, self.accepted.endorsement, self.now)
            self.mark = marks.assess(*args)
        live = facets.live(task, self.source, self.now)
        text = "; ".join(
            p for p in (refs.text, self.mark.text if self.mark else "") if p
        )
        details = refs.details + ((live,) if live else ())
        self.out.passed(8, text or "the emblem refers to no other emblem", details)

    def decryption(self):
        # Values we hold a key for are read; values the task needs and we cannot
        # read leave the result indeterminate, not invalid (draft #validation).
        reading = confidential.read(self.record, self.task)
        if reading.result != "ok":
            return self.out.ended(reading.result, 9, reading.text)
        self.out.opened = reading.opened
        self.out.passed(9, reading.text)

    def result(self):
        # What the emblem asks is for the validator's framework to act on, not for
        # this protocol.
        path = self.chain.path
        zone = path[-1].to_text(omit_final_dot=True) if path else ""
        where = (
            f"published in {zone}"
            if path
            else "not validated by DNSSEC, which the profile allows"
        )
        by = (
            f", authorized by {self.accepted.authority},"
            if self.accepted.authority
            else ""
        )
        current = " and current" if "valid" in self.record else ""
        sentences = [
            f"VALID: {where}{by}{current}.",
            treatment.asks(self.record),
            self.mark.note if self.mark else "",
        ]
        self.out.valid(10, " ".join(s for s in sentences if s))
        return True
