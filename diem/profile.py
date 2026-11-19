"""A profile: its types, and how its emblems name their asset.   # draft: #profiles

Profiles differ in data, never in code. A profile is a CDDL file, which is
the published schema, and a policy file, profiles/policy/<name>.toml, which
holds what the schema cannot say: how the profile's emblems are checked against the asset
in front of the validator, whether they need an endorsement, and whether unsigned emblems
may be used. The CDDL rule for a profile's emblem is
named <profile>-emblem, and for the plaintext of one of its encrypted values
<name>-plaintext.
"""

import tomllib
from dataclasses import dataclass

from diem import names
from diem.values import show
from diem.registry import PROFILES_DIR
from diem.type_checks import SCHEMA


@dataclass(frozen=True)
class Profile:
    name: str
    cross_check: tuple  # map keys that identify the asset otherwise (a seal, a serial)
    endorsement: dict  # whether and how the profile asks for issuer authorization
    allows_unsigned: bool  # may an emblem that DNSSEC cannot validate be used?
    # "none", or "after-first-label" to derive an emblem name from a service
    naming: str
    digests: str  # whether references carry a digest: "none", "optional" or "required"
    # encrypted values published with a salted digest of their plaintext
    digested: tuple
    facets: dict  # the facets the profile publishes apart from the emblem, by kind
    # "emblem-zone" if the issuer says what to do when an emblem is invalid
    if_invalid_at: str

    @property
    def requires_endorsement(self):
        return self.endorsement["required"]

    def derive_emblem_name(self, asset):
        """The emblem name for a service name, if the profile derives one: records.example.org
        becomes records._diem.example.org."""
        if self.naming != "after-first-label":
            return None
        label, _, rest = asset.partition(".")
        return f"{label}._diem.{rest}"

    def issuer_of(self, emblem_name):
        """The issuer an endorsement is about: the name above the _diem label."""
        marker = self.endorsement["issuer-above"]
        return f".{emblem_name}".partition(f".{marker}.")[2]

    def check_types(self, record, plaintext=None):
        """Everything wrong with the values in a record; an empty list means all is well.

        plaintext names one of the profile's encrypted values, for checking
        what a recipient reads rather than an emblem.
        """
        if plaintext:
            return SCHEMA.problems(record, f"{plaintext}-plaintext")
        return SCHEMA.problems(record, self.rule) + self._ununderstood_critical_keys(
            record
        )

    @property
    def rule(self):
        return f"{self.name}-emblem"

    def _ununderstood_critical_keys(self, record):
        # A critical key must be understood; others are skipped (draft #data-model).
        understood = SCHEMA.keys(self.rule) | {"crit"}
        return [
            f"critical map key {key!r} is not understood by profile {self.name}"
            for key in record.get("crit", [])
            if key not in understood
        ]

    def describe_types(self, record):
        count = sum(1 for key in record if isinstance(key, str))
        return (
            f"profile {self.name} understood; all {count} map keys have the right types"
        )

    def compare_asset(self, record, evidence):
        """Why the emblem is not about the asset in front of us, or None if it is.

        evidence maps "asset" to the name we were given, and cross-check
        identifiers to what we can see. Only the identifiers present in the
        evidence are compared.
        """
        seen = evidence.get("asset")
        if seen is not None and names.normalize(seen) != names.normalize(
            record["asset"]
        ):
            return f"the emblem is for {record['asset']}, not {seen}"
        for key in self.cross_check:
            if key in evidence and evidence[key] != record.get(key):
                emblem_says, we_see = show(record.get(key)), show(evidence[key])
                return f"{key}: the emblem says {emblem_says}, what we see is {we_see}"
        return None

    def describe_asset(self, record):
        checked = [key for key in self.cross_check if key in record]
        extra = f"; cross-check identifiers: {', '.join(checked)}" if checked else ""
        return f"names {record['asset']}{extra}"


def load(name):
    policy = tomllib.loads((PROFILES_DIR / "policy" / f"{name}.toml").read_text())
    return Profile(
        name,
        tuple(policy["asset"]["cross-check"]),
        policy["endorsement"],
        policy.get("allows-unsigned", False),
        policy.get("naming", {}).get("derive", "none"),
        policy.get("references", {}).get("digests", "none"),
        tuple(policy.get("confidential", {}).get("digested", ())),
        policy.get("facets", {}),
        policy.get("if-invalid", {}).get("at", ""),
    )
