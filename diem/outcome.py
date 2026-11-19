"""What a validation concludes.   # draft: #validation

The result is valid, invalid, or indeterminate. Indeterminate means that
something the profile requires for the validator's purpose could not be
obtained or read. A validator must not present it as invalid: a protected
site must not appear unprotected just because a query timed out.
"""

from typing import NamedTuple

STEP_NAMES = {
    1: "name",
    2: "retrieval",
    3: "DNSSEC",
    4: "types",
    5: "asset",
    6: "validity",
    7: "authorization",
    8: "references",
    9: "decryption",
    10: "result",
}


class Step(NamedTuple):
    number: int
    text: str
    details: tuple = ()  # lines under the step, such as one for each emblem followed


class Outcome:
    def __init__(self, task):
        self.task = task
        self.steps = []
        self.result = ""  # "valid", "invalid" or "indeterminate" once it has ended
        self.ended_at = 0  # the step that ended it
        self.profile = ""  # the profile of the emblem that was read
        self.record = None  # that emblem
        self.rrset = None  # the validated EMBLEM RRset, which a reference may pin
        self.authority = ""  # who authorized it, where the profile asks for that
        self.opened = {}  # the plaintext of each encrypted value that was read
        # sentences to print after the result, such as what an issuer asks when an emblem is invalid
        self.notes = []

    def passed(self, number, text, details=()):
        self.steps.append(Step(number, text, tuple(details)))
        return self

    def valid(self, number, text, details=()):
        return self.ended("valid", number, text, details)

    def invalid(self, number, text, details=()):
        return self.ended("invalid", number, text, details)

    def indeterminate(self, number, text, details=()):
        return self.ended("indeterminate", number, text, details)

    def ended(self, result, number, text, details=()):
        self.result, self.ended_at = result, number
        return self.passed(number, text, details)
