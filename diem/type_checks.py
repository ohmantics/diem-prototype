"""Step 4 of the validation outline: does each value have its type?   # draft: #validation

The types are the profiles' CDDL (diem/cddl.py reads it), applied to records
as this code holds them: text names for map keys, and the classes of
diem.values for tagged values. A tag in the CDDL is therefore checked by
asking the value which CBOR tag it is written with.

Following the draft, unknown map keys in a record are skipped, but maps
nested inside it must match exactly. A reader of the record sees the
problems as sentences, each saying where in the record it is.
"""

import json
import re

from diem import cbor, cddl, values
from diem.registry import PROFILES_DIR

_PRELUDE = {
    "uint": lambda value: type(value) is int and value >= 0,
    "int": lambda value: type(value) is int,
    "tstr": lambda value: isinstance(value, str),
    "bstr": lambda value: isinstance(value, bytes),
    "bool": lambda value: isinstance(value, bool),
    "any": lambda value: True,
}


def _at(where):
    return where or "the record"


class Schema:
    """Checks values against rules.

    extra holds, by rule name, the conditions CDDL cannot state (that a
    validity period does not end before it starts); each is applied to a
    value that already has the right shape.
    """

    def __init__(self, rules, extra=None):
        self.rules, self.extra = rules, extra or {}

    def problems(self, value, rule, where=""):
        """Everything wrong with value as a `rule`, as sentences; none if it conforms."""
        return self._check(value, self.rules[rule], where, closed=False)

    def keys(self, rule):
        """The names of the keys a map rule lists."""
        return {
            key[1] for _, key, _ in self.rules[rule][1] if key and key[0] == "literal"
        }

    def _check(self, value, node, where, closed=True):
        kind = node[0]
        if kind == "name":
            return self._named(value, node[1], where)
        if kind == "map":
            return self._map(value, node[1], where, closed)
        if kind == "array":
            return self._array(value, node[1], where)
        if kind == "tag":
            return self._tag(value, node[1], node[2], where)
        if kind == "choice":
            return self._choice(value, node[1], where)
        if kind == "literal":
            return (
                []
                if value == node[1]
                else [f"{_at(where)} is not {json.dumps(node[1])}"]
            )
        if kind == "regexp":
            fits = isinstance(value, str) and re.fullmatch(node[1], value)
            return [] if fits else [f"{_at(where)} is not in the form {node[1]}"]
        fits = isinstance(value, bytes) and node[1] <= len(value) <= node[2]
        return [] if fits else [f"{_at(where)} has the wrong length"]

    def _named(self, value, name, where):
        body = self.rules.get(name)
        if body is not None and body[0] == "map":
            # descend, to say which member is wrong
            return self._check(value, body, where)
        if body is None:
            fits = _PRELUDE[name](value)
        else:
            fits = not self._check(value, body, where) and self.extra.get(
                name, lambda value: True
            )(value)
        return [] if fits else [f"{_at(where)} is not a valid {name}"]

    def _choice(self, value, alternatives, where):
        if any(
            not self._check(value, alternative, where) for alternative in alternatives
        ):
            return []
        if all(alternative[0] == "literal" for alternative in alternatives):
            return [
                f"{_at(where)} is not one of "
                + ", ".join(json.dumps(a[1]) for a in alternatives)
            ]
        return [f"{_at(where)} is none of the allowed types"]

    def _tag(self, value, number, content, where):
        wire = value.wire() if isinstance(value, values.Value) else None
        if not isinstance(wire, cbor.Tag) or wire.tag != number:
            return [f"{_at(where)} is not a value written with CBOR tag {number}"]
        return self._check(wire.value, content, where)

    def _map(self, value, members, where, closed):
        if not isinstance(value, dict):
            return [f"{_at(where)} is not a map"]
        problems, listed = [], set()
        for occurrence, key, expected in members:
            if key is not None and key[0] == "literal":
                listed.add(key[1])
                problems += self._member(value, key[1], occurrence, expected, where)
        for _, key, expected in members:
            if key is not None and key[0] != "literal":
                for other in set(value) - listed:
                    if not self._check(other, key, where):
                        listed.add(other)
                        problems += self._check(
                            value[other], expected, f"{where}.{other}"
                        )
        extras = [key for key in value if key not in listed]
        if closed and extras:
            problems.append(f"{_at(where)} has a key it does not allow: {extras[0]!r}")
        return problems

    def _member(self, record, name, occurrence, expected, where):
        path = f"{where}.{name}" if where else name
        if name not in record:
            return [] if occurrence == "?" else [f"{path} is missing"]
        # "exists, but the issuer does not know it" suits any key
        if record[name] is values.UNKNOWN:
            return []
        return self._check(record[name], expected, path)

    def _array(self, value, members, where):
        if not isinstance(value, list):
            return [f"{_at(where)} is not an array"]
        if len(members) == 1 and members[0][0] in ("+", "*"):
            if members[0][0] == "+" and not value:
                return [f"{_at(where)} needs at least one entry"]
            expected = [members[0][2]] * len(value)
        elif len(members) == len(value):
            expected = [member[2] for member in members]
        else:
            return [f"{_at(where)} should have {len(members)} entries"]
        return [
            problem
            for position, (item, node) in enumerate(zip(value, expected))
            for problem in self._check(item, node, f"{where}[{position}]")
        ]


def _validity_is_ordered(value):
    return value[0] <= value[1]


SCHEMA = Schema(cddl.read_rules(PROFILES_DIR), extra={"validity": _validity_is_ordered})
