"""Value types.   # draft: #data-model (Value Types), #treatment, #code-lists

Plain values (text, integers, booleans, byte strings, lists, dictionaries)
stand for themselves. The types below need more: an exact decimal, a
timestamp, language-tagged text, a URI, an encrypted value, and the marker
for "exists but unknown to the issuer". Each knows how to put itself on the
wire (the CBOR tag the strawman gives it) and how to be read back.

The predicates that say whether a value has a given type are in
diem/type_checks.py.
"""

from dataclasses import dataclass
from decimal import Decimal

from diem import cbor


class Value:
    def wire(self):
        raise NotImplementedError


@dataclass(frozen=True)
class Dec(Value):
    """An exact decimal, mantissa x 10^exponent (CBOR tag 4).

    The mantissa has no trailing zeros, so that equal numbers have equal
    encodings: 380 is 38 x 10^1, never 380 x 10^0.
    """

    exponent: int
    mantissa: int

    def __post_init__(self):
        if self.mantissa % 10 == 0 and (self.mantissa != 0 or self.exponent != 0):
            raise ValueError("a decimal mantissa must not have trailing zeros")

    @classmethod
    def parse(cls, text):
        sign, digits, exponent = Decimal(text).normalize().as_tuple()
        mantissa = int("".join(map(str, digits)))
        return cls(exponent, -mantissa if sign else mantissa)

    def to_decimal(self):
        return Decimal(self.mantissa).scaleb(self.exponent)

    def wire(self):
        return cbor.Tag(4, [self.exponent, self.mantissa])


@dataclass(frozen=True, order=True)
class Timestamp(Value):
    """Whole seconds since the epoch (CBOR tag 1)."""

    seconds: int

    def wire(self):
        return cbor.Tag(1, self.seconds)


@dataclass(frozen=True)
class Text(Value):
    """Text meant for people, with its language tag (CBOR tag 38)."""

    language: str
    text: str

    def wire(self):
        return cbor.Tag(38, [self.language, self.text])


@dataclass(frozen=True)
class Uri(Value):
    """A reference to another resource (CBOR tag 32)."""

    uri: str

    def wire(self):
        return cbor.Tag(32, self.uri)


@dataclass(frozen=True)
class Encrypted(Value):
    """A COSE_Encrypt0 (tag 16) or COSE_Encrypt (tag 96), kept as decoded."""

    tag: int
    cose: list

    def wire(self):
        return cbor.Tag(self.tag, self.cose)


class Unknown(Value):
    """The map key is present, but the issuer does not know the value."""

    def wire(self):
        return cbor.UNDEFINED

    def __repr__(self):
        return "UNKNOWN"


UNKNOWN = Unknown()

_FROM_TAG = {
    1: Timestamp,
    4: lambda content: Dec(*content),
    16: lambda content: Encrypted(16, content),
    32: Uri,
    38: lambda content: Text(*content),
    96: lambda content: Encrypted(96, content),
}


def from_wire(item):
    """The value for a decoded CBOR tag or simple value; anything else unchanged."""
    if item is cbor.UNDEFINED:
        return UNKNOWN
    if isinstance(item, cbor.Tag) and item.tag in _FROM_TAG:
        try:
            return _FROM_TAG[item.tag](item.value)
        except TypeError as error:
            raise ValueError(f"malformed CBOR tag {item.tag}") from error
    return item


def show(value):
    """A value as a person would write it: 18.4 KGM, not [Dec(-1, 184), 'KGM']."""
    if isinstance(value, list) and len(value) == 2 and isinstance(value[0], Dec):
        return f"{value[0].to_decimal():f} {value[1]}"
    return str(value)


# Constructors, so that records read like the draft's examples.


def quantity(amount, unit):
    """A count (an int) or an exact decimal (a string), with a UNECE unit code."""
    return [amount if isinstance(amount, int) else Dec.parse(amount), unit]


def money(amount, currency):
    return [Dec.parse(amount), currency]


def validity(not_before, not_after):
    return [Timestamp(not_before), Timestamp(not_after)]


def treatment(modality, action):
    return {modality: action}


def citation(scheme, identifier, text=None):
    entry = {"scheme": scheme, "id": identifier}
    if text is not None:
        entry["text"] = text
    return entry
