"""Names and numbers: the strawman's registries.   # draft: #strawman, #data-model

The draft keeps a registry of common map keys, a map key space for each
profile, and registries of enumerated values. Here they are one file,
profiles/keys.toml, and this module answers questions about it. Everything
else works with names; numbers appear only when encoding and decoding.
"""

import tomllib
from functools import cache
from pathlib import Path
from typing import NamedTuple

# The profiles are read from the repository, outside the package, so this code is
# meant to be run from a checkout or an editable install.
PROFILES_DIR = Path(__file__).resolve().parent.parent / "profiles"
KEYS_FILE = PROFILES_DIR / "keys.toml"


@cache
def _tables():
    return tomllib.loads(KEYS_FILE.read_text())


class Slot(NamedTuple):
    """What the encoding needs to know about the value found under a map key.

    key_spaces: where the names of a map's keys are looked up, in order
    enum:       the enumeration that string values come from
    enum_map:   (modality enumeration, action enumeration) for the maps of a
                treatment, {"prohibit": "attack"}: such a map's keys are
                themselves enumerated (a modality), and so are its values
                (an action), so neither is looked up as a map key
    """

    key_spaces: tuple = ()
    enum: str | None = None
    enum_map: tuple | None = None


def slot_for_key(key):
    tables = _tables()
    space = tables["maps-of"].get(key)
    pair = tables["enum-maps"].get(key)
    return Slot(
        (space,) if space else (),
        tables["values-of"].get(key),
        tuple(pair) if pair else None,
    )


def key_number(key_spaces, name):
    for space in key_spaces:
        number = _tables()["keys"].get(space, {}).get(name)
        if number is not None:
            return number
    return None


def key_name(key_spaces, number):
    for space in key_spaces:
        for name, candidate in _tables()["keys"].get(space, {}).items():
            if candidate == number:
                return name
    return None


def has_enum(kind):
    return kind in _tables()["enums"]


def enum_number(kind, name):
    return _tables()["enums"][kind].get(name)


def enum_name(kind, number):
    for name, candidate in _tables()["enums"][kind].items():
        if candidate == number:
            return name
    return None
