"""CBOR diagnostic notation for emblems.   # draft: #examples, #encoded

Two forms, as in the draft. The default shows text names for map keys and
enumerated values, which is how the draft's examples read. With
integers=True it shows what an encoding carries, the integer followed by its
name in a comment, as in the draft's Encoded Example.

Long values are elided the way the draft elides them (`...`), because a
person reading an emblem gains nothing from forty hex digits of digest.
"""

import json
from typing import NamedTuple

from diem import cbor, emblem, registry, values
from diem.registry import Slot

WIDTH = 72
LONG_BYTES = 8  # byte strings longer than this are shown as h'...'
LONG_URI = 40  # URIs longer than this are shown as scheme://host/...


class _Style(NamedTuple):
    integers: bool
    elide: bool


def render(record, integers=False, elide=True, key_spaces=None):
    slot = Slot(key_spaces or emblem.key_spaces_of(record))
    return _value(record, slot, 0, _Style(integers, elide))


def _group(opening, items, closing, indent):
    one_line = opening + ", ".join(items) + closing
    if "\n" not in one_line and len(one_line) + 2 * indent <= WIDTH:
        return one_line
    pad = "  " * (indent + 1)
    return (
        opening
        + "\n"
        + ",\n".join(pad + item for item in items)
        + "\n"
        + "  " * indent
        + closing
    )


def _value(value, slot, indent, style):
    if isinstance(value, values.Value):
        return _wire(value.wire(), indent, style)
    if isinstance(value, dict):
        return _map(value, slot, indent, style)
    if isinstance(value, (list, tuple)):
        return _group(
            "[", [_value(item, slot, indent + 1, style) for item in value], "]", indent
        )
    if isinstance(value, str) and slot.enum and style.integers:
        return _numbered(registry.enum_number(slot.enum, value), value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, bytes):
        return (
            "h'...'" if style.elide and len(value) > LONG_BYTES else f"h'{value.hex()}'"
        )
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _numbered(number, name):
    return f"{number} / {name} /"


def _wire(item, indent, style):
    if item is cbor.UNDEFINED:
        return "undefined"
    if style.elide and item.tag in (16, 96):
        return f"{item.tag}(...)"
    if style.elide and item.tag == 32 and len(item.value) > LONG_URI:
        scheme, _, rest = item.value.partition("://")
        return f'32("{scheme}://{rest.split("/")[0]}/...")'
    return f"{item.tag}({_value(item.value, Slot(), indent, style)})"


def _map(mapping, slot, indent, style):
    entries = [
        _entry(key, value, slot, indent, style) for key, value in mapping.items()
    ]
    if style.integers:
        entries.sort(key=lambda entry: cbor.encode(entry[0]))
    return _group("{", [text for _, text in entries], "}", indent)


def _entry(key, value, slot, indent, style):
    """The sort key (the number, else the name) and the text of one map entry."""
    if slot.enum_map:
        modality, action = slot.enum_map
        number = registry.enum_number(modality, key)
        child = Slot(enum=action)
    elif isinstance(key, str):
        number = registry.key_number(slot.key_spaces, key)
        child = registry.slot_for_key(key)
    else:
        number, child = key, Slot()
    if isinstance(key, int):
        label = str(key)
    elif style.integers and number is not None:
        label = _numbered(number, key)
    else:
        label = json.dumps(key)
    return (
        key if number is None else number
    ), f"{label}: {_value(value, child, indent + 1, style)}"
