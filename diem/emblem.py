"""An emblem as a dictionary of text names, and its CBOR.   # draft: #data-model, #strawman

In memory an emblem is a dict whose keys are the names the draft uses
("profile", "asset", "valid", ...). On the wire the names become the
integers of profiles/keys.toml and the map is encoded deterministically
(diem/cbor.py). The same record can also be encoded with its names left
as text, which is the form the CDDL in profiles/ describes.

A key that is not registered may still be used if it contains a dot: it
names a key of the issuer's own, under a domain the issuer controls, and
travels as text.
"""

from diem import cbor, registry, values
from diem.registry import Slot


def _enum_value(kind, name, text_names):
    """The integer for an enumerated value, or the name itself with text names."""
    if text_names:
        return name
    number = registry.enum_number(kind, name)
    if number is None:
        raise ValueError(f"{name!r} is not a {kind}")
    return number


def _key(name, slot, text_names):
    """A map key as it goes on the wire: an integer, or text for an issuer's own key."""
    number = None if text_names else registry.key_number(slot.key_spaces, name)
    if number is not None:
        return number
    if text_names or "." in name:
        return name
    raise KeyError(f"{name!r} is not a registered map key here")


def _wire_map(mapping, slot, text_names):
    """A map with keys and enumerated values replaced as the slot says (registry.Slot)."""
    if slot.enum_map:
        modality, action = slot.enum_map
        return {
            _enum_value(modality, key, text_names): _wire(
                value, Slot(enum=action), text_names
            )
            for key, value in mapping.items()
        }
    return {
        _key(key, slot, text_names): _wire(
            value, registry.slot_for_key(key), text_names
        )
        for key, value in mapping.items()
    }


def _wire(value, slot, text_names):
    """A value as plain CBOR-ready data: dictionaries, lists, scalars and tags."""
    if isinstance(value, values.Value):
        return value.wire()
    if isinstance(value, dict):
        return _wire_map(value, slot, text_names)
    if isinstance(value, (list, tuple)):
        return [_wire(item, slot, text_names) for item in value]
    if isinstance(value, str) and slot.enum:
        return _enum_value(slot.enum, value, text_names)
    return value


def key_spaces_of(record):
    """Where an emblem's key names are registered: its profile, then the common keys."""
    return (record["profile"], "common")


def to_cbor(record, key_spaces=None, text_names=False):
    """The deterministic CBOR for a record.

    key_spaces says where the names are registered; it defaults to the
    record's profile and the common keys. Pass another (the plaintext of an
    encrypted value, say) to encode a map that is not an emblem.
    """
    slot = Slot(key_spaces or key_spaces_of(record))
    return cbor.encode(_wire_map(record, slot, text_names))


def _named(item, slot):
    """The reverse of _wire: tags become values, integers become names as the slot says."""
    item = values.from_wire(item)
    if isinstance(item, dict):
        return _named_map(item, slot)
    if isinstance(item, list):
        return [_named(element, slot) for element in item]
    if isinstance(item, int) and not isinstance(item, bool) and slot.enum:
        name = registry.enum_name(slot.enum, item)
        return item if name is None else name
    return item


def _named_map(mapping, slot):
    """The reverse of _wire_map."""
    if slot.enum_map:
        modality, action = slot.enum_map
        return {
            registry.enum_name(modality, key) or key: _named(value, Slot(enum=action))
            for key, value in mapping.items()
        }
    result = {}
    for key, value in mapping.items():
        name = registry.key_name(slot.key_spaces, key) if isinstance(key, int) else None
        # A number nobody here has registered stays a number; checking
        # (profile.py) decides whether that matters.
        result[name or key] = _named(
            value, registry.slot_for_key(name) if name else Slot()
        )
    return result


def from_cbor(data, key_spaces=None):
    """The record for deterministic CBOR; the profile is read from the map itself."""
    wire = cbor.decode(data)
    if not isinstance(wire, dict):
        raise ValueError("an emblem is a map")
    if key_spaces is None:
        profile_number = registry.key_number(("common",), "profile")
        profile = registry.enum_name("profile-id", wire.get(profile_number))
        if profile is None:
            raise ValueError("the emblem does not name a profile this code knows")
        key_spaces = (profile, "common")
    return _named_map(wire, Slot(key_spaces))


def select(records, profile):
    """The record for the profile we understand; others are skipped (#multi-profile)."""
    for record in records:
        if record.get("profile") == profile.name:
            return record
    return None
