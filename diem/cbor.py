"""Deterministic CBOR for EMBLEM RDATA.   # draft: #strawman

RDATA is one CBOR map in the core deterministic encoding of RFC 8949
section 4.2.1, plus the draft's canonical decimals (no trailing zeros in the
mantissa). cbor2 does the work, except that its canonical mode is not used:
it orders map keys by the older RFC 7049 rule (shorter encodings first, so -1
before 24) where RFC 8949 orders them by the bytes of their encodings (24
before -1). Tags are kept as tags, because cbor2 would turn tags 1 and 4 into
datetimes and Decimals and hide whether a mantissa was canonical.
"""

from collections.abc import Mapping

import cbor2

Tag = cbor2.CBORTag
UNDEFINED = cbor2.undefined


def _ordered(item):
    """A copy of item with every map's keys in bytewise order of their encodings."""
    if isinstance(item, dict):
        return {
            key: _ordered(value)
            for key, value in sorted(
                item.items(), key=lambda pair: cbor2.dumps(pair[0])
            )
        }
    if isinstance(item, (list, tuple)):
        return [_ordered(element) for element in item]
    if isinstance(item, Tag):
        return Tag(item.tag, _ordered(item.value))
    return item


def encode(item):
    return cbor2.dumps(_ordered(item))


def _plain(item):
    """cbor2 returns tuples and frozen maps in tags; the rest of us use lists and dicts."""
    if isinstance(item, Mapping):
        return {key: _plain(value) for key, value in item.items()}
    if isinstance(item, (list, tuple)):
        return [_plain(element) for element in item]
    if isinstance(item, Tag):
        return Tag(item.tag, _plain(item.value))
    return item


def _keep_tag(number):
    return lambda content, *_: Tag(number, content)


def _load(data):
    kept = {number: _keep_tag(number) for number in (1, 4, 32)}
    return _plain(
        cbor2.loads(
            data,
            semantic_decoders=kept,
            allow_indefinite=False,
            allow_duplicate_keys=False,
        )
    )


def _has_untidy_decimal(item):
    """Is there a decimal whose mantissa could be shorter (380 x 10^0 for 38 x 10^1)?"""
    if isinstance(item, Tag):
        if item.tag == 4:
            exponent, mantissa = item.value
            if mantissa % 10 == 0 and (exponent, mantissa) != (0, 0):
                return True
        return _has_untidy_decimal(item.value)
    if isinstance(item, dict):
        item = list(item.values())
    return isinstance(item, list) and any(
        _has_untidy_decimal(element) for element in item
    )


def problems(data):
    """Everything wrong with data as a deterministic encoding, as sentences."""
    try:
        item = _load(data)
        found = []
        if encode(item) != data:
            found.append("not in core deterministic form (RFC 8949 section 4.2.1)")
        if _has_untidy_decimal(item):
            found.append("a decimal mantissa has trailing zeros")
        return found
    except (cbor2.CBORError, ValueError, TypeError, EOFError) as error:
        return [f"not decodable: {error}"]


def decode(data):
    """Decode one item, rejecting anything that is not deterministic."""
    found = problems(data)
    if found:
        raise ValueError("; ".join(found))
    return _load(data)
