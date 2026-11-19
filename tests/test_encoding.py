"""The strawman encoding: the draft's Encoded Example, and the encoding rules.   # draft: #strawman, #encoded"""

import cbor2
import pytest

from diem import cbor, edn, emblem
from examples.records import ALL, logistics
from tests import draft_text

ENCODED_EXAMPLE = bytes.fromhex(
    "a50105027825702d3230323631303331"
    "2d303034322e5f6469656d2e70616c6c"
    "6574732e6578616d706c652062564e21"
    "6630303031323322624854"
)


def test_ispm15_record_is_the_drafts_encoded_example():
    data = emblem.to_cbor(logistics.PALLET)
    assert len(data) == 59
    assert data == ENCODED_EXAMPLE


def test_ispm15_record_prints_as_the_drafts_encoded_example():
    shown = edn.render(logistics.PALLET, integers=True)
    assert shown.splitlines()[1:3] == [
        "  1 / profile /: 5 / ispm15 /,",
        '  2 / asset /: "p-20261031-0042._diem.pallets.example",',
    ]
    assert '  -3 / measure /: "HT"' in shown


@pytest.mark.skipif(
    not draft_text.available(),
    reason="the draft is not next to this repository (set DIEM_DRAFT to its path)",
)
def test_integer_form_matches_the_drafts_diagnostic_notation():
    (block,) = draft_text.blocks("# Encoded Example {#encoded}", "# Changes from")
    assert draft_text.squeeze(
        edn.render(logistics.PALLET, integers=True)
    ) == draft_text.squeeze(block)


def test_encoded_example_decodes_to_the_record():
    assert emblem.from_cbor(ENCODED_EXAMPLE) == logistics.PALLET


@pytest.mark.parametrize("example", ALL, ids=lambda example: example.owner)
def test_every_example_is_deterministic_and_survives_a_round_trip(example):
    data = emblem.to_cbor(example.record, example.key_spaces)
    assert cbor.problems(data) == []
    assert emblem.from_cbor(data, example.key_spaces) == example.record


def test_cbor2_reads_what_we_write():
    expected = {
        1: 5,
        2: "p-20261031-0042._diem.pallets.example",
        -1: "VN",
        -2: "000123",
        -3: "HT",
    }
    assert cbor2.loads(emblem.to_cbor(logistics.PALLET)) == expected
    assert cbor2.dumps(expected, canonical=True) == ENCODED_EXAMPLE


@pytest.mark.parametrize("example", ALL, ids=lambda example: example.owner)
def test_cbor2_reads_every_example(example):
    data = emblem.to_cbor(example.record, example.key_spaces)
    assert len(cbor2.loads(data)) == len(example.record)


def test_map_keys_are_ordered_bytewise_not_by_length():
    # 24 encodes as 18 18 and -1 as 20, so core deterministic order puts 24 first.
    assert cbor.encode({-1: 0, 24: 0}) == bytes.fromhex("a21818002000")


def test_decimal_mantissa_without_trailing_zeros():
    assert cbor.problems(cbor.encode(cbor.Tag(4, [0, 380]))) == [
        "a decimal mantissa has trailing zeros"
    ]
    assert cbor.problems(cbor.encode(cbor.Tag(4, [1, 38]))) == []


def test_non_deterministic_encodings_are_reported():
    not_deterministic = ["not in core deterministic form (RFC 8949 section 4.2.1)"]
    assert cbor.problems(bytes.fromhex("1800")) == not_deterministic  # 0 in two octets
    assert (
        cbor.problems(bytes.fromhex("a202020101")) == not_deterministic
    )  # keys out of order
    assert cbor.problems(bytes.fromhex("9f01ff"))  # indefinite length
    assert cbor.problems(bytes.fromhex("a201010101"))  # repeated key


def test_issuer_defined_keys_travel_as_text():
    record = {**logistics.PALLET, "forensics.pallets.example": "batch 7"}
    assert emblem.from_cbor(emblem.to_cbor(record)) == record


def test_unregistered_keys_without_a_domain_are_refused():
    with pytest.raises(KeyError):
        emblem.to_cbor({**logistics.PALLET, "colour": "red"})
