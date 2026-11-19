"""Step 4 of the validation outline: values are checked against their types.   # draft: #validation, #data-model"""

import pytest

from diem import profile
from diem.values import UNKNOWN, Dec, Text, quantity, validity
from examples.records import logistics, pouch


def problems(record, profile_name, plaintext=None):
    return profile.load(profile_name).check_types(record, plaintext)


def test_a_lowercase_country_code_is_rejected():
    assert problems({**logistics.PALLET, "country": "vn"}, "ispm15") == [
        "country is not a valid country-code"
    ]


def test_a_value_outside_an_enumeration_is_rejected():
    assert problems({**logistics.PALLET, "measure": "XX"}, "ispm15") == [
        'measure is not one of "HT", "MB", "DH", "SF"'
    ]


def test_a_missing_required_key_is_reported():
    record = {key: value for key, value in pouch.EMBLEM.items() if key != "seal"}
    assert problems(record, "diplomatic-pouch") == ["seal is missing"]


def test_a_validity_period_that_ends_before_it_starts_is_rejected():
    record = {**pouch.EMBLEM, "valid": validity(1794355200, 1793750400)}
    assert problems(record, "diplomatic-pouch") == ["valid is not a valid validity"]


def test_a_nested_value_is_located():
    transport = {**logistics.CONSIGNMENT["transport"], "port-of-lading": "vnsgn"}
    record = {**logistics.CONSIGNMENT, "transport": transport}
    assert problems(record, "consignment") == [
        "transport.port-of-lading is not a valid unlocode"
    ]


def test_an_amount_must_be_an_exact_decimal_where_money_is_meant():
    plaintext = {**logistics.VALUATION, "total": [300, "USD"]}
    assert problems(plaintext, "consignment", "valuation") == [
        "total is not a valid money"
    ]


def test_a_count_is_a_quantity_too():
    assert (
        problems(
            {**pouch.EMBLEM, "gross-mass": quantity(18, "KGM")}, "diplomatic-pouch"
        )
        == []
    )


def test_a_value_unknown_to_the_issuer_is_allowed_for_any_key():
    assert problems({**pouch.EMBLEM, "seal": UNKNOWN}, "diplomatic-pouch") == []


def test_unknown_keys_are_skipped():
    assert problems({**pouch.EMBLEM, 99: "something newer"}, "diplomatic-pouch") == []


def test_a_critical_key_that_is_not_understood_is_reported():
    record = {**pouch.EMBLEM, "crit": [99]}
    assert problems(record, "diplomatic-pouch") == [
        "critical map key 99 is not understood by profile diplomatic-pouch"
    ]


def test_a_record_for_another_profile_is_rejected():
    assert (
        problems(logistics.PALLET, "consignment")[0] == 'profile is not "consignment"'
    )


def test_decimal_mantissas_are_canonical():
    assert Dec.parse("380") == Dec(1, 38)
    assert Dec.parse("19.3") == Dec(-1, 193)
    assert Dec.parse("0.0") == Dec(0, 0)
    with pytest.raises(ValueError):
        Dec(0, 380)


def test_decimals_compare_exactly():
    total = sum(
        Dec.parse(price).to_decimal() * count
        for price, count in (("380", 600), ("420", 500), ("465", 300))
    )
    assert total == Dec.parse("577500").to_decimal()


def test_text_carries_its_language():
    assert Text("en", "Example").wire().value == ["en", "Example"]
