"""Every example record in the draft builds, type-checks and prints as the draft shows it.   # draft: #examples"""

import pytest

from diem import edn, profile
from examples.records import ALL
from tests import draft_text

pytestmark = pytest.mark.parametrize("example", ALL, ids=lambda example: example.owner)


def test_example_has_the_types_its_profile_gives_it(example):
    checker = profile.load(example.profile_name)
    assert checker.check_types(example.record, example.plaintext or None) == []


def test_example_prints(example):
    text = edn.render(example.record, key_spaces=example.key_spaces)
    numbers = edn.render(example.record, integers=True, key_spaces=example.key_spaces)
    for shown in (text, numbers):
        assert shown.startswith("{") and shown.rstrip().endswith("}")
    # the text form names each key of the record
    assert all(key in text for key in example.record if isinstance(key, str))


@pytest.mark.skipif(
    not draft_text.available(),
    reason="the draft is not next to this repository (set DIEM_DRAFT to its path)",
)
def test_example_prints_as_in_the_draft(example):
    in_draft = [
        shown
        for block in draft_text.blocks(
            "# Example Use Cases {#examples}", "# Open Issues"
        )
        for shown in draft_text.maps(block)
    ]
    assert len(in_draft) == len(ALL)
    printed = draft_text.squeeze(
        edn.render(example.record, key_spaces=example.key_spaces)
    )
    assert printed == in_draft[ALL.index(example)]
