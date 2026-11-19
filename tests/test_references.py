"""Step 8: references between emblems, and the facets that never decide.   # draft: #hierarchy, #facets"""

import dataclasses

import dns.rrset
import pytest

from diem import names, references, validator, zones
from diem.hierarchy import Hierarchy
from diem.sources import InMemoryDNS
from examples import pallet, pallet_world as pallets
from examples.build import emblems


@pytest.fixture(scope="module")
def world():
    return zones.build(pallets.hierarchy(pallets.consignment()), pallets.NOW)


def run(task, world, down=()):
    return validator.validate(task, InMemoryDNS(world, down=down), pallets.NOW)


def test_a_reference_with_a_diem_label_is_absolute_and_any_other_is_relative():
    here = "sn-1._diem.maker.example"
    assert names.absolute("pro.x1.models", here) == "pro.x1.models._diem.maker.example"
    other = "p-1._diem.pallets.example"
    assert names.absolute(other, here) == other


def test_a_digest_does_not_depend_on_the_order_of_the_records_or_their_ttl():
    def txt(ttl, *texts):
        return dns.rrset.from_text_list("a.example.", ttl, "IN", "TXT", texts)

    assert references.rrset_digest(txt(300, '"x"', '"y"')) == references.rrset_digest(
        txt(60, '"y"', '"x"')
    )
    assert references.rrset_digest(txt(300, '"x"')) != references.rrset_digest(
        txt(300, '"z"')
    )


def test_customs_follows_each_content_to_its_own_zone_and_checks_its_digest(world):
    outcome = run(pallet.customs_task(world), world)
    assert outcome.result == "valid"
    details = outcome.steps[7].details
    assert "followed 4 references" in outcome.steps[7].text
    assert sum("its digest matches" in line for line in details) == 4
    assert any("ispm15, endorsed by nppo.vn.example" in line for line in details)
    assert sum(line.startswith("  ") and "x1.models" in line for line in details) == 3


def test_a_referenced_emblem_that_changed_since_it_was_pinned_is_invalid_at_step_8(
    world,
):
    pro = {**pallets.records.VARIANT, "model": "X1 Pro, corrected"}
    specs = [
        (
            dataclasses.replace(
                spec,
                records=emblems(
                    pallets.records.FAMILY,
                    pallets.variants()[0],
                    pro,
                    pallets.variants()[2],
                    pallets.records.ITEM,
                ),
            )
            if spec.name.to_text() == "_diem.maker.example."
            else spec
        )
        for spec in pallets.hierarchy(pallets.consignment()).specs
    ]
    changed = zones.build(Hierarchy(specs), pallets.NOW)
    outcome = run(pallet.customs_task(changed), changed)
    assert (outcome.result, outcome.ended_at) == ("invalid", 8)
    assert "differs from the digest" in outcome.steps[-1].text


def test_a_live_position_that_times_out_does_not_change_the_result(world):
    outcome = run(pallet.customs_task(world), world, down=[pallets.LIVE_SERVER])
    assert outcome.result == "valid"
    assert "optional, so nothing changes" in outcome.steps[7].details[-1]


def test_the_live_position_is_signed_for_minutes_only(world):
    task = pallet.customs_task(world)
    late = validator.validate(task, InMemoryDNS(world), pallets.NOW + 600)
    assert late.steps[7].details[-1].startswith("no live position is used")
    assert "expired" in late.steps[7].details[-1]


def test_a_device_is_followed_through_its_variant_to_its_family(world):
    task = pallet.device_task(world, pallets.ITEM_NAME, "35791A7C")
    outcome = run(task, world)
    assert outcome.result == "valid"
    assert outcome.steps[7].details == (
        "pro.x1.models._diem.maker.example: valid (product-class)",
        "  x1.models._diem.maker.example: valid (product-class)",
    )


def test_a_serial_the_maker_never_issued_is_proved_absent_at_step_3(world):
    task = pallet.device_task(world, "sn-0badf00d._diem.maker.example", "0BADF00D")
    outcome = run(task, world)
    assert (outcome.result, outcome.ended_at) == ("invalid", 3)
    assert "nothing is published" in outcome.steps[-1].text


def test_a_serial_that_differs_from_the_label_is_invalid_at_step_5(world):
    outcome = run(pallet.device_task(world, pallets.ITEM_NAME, "35791A7D"), world)
    assert (outcome.result, outcome.ended_at) == ("invalid", 5)


def test_a_reference_back_to_an_emblem_being_validated_is_invalid(world):
    record = {"class-ref": "x1.models"}
    task = pallet.device_task(world, "x1.models._diem.maker.example", "")
    found = references.follow(record, task, None, 0, None)
    assert found.result == "invalid" and "refers back" in found.text


def test_the_customs_arithmetic_uses_exact_decimals(world):
    record = pallets.consignment()
    outcome = run(pallet.customs_task(world), world)
    sentences = pallet.customs_arithmetic(
        outcome.opened["valuation"], record["contents"]
    )
    assert sentences[0].startswith("the lines add up to 577,500 USD")
    assert sentences[1].startswith("the quantities match")
    assert "price paid, 577,500 USD" in sentences[2] and "(4,355 USD)" in sentences[2]
