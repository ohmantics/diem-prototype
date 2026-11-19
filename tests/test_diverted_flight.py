"""A flight diverted to a state nobody encrypted for: each check lands where the example says.   # draft: #open-issues"""

import pytest

from diem import zones
from diem.sources import BundleSource, InMemoryDNS
from diem.validator import validate
from examples import diverted_flight as flight, diverted_world as world_of
from examples.diverted_world import (
    CITES,
    DATASET,
    DRIVE,
    MEDICAL,
    NOW,
    PERMIT,
    POUCH,
    SERIAL,
)


@pytest.fixture(scope="module")
def world():
    return zones.build(world_of.hierarchy(), NOW)


@pytest.fixture(scope="module")
def carried(world):
    source = InMemoryDNS(world)
    found = {
        name: flight.bundle(source, name) for name in (MEDICAL, CITES, POUCH, DATASET)
    }
    found[DRIVE] = flight.bundle(source, DRIVE, DATASET)
    return found


def offline(world, carried, name, profile, evidence=None, **more):
    task = flight.task(world, name, profile, evidence, **more)
    return validate(task, BundleSource(carried[name]), NOW)


def ends(outcome):
    return outcome.result, outcome.ended_at


def test_every_package_validates_offline_in_the_diverted_state(world, carried):
    for name, profile, evidence in (
        (MEDICAL, "dg-package", None),
        (CITES, "cites-permit", {"permit-number": PERMIT}),
        (POUCH, "diplomatic-pouch", flight.SEEN_POUCH),
        (DRIVE, "storage-device", {"serial": SERIAL}),
        (DRIVE, "dg-package", None),
        (DATASET, "dataset", None),
    ):
        assert offline(world, carried, name, profile, evidence).result == "valid", name


def test_the_pouch_treatments_and_seal_are_readable_and_the_seal_is_checked(
    world, carried
):
    outcome = offline(world, carried, POUCH, "diplomatic-pouch", flight.SEEN_POUCH)
    assert "do not open, do not detain" in outcome.steps[-1].text
    wrong = {**flight.SEEN_POUCH, "seal": "XC-2026-114358"}
    assert ends(offline(world, carried, POUCH, "diplomatic-pouch", wrong)) == (
        "invalid",
        5,
    )


def test_a_permit_number_that_differs_from_the_one_printed_is_invalid_at_step_5(
    world, carried
):
    outcome = offline(
        world, carried, CITES, "cites-permit", {"permit-number": "XA-CITES-2026-0234"}
    )
    assert ends(outcome) == ("invalid", 5)


def test_what_was_encrypted_for_the_planned_state_stays_closed_where_the_task_needs_it(
    world, carried
):
    for name, profile, key in (
        (MEDICAL, "dg-package", "valuation"),
        (DATASET, "dataset", "details"),
        (POUCH, "diplomatic-pouch", "courier"),
    ):
        evidence = flight.SEEN_POUCH if name == POUCH else None
        outcome = offline(world, carried, name, profile, evidence, needs=(key,))
        assert ends(outcome) == ("indeterminate", 9), key


def test_the_drive_has_a_record_for_each_profile_and_each_validator_uses_its_own(
    world, carried
):
    assert (
        "2 EMBLEM records" in offline(world, carried, DRIVE, "dg-package").steps[1].text
    )
    assert (
        "profile dg-package"
        in offline(world, carried, DRIVE, "dg-package").steps[3].text
    )
    assert (
        "profile storage-device"
        in offline(world, carried, DRIVE, "storage-device", {"serial": SERIAL})
        .steps[3]
        .text
    )


def test_the_drive_refers_to_the_dataset_which_asks_that_it_not_be_read(world, carried):
    outcome = offline(
        world, carried, DRIVE, "storage-device", {"serial": SERIAL}, follow=("dataset",)
    )
    assert outcome.steps[7].details == (f"{DATASET}: valid (dataset)",)
    dataset = offline(world, carried, DATASET, "dataset")
    assert "do not read" in dataset.steps[-1].text


def test_a_reference_cannot_be_followed_from_a_bundle_that_lacks_the_dataset(
    world, carried
):
    lacking = {**carried, DRIVE: flight.bundle(InMemoryDNS(world), DRIVE)}
    outcome = offline(
        world, lacking, DRIVE, "storage-device", {"serial": SERIAL}, follow=("dataset",)
    )
    assert ends(outcome) == ("indeterminate", 8)


def test_online_the_live_position_is_there_and_offline_it_is_only_optional(
    world, carried
):
    live = validate(flight.task(world, MEDICAL, "dg-package"), InMemoryDNS(world), NOW)
    assert live.steps[7].details[-1].startswith("live position")
    assert (
        "optional"
        in offline(world, carried, MEDICAL, "dg-package").steps[7].details[-1]
    )


def test_online_a_withdrawn_permit_is_proved_absent_while_the_carried_bundle_still_validates(
    carried,
):
    withdrawn = zones.build(world_of.hierarchy(withdrawn=True), NOW)
    task = flight.task(withdrawn, CITES, "cites-permit", {"permit-number": PERMIT})
    assert ends(validate(task, InMemoryDNS(withdrawn), NOW)) == ("invalid", 3)
    assert validate(task, BundleSource(carried[CITES]), NOW).result == "valid"
