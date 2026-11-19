"""Step 9: encrypted values, bound to their emblem, readable only by their recipients.   # draft: #confidentiality, #validation"""

import pytest

from diem import confidential, profile, validator, zones
from diem.sources import InMemoryDNS
from examples import pallet, pallet_world as pallets, pouch
from examples import pouch_world as world_of


@pytest.fixture(scope="module")
def pouch_world():
    return zones.build(pouch.hierarchy(), pouch.NOW)


@pytest.fixture(scope="module")
def pallet_world():
    return zones.build(pallets.hierarchy(pallets.consignment()), pallets.NOW)


def customs(world, **more):
    task = pallet.customs_task(world, **more)
    return validator.validate(task, InMemoryDNS(world), pallets.NOW)


def test_the_receiving_state_reads_the_courier(pouch_world):
    outcome = validator.validate(
        pouch.task(pouch_world), InMemoryDNS(pouch_world), pouch.NOW
    )
    assert outcome.result == "valid"
    assert outcome.opened["courier"]["name"] == "A. Courier-Example"


def test_a_third_state_that_needs_the_courier_is_indeterminate_at_step_9(pouch_world):
    task = pouch.task(pouch_world, keys=())
    outcome = validator.validate(task, InMemoryDNS(pouch_world), pouch.NOW)
    assert (outcome.result, outcome.ended_at) == ("indeterminate", 9)


def test_a_ciphertext_moved_to_another_emblem_does_not_decrypt():
    record = pouch.record()
    moved = {**record, "asset": "other._pouch._diem.mfa.gov.example"}
    policy = profile.load("diplomatic-pouch")
    task = validator.Task(
        emblem_name="x",
        how_named="",
        profile=policy,
        evidence={},
        trust_anchor=[],
        keys=(pouch.RECEIVER,),
    )
    reading = confidential.read(moved, task)
    assert reading.result == "invalid" and "courier" in reading.text


def test_either_customs_authority_can_read_the_valuation(pallet_world):
    for who in (pallets.ORIGIN, pallets.DESTINATION):
        outcome = customs(pallet_world, keys=(who,))
        assert outcome.result == "valid"
        assert outcome.opened["valuation"]["invoice"] == "INV-2026-10-4471"


def test_a_reader_that_is_not_customs_needs_nothing_and_reads_nothing(pallet_world):
    outcome = customs(pallet_world, keys=(), needs=())
    assert (outcome.result, outcome.opened) == ("valid", {})
    assert "does not need to read them" in outcome.steps[8].text


def test_a_reader_that_needs_the_valuation_without_a_key_is_indeterminate(pallet_world):
    outcome = customs(pallet_world, keys=())
    assert (outcome.result, outcome.ended_at) == ("indeterminate", 9)


def test_a_valuation_that_is_not_the_one_digested_is_invalid_at_step_9():
    record = {**pallets.consignment(), "valuation-digest": bytes(32)}
    world = zones.build(pallets.hierarchy(record), pallets.NOW)
    outcome = customs(world)
    assert (outcome.result, outcome.ended_at) == ("invalid", 9)
    assert "digest" in outcome.steps[-1].text


def test_the_salted_digest_does_not_reveal_a_guessable_value():
    plain = {"method": "transaction-value", "related-party": False}
    first = confidential.salted_digest({**plain, "salt": b"a" * 16}, "valuation")
    assert first != confidential.salted_digest(
        {**plain, "salt": b"b" * 16}, "valuation"
    )


def test_the_draft_records_are_really_encrypted_to_the_recipients_they_name():
    from examples.records import pouch as draft

    outcome = confidential.read(
        draft.EMBLEM,
        validator.Task(
            emblem_name=draft.ASSET,
            how_named="",
            profile=profile.load("diplomatic-pouch"),
            evidence={},
            trust_anchor=[],
            keys=(draft.RECEIVER,),
            needs=("courier",),
        ),
    )
    assert outcome.opened["courier"]["name"] == "A. Courier-Example"
    stranger = pallets.ORIGIN
    task = validator.Task(
        emblem_name=draft.ASSET,
        how_named="",
        profile=profile.load("diplomatic-pouch"),
        evidence={},
        trust_anchor=[],
        keys=(stranger,),
        needs=("courier",),
    )
    assert confidential.read(draft.EMBLEM, task).result == "indeterminate"


def test_a_recipient_key_is_used_only_for_the_recipient_it_names(pouch_world):
    source = InMemoryDNS(pouch_world)
    key = confidential.public_key(
        world_of.RECEIVER.name, world_of.KEY_NAME, source, pouch_world.anchor, pouch.NOW
    )
    assert key.public == world_of.RECEIVER.public
    with pytest.raises(ValueError, match="not someone-else.example"):
        confidential.public_key(
            "someone-else.example", world_of.KEY_NAME, source, pouch_world.anchor, pouch.NOW
        )


def test_a_recipient_key_outside_its_validity_period_is_not_used():
    later = pouch.NOW + 400 * 86400  # after the key's validity, with fresh signatures
    world = zones.build(pouch.hierarchy(), later)
    with pytest.raises(ValueError, match="not valid at this time"):
        confidential.public_key(
            world_of.RECEIVER.name, world_of.KEY_NAME, InMemoryDNS(world), world.anchor, later
        )
