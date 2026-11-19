"""A person as the asset: badges that rotate, a mission that says what to do, a convoy that is encrypted.   # draft: #ex-peacekeepers"""

import pytest

from diem import zones
from diem.sources import InMemoryDNS
from diem.validator import validate
from examples import peacekeepers as example, peacekeepers_world as world_of


@pytest.fixture(scope="module")
def world():
    return zones.build(world_of.hierarchy(), world_of.NOW)


def run(world, name, profile, now=world_of.NOW, source=None, **more):
    task = example.task(world, name, profile, **more)
    return validate(task, source or InMemoryDNS(world), now)


def test_a_current_badge_is_valid_and_endorsed_by_the_deploying_organization(world):
    outcome = run(world, world_of.BADGE, "peacekeeping-personnel")
    assert outcome.result == "valid"
    assert outcome.authority == "peace.example"
    assert "do not attack, do not detain" in outcome.steps[-1].text


def test_a_badge_from_a_previous_rotation_is_proved_absent_and_the_mission_says_what_to_do(
    world,
):
    outcome = run(world, world_of.OLD_BADGE, "peacekeeping-personnel")
    assert (outcome.result, outcome.ended_at) == ("invalid", 3)
    assert outcome.steps[-1].number == 3
    note = outcome.notes[-1]
    assert "report (requested), verify-identity (requested)" in note
    assert "https://mission.example/report" in note


def test_the_mission_emblem_is_not_trusted_if_it_is_not_endorsed(world):
    outcome = run(world, world_of.OLD_BADGE, "peacekeeping-personnel", authorities=())
    assert "not usable either" in outcome.notes[-1]


def test_the_missions_server_sees_every_badge_check(world):
    source = InMemoryDNS(world)
    run(world, world_of.BADGE, "peacekeeping-personnel", source=source)
    seen = {q.server for q in source.log if q.name.to_text(True) == world_of.BADGE}
    assert seen == {"the mission's emblem server"}


@pytest.mark.parametrize("who", [world_of.OPERATIONS, world_of.LIAISON])
def test_the_convoy_position_is_read_by_either_recipient(world, who):
    outcome = run(
        world, world_of.CONVOY, "peacekeeping-convoy", keys=(who,), needs=("position",)
    )
    assert outcome.result == "valid"
    assert str(outcome.opened["position"]["latitude"].to_decimal()) == "12.5"


def test_anyone_else_cannot_follow_the_convoy(world):
    outcome = run(world, world_of.CONVOY, "peacekeeping-convoy", needs=("position",))
    assert (outcome.result, outcome.ended_at) == ("indeterminate", 9)


def test_a_position_replayed_ten_minutes_later_no_longer_validates(world):
    outcome = run(world, world_of.CONVOY, "peacekeeping-convoy", now=world_of.NOW + 600)
    assert (outcome.result, outcome.ended_at) == ("invalid", 3)
