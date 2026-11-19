"""Step 7: endorsements, stapled and queried, and the mark facet of step 8.   # draft: #endorsement, #marks"""

import pytest

import dns.name

from diem import endorsement, validator, zones
from diem.values import treatment
from diem.bundle import Bundle
from diem.sources import BundleSource, InMemoryDNS
from examples import hospital, hospital_world

DAY = 86400
HOME, OTHER = hospital_world.HOME_MINISTRY, hospital_world.OTHER_MINISTRY


def world_with(**changes):
    emblem_bytes = changes.pop("emblem_bytes", hospital_world.published_emblem())
    return zones.build(
        hospital_world.hierarchy(emblem_bytes, **changes), hospital_world.NOW
    )


@pytest.fixture(scope="module")
def world():
    return world_with()


def run(world, *authorities, now=hospital_world.NOW, canonical=True, source=None):
    task = hospital.task(world, authorities[0], canonical)
    task.authorities = authorities
    return validator.validate(task, source or InMemoryDNS(world), now)


def failure(outcome):
    return outcome.result, outcome.steps[-1].number, outcome.steps[-1].text


def test_the_stapled_endorsement_validates_without_asking_the_ministry(world):
    source = InMemoryDNS(world)
    outcome = run(world, HOME, source=source)
    assert outcome.result == "valid"
    assert "stapled endorsement from health.gov.example" in outcome.steps[6].text
    assert "the health.gov.example. server" not in {
        query.server for query in source.log
    }


def test_the_endorsement_of_a_recognized_ministry_is_queried_when_not_stapled(world):
    source = InMemoryDNS(world)
    outcome = run(world, OTHER, source=source)
    assert outcome.result == "valid"
    assert "queried endorsement from health.xb.example" in outcome.steps[6].text
    assert "the health.xb.example. server" in {query.server for query in source.log}


def test_the_stapled_chain_is_a_bundle_of_the_endorsement_and_its_chain_to_the_root():
    assert len(Bundle.from_bytes(hospital_world.staple())) == 8


def test_an_expired_staple_is_replaced_by_asking_the_authority_when_it_still_endorses():
    later = hospital_world.NOW + 10 * DAY
    fresh = zones.build(
        hospital_world.hierarchy(hospital_world.published_emblem()), later
    )
    outcome = run(fresh, HOME, now=later)
    assert outcome.result == "valid"
    assert "had expired, so the authority was asked instead" in outcome.steps[6].text
    assert "queried endorsement from health.gov.example" in outcome.steps[6].text


def test_an_expired_staple_and_a_withdrawn_endorsement_are_invalid_at_step_7():
    later = hospital_world.NOW + 10 * DAY
    gone = zones.build(
        hospital_world.hierarchy(hospital_world.published_emblem(), home_scope=None),
        later,
    )
    result, step, text = failure(run(gone, HOME, now=later))
    assert (result, step) == ("invalid", 7)
    assert "had expired" in text and "proves that it has not endorsed" in text


def test_an_expired_staple_offline_cannot_be_replaced_and_is_indeterminate(world):
    later = hospital_world.NOW + 8 * DAY
    emblem_only = BundleSource(
        InMemoryDNS(world)
        .fetch(hospital_world.EMBLEM_NAME, "EMBLEM")
        .bundle.to_bytes()
    )
    outcome = run(world, HOME, now=later, source=emblem_only)
    assert (outcome.result, outcome.ended_at) == ("indeterminate", 7)


def test_a_staple_altered_by_the_issuer_is_invalid_at_step_7():
    altered = hospital_world.staple().replace(b"hospital.example", b"hospital.exampla")
    bad = hospital_world.emblem.to_cbor(hospital_world.emblem_record(altered))
    result, step, text = failure(run(world_with(emblem_bytes=bad), HOME))
    assert (result, step) == ("invalid", 7)
    assert "does not verify" in text


def test_an_endorsement_that_does_not_cover_the_emblem_is_invalid_at_step_7():
    narrower = world_with(
        other_scope=[
            "protective-red-crescent",
            treatment("prohibit", "attack"),
        ]
    )
    result, step, text = failure(run(narrower, OTHER))
    assert (result, step) == ("invalid", 7)
    assert "its scope does not cover protective-red-cross" in text


def test_an_endorsement_bound_to_another_key_is_invalid_at_step_7(world, monkeypatch):
    monkeypatch.setattr(endorsement, "dnskey_digest", lambda zone, key: bytes(32))
    result, step, text = failure(run(world, HOME))
    assert (result, step) == ("invalid", 7)
    assert "names a key of hospital.example other than the one in use" in text


def test_an_authority_that_has_not_endorsed_the_issuer_proves_it():
    result, step, text = failure(run(world_with(other_scope=None), OTHER))
    assert (result, step) == ("invalid", 7)
    assert text == "health.xb.example proves that it has not endorsed hospital.example"


def test_any_one_endorsement_from_a_recognized_authority_suffices():
    assert run(world_with(other_scope=None), OTHER, HOME).result == "valid"


def test_an_authority_that_cannot_be_reached_leaves_the_result_indeterminate(world):
    source = InMemoryDNS(world, down=["the health.xb.example. server"])
    assert failure(run(world, OTHER, source=source))[:2] == ("indeterminate", 7)


def test_a_validator_that_recognizes_no_authority_cannot_accept(world):
    task = hospital.task(world, HOME)
    task.authorities = ()
    outcome = validator.validate(task, InMemoryDNS(world), hospital_world.NOW)
    assert (outcome.result, outcome.steps[-1].number) == ("invalid", 7)


def test_a_removed_emblem_is_invalid_at_step_3_because_its_absence_is_proved():
    result, step, text = failure(run(world_with(emblem_bytes=None), HOME))
    assert (result, step) == ("invalid", 3)
    assert "nothing is published" in text


def test_a_mark_that_is_not_the_endorsed_image_is_not_authorized_but_the_emblem_is_valid():
    outcome = run(world_with(mark_image=hospital_world.OTHER_IMAGE), HOME)
    assert outcome.result == "valid"
    assert "NOT authorized" in outcome.steps[7].text
    assert "Mark not authorized" in outcome.steps[-1].text


def test_a_mark_that_is_not_svg_tiny_ps_is_not_shown_but_the_emblem_is_valid():
    script = hospital_world.MARK_IMAGE.replace(b"<title>", b"<script>1</script><title>", 1)
    assert script != hospital_world.MARK_IMAGE
    outcome = run(world_with(mark_image=script), HOME)
    assert outcome.result == "valid"
    assert (
        "not SVG Tiny PS" in outcome.steps[7].text
        and "No mark shown." in outcome.steps[-1].text
    )


def test_a_missing_mark_facet_does_not_change_the_result():
    outcome = run(world_with(mark_image=None), HOME)
    assert outcome.result == "valid" and "No mark shown." in outcome.steps[-1].text


def test_the_endorsed_mark_alone_is_enough_for_a_validator_that_knows_nothing_of_ihl(
    world,
):
    outcome = run(world, HOME, canonical=False)
    assert outcome.result == "valid"
    assert (
        outcome.steps[7].text
        == "visual mark retrieved; its digest matches the endorsement"
    )


def test_the_issuer_is_the_name_above_the_diem_label(world):
    assert (
        hospital.profile.load("ihl-protective").issuer_of(hospital_world.EMBLEM_NAME)
        == "hospital.example"
    )
    assert (
        hospital.profile.load("ihl-protective").derive_emblem_name(
            hospital_world.ASSET
        )
        == hospital_world.EMBLEM_NAME
    )
    assert dns.name.from_text(hospital_world.ISSUER) in world.zones
