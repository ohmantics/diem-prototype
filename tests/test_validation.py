"""The validation outline on the pouch: each failure lands on the expected step.   # draft: #validation, #examples"""

import dataclasses

import pytest

import dns.name
import dns.rdata
import dns.rdatatype

from diem import dnssec, rrtypes, zones
from diem.values import quantity
from diem.bundle import Bundle
from diem.sources import BundleSource, InMemoryDNS
from diem.validator import validate
from examples import pouch

DAY = 86400


@pytest.fixture(scope="module")
def world():
    return zones.build(pouch.hierarchy(), pouch.NOW)


@pytest.fixture(scope="module")
def bundle(world):
    return InMemoryDNS(world).fetch(pouch.EMBLEM_NAME, "EMBLEM").bundle.to_bytes()


def run(
    world, source, now=pouch.NOW, seen=pouch.SEEN_ON_THE_POUCH, name=pouch.EMBLEM_NAME
):
    task = pouch.task(world, seen)
    task.emblem_name = name
    return validate(task, source, now)


def test_online_validation_is_valid_and_visits_each_server_in_order(world):
    source = InMemoryDNS(world)
    outcome = run(world, source)
    assert outcome.result == "valid"
    assert [step.number for step in outcome.steps] == list(range(1, 11))
    assert [
        query.server for query in source.log if query.rdtype == dns.rdatatype.DNSKEY
    ] == [
        "the root server",
        "the example. server",
        "the gov.example. server",
        "the mfa.gov.example. server",
        "the emblem server",
    ]


def test_only_the_emblem_server_sees_the_emblem_name(world):
    source = InMemoryDNS(world)
    run(world, source)
    full = {
        query.server
        for query in source.log
        if query.name == dns.name.from_text(pouch.EMBLEM_NAME)
    }
    assert full == {"the emblem server"}
    assert [
        (query.server, query.name.to_text())
        for query in source.log
        if query.rdtype == dns.rdatatype.NS
    ][:2] == [("the root server", "example."), ("the example. server", "gov.example.")]


def test_offline_validation_is_valid_and_asks_nobody(world, bundle):
    source = BundleSource(bundle)
    assert run(world, source).result == "valid"
    assert source.log == ()


def test_a_bundle_survives_serialization(bundle):
    assert Bundle.from_bytes(bundle).to_bytes() == bundle


def test_a_seal_that_differs_is_invalid_at_step_5(world):
    outcome = run(
        world,
        InMemoryDNS(world),
        seen={**pouch.SEEN_ON_THE_POUCH, "seal": "XA-2026-114358"},
    )
    assert (outcome.result, outcome.steps[-1].number) == ("invalid", 5)
    assert "seal" in outcome.steps[-1].text


def test_a_mass_that_differs_is_invalid_at_step_5(world):
    seen = {**pouch.SEEN_ON_THE_POUCH, "gross-mass": quantity("19.4", "KGM")}
    outcome = run(world, InMemoryDNS(world), seen=seen)
    assert (
        outcome.steps[-1].text
        == "gross-mass: the emblem says 18.4 KGM, what we see is 19.4 KGM"
    )


def test_a_bundle_used_after_the_tld_signatures_expire_is_invalid_at_step_3(
    world, bundle
):
    outcome = run(world, BundleSource(bundle), now=pouch.NOW + 15 * DAY)
    assert (outcome.result, outcome.steps[-1].number) == ("invalid", 3)
    assert "DNSKEY records of example. expired" in outcome.steps[-1].text


def test_a_bundle_used_before_its_signatures_begin_is_invalid_at_step_3(world, bundle):
    assert run(world, BundleSource(bundle), now=pouch.NOW - DAY).steps[-1].number == 3


def test_a_tampered_bundle_is_invalid_at_step_3(world, bundle):
    tampered = bundle.replace(b"XA-2026-114357", b"XA-2026-114358")
    outcome = run(
        world,
        BundleSource(tampered),
        seen={**pouch.SEEN_ON_THE_POUCH, "seal": "XA-2026-114358"},
    )
    assert (outcome.result, outcome.steps[-1].number) == ("invalid", 3)
    assert "does not verify" in outcome.steps[-1].text


def test_an_emblem_past_its_validity_period_is_invalid_at_step_6(world):
    outcome = run(world, InMemoryDNS(world), now=1794355200 + DAY)
    assert (outcome.result, outcome.steps[-1].number) == ("invalid", 6)


def test_a_server_that_does_not_answer_is_indeterminate_at_step_2(world):
    outcome = run(world, InMemoryDNS(world, down=["the emblem server"]))
    assert (outcome.result, outcome.steps[-1].number) == ("indeterminate", 2)


def test_a_bundle_that_cannot_be_read_is_indeterminate_at_step_2(world):
    assert run(world, BundleSource(b"\x01\x02\x03")).steps[-1].number == 2


def test_a_removed_emblem_is_invalid_at_step_3_because_its_absence_is_proved(world):
    name = "zzzz-zzzz-zzzz._pouch._diem.mfa.gov.example"
    source = InMemoryDNS(world)
    outcome = run(world, source, name=name)
    assert (outcome.result, outcome.steps[-1].number) == ("invalid", 3)
    assert "nothing is published" in outcome.steps[-1].text


def test_nonexistence_is_proved_for_a_name_and_for_a_type(world):
    anchor, source = world.anchor, InMemoryDNS(world)
    assert (
        dnssec.verify(
            source.fetch("nothing._pouch._diem.mfa.gov.example", "EMBLEM"),
            anchor,
            pouch.NOW,
        ).absent
        == "nxdomain"
    )
    assert (
        dnssec.verify(source.fetch(pouch.EMBLEM_NAME, "TXT"), anchor, pouch.NOW).absent
        == "nodata"
    )
    assert (
        dnssec.verify(
            source.fetch(pouch.EMBLEM_NAME, "EMBLEM"), anchor, pouch.NOW
        ).absent
        == ""
    )


def test_the_wrong_trust_anchor_validates_nothing(world, bundle):
    not_the_root_key = [dns.rdata.from_text("IN", "DS", "1 13 2 " + "00" * 32)]
    chain = dnssec.verify(
        BundleSource(bundle).fetch(pouch.EMBLEM_NAME, "EMBLEM"),
        not_the_root_key,
        pouch.NOW,
    )
    assert (chain.secure, chain.reason) == (
        False,
        "no key of the root matches the DS record that names it",
    )


def unsigned(bundle):
    """The same answer with its signatures taken off, and the keys that lead to the root kept."""
    found = Bundle.from_bytes(bundle)
    bare = Bundle()
    bare.add(found.get(dns.name.from_text(pouch.EMBLEM_NAME), rrtypes.EMBLEM)[0])
    for kind in (dns.rdatatype.DNSKEY, dns.rdatatype.DS):
        for pair in found.rrsets_of_type(kind):
            bare.add(*pair)
    return bare.to_bytes()


def allowing_unsigned(world):
    task = pouch.task(world)
    task.profile = dataclasses.replace(task.profile, allows_unsigned=True)
    return task


def test_an_unsigned_emblem_is_invalid_at_step_3_unless_the_profile_permits_it(
    world, bundle
):
    outcome = validate(pouch.task(world), BundleSource(unsigned(bundle)), pouch.NOW)
    assert (outcome.result, outcome.ended_at) == ("invalid", 3)
    permitted = validate(
        allowing_unsigned(world), BundleSource(unsigned(bundle)), pouch.NOW
    )
    assert permitted.result == "valid"
    assert "not validated, which the profile allows" in permitted.steps[2].text
    assert "not validated by DNSSEC" in permitted.steps[-1].text


def test_bogus_data_is_invalid_at_step_3_even_where_the_profile_permits_unsigned(
    world, bundle
):
    tampered = bundle.replace(b"XA-2026-114357", b"XA-2026-114358")
    task = allowing_unsigned(world)
    task.evidence = {**task.evidence, "seal": "XA-2026-114358"}
    outcome = validate(task, BundleSource(tampered), pouch.NOW)
    assert (outcome.result, outcome.ended_at) == ("invalid", 3)
    expired = validate(
        allowing_unsigned(world), BundleSource(bundle), pouch.NOW + 15 * DAY
    )
    assert (expired.result, expired.ended_at) == ("invalid", 3)


def test_a_response_too_big_for_one_udp_answer_is_said_to_need_tcp(world):
    from examples import hospital_world

    big = zones.build(
        hospital_world.hierarchy(hospital_world.published_emblem()),
        hospital_world.NOW,
    )
    found = InMemoryDNS(big).fetch(hospital_world.EMBLEM_NAME, "EMBLEM")
    assert "too big for one UDP answer" in found.transport
    assert "retries over TCP" in found.transport
    small = InMemoryDNS(world).fetch(pouch.EMBLEM_NAME, "EMBLEM")
    assert "UDP" not in small.transport
