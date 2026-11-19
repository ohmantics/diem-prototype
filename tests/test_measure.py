"""The measurement scripts run, and agree with what the code encodes.   # draft: #encoded"""

import pytest

from measure import bundles, common, pq, recipients, sizes


@pytest.fixture(scope="module")
def listed():
    return {item.label: item for item in common.items()}


def test_the_ispm15_record_is_the_59_octets_of_the_drafts_encoded_example(listed):
    assert listed["ispm15 pallet"].rdata_octets() == 59


def test_a_bundle_gets_smaller_as_the_trust_anchor_gets_closer(listed):
    root, tld, issuer, emblem_zone = bundles.sizes(listed["item"])
    assert root > tld > issuer > emblem_zone


def test_a_separate_zone_signing_key_makes_a_bundle_larger(listed):
    assert sum(bundles.sizes(listed["item"], split=True)) > sum(
        bundles.sizes(listed["item"])
    )


def test_each_recipient_after_the_second_costs_the_same():
    steps = {
        recipients.octets("valuation", n + 1) - recipients.octets("valuation", n)
        for n in (2, 3, 4)
    }
    assert len(steps) == 1


def test_post_quantum_signatures_are_too_big_for_an_nfc_tag(listed):
    item = listed["item"]
    chain = {
        keys.name
        for keys, _ in item.answer().bundle.rrsets_of_type(pq.rdatatype.DNSKEY)
    }
    assert (
        pq.size(item, bundles.anchor_zones(item)[3], chain, split=False)
        > common.NFC_TAG
    )


def test_the_scripts_print_tables(capsys):
    for script in (sizes, bundles):
        script.main()
    assert "| item |" in capsys.readouterr().out


def test_the_example_consignment_is_variant_a_and_one_shared_encryption_is_smaller(
    listed,
):
    from measure import consignment

    assert len(consignment.rdata("a", 2)) == listed["consignment"].rdata_octets()
    assert len(consignment.rdata("c", 2)) < len(consignment.rdata("b", 2))
