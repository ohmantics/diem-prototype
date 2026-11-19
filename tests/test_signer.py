"""A zone speaks only for names at or below it (RFC 4035 section 5.3.1).   # draft: #validation

An attacker who holds a properly delegated, properly signed zone of their own
(evil.) must not be able to sign an emblem, a delegation or a proof of absence
for a name in somebody else's zone.
"""

import pytest

import dns.name
import dns.rdataclass
import dns.rdatatype as rdatatype
import dns.rrset

from diem import denial, dnssec, rrtypes, zones
from diem.bundle import Bundle
from diem.hierarchy import Hierarchy, ZoneSpec
from diem.sources import Answer
from examples import pouch

EVIL = dns.name.from_text("evil.")
EMBLEM_ZONE = dns.name.from_text("_diem.mfa.gov.example.")
NAME = dns.name.from_text(pouch.EMBLEM_NAME)


@pytest.fixture(scope="module")
def world():
    specs = [*pouch.hierarchy().specs, ZoneSpec(EVIL, "evil server", "an attacker's zone")]
    return zones.build(Hierarchy(specs), pouch.NOW)


def sign(rrset, signer):
    """RRSIGs over rrset by signer's key, in signer's name."""
    return zones.signature(
        rrset, zones.signing_key(signer), signer, pouch.NOW - 3600, pouch.NOW + 3600
    )


def chain_to(world, zone, bundle):
    """Put zone's DNSKEYs, and the DS records and DNSKEYs above it, in the bundle."""
    name = zone
    while True:
        bundle.add(*world.zones[name]._pair(name, rdatatype.DNSKEY))
        if name == dns.name.root:
            return
        parent = name.parent()
        while parent not in world.zones:
            parent = parent.parent()
        bundle.add(*world.zones[parent]._pair(name, rdatatype.DS))
        name = parent


def emblem(world):
    return world.zones[EMBLEM_ZONE].rrsets[(NAME, rrtypes.EMBLEM)]


def verify(world, bundle, status="answer", rdtype=rrtypes.EMBLEM):
    answer = Answer(NAME, rdtype, status, bundle, "")
    return dnssec.verify(answer, world.anchor, pouch.NOW)


def test_the_real_emblem_is_secure(world):
    bundle = Bundle()
    bundle.add(emblem(world), world.zones[EMBLEM_ZONE].signatures[(NAME, rrtypes.EMBLEM)])
    chain_to(world, EMBLEM_ZONE, bundle)
    assert verify(world, bundle).secure


def test_an_emblem_signed_by_another_zone_is_bogus(world):
    bundle = Bundle()
    bundle.add(emblem(world), sign(emblem(world), EVIL))
    chain_to(world, EVIL, bundle)
    chain = verify(world, bundle)
    assert chain.status == "bogus"
    assert "a zone they are not in" in chain.reason


def test_a_delegation_signed_by_another_zone_is_bogus(world):
    # The attacker makes a key for the emblem's zone, signs the emblem with it,
    # and signs a DS record for that zone with the key of evil.
    impostor = zones.signing_key(dns.name.from_text("impostor."))
    keys = dns.rrset.from_rdata(EMBLEM_ZONE, zones.TTL, impostor[1])
    ds = dns.rrset.from_rdata(
        EMBLEM_ZONE, zones.TTL, dns.dnssec.make_ds(EMBLEM_ZONE, impostor[1], "SHA256")
    )
    at = (pouch.NOW - 3600, pouch.NOW + 3600)
    bundle = Bundle()
    bundle.add(emblem(world), zones.signature(emblem(world), impostor, EMBLEM_ZONE, *at))
    bundle.add(keys, zones.signature(keys, impostor, EMBLEM_ZONE, *at))
    bundle.add(ds, sign(ds, EVIL))
    chain_to(world, EVIL, bundle)
    chain = verify(world, bundle)
    assert chain.status == "bogus"
    assert "not by a zone above it" in chain.reason


def test_a_proof_of_absence_from_another_zone_is_bogus(world):
    label = denial._label(denial.name_hash(NAME))
    nsec3 = dns.rrset.from_text(
        dns.name.from_text(label, EVIL),
        zones.TTL,
        dns.rdataclass.IN,
        rdatatype.NSEC3,
        f"1 0 0 - {label} A RRSIG",
    )
    bundle = Bundle()
    bundle.add(nsec3, sign(nsec3, EVIL))
    chain_to(world, EVIL, bundle)
    chain = verify(world, bundle, status="nodata")
    assert chain.status == "bogus"
    assert "cannot speak for" in chain.reason


def test_an_opt_out_gap_proves_nothing():
    zone = dns.name.from_text("example.")
    qname = dns.name.from_text("a.b.example.")
    apex, wanted = denial.name_hash(zone), denial.name_hash(qname)
    # One record for the apex whose gap runs all the way round, so it covers every hash.
    for flags, proved in ((0, "nxdomain"), (1, None)):
        nsec3 = dns.rrset.from_text(
            dns.name.from_text(denial._label(apex), zone),
            zones.TTL,
            dns.rdataclass.IN,
            rdatatype.NSEC3,
            f"1 {flags} 0 - {denial._label(apex)} SOA NS DNSKEY RRSIG",
        )
        assert wanted != apex
        assert denial.prove([nsec3], zone, qname, rrtypes.EMBLEM) == proved
