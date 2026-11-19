"""The files for the containers: the same zones as local mode, and the addresses compose.yaml gives.   # draft: #roles"""

import re
from pathlib import Path

import dns.name
import dns.zone
import pytest

from compose import generate
from diem import zones
from diem.hierarchy import server_role
from examples import hospital_world, pouch

ROOT = Path(__file__).parent.parent


def worlds():
    for now, hierarchy in generate.EXAMPLES.values():
        yield zones.build(generate.with_name_server_addresses(hierarchy()), now)


def test_compose_yaml_gives_each_service_the_address_the_zones_name():
    found, service = {}, None
    for line in (ROOT / "compose.yaml").read_text().splitlines():
        if match := re.match(r"^  ([a-z-]+):", line):
            service = match.group(1)
        if match := re.search(r'ipv4_address: "\$\{DIEM_NET:-([\d.]+)\}\.(\d+)"', line):
            found[service] = f"{match.group(1)}.{match.group(2)}"
    assert found == generate.ADDRESSES


def test_the_network_prefix_can_be_moved():
    moved = generate.addresses(generate.network_prefix("192.168.53"))
    assert moved["root"] == "192.168.53.10"
    assert moved["resolver"] == "192.168.53.53"


def test_a_bad_network_prefix_is_refused():
    for bad in ("10.53", "10.53.0.0", "10.53.300"):
        with pytest.raises(SystemExit):
            generate.network_prefix(bad)


def test_every_zone_is_held_by_a_server_role():
    roles = {spec.name.to_text(): server_role(spec) for spec in pouch.hierarchy().specs}
    assert roles == {
        ".": "root",
        "example.": "tld",
        "gov.example.": "issuer-dns",
        "mfa.gov.example.": "issuer-dns",
        "_diem.mfa.gov.example.": "emblem-server",
        "customs.xb.example.": "issuer-dns",
    }
    roles = {
        spec.name.to_text(): server_role(spec)
        for spec in hospital_world.hierarchy().specs
    }
    assert roles == {
        ".": "root",
        "example.": "tld",
        "gov.example.": "issuer-dns",
        "health.gov.example.": "authorities",
        "health.xb.example.": "authorities",
        "hospital.example.": "issuer-dns",
        "_diem.hospital.example.": "emblem-server",
    }


def test_a_zone_file_holds_the_signed_zone_and_the_glue_for_its_children():
    for signed in worlds():
        check_zone_files(signed)


def check_zone_files(signed):
    for zone in signed.zones.values():
        parsed = dns.zone.from_text(
            generate.zone_file(zone, signed),
            origin=zone.name,
            relativize=False,
            check_origin=False,
        )
        for (name, rdtype), rrset in zone.rrsets.items():
            assert parsed.get_rdataset(name, rdtype) == rrset
        for (name, rdtype), signatures in zone.signatures.items():
            assert parsed.get_rdataset(name, "RRSIG", rdtype) == signatures
        for child in signed.hierarchy.children(zone.name):
            glue = parsed.get_rdataset(dns.name.Name((b"ns",)) + child.name, "A")
            assert [rdata.address for rdata in glue] == [
                generate.ADDRESSES[server_role(child)]
            ]
