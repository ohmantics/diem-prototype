"""Write the files the containers of compose.yaml read.   # draft: #roles

compose.yaml runs this in its "generate" service, into the "zones" volume, so
nothing needs to be installed on the Docker host. It can also be run by hand,
with the package installed, to read the zone files:

    python -m compose.generate hospital --output compose/generated

The zones are the ones a local example builds and signs (diem/zones.py), so
the authoritative servers hold exactly the data that the in-memory DNS does.
One example is served at a time: each signs its zones as of its own date, and
the resolver is told to validate as of that date, which no single date could
do for both.
Each zone is written as a signed zone file for Knot, which serves it as it
is and signs nothing. Each container gets one directory: a Knot configuration
and zone files for the servers, and for the resolver the root hints and the
root trust anchor.

The one thing added to the zones is what a real resolver needs and the
in-memory DNS does not: an address for each name server, which is signed in
the zone that names it, and repeated unsigned as glue in the parent. Because
the addresses are signed into the zones, they are fixed before any server
starts, and compose.yaml gives each service a fixed address on a /24 whose
first three octets are DIEM_NET (default 10.53.0, the network BIND's own
system tests use). Set DIEM_NET if that range is in use where you run this.
"""

import argparse
import dataclasses
import ipaddress
import os
import shutil
from pathlib import Path

import dns.name
import dns.rdata
import dns.rdataclass as rdataclass
import dns.rdatatype as rdatatype

from diem import zones
from diem.hierarchy import server_role as role_of
from examples import hospital_world, pouch


# Each example: the date its data is valid at, and the zones it publishes.
EXAMPLES = {
    "pouch": (pouch.NOW, pouch.hierarchy),
    "hospital": (
        hospital_world.NOW,
        lambda: hospital_world.hierarchy(hospital_world.published_emblem()),
    ),
}

# The last octet of each service's address on the network of compose.yaml,
# which gives every service the same one.
HOSTS = {
    "root": 10,
    "tld": 11,
    "issuer-dns": 12,
    "emblem-server": 13,
    "authorities": 14,
    "resolver": 53,
}
DEFAULT_NET = "10.53.0"


def network_prefix(net=None):
    """The first three octets of the /24 that compose.yaml uses, from DIEM_NET."""
    net = net or os.environ.get("DIEM_NET") or DEFAULT_NET
    try:
        ipaddress.IPv4Network(f"{net}.0/24")
    except ValueError:
        raise SystemExit(
            f"DIEM_NET={net!r}: give the first three octets of a /24, e.g. 10.53.0"
        )
    return net


def addresses(net=DEFAULT_NET):
    return {role: f"{net}.{host}" for role, host in HOSTS.items()}


ADDRESSES = addresses()


def with_name_server_addresses(hierarchy, where=ADDRESSES):
    """The hierarchy with an A record for each zone's name server in the zone itself."""
    specs = []
    for spec in hierarchy.specs:
        address = dns.rdata.from_text(
            rdataclass.IN, rdatatype.A, where[role_of(spec)]
        )
        host = dns.name.Name((b"ns",)) + spec.name
        specs.append(
            dataclasses.replace(
                spec, records=spec.records + ((host, rdatatype.A, address.to_wire()),)
            )
        )
    return type(hierarchy)(specs)


def zone_file(zone, world, where=ADDRESSES):
    """A zone as text: its records and signatures, and the glue for each child that is served from below it."""
    lines = [
        rrset.to_text()
        for _, rrset in sorted(zone.rrsets.items(), key=_apex_first(zone))
    ]
    lines += [
        rrsig.to_text()
        for _, rrsig in sorted(zone.signatures.items(), key=_apex_first(zone))
    ]
    for child in world.hierarchy.children(zone.name):
        host = dns.name.Name((b"ns",)) + child.name
        lines.append(f"{host} {zones.TTL} IN A {where[role_of(child)]}")
    return "\n".join(lines) + "\n"


def _apex_first(zone):
    return lambda item: (item[0][0] != zone.name, item[0][0].to_text(), item[0][1])


def _file_name(name):
    return (name.to_text().strip(".") or "root") + ".zone"


def knot_config(held, storage):
    config = (
        "server:\n  listen: 0.0.0.0@53\n\n"
        "log:\n  - target: stdout\n    any: info\n\n"
        f"template:\n  - id: default\n    storage: {storage}\n    dnssec-signing: off\n"
    )
    if held:
        config += "\nzone:\n" + "".join(
            f"  - domain: {zone.name}\n    file: {_file_name(zone.name)}\n"
            for zone in held
        )
    return config


def unbound_config(now, net=DEFAULT_NET):
    return (
        "server:\n"
        "  interface: 0.0.0.0\n"
        f"  access-control: {net}.0/24 allow\n"
        "  root-hints: /zones/resolver/root.hints\n"
        "  trust-anchor-file: /zones/resolver/root.key\n"
        "  # The example's signatures and emblem are valid on its date, so validate as of then.\n"
        f"  val-override-date: {now}\n"
    )


def write(directory, files):
    directory.mkdir(parents=True)
    for name, text in files.items():
        (directory / name).write_text(text)


def clear(output):
    """Empty the output directory, which in compose.yaml is a volume's mount point and cannot be removed."""
    output.mkdir(parents=True, exist_ok=True)
    for entry in output.iterdir():
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def main():
    parser = argparse.ArgumentParser(
        description="Write the files that compose.yaml mounts, for one example."
    )
    parser.add_argument("example", choices=EXAMPLES)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/zones"),
        help="directory to write into (default /zones, the volume in compose.yaml)",
    )
    options = parser.parse_args()
    net = network_prefix()
    where = addresses(net)
    now, hierarchy = EXAMPLES[options.example]
    clear(options.output)
    world = zones.build(with_name_server_addresses(hierarchy(), where), now)
    for role in where.keys() - {"resolver"}:
        held = [zone for zone in world.zones.values() if role_of(zone.spec) == role]
        files = {_file_name(zone.name): zone_file(zone, world, where) for zone in held}
        storage = f"/zones/{role}"
        write(options.output / role, {"knot.conf": knot_config(held, storage), **files})
    root = world.hierarchy.root.name
    anchor = world.anchor[0]
    write(
        options.output / "resolver",
        {
            "unbound.conf": unbound_config(now, net),
            "root.hints": f". {zones.TTL} IN NS ns.\nns. {zones.TTL} IN A {where['root']}\n",
            "root.key": f"{root} IN DS {anchor.to_text()}\n",
        },
    )
    print(
        f"{options.example}: {len(world.zones)} signed zones written to {options.output},"
        f" for servers on {net}.0/24"
    )


if __name__ == "__main__":
    main()
