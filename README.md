# DIEM prototype

This is prototype code that accompanies the Internet-Draft
[draft-rosenberg-diem-architecture-03](https://datatracker.ietf.org/doc/draft-rosenberg-diem-architecture/),
which was presented to the IETF's [DIEM working group](https://datatracker.ietf.org/wg/diem/about/) at IETF 127.
It illustrates the draft's examples as running code, and measures the sizes of the encoded emblems and bundles.

**It is not production code, and it is not a specification.**

- The record encoding is the draft's *strawman*, offered for discussion. It is not a proposed wire format.
- Every signing and encryption key is derived from a public name, so all the keys are worthless by design.
- The DNSSEC validator in `diem/dnssec.py` is a small one, written to show the draft's validation steps. It handles only what the examples publish (see [Limitations](#limitations)).
- The scenarios (states XA, XB and XC, hospitals, pouches, peacekeepers) are illustrations. The profiles in `profiles/` are sketches that make the examples run, not proposals for any registry.

Comments are welcome on the DIEM working group's [mailing list](https://datatracker.ietf.org/wg/diem/about/).

## What it shows

A digital emblem is authenticated, typed metadata about an asset, published in the DNS and protected by DNSSEC.
An asset can be a hospital's records service, a pallet of phones, a diplomatic pouch, or a person serving with a peacekeeping mission.
A validator finds an emblem with an ordinary DNS query, checks it with ordinary DNSSEC validation, and reads it under a *profile* that says what its keys mean.
Use cases differ in their profiles, not in their plumbing: third-party endorsement, encrypted values and offline bundles work the same way for every profile.

Each example builds a small DNSSEC-signed DNS hierarchy, with a delegation at `_diem`.
It then walks through the draft's validation outline step by step, and runs variants that fail at different steps.
Confidential values are encrypted with HPKE to the recipients each example names.

| Example | What it shows |
|---|---|
| `examples.hospital` | an IHL protective emblem; stapled and queried endorsements; a visual mark |
| `examples.pouch` | a diplomatic pouch validated online and from an offline bundle; a value encrypted to the receiving state |
| `examples.pallet` | a consignment that references its products; a live facet; values encrypted to customs |
| `examples.peacekeepers` | rotating badges, a mission's instructions, an encrypted convoy position |
| `examples.diverted_flight` | an open issue: a flight diverted to a state nobody encrypted for (a scenario suggested by Rohan Mahy) |
| `examples` | every example record in the draft, type-checked and printed |

## Quick start with Docker

You don't need Python on your machine; everything runs in containers.

**1. Install Docker.** On macOS or Windows, install [Docker Desktop](https://docs.docker.com/desktop/) and start it.
On Linux, install [Docker Engine](https://docs.docker.com/engine/install/) with the Compose plugin.
Check that it works:

```sh
docker compose version      # should print "Docker Compose version v2..." or later
```

**2. Get this repository and open a terminal in it.** Every command below is run from the directory that holds `compose.yaml`.
That file describes all the containers, and `docker compose` reads it from the current directory, so you never name it.

```sh
cd diem-prototype
```

**3. Run an example.**

```sh
docker compose run --rm --build local examples.hospital
```

The first run builds an image of this code, which takes a minute or two; later runs start at once.
It prints the example's DNS hierarchy and records, then a step-by-step validation ending in `VALID`, then variants that fail at different steps.
Replace `examples.hospital` with any module from the table above.
`local` is the name of a container in `compose.yaml` that runs one example with everything in memory, and `--rm` deletes it afterwards.

**4. Run the same example against real DNS servers.** This starts eight containers:

- **generate:** signs the example's zones and writes them out as zone files, then exits.
- **root, tld, issuer-dns, emblem-server, authorities:** Knot DNS serving the root, a top-level domain, the issuers' ordinary DNS, an emblem server behind the `_diem` delegation, and the authorities that endorse. These are the roles of the draft's Roles section (`#roles`).
- **resolver:** Unbound as a validating resolver, configured with only the root hints and the example's root trust anchor.
- **capture:** records what the resolver sends upstream, so the walkthrough can show who saw which query.

```sh
docker compose up -d --build --wait     # build, sign the zones, start the servers in the background
docker compose run --rm validator       # validate the hospital emblem through the resolver
docker compose down --volumes           # stop and remove everything, including the zones
```

The `up` step should end with every server reported as `Healthy` (`generate` shows `Exited`, which is expected).
It has been tested on Linux with Docker Engine 29 and Compose 5.8.
The validator's walkthrough is the same as in memory, except that it says whether answers came over UDP or TCP, and its "who saw a query" lines come from the packet capture.
So they reflect what a real resolver does (QNAME minimisation, caching).
The validator sends its queries with the DO bit set and checks every signature itself; it doesn't rely on the resolver's AD bit.

**The other example.** Only `hospital` (the default) and `pouch` are served this way, one at a time.
To switch, take the hierarchy down first and set `DIEM_EXAMPLE` for both commands:

```sh
docker compose down --volumes
export DIEM_EXAMPLE=pouch
docker compose up -d --wait
docker compose run --rm validator
```

The pallet, peacekeepers and diverted-flight examples use online-signed zones, so they run in memory only.
The same goes for the variants that change what is published (a removed emblem, a different mark).

**Addresses.** The servers' addresses are signed into the zones (and the resolver's root hints), so each container needs a fixed address.
The default network is `10.53.0.0/24`, the range BIND's own test suite uses.
If that range is already in use on your machine or VPN, `up` fails with an error such as `Pool overlaps with other one on this address space`.
In that case, pick another /24 by giving its first three octets:

```sh
docker compose down --volumes
export DIEM_NET=192.168.153
docker compose up -d --wait
```

You can also put `DIEM_EXAMPLE` and `DIEM_NET` in a `.env` file next to `compose.yaml`.

**Looking at the zones.** `docker compose exec issuer-dns ls /zones` lists the generated files while the hierarchy is up.
You can also write them to a local directory with Python (below): `python -m compose.generate hospital --output compose/generated`.

**If something goes wrong.** `docker compose logs generate` shows whether the zones were written, and `docker compose logs resolver` shows Unbound's view.
`docker compose down --volumes` followed by `up` starts from scratch.

## Running with Python

You need Python 3.11 or later.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[test]"
python -m examples.hospital         # or any module in the table above
python -m pytest
```

Install in editable mode (`-e`) and run from the repository root, because the code reads `profiles/` from the checkout.
A few tests compare the code with the draft's text. They are skipped unless the draft's source is checked out next to this repository, or `DIEM_DRAFT` points at it.
The CDDL tests are skipped unless the [`cddl`](https://github.com/anweiss/cddl) tool is on the `PATH`.

## Where the draft is in the code

| Draft section | Where |
|---|---|
| Roles and Trust (`#roles`) | `diem/hierarchy.py`, `diem/zones.py`, `compose.yaml` |
| Naming and Discovery (`#discovery`) | `diem/names.py`, `diem/sources.py`, `diem/network.py` |
| Data Model (`#data-model`) | `diem/values.py`, `diem/emblem.py`, `diem/registry.py`, `profiles/` |
| Several Profiles for One Asset (`#multi-profile`) | `emblem.select` |
| Treatment (`#treatment`) | `diem/treatment.py` |
| Visual Marks (`#marks`) | `diem/marks.py`, `diem/svg_tiny_ps.py` |
| Facets (`#facets`) | `diem/facets.py`, `diem/zones.py` (the online-signed zone) |
| Hierarchy and Composition (`#hierarchy`) | `diem/references.py` |
| Authorization and Endorsement (`#endorsement`) | `diem/endorsement.py`; a staple is built in `examples/hospital_world.py` |
| Confidentiality (`#confidentiality`) | `diem/confidential.py`, `diem/cose_hpke.py`; NSEC3 in `diem/denial.py` |
| Offline and Constrained Validation (`#offline`) | `diem/bundle.py`, `diem/dnssec.py` |
| Lifecycle (`#lifecycle`) | proofs of absence in `diem/denial.py` |
| Undetectable Validation (`#undetectable`) | the query log in `diem/sources.py` and `diem/capture.py` |
| Defining a Profile (`#profiles`) | `diem/profile.py`; a CDDL file and a policy file per profile in `profiles/` |
| Validation Outline (`#validation`) | `diem/validator.py`, one method per step |
| Strawman Encoding (`#strawman`, `#encoded`) | `diem/cbor.py`, `diem/edn.py`, `profiles/keys.toml`; `tests/test_encoding.py` |
| Example Use Cases (`#examples`) | `examples/` |
| Open Issues (`#open-issues`) | `examples/diverted_flight.py` |

The first line of each module in `diem/` names the draft sections it implements.

## Measurements

`measure/` computes record and bundle sizes (against NFC and QR capacity), the cost of each extra encryption recipient, and sizes with post-quantum signatures.
It also captures what `dig` and `delv` see against the Compose hierarchy.
`measure/README.md` explains how; `measure/results/` holds the output.

## Limitations

These are deliberate, to keep the code small enough to read alongside the draft:

- **DNSSEC.** One algorithm (ECDSA P-256), signed delegations only, NSEC3 only (with RFC 9276 parameters).
  No unsigned delegations, NSEC, wildcard expansion, CNAME/DNAME, key flags such as REVOKE, or algorithm policy.
  A deployed validator would use a complete DNSSEC implementation.
- **Unsigned emblems.** A profile can permit unsigned emblems. The code doesn't look for proof that a zone is unsigned, so it can't tell an unsigned zone from one whose signatures were stripped in transit.
- **Keys.** All keys are deterministic and public. Nothing here should be used to protect anything.
- **Encoding and profiles.** These follow the draft's strawman. They will change as the working group decides what to standardise.

## License

BSD-3-Clause; see `LICENSE`.
