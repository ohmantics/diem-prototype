# Measurements

Sizes and fits of the examples' records, computed from the code in `diem/` and `examples/` and
nothing else. Nothing in `diem/` depends on this directory. Run the Python commands from the repository
root with the package installed (see the top-level README). `capture.sh` needs no Python, but it does need
a Linux Docker host with BIND's `dig` and `delv`, because it queries the containers' addresses directly:

| Command | Writes | Measures |
|---|---|---|
| `python -m measure.sizes > measure/results/sizes.md` | `sizes.md` | RDATA, RR and UDP answer size of every example record; totals for a pallet |
| `python -m measure.bundles > measure/results/bundles.md` | `bundles.md` | offline bundle sizes for four trust-anchor placements and two key layouts; fits in an NFC tag and in QR codes |
| `python -m measure.recipients > measure/results/recipients.md` | `recipients.md` | what each added HPKE recipient costs, and how many fit one UDP answer |
| `python -m measure.pq > measure/results/pq.md` | `pq.md` | bundle sizes if zones signed with ML-DSA-65 |
| `measure/capture.sh hospital > measure/results/capture-hospital.txt` (or `pouch`) | `capture-*.txt` | what `dig` and `delv` see against the Compose hierarchy: sizes, truncation, TCP, validation |

## The records and the bundles

Fifteen records are measured: the emblem and endorsement of each example that a person might carry
or a validator fetch (hospital, product family, three variants, one item, a pallet's ISPM 15 data, the
consignment, a pouch, a badge, the mission, a convoy position, and the three endorsements). The
answer is the whole UDP response as dnspython serializes it: header, question, the RRset, its RRSIG and
an EDNS OPT record, with name compression.

A bundle is the answer and the DNSKEY and DS records, with their signatures, that lead to a trust
anchor, serialized as uncompressed resource records (diem/bundle.py). The four anchor placements are
the root; the top-level domain; the issuer's own zone (the zone that holds the `_diem` delegation); and the
zone that holds the emblem. The zones of this code are signed with one key each, used for every RRset;
`bundles.md` therefore also gives the sizes with a separate zone-signing key (one more DNSKEY in every
set), which is how many deployed zones are signed. A stapled endorsement inside the hospital emblem is
part of its record, and its chain is anchored at the root whatever the bundle's own anchor.

QR capacities are those of a version-40 code in byte mode (L 2,953, M 2,331, Q 1,663, H 1,273
octets); an NFC tag is taken to hold 888 octets (NTAG216).

## Post-quantum sizes

Every key of a post-quantum zone becomes a real ML-DSA-65 key (1,952 octets) and every signature by such a zone a real
ML-DSA-65 signature (3,309 octets), under the private-use algorithm number 253; the DS record of a post-quantum
child is made over its new key. The signature is over the RDATA of the RRset, not the signed data of RFC 4034, because
only the sizes are measured and nothing validates algorithm 253. (A real private algorithm also prefixes keys and
signatures with a domain name, RFC 4034 appendix A.1.1; the few octets that adds are not counted.)

## Recipients

One recipient gets a COSE_Encrypt0 (HPKE integrated encryption); two or more get a COSE_Encrypt whose content
key is sealed to each (HPKE key encryption). `recipients.md` seals the draft's valuation and parties to up to six
recipients, and the pouch's courier and the convoy's position likewise, and reports the whole-emblem answer against
the 1,232-octet payload of DNS Flag Day 2020.

## Versions

The results in `results/` were produced in November 2026 on Debian 13 (Linux 6.x) with Python
3.13.5, cbor2 6.3.0, cryptography 50.0.2, dnspython 2.9.2, pyhpke 0.6.5; and for the captures Docker
Engine 29.10.0, Compose 5.8.0, Knot DNS 3.6.2 and Unbound 1.26.2 (`compose.yaml`), and BIND's `dig` and `delv`
9.20.30. HPKE encapsulation and the salt of a valuation are random, so the sizes of encrypted values are exact but
their bytes differ from run to run.

`delv` validates against the host's clock, while the zones are signed as of each example's date. Its line in a
capture therefore says "fully validated" only for about two weeks after that date (the top-level domain signs for
14 days); re-run later, it reports a broken trust chain. The `dig` lines do not depend on the date.
