"""Step 3 of the validation outline: DNSSEC.   # draft: #validation, #offline

The validator does not rely on a resolver's AD bit, which is a judgment made
once that cannot be re-examined. It takes the RRsets and signatures in a
bundle, or collected by a resolver, and checks every signature itself, all
as of one instant, `now`: signatures can expire between queries, and a
bundle's life is that of the shortest signature in it. Bogus data is a
failure, never a partial result, and every failure carries a readable reason.

This is a small validator written to show the draft's steps, not a complete
implementation of RFC 4035. It handles what the examples publish: one
algorithm (ECDSA P-256), signed delegations, and NSEC3 with the parameters
of RFC 9276. It does not handle unsigned delegations, NSEC, wildcard
expansion, CNAME or DNAME, key flags such as REVOKE, or an algorithm policy.
A real validator would use a complete DNSSEC library.
"""

from dataclasses import dataclass, field

import dns.dnssec
import dns.name
import dns.rdataset
import dns.rdatatype as rdatatype

from diem import denial, rrtypes, times


class Bogus(Exception):
    """Data that fails DNSSEC validation; the message says why."""


class Expired(Bogus):
    """Signatures that were good once, and have run out."""


def _text(name):
    return "the root" if name == dns.name.root else name.to_text()


class Checker:
    def __init__(self, bundle, anchor, now):
        self.bundle, self.anchor, self.now = bundle, anchor, now
        self.path, self.expires, self.trusted = [], None, {}

    def rrset(self, name, rdtype):
        rrset, signatures = self.bundle.get(name, rdtype)
        if rrset is None:
            raise Bogus(
                f"the chain has no {rrtypes.text(rdtype)} records for {_text(name)}"
            )
        signer = self._signer(rrset, signatures)
        if not rrset.name.is_subdomain(signer):
            raise Bogus(
                f"the {rrtypes.text(rdtype)} records of {_text(name)} are signed by "
                f"{_text(signer)}, a zone they are not in"
            )
        self._check(rrset, signatures, signer, self._zone_keys(signer))
        return rrset

    def absence(self, qname, qtype):
        sets = self.bundle.rrsets_of_type(rdatatype.NSEC3)
        if not sets:
            raise Bogus(
                "the answer has neither the records nor a proof that they do not exist"
            )
        zone = self._signer(*sets[0])
        if not qname.is_subdomain(zone):
            raise Bogus(
                f"the NSEC3 records are from {_text(zone)}, which cannot speak for "
                f"{qname.to_text()}"
            )
        for rrset, signatures in sets:
            if rrset.name.parent() != zone or self._signer(rrset, signatures) != zone:
                raise Bogus(f"the NSEC3 records are not all from {_text(zone)}")
            self._check(rrset, signatures, zone, self._zone_keys(zone))
        proved = denial.prove([rrset for rrset, _ in sets], zone, qname, qtype)
        if proved is None:
            raise Bogus(
                f"the NSEC3 records do not prove that {qname.to_text()} is absent"
            )
        return proved

    def _signer(self, rrset, signatures):
        if signatures is None:
            raise Bogus(
                f"the {rrtypes.text(rrset.rdtype)} records of {_text(rrset.name)} "
                "are not signed"
            )
        return signatures[0].signer

    def _zone_keys(self, zone):
        """The DNSKEY records of a zone that lead back to the trust anchor."""
        if zone not in self.trusted:
            keys, signatures = self.bundle.get(zone, rdatatype.DNSKEY)
            if keys is None:
                raise Bogus(f"the chain has no DNSKEY records for {_text(zone)}")
            delegation = self._delegation(zone)
            trusted = [
                key for key in keys if any(_matches(zone, key, ds) for ds in delegation)
            ]
            if not trusted:
                raise Bogus(
                    f"no key of {_text(zone)} matches the DS record that names it"
                )
            self._check(
                keys, signatures, zone, dns.rdataset.from_rdata_list(keys.ttl, trusted)
            )
            self.trusted[zone] = keys
            self.path.append(zone)
        return self.trusted[zone]

    def _delegation(self, zone):
        """The DS records for a zone: the trust anchor for the root, else its DS RRset."""
        if zone == dns.name.root:
            return self.anchor
        ds, signatures = self.bundle.get(zone, rdatatype.DS)
        if ds is None:
            raise Bogus(
                f"the chain has no DS record for {zone.to_text()}, "
                "so it is not securely delegated"
            )
        parent = self._signer(ds, signatures)
        if parent == zone or not zone.is_subdomain(parent):
            raise Bogus(
                f"the DS record for {zone.to_text()} is signed by {_text(parent)}, "
                "not by a zone above it"
            )
        self._check(ds, signatures, parent, self._zone_keys(parent))
        return ds

    def _check(self, rrset, signatures, zone, keys):
        """Check the signatures on an RRset with keys already validated for zone."""
        what = f"{rrtypes.text(rrset.rdtype)} records of {_text(rrset.name)}"
        if signatures is None:
            raise Bogus(f"the {what} are not signed")
        current = [
            sig for sig in signatures if sig.inception <= self.now <= sig.expiration
        ]
        if not current:
            problem = _out_of_date(what, signatures, self.now)
            raise (
                Expired if self.now > max(s.expiration for s in signatures) else Bogus
            )(problem)
        try:
            dns.dnssec.validate(
                rrset, signatures, {zone: keys}, now=self.now
            )
        except dns.dnssec.ValidationFailure as failure:
            raise Bogus(f"the signature on the {what} does not verify") from failure
        expiry = min(sig.expiration for sig in current)
        self.expires = expiry if self.expires is None else min(self.expires, expiry)


def _out_of_date(what, signatures, now):
    latest = max(sig.expiration for sig in signatures)
    if now > latest:
        return f"the signature on the {what} expired at {times.moment(latest)}"
    first = min(sig.inception for sig in signatures)
    return f"the signature on the {what} is not valid until {times.moment(first)}"


def _matches(zone, key, ds):
    """Does this DS record (or trust anchor) name this key?"""
    made = dns.dnssec.make_ds(zone, key, dns.dnssec.DSDigest(ds.digest_type))
    return made.key_tag == ds.key_tag and made.digest == ds.digest


@dataclass
class Chain:
    # "secure"; "unsigned" (the answer carries no signatures at all, which a profile
    # may accept); or "bogus" (signatures that fail, which is always treated as absent).
    # "unsigned" is not RFC 4035's "insecure": this code does not look for a proof that
    # the zone is unsigned, so it cannot tell an unsigned zone from signatures stripped
    # in transit, and a profile that accepts unsigned emblems accepts that downgrade.
    status: str
    reason: str = ""
    expired: bool = False  # bogus because its signatures have run out
    path: tuple = ()  # the zones from the root down whose keys were validated
    rrset: object = None  # the answer, as received
    absent: str = ""  # "nxdomain" or "nodata" if the zone proves nothing is there
    expires: int = 0  # when the first of the signatures relied on expires
    # zone -> the DNSKEY RRset validated for it
    keys: dict = field(default_factory=dict)

    @property
    def secure(self):
        return self.status == "secure"

    def describe(self):
        zones = " > ".join(
            "root" if zone == dns.name.root else zone.to_text(omit_final_dot=True)
            for zone in self.path
        )
        return f"secure: {zones}; signatures good until {times.moment(self.expires)}"


def verify(answer, anchor, now):
    """Check an answer against the trust anchor (DS records of the root's key) at now."""
    checker = Checker(answer.bundle, anchor, now)
    rrset, signatures = answer.bundle.get(answer.name, answer.rdtype)
    if answer.status == "answer" and signatures is None:
        return Chain("unsigned", "the emblem records are not signed", rrset=rrset)
    try:
        if answer.status == "answer":
            checker.rrset(answer.name, answer.rdtype)
            absent = ""
        else:
            absent = checker.absence(answer.name, answer.rdtype)
    except Bogus as problem:
        return Chain(
            "bogus", str(problem), rrset=rrset, expired=isinstance(problem, Expired)
        )
    return Chain(
        "secure",
        path=tuple(checker.path),
        rrset=rrset,
        absent=absent,
        expires=checker.expires,
        keys=checker.trusted,
    )
