"""Confidential values inside signed emblems.   # draft: #confidentiality

Some values are for a few readers only. The issuer encrypts them to the HPKE
keys of the recipients its profile names (diem/cose_hpke.py), and publishes
the ciphertext in the emblem, so DNSSEC signs what everyone sees and only a
recipient can read it, whichever server or cache the record came from.

A recipient is a party whose role a profile names in advance (origin and
destination customs, a receiving state, an operations center); it publishes its
HPKE public key in its own zone, so that an issuer can find it.

Each ciphertext is bound to its emblem and map key, so that it cannot be
moved to another emblem or field. A profile may also ask for a salted digest
of the plaintext beside the ciphertext, so that a recipient can later prove
to a third party what the issuer published. The salt is a member of the
plaintext, and so it is disclosed only with it.
"""

import hashlib
from dataclasses import dataclass

from diem import cbor, cose_hpke, dnssec, emblem, names
from diem.values import Encrypted, validity


@dataclass(frozen=True)
class Recipient:
    name: str  # the zone in which the recipient publishes its key
    kid: bytes
    public: bytes
    private: bytes = b""  # held by the recipient alone


def recipient(name):
    """A recipient of the test world, whose keys come from its name (and so are worthless)."""
    public, private = cose_hpke.key_pair(f"recipient {name}".encode())
    return Recipient(name, hashlib.sha256(name.encode()).digest()[:8], public, private)


def key_record(who, not_before, not_after):
    """The emblem in which a recipient publishes its public key, in its own zone."""
    return {
        "profile": "recipient-key",
        "asset": who.name,
        "key-id": who.kid,
        "cose-alg": cose_hpke.HPKE_0,
        "public-key": who.public,
        "valid": validity(not_before, not_after),
    }


def public_key(name, owner, source, anchor, now):
    """A recipient's public key as its zone publishes it, validated with DNSSEC,
    for the recipient it names, and current at now."""
    chain = dnssec.verify(source.fetch(owner, "EMBLEM"), anchor, now)
    if not chain.secure or chain.absent:
        raise ValueError(f"no validated key for {name} at {owner}")
    for rdata in chain.rrset:
        record = emblem.from_cbor(rdata.data)
        if record.get("profile") != "recipient-key":
            continue
        if names.normalize(record["asset"]) != names.normalize(name):
            raise ValueError(f"the key at {owner} is for {record['asset']}, not {name}")
        start, end = (moment.seconds for moment in record["valid"])
        if not start <= now <= end:
            raise ValueError(f"the key for {name} at {owner} is not valid at this time")
        return Recipient(name, record["key-id"], record["public-key"])
    raise ValueError(f"no recipient-key record for {name} at {owner}")


# Encrypting and decrypting.


def binding(asset, key):
    # The external AAD of the COSE structure: the emblem and map key it belongs to.
    return cbor.encode(["DIEM", names.normalize(asset), key])


def encrypt(plaintext, key, asset, recipients):
    """The encrypted value for a map key of an emblem: one recipient or several."""
    data = emblem.to_cbor(plaintext, (key,))
    aad = binding(asset, key)
    if len(recipients) == 1:
        return Encrypted(
            16, cose_hpke.encrypt0(data, recipients[0].kid, recipients[0].public, aad)
        )
    return Encrypted(
        96, cose_hpke.encrypt(data, [(r.kid, r.public) for r in recipients], aad)
    )


def salted_digest(plaintext, key):
    """The digest an issuer publishes beside an encrypted value; the plaintext holds the salt."""
    return hashlib.sha256(emblem.to_cbor(plaintext, (key,))).digest()


@dataclass
class Reading:
    result: str  # "ok", "invalid" or "indeterminate"
    text: str
    opened: dict  # map key -> plaintext


def read(record, task):
    """Step 9: read the encrypted values this validator holds a key for, and the task needs."""
    opened, unread, holders = {}, [], set()
    for key, value in record.items():
        if not isinstance(value, Encrypted):
            continue
        held = _held(value, task.keys)
        if held is None and key in task.needs:
            return Reading(
                "indeterminate",
                f"{_quoted([key])} is encrypted, and this validator holds no key it is encrypted to",
                {},
            )
        if held is None:
            unread.append(key)
            continue
        plaintext, problem = decrypt(record, key, value, held, task.profile)
        if problem:
            return Reading("invalid", f"{_quoted([key])}: {problem}", {})
        opened[key] = plaintext
        holders.add(held.name)
    return Reading("ok", _describe(opened, holders, unread, task), opened)


def _held(value, keys):
    kids = cose_hpke.recipients_of(value.tag, value.cose)
    return next((key for key in keys if key.kid in kids), None)


def decrypt(record, key, value, held, policy):
    """(the plaintext, or None; a sentence about what is wrong with it, or None)."""
    try:
        data = cose_hpke.decrypt(
            value.tag,
            value.cose,
            held.kid,
            held.private,
            binding(record["asset"], key),
        )
        plaintext = emblem.from_cbor(data, (key,))
    except (cose_hpke.CannotDecrypt, ValueError) as error:
        return None, str(error)
    problems = policy.check_types(plaintext, key)
    if problems:
        return None, "; ".join(problems)
    if key in policy.digested and record.get(f"{key}-digest") != salted_digest(
        plaintext, key
    ):
        return (
            None,
            "the plaintext is not the one the digest published beside it covers",
        )
    return plaintext, None


def _quoted(keys):
    """Map keys as a sentence names them: "valuation" and "parties"."""
    return " and ".join(f'"{key}"' for key in keys)


def _describe(opened, holders, unread, task):
    parts = []
    if opened:
        digests = [key for key in opened if key in task.profile.digested]
        who = " and ".join(sorted(holders))
        parts.append(
            f"{_quoted(opened)} decrypted with the key of "
            f"{who}; every value has its type"
            + (f"; the digest of {_quoted(digests)} matches" if digests else "")
        )
    if unread:
        are = "is" if len(unread) == 1 else "are"
        parts.append(
            f"{_quoted(unread)} {are} encrypted, and this task does not need to read {'it' if len(unread) == 1 else 'them'}"
        )
    return "; ".join(parts) or "nothing is encrypted"
