"""COSE encryption to HPKE recipients.   # draft: #confidentiality

An encrypted value is a COSE structure (RFC 9052) whose recipients hold HPKE
keys, as draft-ietf-cose-hpke-27 defines. One recipient gets a COSE_Encrypt0
(HPKE integrated encryption); several get a COSE_Encrypt, whose content key
is sealed to each of them (HPKE key encryption). Only one suite is used:
DHKEM(P-256, HKDF-SHA256) with AES-128-GCM. The numbers are the draft's
"assumed" algorithm values, which IANA has not yet assigned.

Keys here are raw: an uncompressed P-256 point to encrypt to, and the
private scalar to decrypt.
"""

import hashlib
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from diem import cbor

HPKE_0 = 35  # integrated encryption: one recipient
HPKE_0_KE = 46  # key encryption: any number of recipients
A128GCM = 1
ALG, KID, IV, EK = 1, 4, 5, -4  # COSE header labels; "ek" is the encapsulated key
SUITE = CipherSuite.new(
    KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM
)


class CannotDecrypt(Exception):
    """The message says why the value could not be decrypted."""


def key_pair(seed):
    """(public, private) as raw bytes: an uncompressed point and a 32-octet scalar.

    The private key is derived from the seed, so it is a deterministic
    demonstration key: worthless, and not for real use.
    """
    scalar = int.from_bytes(hashlib.sha256(seed).digest(), "big") % 2**250 + 1
    point = (
        ec.derive_private_key(scalar, ec.SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
    )
    return point, scalar.to_bytes(32, "big")


def _private(scalar):
    return SUITE.kem.deserialize_private_key(scalar)


def _enc_structure(context, protected, external_aad):
    # RFC 9052, section 5.3; the external AAD is how a value is bound to its emblem.
    return cbor.encode([context, protected, external_aad])


def encrypt0(plaintext, kid, public, external_aad=b""):
    """A COSE_Encrypt0 body: [protected, unprotected, ciphertext]."""
    protected = cbor.encode({ALG: HPKE_0})
    aad = _enc_structure("Encrypt0", protected, external_aad)
    enc, ciphertext = _seal(public, plaintext, b"", aad)
    return [protected, {KID: kid, EK: enc}, ciphertext]


def encrypt(plaintext, recipients, external_aad=b""):
    """A COSE_Encrypt body for [(kid, public)]: the content is encrypted once, its key to each."""
    key, iv = AESGCM.generate_key(128), os.urandom(12)
    protected = cbor.encode({ALG: A128GCM})
    aad = _enc_structure("Encrypt", protected, external_aad)
    ciphertext = AESGCM(key).encrypt(iv, plaintext, aad)
    return [
        protected,
        {IV: iv},
        ciphertext,
        [_recipient(key, *each) for each in recipients],
    ]


def _recipient(key, kid, public):
    protected = cbor.encode({ALG: HPKE_0_KE, KID: kid})
    enc, wrapped = _seal(public, key, _info(protected), b"")
    return [protected, {EK: enc}, wrapped]


def _seal(public, plaintext, info, aad):
    enc, context = SUITE.create_sender_context(
        SUITE.kem.deserialize_public_key(public), info
    )
    return enc, context.seal(plaintext, aad)


def _open(enc, private, ciphertext, info, aad):
    return SUITE.create_recipient_context(enc, _private(private), info).open(
        ciphertext, aad
    )


def _info(recipient_protected):
    # draft-ietf-cose-hpke section 3.3.1: binds the content algorithm to the recipient.
    return cbor.encode(["HPKE Recipient", A128GCM, recipient_protected, b""])


def recipients_of(tag, cose):
    """The key identifiers a value is encrypted to."""
    if tag == 16:
        return [cose[1][KID]]
    return [cbor.decode(entry[0])[KID] for entry in cose[3]]


def decrypt(tag, cose, kid, private, external_aad=b""):
    """The plaintext for the holder of the private key named kid; CannotDecrypt if it fails."""
    try:
        if tag == 16:
            protected, header, ciphertext = cose
            aad = _enc_structure("Encrypt0", protected, external_aad)
            return _open(header[EK], private, ciphertext, b"", aad)
        return _decrypt_content(cose, kid, private, external_aad)
    except (KeyError, ValueError, IndexError, StopIteration) as error:
        raise CannotDecrypt("the value is malformed") from error
    except Exception as error:  # pyhpke and AES-GCM report a failed tag in several ways
        raise CannotDecrypt(
            "the value does not decrypt: it was altered, or was made for another emblem"
        ) from error


def _decrypt_content(cose, kid, private, external_aad):
    protected, header, ciphertext, recipients = cose
    mine = next(entry for entry in recipients if cbor.decode(entry[0])[KID] == kid)
    key = _open(mine[1][EK], private, mine[2], _info(mine[0]), b"")
    aad = _enc_structure("Encrypt", protected, external_aad)
    return AESGCM(key).decrypt(header[IV], ciphertext, aad)
