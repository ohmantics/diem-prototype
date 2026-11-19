"""The examples of draft-ietf-cose-hpke-27 (Section 5) decrypt, and our own values round-trip.   # draft: #confidentiality"""

import pytest

from diem import cbor, cose_hpke

PLAINTEXT = b"This is the content.\n"  # the draft's vectors include the newline

# Section 5.1: COSE_Encrypt0, suite HPKE-0, recipient "bob".
ENCRYPT0 = (
    "d08344a1011823a20443626f622358410457229bdd99407b384a9e59fa15"
    "53224d58b106e9ebebdaa06d2126bd96757674847669966ecb0dcdf21af5"
    "623f19f0b799b0cddf3ee930b739dd474f6282de0158253f3c1595e9d252"
    "e816215a9ce73f47ba4b57acb06ecc39ca5a03a14108bbe7807af5688d61"
)
BOB_ENCRYPT0 = "eca39300147c91a2a65d17e00ea278b57a14178245bf5686d9a404cca1816b8e"

# Section 5.2: COSE_Encrypt, HPKE-0-KE to recipient "bob", content AES-128-GCM.
ENCRYPT = (
    "d8608443a10101a1055089115f10ecc1c7fd834442cb87929bc15825534d"
    "b92f5366e3cadd096774a9576bb8d8867e75ea38c329ecfc7b8793c5a4ae"
    "9603e5b0b6818349a201182e0443626f62a12358410417cd85837981ddb1"
    "4963061ab5fb7308988eb922f87cf6cf6ef83556f7657922c9815947e41b"
    "9bc932e48c6f1c4677d9a5506a30d694587628b5193a4cde2f3f58204b50"
    "8a340e463c317f4e62fb8d08c887cac4788087ad022562d05855a50ca4a0"
)
BOB_ENCRYPT = "b1162c568efcba91c8e4e82f66e36b45aa10bc55228cf65ecd3bb29cfb09f989"


def open_draft_example(hexed, d):
    item = cbor.decode(bytes.fromhex(hexed))
    kid = cose_hpke.recipients_of(item.tag, item.value)[0]
    assert kid == b"bob"
    return cose_hpke.decrypt(item.tag, item.value, kid, bytes.fromhex(d))


def test_the_draft_encrypt0_example_decrypts():
    assert open_draft_example(ENCRYPT0, BOB_ENCRYPT0) == PLAINTEXT


def test_the_draft_encrypt_example_decrypts():
    assert open_draft_example(ENCRYPT, BOB_ENCRYPT) == PLAINTEXT


@pytest.mark.parametrize("recipients", [1, 2])
def test_our_values_round_trip_for_each_recipient(recipients):
    keys = [cose_hpke.key_pair(bytes([n])) for n in range(recipients)]
    given = [(bytes([n]), public) for n, (public, _) in enumerate(keys)]
    aad = b"emblem and key"
    if recipients == 1:
        tag, cose = 16, cose_hpke.encrypt0(PLAINTEXT, *given[0], aad)
    else:
        tag, cose = 96, cose_hpke.encrypt(PLAINTEXT, given, aad)
    for (kid, _), (_, private) in zip(given, keys):
        assert cose_hpke.decrypt(tag, cose, kid, private, aad) == PLAINTEXT
    with pytest.raises(cose_hpke.CannotDecrypt):
        cose_hpke.decrypt(tag, cose, given[0][0], keys[0][1], b"another emblem")
