"""Domain names as the draft compares them.   # draft: #discovery, #endorsement

Names are compared in A-label form, lowercase and without a trailing dot, so
internationalized names are carried as A-labels in emblems.
"""

import base64
import hashlib


def normalize(name):
    if not name.isascii():
        raise ValueError(f"{name!r} is not in A-label form")
    return name.lower().rstrip(".")


def endorsement_name(authority, issuer):
    """Where an authority publishes its endorsement of an issuer.

    The label is a digest of the issuer's name, so that the authority's list
    of endorsed issuers cannot be listed directly, while a validator that knows
    the issuer can find the endorsement. Anyone who guesses an issuer can confirm
    the endorsement too, since a hash of a public name can be dictionary-tested.
    """
    digest = hashlib.sha256(normalize(issuer).encode()).digest()[:20]
    label = base64.b32hexencode(digest).decode().lower()
    return f"{label}._endorse.{normalize(authority)}"


# the label an issuer's emblem names sit under (draft #discovery)
EMBLEM_LABEL = "_diem"


def emblem_zone(emblem_name):
    """The zone an issuer's emblems sit in: sn-1._diem.maker.example is in _diem.maker.example."""
    labels = normalize(emblem_name).split(".")
    if EMBLEM_LABEL not in labels:
        return ""
    return ".".join(labels[labels.index(EMBLEM_LABEL) :])


def absolute(reference, emblem_name):
    """The name a reference points to.

    A reference with a _diem label is already absolute; any other is relative to
    the emblem zone of the emblem that makes it, and so cannot lead outside the
    issuer's zone (draft #hierarchy).
    """
    reference = normalize(reference)
    if EMBLEM_LABEL in reference.split("."):
        return reference
    return f"{reference}.{emblem_zone(emblem_name)}"


def facet_name(emblem_name, label):
    """Where a dynamic facet of an emblem is published: c-1._diem.x.example is
    c-1._live._diem.x.example for the label _live."""
    head, _, rest = normalize(emblem_name).partition(f".{EMBLEM_LABEL}.")
    return f"{head}.{label}.{EMBLEM_LABEL}.{rest}"
