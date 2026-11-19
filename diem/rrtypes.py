"""The resource record types of the strawman.   # draft: #encoded

EMBLEM and ENDORSE have no assigned type codes, so private-use numbers stand
in for them, as in the draft's Encoded Example.
"""

import dns.rdata
import dns.rdataclass
import dns.rdatatype

EMBLEM = 65280
ENDORSE = 65281
_NAMES = {"EMBLEM": EMBLEM, "ENDORSE": ENDORSE}


def number(name):
    """The type number for a name such as "EMBLEM" or "DNSKEY"."""
    return _NAMES.get(name) or dns.rdatatype.from_text(name)


def text(rdtype):
    for name, candidate in _NAMES.items():
        if candidate == rdtype:
            return name
    return dns.rdatatype.to_text(rdtype)


def rdata(rdtype, data):
    """The RDATA of a record of a type this library has no class for."""
    return dns.rdata.from_wire(dns.rdataclass.IN, rdtype, data, 0, len(data))
