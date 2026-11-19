# Post-quantum bundle sizes (octets)

Generated with Python 3.13.5, cbor2 6.3.0, cryptography 50.0.2, dnspython 2.9.2, pyhpke 0.6.5.

| zones signed with ML-DSA-65 | smallest | largest | the largest is | fit NFC |
|---|---:|---:|---|---:|
| all zones, anchored at the root, separate KSK and ZSK | 32298 | 65633 | hospital emblem | 0 |
| all zones, anchored at the issuer zone, separate KSK and ZSK | 10892 | 44225 | hospital emblem | 0 |
| only the issuer's zones, anchored at the root, separate KSK and ZSK | 11600 | 24237 | hospital emblem | 0 |
| all zones, anchored at the issuer zone, one key per zone | 8909 | 36309 | hospital emblem | 0 |

Of 15 bundles. One ML-DSA-65 signature is 3,309 octets and one key 1,952.
