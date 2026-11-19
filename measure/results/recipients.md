# Cost of recipients

Generated with Python 3.13.5, cbor2 6.3.0, cryptography 50.0.2, dnspython 2.9.2, pyhpke 0.6.5.

| recipients | valuation (octets) | parties (octets) | consignment RDATA, both fields | answer, both fields | answer, valuation only |
|---:|---:|---:|---:|---:|---:|
| 1 | 347 | 384 | 1237 | 1431 | 1431 |
| 2 | 522 | 559 | 1587 | 1781 | 1606 |
| 3 | 641 | 678 | 1825 | 2019 | 1725 |
| 4 | 760 | 797 | 2063 | 2257 | 1844 |
| 5 | 879 | 916 | 2301 | 2495 | 1963 |
| 6 | 998 | 1035 | 2539 | 2733 | 2082 |

One recipient is a COSE_Encrypt0; two or more are a COSE_Encrypt.
Each recipient after the second adds 119 octets to a field (the first step, from Encrypt0 to Encrypt, adds 175).
Even with one recipient, the consignment answer exceeds 1232 octets, whether both fields or only the valuation are sealed.
Without the pinning digests and the salt, the consignment answer (not the RDATA) to one recipient per field is 1237 octets.

UDP answer for the whole emblem, as one field goes to more recipients:

| field | 1 recipient | 2 recipients | 3 recipients | 4 recipients | 5 recipients | 6 recipients | most that fit |
|---|---:|---:|---:|---:|---:|---:|---:|
| pouch, courier | 582 | 757 | 876 | 995 | 1114 | 1233 | 5 |
| convoy position, position | 395 | 570 | 689 | 808 | 927 | 1046 | 6 |

A recipient's published key (a recipient-key emblem): 110 octets of RDATA.
