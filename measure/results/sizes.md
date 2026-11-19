# Sizes of the example records (octets)

Generated with Python 3.13.5, cbor2 6.3.0, cryptography 50.0.2, dnspython 2.9.2, pyhpke 0.6.5.

| record | type | RDATA | RR on the wire | answer (serialized) | fits 1232 |
|---|---|---:|---:|---:|---:|
| hospital emblem | EMBLEM | 1937 | 1979 | 2126 | NO |
| hospital endorsement | ENDORSE | 113 | 185 | 328 | yes |
| product family | EMBLEM | 120 | 161 | 305 | yes |
| variant std | EMBLEM | 81 | 126 | 270 | yes |
| variant pro | EMBLEM | 85 | 130 | 274 | yes |
| variant max | EMBLEM | 85 | 130 | 274 | yes |
| item | EMBLEM | 69 | 112 | 256 | yes |
| ispm15 pallet | EMBLEM | 59 | 108 | 254 | yes |
| ispm15 endorsement | ENDORSE | 73 | 142 | 282 | yes |
| consignment | EMBLEM | 1587 | 1633 | 1781 | NO |
| pouch | EMBLEM | 381 | 436 | 582 | yes |
| badge | EMBLEM | 86 | 137 | 283 | yes |
| mission emblem | EMBLEM | 63 | 96 | 242 | yes |
| mission endorsement | ENDORSE | 158 | 225 | 375 | yes |
| convoy position | EMBLEM | 374 | 422 | 574 | yes |

- 1,400 item emblems: 96,600 octets of RDATA (96.6 KB).
- Family, three variants, consignment and pallet: 2,017 octets of RDATA.
- Everything above, once: 98,617 octets of RDATA (98.6 KB).
- The consignment's encrypted fields: valuation 522, parties 559

## The consignment emblem under four encodings

- **a**: as in the example: valuation and parties each a COSE_Encrypt to every recipient; reference digests, valuation digest, salt.
- **b**: as a, without the four reference digests (optional in the draft).
- **c**: valuation and parties in one COSE_Encrypt to every recipient (one content key, one recipient list); no reference digests; valuation digest and salt kept.
- **d**: as c, without the valuation digest and the salt.

RDATA in octets by number of recipients; a UDP answer adds 194 octets to the RDATA (header, question, owner names, RRSIG, EDNS), and must stay within 1232.

| variant | 1 | 2 | 3 | 4 | answer at 1 | most recipients that fit (of 8) | each added recipient |
|---|---:|---:|---:|---:|---:|---:|---:|
| a | 1237 | 1587 | 1825 | 2063 | 1431 | none | +238 |
| b | 1097 | 1447 | 1685 | 1923 | 1291 | none | +238 |
| c | 1010 | 1185 | 1304 | 1423 | 1204 | 1 | +119 |
| d | 957 | 1132 | 1251 | 1370 | 1151 | 1 | +119 |

One recipient is a COSE_Encrypt0; two or more are a COSE_Encrypt. The last column is the cost of the third recipient.
