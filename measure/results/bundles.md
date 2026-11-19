# Offline bundle sizes (octets)

Generated with Python 3.13.5, cbor2 6.3.0, cryptography 50.0.2, dnspython 2.9.2, pyhpke 0.6.5.

## One key per zone, as the zones of this code are signed

| bundle | root | top-level domain | issuer zone | emblem zone |
|---|---:|---:|---:|---:|
| hospital emblem | 3507 | 3177 | 2797 | 2369 |
| hospital endorsement | 1689 | 1359 | 589 | 589 |
| product family | 1652 | 1322 | 948 | 538 |
| variant std | 1621 | 1291 | 917 | 507 |
| variant pro | 1625 | 1295 | 921 | 511 |
| variant max | 1625 | 1295 | 921 | 511 |
| item | 1605 | 1275 | 901 | 491 |
| ispm15 pallet | 1631 | 1301 | 923 | 501 |
| ispm15 endorsement | 1239 | 909 | 531 | 531 |
| consignment | 3177 | 2847 | 2465 | 2031 |
| pouch | 2351 | 2021 | 1257 | 835 |
| badge | 1662 | 1332 | 954 | 532 |
| mission emblem | 1603 | 1273 | 895 | 473 |
| mission endorsement | 1375 | 1045 | 671 | 671 |
| convoy position | 2426 | 2096 | 1718 | 838 |

Bundles that fit, of 15:

| carrier (octets) | root | top-level domain | issuer zone | emblem zone |
|---|---:|---:|---:|---:|
| NFC tag (888) | 0 | 0 | 3 | 13 |
| QR v40, level L (2953) | 13 | 14 | 15 | 15 |
| QR v40, level M (2331) | 11 | 13 | 13 | 14 |
| QR v40, level Q (1663) | 10 | 11 | 12 | 13 |
| QR v40, level H (1273) | 1 | 3 | 12 | 13 |

## A separate zone-signing key in every zone, as many deployed zones are

| bundle | root | top-level domain | issuer zone | emblem zone |
|---|---:|---:|---:|---:|
| hospital emblem | 3871 | 3462 | 2995 | 2471 |
| hospital endorsement | 2044 | 1635 | 687 | 687 |
| product family | 2010 | 1601 | 1140 | 637 |
| variant std | 1979 | 1570 | 1109 | 606 |
| variant pro | 1983 | 1574 | 1113 | 610 |
| variant max | 1983 | 1574 | 1113 | 610 |
| item | 1963 | 1554 | 1093 | 590 |
| ispm15 pallet | 1993 | 1584 | 1119 | 602 |
| ispm15 endorsement | 1500 | 1091 | 626 | 626 |
| consignment | 3543 | 3134 | 2665 | 2134 |
| pouch | 2804 | 2395 | 1453 | 936 |
| badge | 2024 | 1615 | 1150 | 633 |
| mission emblem | 1965 | 1556 | 1091 | 574 |
| mission endorsement | 1634 | 1225 | 764 | 764 |
| convoy position | 2895 | 2486 | 2021 | 945 |

Bundles that fit, of 15:

| carrier (octets) | root | top-level domain | issuer zone | emblem zone |
|---|---:|---:|---:|---:|
| NFC tag (888) | 0 | 0 | 3 | 11 |
| QR v40, level L (2953) | 13 | 13 | 14 | 15 |
| QR v40, level M (2331) | 11 | 11 | 13 | 14 |
| QR v40, level Q (1663) | 2 | 11 | 12 | 13 |
| QR v40, level H (1273) | 0 | 2 | 11 | 13 |

The hospital emblem carries its endorsement and the chain that validates it inside the record; that stapled chain is anchored at the root whatever the bundle's own anchor.
