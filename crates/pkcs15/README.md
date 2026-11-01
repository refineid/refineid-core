# refineid-pkcs15

PKCS#15 file-system reads for FINEID cards: application and file
selection, bounded binary reads, certificate retrieval as plain DER,
EF.TokenInfo parsing with the typed chip-serial forms, and EF.AOD
parsing into each password object's reference and length range.

The operations layer on any `refineid-apdu` transport as default trait
methods; they issue only replay-safe typed commands. Certificate files and
EF.AOD on FINEID cards are public and need no PIN; nothing in this crate
touches a credential path.

Reader discovery, card-generation classification from certificate
contents, and X.509 parsing are deliberately out of scope; consumers
receive DER bytes and typed serials.

File identifiers and layout are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications)
(S4-1 and S4-2) and ISO/IEC 7816-15.
