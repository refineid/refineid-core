# FINEID specifications

The specifications these crates are traced to, with links to the current
published documents. The full index, including every prior version, is on
the DVV [FINEID specifications](https://dvv.fi/en/fineid-specifications)
page; the per-generation card versions are in the
[supported cards](supported-cards.md) reference.

Code comments and the provenance record cite these by document and section
number rather than by URL, so a citation stays valid as a document is
revised; this page resolves those names to the documents.

## DVV FINEID documents

- [FINEID S1 v4.2](https://dvv.fi/documents/16079645/17324992/S1v42_v1.2.pdf)
  -- Electronic ID Application (citizen eID): VERIFY, the MSE/PSO signing
  and decipher choreography, CHANGE REFERENCE DATA and RESET RETRY
  COUNTER, and the algorithm-reference tables.
- [FINEID S4-1 v4.2](https://dvv.fi/documents/16079645/17324992/S4-1v42.pdf)
  -- Implementation profile 1 (citizen eID): key references and PIN
  lengths. The card generations implement earlier versions (v3.0, v3.1,
  v4.0); see the supported-cards reference.
- [FINEID S4-2 v4.0](https://dvv.fi/documents/16079645/17324992/S42_v4_0.pdf)
  -- Implementation profile 2 (organizational usage): the organizational
  credential and key numbering.
- [FINEID S2 v5.2](https://dvv.fi/documents/16079645/17324992/S2v52.pdf)
  -- the certificate and directory profile behind the on-card CA
  certificates.
- [Gixel IAS ECC v1.0.1](https://dvv.fi/documents/16079645/17324992/IAS+ECC+v1_0_1UK.pdf)
  -- the IAS-ECC card specification; the organizational card's local
  security-data-object key reference follows its section 4.4.
- [ICAO Doc 9303 Part 11](https://dvv.fi/documents/16079645/17324992/ICAO_9303_p11_cons_en.pdf)
  -- the PACE protocol and secure messaging.
- [Technology note -- ATR bytes](https://dvv.fi/documents/16079645/17324992/Technology+note+-+ATR+bytes.pdf)
  -- the card ATR/ATS catalog behind the supported-cards reference.

## External standards

Cited by identifier, published by their standards bodies rather than DVV:
ISO/IEC 7816 (parts 3, 4, 5, 8, and 15); BSI TR-03110-3 (PACE); RFC 5639
(brainpoolP384r1); NIST SP 800-38A and 800-38B (the AES and CMAC
known-answer vectors); and RFC 5280, RFC 5480, and RFC 8017 (X.509,
elliptic-curve subject public keys, and PKCS#1).
