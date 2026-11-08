# Test vectors

Fixtures used only by `#[cfg(test)]` code in this crate.
They are **not** trust anchors and must never be loaded by production code.
The only certificates the crate ships are the EU list-signing certificates in `../trust-anchors/`.

## `dvv-gov-root-ca-g3-ecc.der` and `dvv-gov-root-ca-g3-rsa.der`

The two public DVV *Gov. Root CA - G3* certificates (ECC and RSA), from
`proxy.fineid.fi/ca/dvvroot3ec.crt` and `proxy.fineid.fi/ca/dvvroot3rc.crt` (FINEID S2 section 8.5).
Test fixtures only: they are not shipped anchors, and no production path loads them.
The chain tests use the ECC root as the approved anchor above the intermediate below and the RSA root as an unrelated self-signed certificate;
other tests use either as a well-formed certificate with a real subject.

## `sectigo-qualified-time-stamping-root-r45.der`

The self-signed *Sectigo Qualified Time Stamping Root R45* certificate.
Test fixture only, not a shipped anchor: the timestamp-path tests use it as the self-issued certificate that ends an embedded chain.

## `fineid-intermediate-01-citizen-g4e.der`

The DVV *Citizen Certificates - G4E* intermediate CA,
byte-for-byte identical to `platform/apple/RefineID/Resources/fineid-intermediate-01-citizen-g4e.der`
(verify with `shasum -a 256`).
Copied here so the `cert_chain` tests can build a real two-link chain without reaching outside the crate directory:

- leaf  = this intermediate (`ecdsa-with-SHA384`, EC P-384)
- issuer = `dvv-gov-root-ca-g3-ecc.der` (self-signed root)

The intermediate's `issuer` DN is byte-identical to the ECC root's `subject` DN,
and the root's key verifies the intermediate's signature,
so `walk_chain` resolves the issuer from the pool and exercises the real ECDSA-P384/SHA-384 chain-verify path.

## `sectigo-qualified-tsa-signer-3.der` and `sectigo-qualified-tsa-ca-r35.der`

The Sectigo *Qualified Time Stamping Signer #3* leaf certificate and *Qualified Time Stamping CA R35*
intermediate CA certificate embedded in RFC 3161 tokens from `http://timestamp.sectigo.com/qualified`.
Copied here so timestamp chain verification tests can exercise the full 3-certificate chain
(`Signer #3` -> `CA R35` -> `sectigo-qualified-time-stamping-root-r45.der`) offline without network access.


## `icao-pkd-un-csca-2.pem`

The self-signed *United Nations CSCA* root certificate (RSA, `sha256WithRSAEncryption`) from the ICAO PKD.
The `verify` tests use it as a public RSA-PKCS1v15-SHA256 accept case:
a self-signed certificate's signature verifies under its own key over its own TBS bytes, so no private key is needed.

## `verification-stamp-{finnish,swedish,english}.txt`

The verification stamp's content stream for each middle-line language, as `pades::prepare` renders it,
with the random tilt's rotation line left out.
The `stamp` tests compare every other operator line verbatim, so any change to the mark's geometry,
glyph placement or text shows up as a fixture difference to review.
