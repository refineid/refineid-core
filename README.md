# refineid-core

Platform-independent RefineID protocol core, as a family of small,
separately auditable Rust crates.

RefineID is an open implementation for FINEID electronic identity cards.
This repository is populated in reviewed slices: code is reconstructed at
explicit trust boundaries, tested in isolation, and admitted only when it
starts with zero known policy debt. Platform integration (PC/SC backends,
graphical shells, OS keychain bridges) lives outside this repository; these
crates stay transport-agnostic and country-profile-neutral.

## Crates

- `crates/apdu` (`refineid-apdu`) -- typed ISO 7816-4 commands, status
  words, outgoing command chaining, and the card transport port, with
  separate replay-safe and credential command ownership paths.
- `crates/atr` (`refineid-atr`) -- ISO 7816-3 Answer to Reset parsing as
  a typed structure: transmission convention, offered protocols, and the
  historical bytes.
- `crates/auth` (`refineid-auth`) -- PIN and PUK role types, VERIFY
  PIN1/PIN2 over the credential-command path for both citizen and
  organizational cards, the counter-safe status probe that resolves the
  card's credential numbering, the CHANGE REFERENCE DATA and RESET RETRY
  COUNTER (unblock) chains, and the retry-risk policy.
- `crates/ber` (`refineid-ber`) -- minimal BER-TLV encoder and decoder
  with a typed tag layer.
- `crates/cms` (`refineid-cms`) -- strict-DER CMS `SignedData` parsing and
  offline signature verification, with the RSA and ECDSA verification
  primitives and the X.509 certificate machinery they need. The
  host-side trust checks for card-delivered documents; verify-only by
  design, no key generation and no platform crypto dependency.
- `crates/digest` (`refineid-digest`) -- typed SHA-2 digest values and
  hash-algorithm identifiers with the digest lengths as named constants;
  no key material, no card I/O.
- `crates/emrtd` (`refineid-emrtd`) -- ICAO 9303 eMRTD application file
  reading and parsing (EF.COM inventory, TD1 MRZ, encoded face), and
  passive authentication: EF.SOD signature, data-group hash comparison,
  and the DSC-to-CSCA chain against verifier-supplied trust anchors.
- `crates/pace` (`refineid-pace`) -- Card Access Number input type, the
  PACE handshake, and secure messaging.
- `crates/pin-cache` (`refineid-pin-cache`) -- process-lifetime negative
  PIN cache: a card-rejected PIN is retained only as a keyed fingerprint
  and refused locally, so software never re-offers a known-bad value and
  burns another card retry.
- `crates/pkcs15` (`refineid-pkcs15`) -- PKCS#15 file-system reads:
  selection, bounded reads, certificates as plain DER, EF.TokenInfo, and
  the typed chip-serial forms.
- `crates/rapp` (`refineid-rapp`) -- the transport-independent Remote
  Authorization Proxy Protocol core: offer and pairing lifecycle, the
  mandatory Noise `XXpsk3` handshake and transport cipher, session and
  operation engines, and the optional UniFFI `bindings` surface that
  platform apps link. Transports stay underlays outside the protocol.
- `crates/remote` (`refineid-remote`) -- typed remote-operation vocabulary
  for the Remote Authorization Proxy Protocol (RAPP): the closed profile,
  action, key-profile, and signature-algorithm registries with their
  invariants carried by construction. Names and invariants only; the
  protocol engine lives in `crates/rapp`.
- `crates/sign` (`refineid-sign`) -- card-side private-key operations: the
  MSE/PSO choreography for the pre-hashed RSA (PKCS#1 and PSS) and P-384
  ECDSA signing chains, over both the citizen chain (PSO:HASH then an empty
  PSO:CDS) and the organizational chain (an inline-digest PSO:CDS), plus
  RSA decipher (PSO:DECIPHER over a command-chained cryptogram).
- `crates/x509` (`refineid-x509`) -- SubjectPublicKeyInfo extraction from a
  certificate: classifies the public key (RSA size, or a NIST curve) and
  exposes the SPKI bytes, pairing a certificate with the right signing
  chain. Not certificate validation.

The crate family now covers a full FINEID card session: transport,
reads, PACE, PIN operations, signing, decipher, and the certificate
public key. Later work stays outside this core by design (platform
integration, full X.509 with revocation, document-format signing).

## Security posture

- PIN1, PIN2, and the PUK are distinct non-clonable types.
- PIN2 retention is bounded to a one-minute convenience window measured from
  the last card-confirmed use; the window never extends to PIN management.
- Credential and CAN input are accepted only through explicitly unvalidated,
  zeroize-on-drop boundaries and reconstructed into validated role types.
- Anonymous protocol numbers are rejected. Hexadecimal wire values may appear
  only in a meaningful named constant or an independently audited wire/KAT
  fixture.

Constraints are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications),
[ICAO Doc 9303](https://www.icao.int/publications/doc-series/doc-9303), and
the ISO/IEC 7816 series. See
[credential custody](docs/security/credential-custody.md),
the [core migration policy](docs/architecture/core-migration.md),
[public provenance](docs/governance/public-provenance.md), the
[FINEID specifications](docs/reference/specifications.md), and the
[supported cards](docs/reference/supported-cards.md).

## Build and check

```sh
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run --locked -p xtask -- check-magic-numbers
```

### Managing build cache

Incremental compilation caches and old dependency artifacts in `target/` can grow during local development.

```sh
# Sweep unused artifacts older than 14 days
cargo sweep -t 14

# Clean incremental compilation cache if disk space is needed
find target -type d -name "incremental" -prune -exec rm -rf {} +
```
