# PKCS#11 Architecture, v3.2 Evolution, and OpenPGP Key Certification Plan

This document records the architectural roadmap for the RefineID PKCS#11
subsystem, OASIS PKCS#11 v3.2 interface support, and one-command OpenPGP
key certification using the card's Qualified Signature key (PIN2).

Platform CLI integration lives in `refineid-unix` (`crates/refineid-client`),
driving the transport-agnostic and country-profile-neutral protocol engines in
`refineid-core`.

---

## 1. Guiding Philosophy: No Gatekeeping

RefineID does not act as a gatekeeper restricting how cardholders use their
own cryptographic hardware:

- The smartcard belongs to the cardholder, and both the Authentication key
  (PIN1) and the Qualified Signature key (PIN2) are valid cryptographic
  primitives.
- Middleware must expose both keys safely, transparently, and robustly.
- Security boundaries are enforced through clear token and slot separation
  rather than artificial feature gating.

---

## 2. Two-Flavor PKCS#11 Architecture (`auth` vs. `sign`)

### Problem Statement

Host consumers of PKCS#11 (such as web browsers, email clients, SSH agents,
and GnuPG) often enumerate slots and tokens blindly:

- If both PIN1 (Authentication) and PIN2 (Qualified Signature) keys are
  presented in a single token or shared slot without isolation, applications
  like Firefox or NSS may prompt eagerly for PIN2 during browser startup or
  TLS negotiation.
- Unintended PIN2 prompts confuse cardholders and risk exhausting the card's
  strict 3-attempt PIN2 retry counter.

### Solution: Separate Shared Libraries

`refineid-core` (`crates/pkcs11`) will parameterize the token profile to
produce two distinct `cdylib` artifacts:

1. **`librefineid_pkcs11_auth`**:
   - **Target**: Everyday authentication, web identification, and developer tooling.
   - **Key Reference**: `KEY_REF_AUTH` (PIN1-gated, NIST P-384 or RSA-3072).
   - **Certificate**: Citizen Authentication Certificate (`EF.CD #1` / `EF.4331`).
   - **PIN Policy**: PIN1 (4–12 digits). Short-lived in-memory caching allowed
     within strict process boundaries (§ credential custody).
   - **Consumers**: Firefox/NSS client-certificate TLS, Suomi.fi web login,
     Web-eID, OpenSSH client authentication (`ssh-add -s`).

2. **`librefineid_pkcs11_sign`**:
   - **Target**: Qualified electronic signatures, non-repudiation, and high-assurance
     attestations.
   - **Key Reference**: `KEY_REF_SIGN` (PIN2-gated, NIST P-384).
   - **Certificate**: Qualified Signature Certificate (`EF.CD #2` / `EF.4332`).
   - **PIN Policy**: PIN2 (6–12 digits). Strictly `CKA_ALWAYS_AUTHENTICATE = TRUE`.
     The card chip drops PIN verification after every single signature
     (`userConsent = 1`); zero software caching.
   - **Consumers**: GnuPG (`gnupg-pkcs11-scd`), Sequoia PGP, PDF/PAdES signers,
     and enterprise document signers.

Both libraries share the underlying APDU, BER-TLV, and PC/SC protocol core in
`refineid-core`.

---

## 3. OASIS PKCS#11 Specification Version 3.2 Support

`refineid-pkcs11` was initially implemented against PKCS#11 v2.40. The engine
will be modernized to conform to the
[OASIS PKCS#11 Cryptographic Token Interface Base Specification Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html):

1. **Dynamic Interface Discovery**:
   - Implement `C_GetInterfaceList` and `C_GetInterface` to allow modern consumers
     to query and negotiate specific interface versions (e.g. `"PKCS 11"` `3.2`).
2. **Backward Compatibility**:
   - Continue exposing `C_GetFunctionList` returning the standard PKCS#11 v2.40
     function pointer table, preserving full compatibility with legacy
     consumers (including Firefox NSS).
3. **Fork Safety**:
   - Implement `CKF_FORK_SAFE` semantics so Unix processes that fork after
     `C_Initialize` handle smartcard sessions and PC/SC contexts safely.
4. **Modern Mechanism Metadata**:
   - Report correct mechanism information for `CKM_ECDSA`, `CKM_ECDSA_SHA384`,
     and message-based signing APIs where applicable.

---

## 4. One-Command OpenPGP Certification CLI

To allow cardholders to anchor their daily development identity in their national
eID without dealing with daemon bridging or brittle `scdaemon` configs, a direct
CLI verb will be provided in `refineid-unix` (`crates/refineid-client`):

```sh
refineid card sign-pgp-key <FINGERPRINT_OR_KEYID>
```

### Execution Flow

```text
User executes: refineid card sign-pgp-key <KEY_ID>
  │
  ├─ 1. Query local GnuPG keyring (or path) for the target public key & User ID.
  │
  ├─ 2. Read on-card Qualified Signature Certificate (EF.4332) via refineid-core.
  │     Extract subject name and NIST P-384 public key.
  │
  ├─ 3. Construct canonical OpenPGP certification hash (RFC 4880 / RFC 9580):
  │     SHA-384 over the canonical public key packet, user ID packet,
  │     and positive-certification signature trailer.
  │
  ├─ 4. Prompt user for PIN2 with zeroizing input buffers and retry-counter guard.
  │
  ├─ 5. Drive PSO:CDS on the card via refineid-sign with KEY_REF_SIGN.
  │     Receive raw ECDSA (r || s).
  │
  ├─ 6. Format OpenPGP Tag 2 Signature Packet (positive certification subpacket).
  │
  └─ 7. Ingest into GnuPG via `gpg --import`.
```

### Advantages

- **Zero configuration**: Does not require `gnupg-pkcs11-scd`, `scdaemon`, or
  custom socket configuration.
- **Convenient Daily Development**: Day-to-day git commits use the fast Ed25519
  key (`ed25519/6FF34D6ABBC1B743`).
- **Verifiable Legal Anchor**: Anyone inspecting the GPG key sees a valid
  cryptographic certification issued by the cardholder's national Qualified
  Signature key.

---

## 5. Implementation Roadmap

### Phase 1: OpenPGP Certification CLI (`refineid-unix`)
- Implement OpenPGP packet canonicalization and packet assembly in
  `refineid-client` (or an auxiliary core helper).
- Add the `card sign-pgp-key` CLI verb with PIN2 prompting.
- Validate that `gpg --list-sigs <KEY_ID>` reports the signature from the
  card's qualified key.

### Phase 2: Dual PKCS#11 Library Targets (`refineid-core`)
- Refactor `crates/pkcs11` token state to support configurable profiles:
  `Profile::Auth` and `Profile::Sign`.
- Export two distinct cdylib builds in `Cargo.toml`: `refineid_pkcs11_auth`
  and `refineid_pkcs11_sign`.
- Validate with NSS (`nss_debug`) and OpenSSH.

### Phase 3: OASIS PKCS#11 v3.2 Compliance (`refineid-core`)
- Implement `C_GetInterfaceList` and `C_GetInterface`.
- Expose v3.2 interface structures alongside the existing v2.40 function table.
- Verify compatibility with modern PKCS#11 v3.x test suites.
